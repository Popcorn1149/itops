"""Giám sát tài nguyên CPU / RAM / Disk: phân tích SNMP hrStorage, Windows qua SSH, threshold, API /resources, lịch sử."""
import asyncio

from app import scheduler
from app.collectors.base import apply_resources
from app.collectors.snmp import parse_storage
from app.collectors.ssh import _sections, parse_windows

RAM, VMEM, DISK, OTHER = "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.3", "1.3.6.1.2.1.25.2.1.4", "1.3.6.1.2.1.25.2.1.1"


def test_storage_linux_subtracts_buffers_cache():
    rows = {
        "1": {"type": RAM, "descr": "Physical memory", "unit": 1024, "size": 8_000_000, "used": 6_000_000},
        "6": {"type": OTHER, "descr": "Memory buffers", "unit": 1024, "size": 8_000_000, "used": 500_000},
        "7": {"type": OTHER, "descr": "Cached memory", "unit": 1024, "size": 2_000_000, "used": 1_500_000},
        "10": {"type": VMEM, "descr": "Swap space", "unit": 1024, "size": 2_000_000, "used": 200_000},
        "31": {"type": DISK, "descr": "/", "unit": 4096, "size": 1_000_000, "used": 900_000},
        "35": {"type": DISK, "descr": "/dev/shm", "unit": 4096, "size": 1000, "used": 0},
        "36": {"type": DISK, "descr": "/run", "unit": 4096, "size": 1000, "used": 10},
        "40": {"type": DISK, "descr": "/sys/fs/cgroup", "unit": 4096, "size": 1000, "used": 0},
    }
    st = parse_storage(rows)
    assert round(st["mem"]) == 50          # (6.0 - 0.5 - 1.5) / 8.0
    assert round(st["swap"]) == 10
    assert [d["name"] for d in st["disks"]] == ["/"] and round(st["disks"][0]["pct"]) == 90
    assert st["disks"][0]["size_gb"] == 3.8


def test_storage_pfsense_zfs_dedup_and_int32_overflow():
    from app.collectors.snmp import _u32
    rows = {
        "1": {"type": RAM, "descr": "Physical memory", "unit": 4096, "size": 1_000_000, "used": 300_000},
        "20": {"type": DISK, "descr": "/", "unit": 4096, "size": 5_000_000, "used": 400_000},
        "21": {"type": DISK, "descr": "/tmp", "unit": 4096, "size": 5_000_000, "used": 400_000},     # cùng pool → bỏ
        "22": {"type": DISK, "descr": "/var/log", "unit": 4096, "size": 5_000_000, "used": 400_000},
        "23": {"type": DISK, "descr": "/dev", "unit": 512, "size": 2, "used": 2},                   # devfs → bỏ
        "24": {"type": DISK, "descr": "/big", "unit": 4096, "size": _u32(-294967296), "used": _u32(-1294967296)},
    }
    st = parse_storage(rows)
    names = [d["name"] for d in st["disks"]]
    assert names == ["/", "/big"] and round(st["mem"]) == 30
    big = st["disks"][1]
    assert big["size_gb"] > 15000 and 0 < big["pct"] < 100


def test_storage_windows_drive_names():
    rows = {"1": {"type": DISK, "descr": "C:\\ Label:OS  Serial Number 4a2b", "unit": 4096, "size": 30_000_000, "used": 27_000_000},
            "2": {"type": DISK, "descr": "D:\\ Label:Data  Serial Number 77", "unit": 4096, "size": 100, "used": 10},
            "3": {"type": RAM, "descr": "Physical Memory", "unit": 65536, "size": 262_144, "used": 131_072}}
    st = parse_storage(rows)
    assert [d["name"] for d in st["disks"]] == ["C:", "D:"] and round(st["mem"]) == 50 and st["mem_total_gb"] == 16


def test_windows_ssh_parser():
    out = "##HOST\nFILE-SRV\n##WCPU\n37\n##NPROC\n8\n##WMEM\n16777216 4194304\n##WDISK\nC: 128000000000 12800000000\nD: 4000000000000 400000000000\n##WSVC\nVeeamBackupSvc\n"
    w = parse_windows(_sections(out))
    assert w["cpu"] == 37 and round(w["mem"]) == 75 and round(w["mem_total_gb"]) == 16
    assert [(d["name"], d["pct"]) for d in w["disks"]] == [("C:", 90.0), ("D:", 90.0)]
    assert w["stopped_services"] == ["VeeamBackupSvc"]


def test_thresholds_levels_legacy_and_off():
    data, st, notes = {}, ["ok"], []
    m = apply_resources(data, {}, st, notes, cpu=82, mem=93, disks=[{"name": "/", "pct": 96}, {"name": "/data", "pct": 87}])
    assert m == {"cpu": 82, "mem": 93, "disk": 96}
    assert st == ["ok"]                                   # vượt threshold không làm check lỗi (không trừ uptime)
    assert data["res"]["levels"] == {"cpu": "attention", "mem": "trouble", "disk": "critical"} and data["res"]["level"] == "critical"
    assert any("CPU 82% (Attention ≥ 80%)" in n for n in notes) and any("Ổ khác vượt threshold: /data 87%" in n for n in notes)
    d2 = {}
    apply_resources(d2, {"cpu_attention": 40, "mem_attention": "", "mem_trouble": "", "mem_critical": "", "disk_attention": 0,
                         "disk_trouble": 0, "disk_critical": 0}, [], [], cpu=50, mem=99, disks=[{"name": "/", "pct": 99}])
    assert d2["res"]["levels"] == {"cpu": "attention", "mem": "ok", "disk": "ok"}     # để trống/0 = tắt mức đó
    d3 = {}
    apply_resources(d3, {"datastore_warn": 60}, [], [], disks=[{"name": "ds1", "pct": 70}])
    assert d3["res"]["levels"]["disk"] == "trouble"       # khoá cũ của ESXi: warn → Trouble
    d4 = {}
    apply_resources(d4, {"cpu_warn": 85, "cpu_fail": 95}, [], [], cpu=82)
    assert d4["res"]["levels"]["cpu"] == "ok"             # check cũ chỉ có 2 mức → không tự thêm Attention


def test_resources_api_with_demo_and_history(client, admin, clean):
    from app.db import SessionLocal
    from app.seed import seed_demo
    db = SessionLocal()
    seed_demo(db)
    db.close()
    checks = client.get("/api/checks", headers=admin).json()

    import random
    random.seed(7)   # dữ liệu mẫu có nhiễu ngẫu nhiên → cố định để kết quả ổn định
    async def run_all():
        for _ in range(2):
            for c in checks:
                await scheduler.run_check(c["id"])
    asyncio.run(run_all())

    r = client.get("/api/resources", headers=admin).json()
    names = {x["name"]: x for x in r["rows"]}
    for n in ("pfSense-HQ", "SW-CORE", "ESXi-02", "NAS-Synology", "FILE-SRV", "ERP-DB", "MONITOR", "DC01", "ERP-APP"):
        assert n in names, n
    assert names["ERP-DB"]["levels"]["mem"] == "trouble"                     # 93% (Trouble 92, Critical 97)
    assert names["FILE-SRV"]["disk_name"] == "D:" and names["FILE-SRV"]["levels"]["disk"] == "attention"   # 89%
    assert names["ESXi-02"]["level"] == "trouble" and names["ESXi-02"]["disk_name"] == "ds-ssd"
    assert names["DC01"]["has_history"] is False and names["DC01"]["via"] == "esxi"
    assert r["rows"][0]["level"] != "ok"                  # có vấn đề xếp trước
    assert r["summary"]["mem"]["trouble"] >= 1 and r["problems"] >= 3
    unc = {u["name"] for u in r["uncovered"]}
    assert "UPS-RACK" not in names or "UPS-RACK" not in unc
    assert "TEST-OLD" not in unc                          # VM tắt không bị nhắc

    h = client.get(f"/api/resources/history?check_id={names['ERP-DB']['check_id']}&hours=1", headers=admin).json()
    assert len(h["points"]) == 2 and {"cpu", "mem", "disk"} <= set(h["points"][0])
    assert h["stats"]["mem"]["max"] >= 85

    d = client.get("/api/dashboard", headers=admin).json()["resources"]
    assert d["total"] == r["total"] and d["top"] and d["top"][0]["level"] != "ok"

    # tắt check → thiết bị không còn trong danh sách tài nguyên
    cid = names["ERP-DB"]["check_id"]
    client.put(f"/api/checks/{cid}", headers=admin, json={"enabled": False})
    r2 = client.get("/api/resources", headers=admin).json()
    assert "ERP-DB" not in {x["name"] for x in r2["rows"]}


def test_storage_pfsense_bsnmpd_quirks():
    """bsnmpd (pfSense): 'Real Memory Metrics' = RAM tiến trình dùng; nhiều dòng RAM kernel; disk mang kiểu hrFS*, tên 'mount, type: x, dev: y'."""
    FS_ZFS, FS_UFS = "1.3.6.1.2.1.25.3.9.1", "1.3.6.1.2.1.25.3.9.3"
    rows = {
        "1": {"type": RAM, "descr": "Real Memory Metrics", "unit": 4096, "size": 102_400, "used": 90_000},    # 400 MB
        "2": {"type": RAM, "descr": "Shared Real Memory Metrics", "unit": 4096, "size": 2000, "used": 0},
        "3": {"type": VMEM, "descr": "Swap:/dev/ada0p3", "unit": 4096, "size": 262_144, "used": 2_000},
        "4": {"type": FS_ZFS, "descr": "/, type: zfs, dev: pfSense/ROOT/default", "unit": 4096, "size": 5_000_000, "used": 300_000},
        "5": {"type": FS_ZFS, "descr": "/var/log, type: zfs, dev: pfSense/var/log", "unit": 4096, "size": 4_900_000, "used": 200_000},
        "6": {"type": FS_ZFS, "descr": "/tmp, type: zfs, dev: pfSense/tmp", "unit": 4096, "size": 4_700_100, "used": 100},
        "7": {"type": FS_UFS, "descr": "/dev, type: devfs, dev: devfs", "unit": 512, "size": 2, "used": 2},
        "8": {"type": FS_UFS, "descr": "/boot, type: ufs, dev: /dev/ada0p1", "unit": 4096, "size": 100_000, "used": 50_000},
        "100": {"type": RAM, "descr": "kernel malloc: temp", "unit": 1, "size": 9_000_000_000, "used": 0},
    }
    st = parse_storage(rows, mem_size_kb=2_000_000)   # ~1.9 GB
    assert round(st["mem"]) == 20 and "mem_note" in st
    names = {d["name"]: d for d in st["disks"]}
    assert set(names) == {"/boot", "/ (zfs pfSense)"}
    z = names["/ (zfs pfSense)"]
    assert round(z["pct"]) == round(500_100 / (500_100 + 4_700_000) * 100)
    assert round(st["swap"], 1) == 0.8


FREEBSD_OUT = """##HOST
FW01.Trustifytechnology.com
##OS
pfSense 2.8.1-RELEASE / 15.0-CURRENT
##BOOT
1758000000
1762000000
##NPROC
4
##CPT
1000 0 500 100 8400
1100 0 560 110 8630
##BMEM
hw.physmem 8462000128
hw.pagesize 4096
vm.stats.vm.v_page_count 2000000
vm.stats.vm.v_inactive_count 300000
vm.stats.vm.v_cache_count 0
vm.stats.vm.v_free_count 1100000
##SWAP
2097152 16000
##BDISK
pfSense/ROOT/default zfs 440000000 2000000 438000000 /
pfSense/var/log zfs 438500000 500000 438000000 /var/log
pfSense/tmp zfs 438000100 100 438000000 /tmp
devfs devfs 1 1 0 /dev
/dev/ada0p1 msdosfs 260000 2000 258000 /boot/efi
tmpfs tmpfs 4000 100 3900 /var/run
"""


def test_freebsd_cli_parser_matches_pfsense_dashboard():
    from app.collectors.ssh import parse_freebsd
    b = parse_freebsd(_sections(FREEBSD_OUT))
    assert b["cpu"] == round((1 - 230 / 400) * 100, 1)          # 57.5%
    assert round(b["mem"]) == 30                                # (2.0M − 0.3M − 1.1M) / 2.0M – công thức Dashboard pfSense
    assert round(b["mem_total_gb"]) == 8 and b["nproc"] == 4 and b["uptime_s"] == 4_000_000
    names = {d["name"]: d for d in b["disks"]}
    assert set(names) == {"/boot/efi", "/ (zfs pfSense)"}
    assert round(names["/ (zfs pfSense)"]["size_gb"]) == 420     # ~ 440 GB (đơn vị KB)
    assert round(b["swap"], 1) == 0.8


def test_pfsense_snmp_plus_cli(monkeypatch):
    import importlib
    pf = importlib.import_module("app.collectors.pfsense")
    from app.collectors.base import Result
    calls = {}

    async def fake_snmp(target, cfg):
        calls["resources"] = cfg.get("resources")
        return Result("ok", "FW01 · 25/25 cổng up · WAN 4/4", None, None, {"ports_total": 25})

    async def fake_cli(host, cfg, prefix=""):
        calls["host"], calls["user"] = host, cfg.get(prefix + "username")
        from app.collectors.ssh import parse_freebsd
        return parse_freebsd(_sections(FREEBSD_OUT))
    monkeypatch.setattr(pf, "snmp_collect", fake_snmp)
    monkeypatch.setattr(pf, "freebsd_resources", fake_cli)
    r = asyncio.run(pf.pfsense("172.17.11.1", {"mode": "snmp", "cli_enabled": True, "cli_username": "admin", "cli_password": "x"}))
    assert calls == {"resources": False, "host": "172.17.11.1", "user": "admin"}
    assert r.status == "ok" and "RAM 30" in r.message and "WAN 4/4" in r.message
    assert r.data["res"]["source"] == "CLI (SSH)" and r.data["res"]["mem_total_gb"] == 7.9 and r.data["ports_total"] == 25

    async def bad_cli(host, cfg, prefix=""):
        raise OSError("Permission denied")
    monkeypatch.setattr(pf, "freebsd_resources", bad_cli)
    r2 = asyncio.run(pf.pfsense("172.17.11.1", {"mode": "snmp", "cli_enabled": True}))
    assert r2.status == "warn" and "CLI lỗi" in r2.message


# ---------------------------------------------------------------- Đường Internet + status site/API
def test_ping_samples_and_jitter():
    from app.collectors.network import ping_samples, jitter
    lin = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.2 ms\n64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.2 ms\n64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=12.2 ms"
    win = "Reply from 8.8.8.8: bytes=32 time=31ms TTL=117\nReply from 8.8.8.8: bytes=32 time<1ms TTL=117"
    vi = "Trả lời từ 8.8.8.8: byte=32 thời gian=30ms TTL=117\nTrả lời từ 8.8.8.8: byte=32 thời gian=34ms TTL=117"
    assert ping_samples(lin) == [10.2, 14.2, 12.2] and jitter([10.2, 14.2, 12.2]) == 3.0
    assert ping_samples(win) == [31.0, 1.0] and ping_samples(vi) == [30.0, 34.0]
    assert jitter([5.0]) is None


def _inet(monkeypatch, pings, dns_ok=True, http_ok=True, ip="1.2.3.4"):
    import importlib
    n = importlib.import_module("app.collectors.network")

    async def fp(t, c, to):
        return {"target": t, **pings[t]}

    async def fd(name, to):
        return {"name": name, "ok": dns_ok, "ms": 12.0, "addr": "142.250.1.1"} if dns_ok else {"name": name, "ok": False, "error": "gaierror"}

    async def fh(url, to):
        return {"url": url, "ok": http_ok, "code": 204 if http_ok else None, "ms": 40.0, **({} if http_ok else {"error": "ConnectError"})}

    async def fi(to):
        return ip
    monkeypatch.setattr(n, "_ping_one", fp)
    monkeypatch.setattr(n, "_dns", fd)
    monkeypatch.setattr(n, "_http_probe", fh)
    monkeypatch.setattr(n, "_public_ip", fi)
    return n


def test_internet_check_states(monkeypatch):
    ok = {"loss": 0.0, "rtt": 9.0, "jitter": 1.0}
    dead = {"loss": 100.0, "rtt": None, "jitter": None}
    n = _inet(monkeypatch, {"1.1.1.1": ok, "8.8.8.8": {**ok, "rtt": 30.0}})
    n._LAST_PUBLIC_IP.clear()
    r = asyncio.run(n.internet("1.1.1.1, 8.8.8.8", {}))
    assert r.status == "ok" and r.latency == 9.0 and "IP 1.2.3.4" in r.message and r.data["reachable"] == 2

    n = _inet(monkeypatch, {"1.1.1.1": ok, "8.8.8.8": {**ok, "rtt": 30.0}}, ip="5.6.7.8")
    r = asyncio.run(n.internet("1.1.1.1, 8.8.8.8", {}))
    assert r.status == "warn" and "đổi đường ra: 1.2.3.4 → 5.6.7.8" in r.message          # WAN failover

    n = _inet(monkeypatch, {"1.1.1.1": ok, "8.8.8.8": dead}, ip=None)
    r = asyncio.run(n.internet("1.1.1.1, 8.8.8.8", {"public_ip": False}))
    assert r.status == "warn" and "1/2 đích không phản hồi: 8.8.8.8" in r.message

    n = _inet(monkeypatch, {"1.1.1.1": {"loss": 40.0, "rtt": 220.0, "jitter": 55.0}})
    r = asyncio.run(n.internet("1.1.1.1", {"public_ip": False}))
    assert r.status == "warn" and "độ trễ cao" in r.message and "jitter 55" in r.message

    n = _inet(monkeypatch, {"1.1.1.1": dead}, dns_ok=True, http_ok=True)
    r = asyncio.run(n.internet("1.1.1.1", {"public_ip": False}))
    assert r.status == "warn" and "ICMP bị chặn" in r.message                              # ping bị chặn nhưng web vẫn ra được

    n = _inet(monkeypatch, {"1.1.1.1": dead, "8.8.8.8": dead}, dns_ok=False, http_ok=False)
    r = asyncio.run(n.internet("1.1.1.1, 8.8.8.8", {"public_ip": False}))
    assert r.status == "fail" and r.message.startswith("Mất Internet")


def test_internet_real_ping_localhost():
    """Ping thật: 127.0.0.1 phản hồi, tên miền .invalid (không tồn tại theo RFC 6761) thì không."""
    from app.collectors.network import internet
    r = asyncio.run(internet("127.0.0.1, khong-ton-tai.invalid", {"count": 2, "timeout": 1, "dns_name": "", "http_url": "", "public_ip": False}))
    t = {x["target"]: x for x in r.data["targets"]}
    assert t["127.0.0.1"]["loss"] == 0 and t["127.0.0.1"]["rtt"] is not None
    assert t["khong-ton-tai.invalid"]["loss"] == 100 and r.status == "warn"


def test_site_health_map_internet_and_api_health(client, admin, clean):
    topo = client.get("/api/topology", headers=admin).json()["tree"]
    assert topo["status"] == "unknown" and topo["sub"] == "chưa gán Line Internet"    # chưa có line → không tô xanh
    h = client.get("/api/health").json()
    assert h["db"] is True and h["scheduler"] in ("off", "ok", "starting") and "receivers_ok" in h
    s1 = client.post("/api/sites", headers=admin, json={"name": "Site trống"}).json()
    s2 = client.post("/api/sites", headers=admin, json={"name": "HQ"}).json()
    c = client.post("/api/checks", headers=admin, json={"name": "Internet HQ", "type": "internet", "target": "1.1.1.1", "site_id": s2["id"],
                                                       "interval": 30, "config": {"demo": True, "demo_status": "fail", "demo_message": "Mất Internet"}}).json()
    sites = {x["name"]: x for x in client.get("/api/sites", headers=admin).json()}
    assert sites["Site trống"]["health"] == "unmonitored"
    assert sites["HQ"]["internet"][0]["name"] == "Internet HQ"
    asyncio.run(scheduler.run_check(c["id"]))
    topo = client.get("/api/topology", headers=admin).json()["tree"]
    assert topo["status"] == "down" and topo["sub"] == "0/1 line · 1 down"
    sn = {x["name"]: x for x in topo["children"]}
    assert sn["HQ"]["status"] == "down" and sn["Site trống"]["sub"] == "chưa giám sát" and sn["Site trống"]["status"] == "unknown"
    assert {x["name"]: x for x in client.get("/api/sites", headers=admin).json()}["HQ"]["health"] == "fail"
    _ = s1


def test_cpu_levels_rearm_and_uptime_not_affected(client, admin, clean, monkeypatch):
    """Kịch bản FW01: CPU dao động 82–96%. Không được có 'DOWN', uptime vẫn 100%, cảnh báo chỉ đóng khi < Rearm (75%)."""
    from app import scheduler as sch
    from app.collectors import COLLECTORS
    from app.collectors.base import Result
    seq = iter([50, 82, 91, 96, 88, 78, 74, None])

    async def fake(target, cfg):
        v = next(seq)
        if v is None:
            return Result("fail", "SNMP không phản hồi")           # mất kết nối thật
        data, notes = {}, []
        apply_resources(data, cfg, [], notes, cpu=v)
        return Result("ok", "FW · " + " · ".join(notes), 2, v, data)
    monkeypatch.setitem(COLLECTORS, "snmp", fake)
    s = client.post("/api/sites", headers=admin, json={"name": "HQ"}).json()
    a = client.post("/api/assets", headers=admin, json={"name": "FW01", "type": "firewall", "site_id": s["id"]}).json()
    c = client.post("/api/checks", headers=admin, json={"name": "FW-Core", "type": "snmp", "target": "10.0.0.1", "asset_id": a["id"],
                                                       "enabled": False, "config": {"alert_after": 2}}).json()
    cpu_alert = lambda: [x for x in client.get("/api/alerts", headers=admin).json() if x.get("metric") == "cpu"]  # noqa: E731

    def step():
        return asyncio.run(sch.run_check(c["id"]))
    assert step()["severity"] is None                                   # 50%
    r = step()                                                          # 82% → Attention, mới 1 lần
    assert r["severity"] == "attention" and r["status"] == "warn" and cpu_alert() == []
    step()                                                              # 91% → Trouble, đủ 2 lần → mở
    al = cpu_alert()
    assert len(al) == 1 and al[0]["severity"] == "trouble" and "Trouble" in al[0]["title"] and "DOWN" not in al[0]["title"]
    assert client.get(f"/api/assets/{a['id']}", headers=admin).json()["status"] == "warning"     # không phải down
    step()                                                              # 96% → Critical
    assert cpu_alert()[0]["severity"] == "critical"
    step(); step()                                                      # 88%, 78% (dưới Attention nhưng ≥ Rearm 75) → vẫn mở
    al = cpu_alert()
    assert len(al) == 1 and "Rearm" in al[0]["message"]
    step()                                                              # 74% < Rearm → đóng
    assert cpu_alert() == []
    lst = next(x for x in client.get("/api/checks", headers=admin).json() if x["id"] == c["id"])
    assert lst["uptime_24h"] == 100.0                                   # vượt threshold không trừ uptime
    assert not [x for x in client.get("/api/alerts", headers=admin).json() if "DOWN" in x["title"]]
    r = step()                                                          # mất kết nối thật (lần 1)
    assert r["severity"] == "down" and r["down"] is True
    lst = next(x for x in client.get("/api/checks", headers=admin).json() if x["id"] == c["id"])
    assert lst["uptime_24h"] == 87.5                                    # 7/8 lần không DOWN
    assert client.get(f"/api/assets/{a['id']}", headers=admin).json()["status"] == "down"


def test_map_counts_internet_lines(client, admin, clean):
    """Mỗi check gán "Line Internet" = 1 line. x/y = số line không DOWN / tổng. Không tự đoán, WAN của firewall không tính."""
    from app.db import SessionLocal
    from app import models
    s = client.post("/api/sites", headers=admin, json={"name": "Trustifytechnology"}).json()
    fw = client.post("/api/assets", headers=admin, json={"name": "FW-Core", "type": "firewall", "site_id": s["id"]}).json()

    def chk(name, typ, target, **cfg):
        return client.post("/api/checks", headers=admin, json={"name": name, "type": typ, "target": target, "site_id": s["id"],
                                                              "asset_id": fw["id"], "enabled": False, "config": cfg}).json()["id"]
    l1 = chk("Line VNPT", "ping", "113.161.119.25", map_role="wan")
    l2 = chk("Line FPT", "internet", "1.1.1.1")
    l3 = chk("Line Viettel", "ping", "27.72.1.1", map_role="wan")
    l4 = chk("Line CMC", "ping", "203.205.1.1", map_role="wan")
    gw = chk("Ping gateway nhà mạng (chưa gán)", "ping", "14.160.1.1")         # IP public nhưng KHÔNG gán → không tính
    snmp = chk("FW-Core (pfsense)", "pfsense", "172.17.11.1", mode="snmp")
    db = SessionLocal()

    def set_state(states):
        for cid, st, sev in states:
            c = db.get(models.Check, cid)
            c.enabled, c.status, c.severity, c.last_latency = True, st, sev, 3.0
            c.last_data = {"latency_ms": 9.0} if c.type == "internet" else ({"wan_up": 4, "wan_total": 4} if c.type == "pfsense" else {"loss": 0})
        db.commit()

    def site_sub():
        topo = client.get("/api/topology", headers=admin).json()["tree"]
        sn = next(x for x in topo["children"] if x["site_id"] == s["id"])
        return sn["status"], sn["sub"], topo["sub"]
    set_state([(l1, "ok", None), (l2, "ok", None), (l3, "ok", None), (l4, "ok", None), (gw, "ok", None), (snmp, "ok", None)])
    checks = {c["name"]: c for c in client.get("/api/checks", headers=admin).json()}
    assert checks["Line VNPT"]["wan_role"] and checks["Ping gateway nhà mạng (chưa gán)"]["wan_role"] is None
    assert checks["Ping gateway nhà mạng (chưa gán)"]["line_suggest"] is True                  # chỉ gợi ý
    assert site_sub() == ("up", "Internet 4/4 line", "4/4 line")
    set_state([(l3, "fail", "down"), (l4, "fail", "down")])
    assert site_sub() == ("warning", "Internet 2/4 line · 2 down", "2/4 line · 2 down")
    set_state([(l1, "fail", "down"), (l2, "fail", "down")])
    assert site_sub()[0] == "down" and site_sub()[1] == "Internet 0/4 line · 4 down"
    site = next(x for x in client.get("/api/sites", headers=admin).json() if x["id"] == s["id"])
    assert [x["name"] for x in site["internet"]] == ["Line CMC", "Line FPT", "Line VNPT", "Line Viettel"]
    db.close()
