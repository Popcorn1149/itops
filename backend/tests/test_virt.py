"""Host ảo hoá: Proxmox API (mock), Hyper-V qua SSH (parse), tổng hợp machines ảo trên host (/api/assets/{id}/guests)."""
import asyncio
import json
import time

import httpx
import pytest

from app import models, scheduler
import importlib
P = importlib.import_module("app.collectors.proxmox")
from app.collectors.ssh import parse_hyperv
from app.db import SessionLocal

GB = 1073741824
NOW = int(time.time())
ROUTES = {
    "/api2/json/version": {"version": "8.2.4"},
    "/api2/json/nodes": [{"node": "pve1", "status": "online", "cpu": 0.25, "maxcpu": 32, "mem": 64 * GB, "maxmem": 128 * GB, "uptime": 86400}],
    "/api2/json/nodes/pve1/status": {"cpuinfo": {"model": "AMD EPYC 7302P", "cpus": 32, "sockets": 1}, "pveversion": "pve-manager/8.2.4",
                                     "rootfs": {"total": 100 * GB, "used": 40 * GB}},
    "/api2/json/nodes/pve1/storage": [{"storage": "local-lvm", "type": "lvmthin", "active": 1, "total": 1000 * GB, "used": 920 * GB},
                                      {"storage": "nfs-off", "active": 0}],
    "/api2/json/nodes/pve1/qemu": [
        {"vmid": 100, "name": "gitlab", "status": "running", "cpu": 0.34, "cpus": 8, "mem": 12 * GB, "maxmem": 16 * GB, "maxdisk": 200 * GB, "uptime": 3600},
        {"vmid": 101, "name": "old-win", "status": "stopped", "cpus": 4, "maxmem": 8 * GB, "maxdisk": 100 * GB},
        {"vmid": 900, "name": "tmpl", "status": "stopped", "template": 1}],
    "/api2/json/nodes/pve1/lxc": [{"vmid": 200, "name": "pihole", "status": "running", "cpu": 0.02, "cpus": 1, "mem": 200 * 1048576,
                                   "maxmem": 512 * 1048576, "disk": 2 * GB, "maxdisk": 8 * GB, "uptime": 7200}],
    "/api2/json/nodes/pve1/qemu/100/snapshot": [{"name": "before-upgrade", "snaptime": NOW - 20 * 86400}, {"name": "current"}],
    "/api2/json/nodes/pve1/qemu/101/snapshot": [{"name": "current"}],
    "/api2/json/nodes/pve1/lxc/200/snapshot": [{"name": "current"}],
    "/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces": {"result": [
        {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
        {"name": "eth0", "ip-addresses": [{"ip-address": "10.0.21.10", "ip-address-type": "ipv4"}, {"ip-address": "fe80::1", "ip-address-type": "ipv6"}]}]},
    "/api2/json/nodes/pve1/qemu/100/agent/get-fsinfo": {"result": [
        {"mountpoint": "/", "type": "ext4", "total-bytes": 100 * GB, "used-bytes": 63 * GB}]},
}


@pytest.fixture
def pve(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["auth"] = req.headers.get("Authorization")
        if req.url.path in ROUTES:
            return httpx.Response(200, json={"data": ROUTES[req.url.path]})
        return httpx.Response(403 if "agent" in req.url.path else 404, json={"data": None})
    real = httpx.AsyncClient
    monkeypatch.setattr(P.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return seen


def test_proxmox_collector(pve):
    r = asyncio.run(P.proxmox("10.0.10.21", {"token_id": "itops@pve!mon", "token_secret": "s3cret", "snapshot_warn_days": 7}))
    assert pve["auth"] == "PVEAPIToken=itops@pve!mon=s3cret"
    assert r.status == "warn", r.message                      # snapshot 20 days + storage 92%
    assert "1/2 running VMs" in r.message and "1/1 LXC" in r.message
    keys = {d["key"]: d for d in r.discovered}
    assert set(keys) == {"pve:pve1", "pve:pve1:100", "pve:pve1:101", "pve:pve1:200"}, "bỏ template"
    host = keys["pve:pve1"]
    assert host["type"] == "host" and host["meta"]["cores"] == 32 and host["meta"]["res"]["cpu"] == 25.0
    g = keys["pve:pve1:100"]["meta"]
    assert keys["pve:pve1:100"]["ip"] == "10.0.21.10" and g["snapshots"] == 1 and g["oldest_snapshot_days"] == 20
    assert g["res"]["cpu"] == 34.0 and g["res"]["mem"] == 75.0 and g["res"]["disk"] == 63.0
    assert keys["pve:pve1:101"]["status"] == "off" and keys["pve:pve1:101"]["meta"]["res"] is None
    lxc = keys["pve:pve1:200"]
    assert lxc["type"] == "container" and lxc["meta"]["kind"] == "lxc" and lxc["meta"]["res"]["disk"] == 25.0
    assert r.data["res"]["disk"] == 92.0, "storage đang hoạt động; storage tắt bị bỏ qua"


def test_proxmox_auth_error(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(P.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(lambda req: httpx.Response(401)), **kw))
    r = asyncio.run(P.proxmox("10.0.10.21", {"token_id": "a@pve!b", "token_secret": "x"}))
    assert r.status == "fail" and "401" in r.message and r.down is False
    r2 = asyncio.run(P.proxmox("10.0.10.21", {}))
    assert r2.status == "fail" and "token" in r2.message


def test_hyperv_parse():
    js = {"host": {"cores": 24, "mem": 128 * GB}, "vms": [
        {"name": "SQL01", "id": "a1", "state": "Running", "cpu": 12, "vcpu": 8, "mem_assigned": 16 * GB, "mem_demand": 12 * GB, "mem_startup": 16 * GB,
         "uptime": 5000, "gen": 2, "ips": ["10.1.1.5", "fe80::1"], "snaps": 2, "oldest": 30, "heartbeat": "OkApplicationsHealthy",
         "vhd_size": 200 * GB, "vhd_file": 80 * GB},
        {"name": "LAB", "id": "b2", "state": "Off", "vcpu": 2, "mem_assigned": 0, "mem_startup": 4 * GB, "ips": [], "snaps": 0}]}
    vms, host, notes = parse_hyperv("noise\n##HV " + json.dumps(js))
    assert host == {"cores": 24, "mem_gb": 128}
    s = {v["name"]: v for v in vms}
    assert s["SQL01"]["status"] == "up" and s["SQL01"]["meta"]["res"]["mem"] == 75.0 and s["SQL01"]["meta"]["mem_mb"] == 16384
    assert s["LAB"]["status"] == "off" and s["LAB"]["meta"]["mem_mb"] == 4096 and s["LAB"]["meta"]["res"] is None
    assert any("SQL01" in n and "30 days" in n for n in notes)
    assert parse_hyperv("")[2], "không có Hyper-V → ghi chú lý do"


def test_guests_view_api(client, admin, clean, pve):
    host = client.post("/api/assets", json={"name": "PVE-T", "type": "host", "ip": "10.0.10.21"}, headers=admin).json()
    with SessionLocal() as db:
        chk = models.Check(name="pve", type="proxmox", target="10.0.10.21", asset_id=host["id"], config={})
        db.add(chk)
        db.commit()
        r = asyncio.run(P.proxmox("10.0.10.21", {"token_id": "a@pve!b", "token_secret": "x"}))
        scheduler._sync_discovered(db, chk, r.discovered)
        db.commit()
    g = client.get(f"/api/assets/{host['id']}/guests", headers=admin).json()
    s = g["summary"]
    assert s["total"] == 3 and s["running"] == 2 and s["vms"] == 2 and s["containers"] == 1
    assert s["vcpu_alloc"] == 9 and g["host"]["cores"] == 32 and s["vcpu_ratio"] == 0.28
    assert s["mem_alloc_gb"] == 16.5 and s["old_snapshots"] == 1
    assert g["platforms"] == ["Proxmox VE"]
    assert g["guests"][0]["name"] == "gitlab", "đang chạy, CPU cao nhất lên đầu"
    gl = g["guests"][0]   # dạng "đang dùng / được cấp"
    assert (gl["cpu_used"], gl["cpu_total"]) == (2.72, 8)
    assert (gl["mem_used_gb"], gl["mem_total_gb"]) == (12.0, 16.0)
    assert (gl["disk_used_gb"], gl["disk_total_gb"]) == (63.0, 100.0)
    off = next(r for r in g["guests"] if r["name"] == "old-win")
    assert off["mem_used_gb"] is None and off["mem_total_gb"] == 8.0 and off["disk_total_gb"] == 100.0, "VM tắt: chỉ có phần cấp"
    lst = {a["id"]: a for a in client.get("/api/assets?type=host", headers=admin).json()}
    assert lst[host["id"]]["guests"] == {"total": 3, "running": 2}


def test_esxi_vm_inventory_over_snmp(client, admin, clean):
    S = importlib.import_module("app.collectors.snmp")
    rows = {"2.1": "DC01", "3.1": "[ds1] DC01/DC01.vmx", "4.1": "Microsoft Windows Server 2022", "5.1": 8192, "6.1": "poweredOn", "9.1": 4, "10.1": "564d-aa",
            "2.2": "WEB", "5.2": 4096, "6.2": "poweredOn", "9.2": 2, "10.2": "564d-bb",
            "2.3": "OLD", "5.3": 2048, "6.3": "poweredOff", "8.3": "notRunning", "9.3": 1, "10.3": "564d-cc"}
    vms = S.parse_vminfo(rows)
    assert [(v["name"], v["status"]) for v in vms] == [("DC01", "up"), ("WEB", "up"), ("OLD", "off")]
    host = client.post("/api/assets", json={"name": "SVR-T", "type": "host", "ip": "10.0.20.2"}, headers=admin).json()
    with SessionLocal() as db:
        chk = models.Check(name="snmp", type="snmp", target="10.0.20.2", asset_id=host["id"], config={})
        db.add(chk)
        db.commit()
        scheduler._sync_discovered(db, chk, vms)
        db.commit()
    g = client.get(f"/api/assets/{host['id']}/guests", headers=admin).json()
    assert g["summary"]["total"] == 3 and g["summary"]["running"] == 2 and g["summary"]["vcpu_alloc"] == 6
    assert g["platforms"] == ["VMware ESXi"]
    assert g["summary"]["allocation_only"] is True, "chỉ SNMP → chỉ có cấp phát"


def test_snmp_and_api_do_not_duplicate_vms(client, admin, clean):
    S = importlib.import_module("app.collectors.snmp")
    host = client.post("/api/assets", json={"name": "SVR-D", "type": "host", "ip": "10.0.20.9"}, headers=admin).json()
    snmp_vms = S.parse_vminfo({"2.1": "DC01", "6.1": "poweredOn", "9.1": 4, "5.1": 8192, "10.1": "u1",
                               "2.2": "OLD", "6.2": "poweredOff", "9.2": 1, "5.2": 1024, "10.2": "u2"})
    with SessionLocal() as db:
        c_snmp = models.Check(name="snmp", type="snmp", target="10.0.20.9", asset_id=host["id"], config={})
        db.add(c_snmp); db.commit()
        scheduler._sync_discovered(db, c_snmp, snmp_vms); db.commit()
        # thêm check ESXi API: nhận lại VM đã có (cùng tên), không tạo bản trùng
        c_api = models.Check(name="esxi", type="esxi", target="10.0.20.9", asset_id=host["id"], config={})
        db.add(c_api); db.commit()
        api_items = [{"key": "host:ha-host", "type": "host", "name": "SVR-D", "status": "up", "meta": {"platform": "esxi", "cores": 24, "mem_gb": 144}},
                     {"key": "vm:1", "parent_key": "host:ha-host", "type": "vm", "name": "DC01", "status": "up",
                      "meta": {"platform": "esxi", "via": "api", "power": "poweredOn", "vcpu": 4, "mem_mb": 8192, "res": {"cpu": 12, "mem": 40}}},
                     {"key": "vm:2", "parent_key": "host:ha-host", "type": "vm", "name": "OLD", "status": "off",
                      "meta": {"platform": "esxi", "via": "api", "power": "poweredOff", "vcpu": 1, "mem_mb": 1024}}]
        scheduler._sync_discovered(db, c_api, api_items); db.commit()
        scheduler._sync_discovered(db, c_snmp, snmp_vms); db.commit()   # SNMP chạy tiếp: bỏ qua vì đã có check ESXi
    g = client.get(f"/api/assets/{host['id']}/guests", headers=admin).json()
    names = sorted(r["name"] for r in g["guests"])
    assert names == ["DC01", "OLD"], names
    assert g["summary"]["running"] == 1 and g["guests"][0]["cpu"] == 12
    assert g["summary"]["allocation_only"] is False, "sau khi có ESXi API thì có số liệu sử dụng"


def test_missing_vm_not_counted(client, admin, clean):
    host = client.post("/api/assets", json={"name": "SVR-M", "type": "host"}, headers=admin).json()
    with SessionLocal() as db:
        chk = models.Check(name="snmp", type="snmp", target="x", asset_id=host["id"], config={})
        db.add(chk); db.commit()
        S = importlib.import_module("app.collectors.snmp")
        scheduler._sync_discovered(db, chk, S.parse_vminfo({"2.1": "A", "6.1": "poweredOn", "10.1": "a", "2.2": "B", "6.2": "poweredOn", "10.2": "b"})); db.commit()
        scheduler._sync_discovered(db, chk, S.parse_vminfo({"2.1": "A", "6.1": "poweredOn", "10.1": "a"})); db.commit()   # B bị xoá khỏi ESXi
    g = client.get(f"/api/assets/{host['id']}/guests", headers=admin).json()
    assert g["summary"]["total"] == 1 and g["summary"]["missing"] == 1 and g["guests"][-1]["missing"] is True
    lst = {a["id"]: a for a in client.get("/api/assets?type=host", headers=admin).json()}
    assert lst[host["id"]]["guests"] == {"total": 1, "running": 1}


def test_snmp_check_merges_esxi_api_perf(monkeypatch):
    S = importlib.import_module("app.collectors.snmp")
    E = importlib.import_module("app.collectors.esxi")
    from app.collectors.base import Result
    seen = {}

    async def fake_esxi(target, cfg):
        seen.update(cfg)
        return Result("ok", "ok", discovered=[
            {"key": "host:h", "type": "host", "name": "SVR"},
            {"key": "vm:1", "parent_key": "host:h", "type": "vm", "name": "AC.Door", "ip": "10.0.20.11", "os": "Microsoft Windows Server 2012 R2 (64-bit)",
             "meta": {"res": {"cpu": 7.5, "mem": 41.0, "disk": 63.2, "disk_name": "C:\\\\"}, "tools": "guestToolsRunning", "uptime_s": 3600, "snapshots": 2}}])
    monkeypatch.setattr(E, "esxi", fake_esxi)
    vms = S.parse_vminfo({"2.1": "AC.Door", "6.1": "poweredOn", "9.1": 8, "5.1": 4096, "10.1": "u1",
                          "2.2": "FW.Test", "6.2": "poweredOff", "9.2": 4, "5.2": 2048, "10.2": "u2"})
    note = asyncio.run(S._merge_esxi_perf("10.0.20.2", {"esxi_user": "ro", "esxi_password": "p"}, vms))
    assert note == "performance data retrieved for 1/2 VMs via API" and seen["username"] == "ro"
    ac = vms[0]
    assert ac["meta"]["res"]["cpu"] == 7.5 and ac["ip"] == "10.0.20.11" and ac["meta"]["vcpu"] == 8, "preserve SNMP inventory and merge API performance data"
    assert "snapshots" not in ac["meta"]
    assert ac["key"] == "vmw:u1", "preserve the SNMP key to avoid changing the asset identity"


def test_esxi_credentials_endpoint(client, admin, clean, monkeypatch):
    from app import main, security
    host = client.post("/api/assets", json={"name": "SVR-C", "type": "host", "ip": "10.0.20.2"}, headers=admin).json()
    with SessionLocal() as db:
        chk = models.Check(name="SVR-C (SNMP)", type="snmp", target="10.0.20.2", asset_id=host["id"],
                           config=security.seal_config({"community": "pub", "vm_inventory": True}),
                           last_data={"vm_inventory": {"rows": 10, "vms": 2}, "vms": {"total": 2, "on": 1}})
        db.add(chk); db.commit()
        cid = chk.id
    calls = []

    async def fake_run(c):
        calls.append(c)
        return None if len(calls) == 1 else {"status": "ok"}   # lần đầu: check đang chạy theo lịch → phải chờ rồi chạy lại
    monkeypatch.setattr(main, "run_check", fake_run)
    g = client.get(f"/api/assets/{host['id']}/guests", headers=admin).json()
    assert g["perf"]["check_id"] == cid and g["perf"]["has_credentials"] is False
    r = client.post(f"/api/assets/{host['id']}/esxi-credentials", json={"user": "ro", "password": "s3cret"}, headers=admin)
    assert r.status_code == 200 and calls == [cid, cid]
    with SessionLocal() as db:
        cfg = security.open_config(db.get(models.Check, cid).config)
    assert cfg["esxi_user"] == "ro" and cfg["esxi_password"] == "s3cret" and cfg["community"] == "pub", "password mã hoá, bí mật cũ giữ nguyên"
    # đổi user, để trống password → giữ password cũ
    client.post(f"/api/assets/{host['id']}/esxi-credentials", json={"user": "ro2", "password": ""}, headers=admin)
    with SessionLocal() as db:
        cfg = security.open_config(db.get(models.Check, cid).config)
    assert cfg["esxi_user"] == "ro2" and cfg["esxi_password"] == "s3cret"
    assert client.get(f"/api/checks/{cid}", headers=admin).json()["config"]["esxi_password"] != "s3cret", "API không trả password"


def test_esxi_api_inventory_fallback_returns_success_note(monkeypatch):
    S = importlib.import_module("app.collectors.snmp")
    E = importlib.import_module("app.collectors.esxi")
    from app.collectors.base import Result

    async def fake_esxi(target, cfg):
        return Result("ok", "ok", discovered=[
            {"key": "vm:1", "type": "vm", "name": "APP01", "ip": "10.0.20.11", "meta": {"res": {"cpu": 12.0}}}
        ])

    monkeypatch.setattr(E, "esxi", fake_esxi)
    result = asyncio.run(S._merge_esxi_perf("10.0.20.2", {"esxi_user": "ro", "esxi_password": "secret"}, []))
    assert isinstance(result, list) and result[0]["name"] == "APP01"
    note = "performance data retrieved via API (SNMP VM inventory was empty)"
    assert S._esxi_perf_succeeded(note) is True
    assert S._esxi_perf_succeeded("API ESXi error: TimeoutError") is False
