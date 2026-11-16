"""2.10.0 – Network traffic (NetFlow / IPFIX through GoFlow2)."""
import json
import os
import sys
import time
from datetime import timedelta

import pytest
from sqlalchemy import text

from app import flows, models
from app.db import SessionLocal
from app.models import now

FW = "172.17.15.1"
NOW_NS = lambda: int(time.time() * 1e9)  # noqa: E731


def rec(src, dst, sp=51000, dp=443, proto="TCP", b=1000, pk=10, ifx=15, exp=FW, t_ns=None, rate=1):
    return {"type": "IPFIX", "time_received_ns": t_ns or NOW_NS(), "sampling_rate": rate, "sampler_address": exp,
            "bytes": b, "packets": pk, "etype": "IPv4", "proto": proto, "src_addr": src, "dst_addr": dst,
            "src_port": sp, "dst_port": dp, "in_if": ifx, "out_if": ifx, "tcp_flags": 24}


NETS = flows.Nets(flows.DEFAULT_LOCAL)


@pytest.fixture
def fresh():
    with SessionLocal() as db:
        db.execute(text("delete from flow_1m; delete from flow_1h; delete from flow_exporters"))
        db.execute(text("delete from settings where key in ('flow', 'flow_rollup')"))
        db.execute(text("delete from alerts where source = 'flow'"))
        db.commit()
    flows.AGG.__init__()
    flows.COLLECTOR.stop()
    flows.COLLECTOR.__init__()
    yield
    flows.COLLECTOR.stop()
    os.environ.pop("FLOW_COLLECTOR_CMD", None)


# ---------------------------------------------------------------- normalising
def test_normalise_directions_and_ports():
    o = flows.normalise(rec("192.168.80.5", "142.250.1.1", 51000, 443, b=500), NETS)
    assert o[2:12] == (15, "192.168.80.5", "142.250.1.1", 6, 443, "o", 500, 0, 10, 0)
    i = flows.normalise(rec("142.250.1.1", "192.168.80.5", 443, 51000, b=9000), NETS)
    assert i[3:9] == ("192.168.80.5", "142.250.1.1", 6, 443, "o", 0) and i[9] == 9000     # same conversation row, download side
    loc = flows.normalise(rec("172.17.11.33", "172.17.13.26", 445, 50111, b=700), NETS)
    assert loc[3:8] == ("172.17.11.33", "172.17.13.26", 6, 445, "l")
    rev = flows.normalise(rec("172.17.13.26", "172.17.11.33", 50111, 445, b=70), NETS)
    assert rev[3:5] == loc[3:5] and rev[8:10] == (0, 70)                                      # one row per pair
    assert flows.normalise(rec("113.161.39.166", "8.8.8.8"), NETS) == "transit"               # WAN copy after NAT
    assert flows.normalise({"src_addr": "", "dst_addr": "1.1.1.1"}, NETS) == "bad"


def test_normalise_protocol_names_mapped_ipv4_and_sampling():
    r = flows.normalise(rec("::ffff:192.168.1.9", "8.8.8.8", 53000, 53, proto="UDP", b=100, rate=10, exp="::ffff:172.17.15.1"), NETS)
    assert r[1] == FW and r[3] == "192.168.1.9" and r[5] == 17 and r[6] == 53 and r[8] == 1000
    assert flows.normalise(rec("192.168.1.9", "8.8.8.8", 0, 0, proto="HOPOPT"), NETS)[5] == 0      # softflowd ICMP bug
    assert flows.normalise(rec("192.168.1.9", "8.8.8.8", 0, 0, proto="ICMP"), NETS)[6] == 0


def test_aggregator_sums_and_counts_local_once():
    a = flows.Aggregator()
    t = NOW_NS() - 120 * 10**9
    for _ in range(3):
        a.add(rec("192.168.80.5", "142.250.1.1", b=100, t_ns=t), NETS)
    a.add(rec("142.250.1.1", "192.168.80.5", 443, 51000, b=5000, t_ns=t), NETS)
    a.add(rec("172.17.11.33", "172.17.13.26", 445, 50111, b=700, ifx=13, t_ns=t), NETS)
    a.add(rec("172.17.11.33", "172.17.13.26", 445, 50111, b=700, ifx=14, t_ns=t), NETS)   # same packets seen on the 2nd VLAN
    a.add(rec("8.8.8.8", "1.1.1.1", t_ns=t), NETS)
    a.add_line("not json", NETS)
    a.add_line("{broken", NETS)
    two = json.dumps(rec("192.168.80.5", "142.250.1.1", b=100, t_ns=t))
    a.add_line(two + two + "\n", NETS)            # GoFlow2 workers wrote two records on one line
    rows = a.pop_finished()
    out = [r for r in rows if r[7] == "o"]
    assert len(out) == 1 and out[0][8:13] == (500, 5000, 50, 10, 6)
    loc = [r for r in rows if r[7] == "l"]
    assert len(loc) == 1 and loc[0][2] == 13 and loc[0][8] == 700
    assert a.stats["transit"] == 1 and a.stats["dup_local"] == 1 and a.stats["bad"] == 1
    assert a.pop_finished() == []


# ---------------------------------------------------------------- storage + API
def _load(rows_recs, minutes_ago=3):
    a = flows.AGG
    t = NOW_NS() - minutes_ago * 60 * 10**9
    for r in rows_recs:
        r["time_received_ns"] = t
        a.add(r, NETS)
    flows.write_rows(a.pop_finished())
    flows.save_exporters(a.take_exporters())


def test_summary_api_names_and_filters(client, admin, viewer, clean, fresh):
    with SessionLocal() as db:
        db.add(models.Asset(name="FW-Core", type="firewall", ip=FW))
        db.add(models.Asset(name="SRV-FILE", type="server", ip="172.17.11.33"))
        db.commit()
    _load([rec("192.168.80.245", "173.194.146.5", 50000, 443, "UDP", b=222_000_000),
           rec("173.194.146.5", "192.168.80.245", 443, 50000, "UDP", b=1_000_000),
           rec("172.17.17.34", "160.79.104.10", 52000, 443, b=30_000_000, ifx=4),
           rec("172.17.11.33", "172.17.13.26", 445, 50111, b=45_000_000, ifx=13)])
    r = client.get("/api/traffic/summary?hours=1", headers=viewer)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["totals"]["b_out"] == 252_000_000 and d["totals"]["b_in"] == 1_000_000 and d["totals"]["hosts"] == 2
    assert d["totals"]["local_bytes"] == 45_000_000
    assert d["hosts"][0]["ip"] == "192.168.80.245"
    assert d["services"][0]["port"] == 443 and d["services"][0]["proto"] == 17
    assert d["remotes"][0]["ip"] == "173.194.146.5" and d["remotes"][0]["services"] == [[17, 443]]
    smb = [c for c in d["conversations"] if c["direction"] == "l"][0]
    assert smb["local_name"] == "SRV-FILE" and smb["port"] == 445
    assert {i["if_index"] for i in d["interfaces"]} == {15, 4, 13}
    assert len(d["series"]) >= 1
    one = client.get("/api/traffic/summary?hours=1&host=172.17.17.34", headers=viewer).json()
    assert one["totals"]["b_out"] == 30_000_000 and len(one["hosts"]) == 1
    loc = client.get("/api/traffic/summary?hours=1&direction=l", headers=viewer).json()
    assert loc["hosts"][0]["ip"] == "172.17.11.33"
    assert client.get("/api/traffic/summary?hours=5", headers=viewer).status_code == 400
    assert client.get("/api/traffic/summary?hours=1").status_code == 401
    st = client.get("/api/traffic/status", headers=viewer).json()
    e = st["exporters"][0]
    assert e["ip"] == FW and e["name"] == "FW-Core" and {i["if_index"] for i in e["interfaces"]} == {15, 4, 13}


def test_settings_validation_and_admin_only(client, admin, viewer, fresh):
    assert client.put("/api/traffic/settings", json={"enabled": True}, headers=viewer).status_code == 403
    assert client.put("/api/traffic/settings", json={"local_networks": "10.0.0.0/8, not-a-net"}, headers=admin).status_code == 400
    assert client.put("/api/traffic/settings", json={"port": 2055, "sflow_port": 2055}, headers=admin).status_code == 400
    r = client.put("/api/traffic/settings", json={"local_networks": "172.17.0.0/16\n192.168.80.0/22", "silent_minutes": 1,
                                                 "keep_minute_days": 999}, headers=admin)
    assert r.status_code == 200, r.text
    s = r.json()["settings"]
    assert s["local_networks"] == ["172.17.0.0/16", "192.168.80.0/22"] and s["silent_minutes"] == 2 and s["keep_minute_days"] == 90
    assert s["enabled"] is False
    logs = client.get("/api/audit?q=traffic_settings", headers=admin).json()
    assert logs and logs[0]["entity"] == "traffic_settings"


def test_interface_names_from_softflowd_ps_and_snmp_aliases(client, admin, clean, fresh):
    with SessionLocal() as db:
        a = models.Asset(name="FW-Core", type="firewall", ip=FW)
        db.add(a); db.flush()
        db.add(models.Check(name="FW-Core (pfsense)", type="pfsense", asset_id=a.id, target=FW, interval=30, enabled=True,
                            last_data={"ports": [{"name": "em0.15", "alias": "TTS_Vlan15"}, {"name": "em0.14", "alias": "IOT_LAB_VLAN14"}]}))
        db.commit()
    _load([rec("192.168.80.5", "1.1.1.1", ifx=3)])
    ps = ("nobody 86371 0.0 0.0 14752 3964 - Ss 15:14 0:00.07 /usr/local/bin/softflowd -i 15:em0.15 -n 172.17.15.29:2055 -v 10\n"
          "nobody 80908 0.3 0.1 17312 5948 - Ss 15:14 0:01.40 /usr/local/bin/softflowd -i 3:em0.14 -n 172.17.15.29:2055 -v 10")
    r = client.put(f"/api/traffic/exporters/{FW}", json={"softflowd_ps": ps, "if_names": {"99": "spare"}}, headers=admin)
    assert r.status_code == 200, r.text
    names = {i["if_index"]: i["name"] for i in r.json()["exporters"][0]["interfaces"]}
    assert names[15] == "em0.15 TTS_Vlan15" and names[3] == "em0.14 IOT_LAB_VLAN14" and names[99] == "spare"
    assert client.put(f"/api/traffic/exporters/{FW}", json={"softflowd_ps": "nothing here"}, headers=admin).status_code == 400
    assert client.put("/api/traffic/exporters/1.2.3.4", json={"name": "x"}, headers=admin).status_code == 404
    s = client.get("/api/traffic/summary?hours=1", headers=admin).json()
    assert s["interfaces"][0]["name"] == "em0.14 IOT_LAB_VLAN14"


# ---------------------------------------------------------------- GoFlow2 child process (fake binary)
def _fake_cmd(tmp_path, recs, exit_after=False):
    f = tmp_path / "flows.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    script = os.path.join(os.path.dirname(__file__), "fake_goflow2.py")
    os.environ["FLOW_COLLECTOR_CMD"] = f'"{sys.executable}" "{script}" "{f}"' + (" --exit" if exit_after else "")


def test_collector_runs_reads_and_stores(client, admin, fresh, tmp_path):
    t = NOW_NS() - 180 * 10**9
    _fake_cmd(tmp_path, [rec("192.168.80.124", "20.44.238.125", 49575, 3478, "UDP", b=30_000_000, t_ns=t)] * 5
              + [rec("8.8.4.4", "1.0.0.1", t_ns=t)])
    cfg = flows.save_settings(SessionLocal(), {"enabled": True})
    cfg["enabled"] = True
    flows.COLLECTOR.supervise(cfg)
    assert flows.COLLECTOR.running()
    for _ in range(50):
        if flows.AGG.stats["lines"] >= 6:
            break
        time.sleep(0.1)
    assert flows.AGG.stats["lines"] == 6 and flows.AGG.stats["transit"] == 1
    flows.write_rows(flows.AGG.pop_finished())
    flows.save_exporters(flows.AGG.take_exporters())
    st = client.get("/api/traffic/status", headers=admin).json()
    assert st["collector"]["running"] and st["stats"]["transit_pct"] > 0
    assert any("starting collection" in x for x in st["collector"]["log"])
    s = client.get("/api/traffic/summary?hours=1", headers=admin).json()
    assert s["totals"]["b_out"] == 150_000_000 and s["services"][0]["port"] == 3478
    cfg["enabled"] = False
    flows.COLLECTOR.supervise(cfg)
    assert not flows.COLLECTOR.running()


def test_collector_crash_is_reported_and_retried(fresh, tmp_path):
    _fake_cmd(tmp_path, [], exit_after=True)
    cfg = dict(flows.DEFAULTS, enabled=True)
    flows.COLLECTOR.supervise(cfg)
    for _ in range(50):
        if flows.COLLECTOR.proc and flows.COLLECTOR.proc.poll() is not None:
            break
        time.sleep(0.1)
    time.sleep(0.2)
    flows.COLLECTOR.supervise(cfg)                     # notices the exit, schedules a retry with back-off
    assert not flows.COLLECTOR.running() and flows.COLLECTOR.restarts == 1
    assert "address already in use" in flows.COLLECTOR.last_error
    assert flows.COLLECTOR.next_try > time.time()


def test_missing_binary_message(fresh, monkeypatch):
    monkeypatch.setenv("FLOW_COLLECTOR", "/nonexistent/goflow2")
    assert flows.build_command(dict(flows.DEFAULTS)) is None
    assert not flows.COLLECTOR.start(dict(flows.DEFAULTS))
    assert "GoFlow2 not found" in flows.COLLECTOR.last_error


def test_build_command_passes_arguments_as_list(monkeypatch, tmp_path):
    exe = tmp_path / "goflow2"
    exe.write_text("")
    monkeypatch.setenv("FLOW_COLLECTOR", str(exe))
    cmd = flows.build_command(dict(flows.DEFAULTS, port=2055, sflow_port=6343))
    assert cmd[0] == str(exe) and cmd[1:3] == ["-listen", "netflow://:2055,sflow://:6343"]
    assert "-transport" in cmd and "file" in cmd and not any(c.startswith("-transport.file") for c in cmd)


# ---------------------------------------------------------------- alerts, roll-up, retention, backup
def test_silent_exporter_and_collector_alerts(fresh, tmp_path):
    with SessionLocal() as db:
        db.add(models.FlowExporter(ip=FW, name="FW-Core", first_seen=now(), last_seen=now() - timedelta(minutes=40),
                                   interfaces={}, if_names={}, flows_total=10))
        db.commit()
    cfg = dict(flows.DEFAULTS, enabled=True)
    _fake_cmd(tmp_path, [])
    flows.COLLECTOR.supervise(cfg)
    with SessionLocal() as db:
        notes = flows.check_alerts(db, cfg)
        db.commit()
        a = db.query(models.Alert).filter_by(source="flow", dedupe_key=f"flow-silent:{FW}").one()
        assert a.status == "open" and "FW-Core" in a.title and notes[0][2] == "trouble"
        assert flows.check_alerts(db, cfg) == []           # not opened twice
        db.get(models.FlowExporter, FW).last_seen = now()
        notes = flows.check_alerts(db, cfg)
        db.commit()
        assert db.get(models.Alert, a.id).status == "resolved" and notes[0][2] == "resolved"
    flows.COLLECTOR.stop()
    flows.COLLECTOR.stopped_at = time.time() - 600
    flows.COLLECTOR.last_error = "GoFlow2 not found."
    with SessionLocal() as db:
        flows.check_alerts(db, cfg)
        db.commit()
        c = db.query(models.Alert).filter_by(dedupe_key="flow-collector").one()
        assert c.status == "open" and "GoFlow2 not found" in c.message
        flows.check_alerts(db, dict(cfg, enabled=False))
        db.commit()
        assert db.get(models.Alert, c.id).status == "resolved"


def test_rollup_once_and_retention(fresh):
    base = (now() - timedelta(hours=3)).replace(minute=10, second=0, microsecond=0)
    rows = []
    for m in range(0, 50, 10):
        ts = base + timedelta(minutes=m)
        rows.append((ts, FW, 15, "192.168.80.5", "1.1.1.1", 6, 443, "o", 100, 1000, 1, 10, 1))
        rows.append((ts, FW, 15, "192.168.80.5", "8.8.8.8", 6, 443, "o", 50, 500, 1, 5, 1))
    old = now() - timedelta(days=30)
    rows.append((old, FW, 15, "192.168.80.6", "1.1.1.1", 6, 443, "o", 1, 1, 1, 1, 1))
    flows.write_rows(rows)
    with SessionLocal() as db:
        assert flows.rollup(db) >= 1
        db.commit()
        h = db.execute(text("select bytes_out, bytes_in, remotes from flow_1h where local_ip = '192.168.80.5' order by ts")).all()
        assert sum(r[0] for r in h) == 750 and max(r[2] for r in h) == 2
        assert flows.rollup(db) == 0                        # watermark: never double counted
        a, b = flows.retention(db, dict(flows.DEFAULTS))
        db.commit()
        assert a == 1 and db.execute(text("select count(*) from flow_1m where local_ip = '192.168.80.6'")).scalar() == 0
        assert b == 0                                       # hourly history is kept 60 days
        n = db.execute(text("select count(*) from flow_1h where local_ip = '192.168.80.6'")).scalar()
        assert n == 1                                       # the old minute was rolled up before it was deleted


def test_backup_skips_traffic_tables(fresh):
    import io
    import zipfile
    from app import dbdump
    from app.db import engine
    flows.write_rows([(now(), FW, 15, "192.168.80.5", "1.1.1.1", 6, 443, "o", 1, 1, 1, 1, 1)])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        man = dbdump.dump_to_zip(engine, z)
    assert "flow_1m" not in man["tables"] and "flow_1h" not in man["tables"] and "flow_exporters" in man["tables"]


def test_stale_goflow2_from_previous_run_is_stopped(fresh, tmp_path):
    """Shift+F5 in VS Code kills Python without cleanup; the next start must free UDP 2055 again."""
    import subprocess
    fake = tmp_path / "goflow2-test"
    fake.write_text("#!/bin/sh\nexec sleep 60\n")
    fake.chmod(0o755)
    old = subprocess.Popen([str(fake)])
    with open(flows._pid_file(), "w") as fh:
        fh.write(str(old.pid))
    assert flows._is_goflow(old.pid)
    flows.reap_stale()
    old.wait(5)
    assert old.returncode is not None and not os.path.exists(flows._pid_file())
    other = subprocess.Popen(["sleep", "30"])                 # a PID that is not GoFlow2 is never touched
    with open(flows._pid_file(), "w") as fh:
        fh.write(str(other.pid))
    flows.reap_stale()
    assert other.poll() is None
    other.kill()


def test_exporter_linked_to_firewall_with_other_ip_gets_vlan_names(client, admin, clean, fresh):
    """pfSense sends flows from its VLAN address (172.17.15.1) while the asset is 172.17.11.1: link once, names follow."""
    with SessionLocal() as db:
        a = models.Asset(name="FW-Core", type="firewall", ip="172.17.11.1")
        db.add(a); db.flush()
        db.add(models.Check(name="FW-Core (pfsense)", type="pfsense", asset_id=a.id, target="172.17.11.1", interval=30, enabled=True,
                            last_data={"ports": [{"name": "em0.15", "alias": "TTS_Vlan15"}]}))
        db.commit()
        aid = a.id
    _load([rec("192.168.80.5", "1.1.1.1", ifx=15)])
    st = client.get("/api/traffic/status", headers=admin).json()
    assert st["exporters"][0]["name"] == "" and any(x["id"] == aid for x in st["assets"])
    r = client.put(f"/api/traffic/exporters/{FW}", json={"asset_id": aid}, headers=admin).json()
    assert r["exporters"][0]["name"] == "FW-Core" and r["exporters"][0]["asset_id"] == aid
    r = client.put(f"/api/traffic/exporters/{FW}", json={"softflowd_ps": "softflowd -i 15:em0.15 -n x:2055"}, headers=admin).json()
    assert r["exporters"][0]["interfaces"][0]["name"] == "em0.15 TTS_Vlan15"
