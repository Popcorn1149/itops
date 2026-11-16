"""Syslog / SNMP trap: phân tích, nhận qua mạng thật, rule → cảnh báo, chống flood, archive, nâng cấp CSDL."""
import asyncio
import socket
import time

import pytest

from app.syslog_parser import parse
from app import events, models
from app.db import SessionLocal


# ---------------------------------------------------------------- parser
@pytest.mark.parametrize("raw,exp", [
    ("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
     dict(facility=4, severity=2, host="mymachine", app="su", device_ts="Oct 11 22:14:15")),
    ("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] An application event",
     dict(facility=20, severity=5, host="mymachine.example.com", app="evntslog", message="An application event")),
    ("<134>Nov  2 21:00:02 filterlog[1234]: 5,,,1000000103,igb0,match,block", dict(app="filterlog", host="")),
    ("<30>Nov  2 21:00:04 dpinger: MONITOR: WAN_FPT is down, omitting from routing group", dict(app="dpinger", severity=6, message="MONITOR: WAN_FPT is down, omitting from routing group")),
    ("<189>88: *Nov  2 21:10:09.123: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to down",
     dict(app="LINK-UPDOWN", severity=3, message="Interface GigabitEthernet1/0/12, changed state to down")),
    ("<166>2026-11-02T14:10:05.120Z esx01.lab Hostd: info hostd[2100] Task Completed", dict(host="esx01.lab", app="Hostd")),
    ("<13>Nov  2 21:12:00 NAS-Synology System: Volume 1 has been degraded", dict(host="NAS-Synology", app="System", severity=5)),
    ("plain text without pri", dict(severity=5, message="plain text without pri")),
    ("<999>bad pri", dict(severity=5)),
    ("<14>1 - - - - - - hello", dict(message="hello", host="")),
])
def test_parser(raw, exp):
    p = parse(raw)
    for k, v in exp.items():
        assert p[k] == v, (k, p)


# ---------------------------------------------------------------- helpers
def send_udp(port, *lines):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for l in lines:
        s.sendto(l.encode() if isinstance(l, str) else l, ("127.0.0.1", port))
    s.close()


def wait_events(client, h, n, timeout=6, **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    t = time.time()
    while time.time() - t < timeout:
        r = client.get(f"/api/events?limit=1000&{qs}", headers=h).json()
        if len(r) >= n:
            return r
        time.sleep(0.2)
    return client.get(f"/api/events?limit=1000&{qs}", headers=h).json()


def ev_alerts(client, h, status="active"):
    return [a for a in client.get(f"/api/alerts?status={status}", headers=h).json() if a.get("source") == "event"]


async def _trap(port, oid, varbinds=(), community="public", v3=None):
    from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
                                             NotificationType, ObjectIdentity, ObjectType, Integer, OctetString, send_notification,
                                             usmHMACSHAAuthProtocol, usmAesCfb128Protocol)
    e = SnmpEngine()
    auth = UsmUserData(v3["user"], v3["auth"], v3["priv"], authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol) if v3 else CommunityData(community, mpModel=1)
    vbs = [ObjectType(ObjectIdentity(o), Integer(v) if isinstance(v, int) else OctetString(v)) for o, v in varbinds]
    await send_notification(e, auth, await UdpTransportTarget.create(("127.0.0.1", port)), ContextData(), "trap",
                            NotificationType(ObjectIdentity(oid)).add_varbinds(*vbs))
    if v3:
        return e
    e.close_dispatcher()


def trap(port, oid, varbinds=(), community="public"):
    asyncio.run(_trap(port, oid, varbinds, community))


# ---------------------------------------------------------------- nhận qua mạng
def test_receivers_listening(client, admin):
    st = client.get("/api/events/stats", headers=admin).json()["receiver"]["listeners"]
    assert st["syslog_udp"]["ok"] and st["syslog_tcp"]["ok"] and st["snmp_trap"]["ok"], st


def test_udp_syslog_mapped_to_asset_by_ip_and_hostname(client, admin, clean, rx):
    a = client.post("/api/assets", json={"name": "SW-CORE", "type": "switch", "ip": "127.0.0.1"}, headers=admin).json()
    b = client.post("/api/assets", json={"name": "esx01.lab", "type": "host", "ip": "10.9.9.9"}, headers=admin).json()
    send_udp(rx["udp"], "<190>Nov  2 21:00:01 SW-CORE sshd[1]: Accepted publickey for admin")
    evs = wait_events(client, admin, 1)
    assert evs[0]["asset_id"] == a["id"] and evs[0]["asset_name"] == "SW-CORE"
    client.delete(f"/api/assets/{a['id']}", headers=admin)
    from app import events
    events.invalidate_caches()
    send_udp(rx["udp"], "<166>2026-11-02T14:10:05Z esx01.lab Hostd: hello from esx")
    evs = wait_events(client, admin, 2)
    assert evs[0]["asset_id"] == b["id"], "Không có IP khớp → khớp theo hostname"


def test_tcp_syslog_newline_and_octet_counting(client, admin, clean, rx):
    m1, m2 = "<14>Nov  2 21:00:01 h1 app: dong mot", "<14>1 2026-11-02T14:00:00Z h2 app2 - - - dong hai co\nxuong dong"
    payload = f"{m1}\n{len(m2.encode())} {m2}<14>Nov  2 21:00:03 h3 app3: dong ba\n".encode()
    s = socket.create_connection(("127.0.0.1", rx["udp"]))
    s.sendall(payload[:30])
    time.sleep(0.1)
    s.sendall(payload[30:])
    s.close()
    evs = wait_events(client, admin, 3)
    msgs = sorted(e["message"] for e in evs)
    assert msgs == sorted(["dong mot", "dong hai co\nxuong dong", "dong ba"]), msgs


def test_snmp_trap_v2c_and_wrong_community(client, admin, clean, rx):
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.7", 7), ("1.3.6.1.2.1.31.1.1.1.1.7", "Gi1/0/7")])
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.8", 8)], community="sai")
    evs = wait_events(client, admin, 1, kind="trap")
    time.sleep(1)
    evs = client.get("/api/events?kind=trap", headers=admin).json()
    assert len(evs) == 1, "Trap sai community phải bị loại"
    e = evs[0]
    assert e["app"] == "linkDown" and e["data"]["if_key"] == "Gi1/0/7" and e["severity"] == 3 and "ifName=Gi1/0/7" in e["message"]


def test_snmp_trap_v3_after_config(client, admin, clean, rx):
    r = client.put("/api/settings/receivers", headers=admin, json={"communities": ["public", "trapcomm"], "v3_users": [
        {"username": "trapv3", "auth_key": "AuthPass123", "priv_key": "PrivPass123", "auth_protocol": "SHA", "priv_protocol": "AES", "engine_id": "8000000001020304"}]})
    assert r.status_code == 200 and r.json()["communities"] == ["__SECRET__", "__SECRET__"]
    assert r.json()["v3_users"][0]["auth_key"] == "__SECRET__"
    time.sleep(0.5)
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.1", [], community="trapcomm")

    async def v3():
        from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, UsmUserData, UdpTransportTarget, ContextData, NotificationType,
                                                 ObjectIdentity, send_notification, usmHMACSHAAuthProtocol, usmAesCfb128Protocol)
        from pysnmp.proto import rfc1902
        e = SnmpEngine(rfc1902.OctetString(hexValue="8000000001020304"))
        await send_notification(e, UsmUserData("trapv3", "AuthPass123", "PrivPass123", authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
                                await UdpTransportTarget.create(("127.0.0.1", rx["trap"])), ContextData(), "trap",
                                NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.2")))
        e.close_dispatcher()
    asyncio.run(v3())
    evs = wait_events(client, admin, 2, kind="trap")
    assert {e["app"] for e in evs} == {"coldStart", "warmStart"}, [e["app"] for e in evs]
    client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": []})


def test_self_test_endpoints(client, admin, clean):
    assert client.post("/api/events/send-test", json={"kind": "syslog"}, headers=admin).json()["ok"]
    r = client.post("/api/events/send-test", json={"kind": "trap"}, headers=admin).json()
    assert r["ok"] and r["event"]["app"] == "itopsSelfTest"
    assert ev_alerts(client, admin) == [], "Tin thử không được sinh cảnh báo"


# ---------------------------------------------------------------- rule
def test_default_rules_switch_port_down_up_same_batch_no_duplicates(client, admin, clean, rx):
    down = "<189>88: *Nov  2 21:10:09: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to down"
    up = "<189>89: *Nov  2 21:11:09: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to up"
    send_udp(rx["udp"], down, down, down)
    wait_events(client, admin, 3)
    al = ev_alerts(client, admin)
    assert len(al) == 1 and "GigabitEthernet1/0/12" in al[0]["title"] and al[0]["count"] == 3, al
    send_udp(rx["udp"], "<189>90: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/13, changed state to down")
    wait_events(client, admin, 4)
    assert len(ev_alerts(client, admin)) == 2, "Port khác → cảnh báo riêng"
    send_udp(rx["udp"], up)
    wait_events(client, admin, 5)
    time.sleep(0.3)
    al = ev_alerts(client, admin)
    assert len(al) == 1 and "1/0/13" in al[0]["title"], "Port 1/0/12 up → chỉ đóng đúng cảnh báo of nó"
    # down + up trong cùng 1 lô
    send_udp(rx["udp"], "<189>91: %LINK-3-UPDOWN: Interface Gi9, changed state to down", "<189>92: %LINK-3-UPDOWN: Interface Gi9, changed state to up")
    wait_events(client, admin, 7)
    time.sleep(0.3)
    assert not any("Gi9" in a["title"] for a in ev_alerts(client, admin))



def test_seed_rules_migrates_legacy_names_without_duplicates(client, admin, clean):
    with SessionLocal() as db:
        legacy = models.EventRule(builtin=True, name="Cổng switch down", enabled=False,   # name saved by the Vietnamese release
                                  description="customized legacy description", threshold=3)
        duplicate = models.EventRule(builtin=True, name="Switch port down", enabled=True,
                                     description="new default duplicate", threshold=1)
        db.add_all([legacy, duplicate])
        db.commit()
        legacy_id = legacy.id

        events.seed_rules(db)
        rows = db.query(models.EventRule).filter_by(builtin=True, name="Switch port down").all()
        assert len(rows) == 1
        assert rows[0].id == legacy_id
        assert rows[0].enabled is False
        assert rows[0].description == "customized legacy description"
        assert rows[0].threshold == 3

        # Startup is idempotent: running the migration again must not add a duplicate.
        events.seed_rules(db)
        assert db.query(models.EventRule).filter_by(builtin=True, name="Switch port down").count() == 1

def test_trap_linkdown_linkup_pairing(client, admin, clean, rx):
    vb = [("1.3.6.1.2.1.2.2.1.1.3", 3), ("1.3.6.1.2.1.31.1.1.1.1.3", "port3")]
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", vb)
    wait_events(client, admin, 1, kind="trap")
    assert len(ev_alerts(client, admin)) == 1
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.4", vb)
    wait_events(client, admin, 2, kind="trap")
    time.sleep(0.3)
    assert ev_alerts(client, admin) == [] and len(ev_alerts(client, admin, "resolved")) == 1


def test_threshold_rule_bruteforce(client, admin, clean, rx):
    fail = "<38>Nov  2 21:10:02 srv1 sshd[2211]: Failed password for invalid user admin from 45.13.2.9"
    send_udp(rx["udp"], *[fail] * 4)
    wait_events(client, admin, 4)
    assert ev_alerts(client, admin) == [], "4 lần < threshold 5"
    send_udp(rx["udp"], fail, fail)
    wait_events(client, admin, 6)
    al = ev_alerts(client, admin)
    assert len(al) == 1 and al[0]["title"].startswith("Repeated failed sign-ins")


def test_drop_rule_filterlog_and_crit_catchall(client, admin, clean, rx):
    send_udp(rx["udp"], "<134>Nov  2 21:00:02 filterlog[123]: 5,,,1000000103,igb0,match,block,in", "<10>Nov  2 21:00:02 r1 kernel: panic: something bad")
    evs = wait_events(client, admin, 1)
    time.sleep(0.5)
    evs = client.get("/api/events", headers=admin).json()
    assert len(evs) == 1 and evs[0]["app"] == "kernel"
    st = client.get("/api/events/stats", headers=admin).json()["receiver"]
    assert st["dropped_rule"] >= 1
    al = ev_alerts(client, admin)
    assert len(al) == 1 and al[0]["severity"] == "critical" and al[0]["title"].startswith("Critical error")


@pytest.mark.parametrize("line,title", [
    ("<30>Nov  2 21:00:04 dpinger: MONITOR: WAN_FPT is down, omitting from routing group", "Gateway WAN down"),
    ("<11>1 2026-11-02T14:00:03Z esx01 vmkernel - - - Lost access to volume 5f2a (DS01) due to connectivity issues", "Datastore connection lost"),
    ("<13>Nov  2 21:12:00 NAS System: Volume 1 has been degraded", "Disk / RAID failure"),
    ("<12>Nov  2 21:13:10 UPS apcupsd: Power failure. Running on UPS batteries.", "UPS switched to battery"),
])
def test_default_vendor_rules(client, admin, clean, rx, line, title):
    send_udp(rx["udp"], line)
    wait_events(client, admin, 1)
    time.sleep(0.2)
    al = ev_alerts(client, admin)
    assert len(al) == 1 and al[0]["title"].startswith(title), al


@pytest.mark.parametrize("line", [
    "<14>Nov  2 21:00:00 h1 backup: Backup job for volume 1 completed successfully",
    "<14>Nov  2 21:00:00 h1 hostd: Updated APDU table",
    "<14>Nov  2 21:00:00 h1 app: user disk usage report",
    "<14>Nov  2 21:00:00 h1 smartd: Device /dev/sda, SMART test passed",
])
def test_no_false_positives(client, admin, clean, rx, line):
    send_udp(rx["udp"], line)
    wait_events(client, admin, 1)
    time.sleep(0.2)
    assert ev_alerts(client, admin) == [], line


def test_custom_rule_crud_test_and_scope(client, admin, viewer, clean, rx):
    a = client.post("/api/assets", json={"name": "core", "type": "switch", "ip": "127.0.0.1"}, headers=admin).json()
    assert client.post("/api/event-rules", json={"name": "x", "pattern": "([bad"}, headers=admin).status_code == 400
    assert client.post("/api/event-rules", json={"name": "x", "pattern": "a"}, headers=viewer).status_code == 403
    r = client.post("/api/event-rules", headers=admin, json={"name": "VLAN đổi", "kind": "syslog", "pattern": r"VLAN (?P<key>\d+) changed",
                                                               "asset_id": a["id"], "alert_severity": "critical", "sort": 1}).json()
    t = client.post("/api/event-rules/test", headers=admin, json={"pattern": r"VLAN (?P<key>\d+) changed", "sample": "<14>Nov 2 21:00:00 core cfg: VLAN 20 changed by admin"}).json()
    assert t["sample"]["match"] and t["sample"]["key"] == "20"
    send_udp(rx["udp"], "<14>Nov  2 21:00:00 core cfg: VLAN 20 changed by admin")
    wait_events(client, admin, 1)
    time.sleep(0.2)
    al = ev_alerts(client, admin)
    assert len(al) == 1 and al[0]["severity"] == "critical" and "(20)" in al[0]["title"]
    rules = client.get("/api/event-rules", headers=viewer).json()
    mine = next(x for x in rules if x["id"] == r["id"])
    assert mine["hits"] == 1 and mine["open_alerts"] == 1 and mine["asset_name"] == "core"
    t2 = client.post("/api/event-rules/test", headers=admin, json={"pattern": "VLAN"}).json()
    assert t2["history"]["matches"] == 1
    client.put(f"/api/event-rules/{r['id']}", json={"enabled": False}, headers=admin)
    send_udp(rx["udp"], "<14>Nov  2 21:00:00 core cfg: VLAN 30 changed by admin")
    wait_events(client, admin, 2)
    time.sleep(0.2)
    assert len(ev_alerts(client, admin)) == 1, "Rule tắt → không sinh cảnh báo mới"
    client.delete(f"/api/event-rules/{r['id']}", headers=admin)


def test_auto_resolve_after_quiet(client, admin, clean, rx):
    send_udp(rx["udp"], "<10>Nov  2 21:00:02 r1 kernel: panic: x")
    wait_events(client, admin, 1)
    time.sleep(0.3)
    assert len(ev_alerts(client, admin)) == 1
    from app.db import SessionLocal
    from app import models, events
    from datetime import timedelta
    db = SessionLocal()
    a = db.query(models.Alert).filter_by(source="event").first()
    a.last_seen = a.last_seen - timedelta(minutes=61)
    db.commit()
    db.close()
    events._housekeep(False)
    assert ev_alerts(client, admin) == []


def test_notifications_sent_for_event_alerts(client, admin, clean, rx, sim_port):
    from tests import simulators as S
    client.put("/api/settings/notify", headers=admin, json={"telegram": {"enabled": True, "bot_token": "1:X", "chat_id": "-1"}, "email": {}, "webhook": {}})
    S.STATE["telegram"].clear()
    try:
        send_udp(rx["udp"], "<30>Nov  2 21:00:04 dpinger: MONITOR: WAN_VT is down, omitting from routing group")
        wait_events(client, admin, 1)
        time.sleep(0.8)
        send_udp(rx["udp"], "<30>Nov  2 21:01:04 dpinger: MONITOR: WAN_VT is available now, adding to routing group")
        wait_events(client, admin, 2)
        time.sleep(0.8)
        texts = [m["text"] for m in S.STATE["telegram"]]
        assert len(texts) == 2 and "WAN_VT" in texts[0] and "recovered" in texts[1], texts
    finally:
        client.put("/api/settings/notify", headers=admin, json={"telegram": {}, "email": {}, "webhook": {}})


# ---------------------------------------------------------------- API, flood, archive
def test_event_filters_stats_unknown(client, admin, viewer, clean, rx):
    client.post("/api/assets", json={"name": "known", "type": "server", "ip": "10.1.1.1"}, headers=admin)
    send_udp(rx["udp"], "<11>Nov  2 21:00:00 x app: loi A", "<12>Nov  2 21:00:00 x app: canh bao B", "<14>Nov  2 21:00:00 x other: info C <script>alert(1)</script>")
    wait_events(client, admin, 3)
    assert [e["message"] for e in client.get("/api/events?max_severity=3", headers=viewer).json()] == ["loi A"]
    assert len(client.get("/api/events?max_severity=4", headers=viewer).json()) == 2
    assert len(client.get("/api/events?q=other", headers=viewer).json()) == 1
    assert len(client.get("/api/events?unknown=true", headers=viewer).json()) == 3
    st = client.get("/api/events/stats", headers=viewer).json()
    assert st["total"] == 3 and st["errors"] == 1 and st["warnings"] == 1
    assert st["unknown_sources"][0]["source_ip"] == "127.0.0.1" and st["unknown_sources"][0]["count"] == 3
    page1 = client.get("/api/events?limit=2", headers=viewer).json()
    page2 = client.get(f"/api/events?limit=2&before_id={page1[-1]['id']}", headers=viewer).json()
    assert len(page1) == 2 and len(page2) == 1 and page2[0]["id"] < page1[-1]["id"]
    assert client.get("/api/settings/receivers", headers=viewer).status_code == 403
    assert client.post("/api/events/send-test", json={}, headers=viewer).status_code == 403


def test_flood_rate_limited_per_source(client, admin, clean, rx):
    from app import events
    before = events.STATS["dropped_rate"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    for i in range(3000):
        s.sendto(f"<14>Nov  2 21:00:00 flood app: msg {i}".encode(), ("127.0.0.1", rx["udp"]))
    s.close()
    time.sleep(2.5)
    stored = len(client.get("/api/events?limit=1000&hours=1", headers=admin).json())
    dropped = events.STATS["dropped_rate"] - before
    assert dropped > 0, "Flood 3000 log/~0.2s phải bị giới hạn"
    assert stored >= 300, "Vẫn nhận phần trong hạn mức"
    assert client.get("/api/dashboard", headers=admin).status_code == 200


def test_retention_and_max_rows(client, admin, clean, rx, monkeypatch):
    from app.db import SessionLocal
    from app import models, events
    from datetime import timedelta
    db = SessionLocal()
    old = models.now() - timedelta(days=40)
    db.add_all([models.Event(message=f"cu {i}", ts=old) for i in range(5)] + [models.Event(message=f"moi {i}") for i in range(10)])
    db.commit()
    db.close()
    monkeypatch.setattr(events, "MAX_EVENTS", 6)
    events._housekeep(True)
    db = SessionLocal()
    msgs = [m for (m,) in db.query(models.Event.message).all()]
    db.close()
    assert len(msgs) == 6 and all(m.startswith("moi") for m in msgs)


def test_import_sqlite_v1_into_postgresql(tmp_path, monkeypatch):
    """Data bản v1 (SQLite, schema migration 0001, none cột/bảng mới) chuyển sang PostgreSQL:
    đúng kiểu (bool/JSON/datetime), khoá ngoại tự tham chiếu, cột mới lấy default, sequence nối tiếp, khoá được chép."""
    import sqlite3
    from alembic import command
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from app import admin_tools
    from app import db as dbm
    from tests.pgtest import head_revision, scratch_db
    src_dir = tmp_path / "v1"
    src_dir.mkdir()
    path = src_dir / "itops.db"
    eng = create_engine(f"sqlite:///{path}")
    with eng.begin() as conn:
        command.upgrade(dbm._alembic_config(conn), "0001")     # đúng schema bản v1
        conn.execute(text("DROP TABLE alembic_version"))         # v1 không có Alembic
    eng.dispose()
    c = sqlite3.connect(path)

    def ins(table, **vals):     # điền cột NOT NULL remaining missing bằng value rỗng theo kiểu – như dữ liệu v1 thật
        for _, name, typ, notnull, _, pk in c.execute(f"PRAGMA table_info({table})"):
            if notnull and not pk and name not in vals:
                vals[name] = 0 if typ.upper() in ("INTEGER", "BOOLEAN", "FLOAT") else "{}" if typ.upper() == "JSON" else \
                    "2026-01-01 00:00:00" if typ.upper() == "DATETIME" else ""
        c.execute(f"INSERT INTO {table} ({', '.join(vals)}) VALUES ({', '.join('?' * len(vals))})", tuple(vals.values()))

    ins("sites", id=1, name="HQ")
    ins("assets", id=2, parent_id=5, name="vm01", site_id=1, backup=1, meta='{"k": 1}')     # con được chèn trước cha
    ins("assets", id=5, name="esx01", site_id=1, backup=0)
    ins("alerts", id=7, asset_id=2, site_id=1, severity="down", title="vm01 DOWN", status="open", count=3,
        opened_at="2026-10-01 08:30:00.123456", suppressed=0, sla_breached=1)
    ins("users", id=1, username="admin", password_hash="x", role="admin", full_name="Quản trị")
    c.commit()
    c.close()
    (src_dir / ".enc_key").write_text("khoa-ma-hoa-v1")
    (src_dir / ".secret_key").write_text("khoa-ky-v1")
    with scratch_db() as pg:
        keys_dir = tmp_path / "data"
        keys_dir.mkdir()
        (keys_dir / ".enc_key").write_text("khoa-dang-co")
        monkeypatch.setattr(admin_tools, "engine", pg)
        monkeypatch.setattr(admin_tools, "SessionLocal", sessionmaker(bind=pg))
        monkeypatch.setattr(admin_tools, "DATA_DIR", str(keys_dir))
        out = admin_tools.import_sqlite(str(path))
        assert "Migrated" in out and "alerts" in out
        with pg.connect() as conn:
            a = conn.execute(text("select title, sla_breached, suppressed, opened_at, count, last_seen from alerts where id=7")).one()
            assert a.title == "vm01 DOWN" and a.sla_breached is True and a.suppressed is False and a.count == 3
            assert a.opened_at.isoformat() == "2026-10-01T08:30:00.123456"
            vm = conn.execute(text("select parent_id, backup, meta from assets where id=2")).one()
            assert vm.parent_id == 5 and vm.backup is True and vm.meta == {"k": 1}
            u = conn.execute(text("select full_name, totp_enabled, totp_last_step from users where username='admin'")).one()
            assert u.full_name == "Quản trị" and u.totp_enabled is False and u.totp_last_step == 0   # cột mới (0002) lấy default
            assert conn.execute(text("select nextval(pg_get_serial_sequence('assets','id'))")).scalar() > 5
            assert conn.execute(text("select version_num from alembic_version")).scalar() == head_revision()
        assert (keys_dir / ".enc_key").read_text() == "khoa-ma-hoa-v1"
        assert any(p.name.startswith(".enc_key.bak-") and p.read_text() == "khoa-dang-co" for p in keys_dir.iterdir())
        import pytest
        with pytest.raises(SystemExit, match="not empty"):
            admin_tools.import_sqlite(str(path))


def test_source_allowlist(client, admin, viewer, clean, rx):
    from app import events
    # mặc định: chỉ mạng nội bộ → 127.0.0.1 được nhận
    assert "127.0.0.0/8" in client.get("/api/settings/receivers", headers=admin).json()["allowed_sources"]
    assert client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [], "allowed_sources": ["sai-ip"]}).status_code == 400
    r = client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [], "allowed_sources": ["10.20.0.0/16", " "]})
    assert r.status_code == 200 and r.json()["allowed_sources"] == ["10.20.0.0/16"]
    before = events.STATS["dropped_acl"]
    send_udp(rx["udp"], "<10>Nov  2 21:00:02 x kernel: panic: tu IP ngoai danh sach")
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.9", 9)])
    time.sleep(1.5)
    assert client.get("/api/events", headers=admin).json() == [] and ev_alerts(client, admin) == []
    st = client.get("/api/events/stats", headers=viewer).json()["receiver"]
    assert st["dropped_acl"] - before == 2 and st["blocked"][0][0] == "127.0.0.1"
    client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [], "allowed_sources": ["127.0.0.1/32"]})
    send_udp(rx["udp"], "<14>Nov  2 21:00:02 x app: duoc phep")
    assert len(wait_events(client, admin, 1)) == 1
    client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [], "allowed_sources": events.DEFAULT_ALLOWED})


def test_allowlist_unit():
    from app import events
    events.set_allowed(["192.168.1.0/24", "10.0.0.5"])
    assert events.allowed("192.168.1.77") and events.allowed("10.0.0.5")
    assert not events.allowed("10.0.0.6") and not events.allowed("8.8.8.8") and not events.allowed("khong-phai-ip")
    events.set_allowed([])
    assert events.allowed("8.8.8.8"), "Danh sách rỗng = nhận tất cả"
    events.set_allowed(events.DEFAULT_ALLOWED)


def test_trap_acl_uses_real_sender_not_agent_address(client, admin, clean, rx):
    """Lỗ hổng tìm ra khi test bằng gói tin thật: trap ghi agentAddress = IP được phép nhưng GỬI TỪ IP bị chặn
    trước đây vẫn lọt qua danh sách IP cho phép. Giờ phải lọc theo IP thật gửi gói."""
    from app import events
    cur = client.get("/api/settings/receivers", headers=admin).json()
    try:
        assert client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [],
                          "allowed_sources": ["10.0.0.0/8"]}).status_code == 200      # 127.0.0.1 (máy gửi thật) bị chặn
        before = events.STATS["dropped_acl"]
        trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.6.3.18.1.3.0", "10.1.0.21"), ("1.3.6.1.2.1.2.2.1.1", 7)])
        time.sleep(1.5)
        assert client.get("/api/events", headers=admin).json() == [], "trap giả agentAddress lọt qua bộ lọc IP"
        assert events.STATS["dropped_acl"] == before + 1 and "127.0.0.1" in events.STATS["blocked"]
    finally:
        client.put("/api/settings/receivers", headers=admin, json={"communities": ["public"], "v3_users": [],
                   "allowed_sources": cur["allowed_sources"]})
    # IP thật được phép → trap vẫn gắn theo agentAddress như trước
    trap(rx["trap"], "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.6.3.18.1.3.0", "10.1.0.21"), ("1.3.6.1.2.1.2.2.1.1", 7)])
    evs = wait_events(client, admin, 1)
    assert evs and evs[0]["source_ip"] == "10.1.0.21" and evs[0]["data"]["via"] == "127.0.0.1"


def test_seed_rules_upgrades_vietnamese_release_in_place(client, admin, clean):
    """A database created by the Vietnamese release (v1/v2) keeps rule IDs and admin settings after the English upgrade."""
    legacy_by_new = {}
    for old, new in events.LEGACY_RULE_NAMES.items():
        legacy_by_new.setdefault(new, old)
    with SessionLocal() as db:
        rows = db.query(models.EventRule).filter_by(builtin=True).all()
        before = {}
        for r in rows:
            r.name = legacy_by_new.get(r.name, r.name)        # includes names identical in both languages
            before[r.id] = (r.name, r.threshold)
            r.threshold = 7
        wan = next(r for r in rows if r.name == "Gateway WAN down (pfSense)")
        db.commit()
        events.seed_rules(db)
        events.seed_rules(db)
        after = {r.id: r for r in db.query(models.EventRule).filter_by(builtin=True)}
        assert set(after) == set(before), "rule IDs must be preserved (no delete/re-create)"
        assert all(r.threshold == 7 for r in after.values()), "admin settings must be preserved"
        assert not [r.name for r in after.values() if events._VI_TEXT.search(r.name)]
        assert after[wan.id].name == "Gateway WAN down (pfSense)"
        for rid, (_, thr) in before.items():                 # restore shared rules for the tests that follow
            after[rid].threshold = thr
        db.commit()
