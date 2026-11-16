"""Security Monitoring: C10 khoá xoá dữ liệu, C11 gộp theo IP source, C12 danh sách khoá, UC-14 cảnh báo audit + tách nhiệm vụ,
B5 SLA, UC-13 log source im lặng, B7/B8 archive + chuỗi hash, B9/C14/C15 đọc Windows Event theo RecordId."""
from datetime import date, datetime, timedelta

import pytest

from app import events as ev_mod, models, secmon
from app.collectors import winevents as W
from app.db import SessionLocal
from app.models import now


def _syslog(msg, ip="10.9.9.1", app="sshd"):
    return {"kind": "syslog", "raw": f"<38>Nov  5 10:00:00 host {app}[1]: {msg}".encode(), "source_ip": ip}


def _alerts(client, admin):
    return client.get("/api/alerts", headers=admin).json()


@pytest.fixture
def audit_on(client, admin):
    client.put("/api/secmon", json={"audit_alert": {"enabled": True, "targets": [{"type": "default"}]}}, headers=admin)
    with SessionLocal() as db:   # bỏ cảnh báo do chính việc bật cấu hình sinh ra
        db.query(models.Alert).filter(models.Alert.source == "audit").delete()
        db.commit()
    secmon._pending.clear()
    yield
    client.put("/api/secmon", json={"audit_alert": {"enabled": False}}, headers=admin)
    with SessionLocal() as db:
        db.query(models.Alert).filter(models.Alert.source == "audit").delete()
        db.commit()


# ---------------------------------------------------------------- C10
def test_reset_blocked_in_production(client, admin, clean, audit_on, monkeypatch):
    monkeypatch.setattr(secmon, "PRODUCTION", True)
    r = client.post("/api/reset-data", json={"confirm": "XOA"}, headers=admin)
    assert r.status_code == 403
    assert client.get("/api/health").json()["production"] is True
    a = [x for x in _alerts(client, admin) if x["source"] == "audit"]
    assert a and a[0]["severity"] == "critical" and "attempted to delete data" in a[0]["title"]
    assert any(x["action"] == "reset_blocked" for x in client.get("/api/audit", headers=admin).json())


# ---------------------------------------------------------------- C11
def test_login_failures_grouped_by_source_ip(client, admin, clean):
    batch = [_syslog(f"Failed password for {u} from 203.0.113.7 port 5{i} ssh2") for i, u in enumerate(["root", "admin", "test", "oracle", "root", "ubuntu"])]
    batch.append(_syslog("Failed password for root from 198.51.100.9 port 22 ssh2"))
    ev_mod.process_batch(batch)
    al = [a for a in _alerts(client, admin) if a["title"].startswith("Repeated failed sign-ins")]
    assert len(al) == 1, "một IP thử nhiều user → 1 cảnh báo"
    assert "203.0.113.7" in al[0]["title"] and al[0]["severity"] == "trouble"
    assert "203.0.113.7" in al[0]["message"]
    assert "Attempted users:" in al[0]["message"] and "oracle" in al[0]["message"] and "admin" in al[0]["message"]


# ---------------------------------------------------------------- C12
def test_arp_rule_only_for_listed_static_ips(client, admin, clean):
    rules = client.get("/api/event-rules", headers=admin).json()
    arp = next(r for r in rules if r["name"].startswith("IP-to-MAC address change"))
    assert arp["enabled"] is False
    r = client.put(f"/api/event-rules/{arp['id']}", json={"enabled": True, "key_filter": "10.0.0.1, 10.0.0.10"}, headers=admin)
    assert r.status_code == 200
    ev_mod.invalidate_caches()
    ev_mod.process_batch([_syslog("arp: 10.0.0.55 moved from aa:aa:aa:aa:aa:01 to aa:aa:aa:aa:aa:02 on igb1", app="kernel")])
    assert not [a for a in _alerts(client, admin) if "IP-to-MAC address change" in a["title"]], "IP DHCP không nằm trong danh sách → không báo"
    ev_mod.process_batch([_syslog("arp: 10.0.0.1 moved from aa:aa:aa:aa:aa:01 to bb:bb:bb:bb:bb:02 on igb1", app="kernel")])
    al = [a for a in _alerts(client, admin) if "IP-to-MAC address change" in a["title"]]
    assert len(al) == 1 and "10.0.0.1" in al[0]["title"] and al[0]["severity"] == "attention"
    client.put(f"/api/event-rules/{arp['id']}", json={"enabled": False, "key_filter": ""}, headers=admin)


# ---------------------------------------------------------------- UC-14
def test_admin_actions_raise_audit_alerts_and_actor_cannot_close(client, admin, clean, audit_on):
    r = client.post("/api/users", json={"username": "boss2", "password": "Boss@12345", "role": "admin"}, headers=admin)
    assert r.status_code == 200
    a = next(x for x in _alerts(client, admin) if x["source"] == "audit")
    assert a["severity"] == "critical" and "created account boss2" in a["title"] and a["actor"] == "admin"
    assert "Performed by: admin" in a["message"] and "create user boss2" in a["message"]
    assert secmon._pending, "thông báo send to dedicated recipients"
    assert client.post(f"/api/alerts/{a['id']}/ack", headers=admin).status_code == 403, "người thực hiện không tự ack"
    h2 = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "boss2", "password": "Boss@12345"}).json()["token"]}
    assert client.post(f"/api/alerts/{a['id']}/ack", headers=h2).status_code == 200, "người khác ack được"
    c = client.post("/api/checks", json={"name": "c", "type": "tcp", "target": "127.0.0.1", "enabled": True, "config": {"port": 1}}, headers=admin).json()
    client.put(f"/api/checks/{c['id']}", json={"enabled": False}, headers=admin)
    assert any("disabled monitoring check c" in x["title"] for x in _alerts(client, admin) if x["source"] == "audit")
    uid = r.json()["id"]
    client.delete(f"/api/users/{uid}", headers=admin)


def test_login_failure_burst_on_itops(client, admin, audit_on):
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert any("repeated failed sign-ins" in x["title"] for x in _alerts(client, admin) if x["source"] == "audit")
    from app import main
    main._FAILED.clear()


# ---------------------------------------------------------------- B5 SLA
def test_business_minutes_and_sla():
    from app.automation.engine import TZ
    cfg = secmon.get_settings()
    biz = cfg["business"]
    sat = datetime(2026, 11, 7, 18, 0, tzinfo=TZ)                     # Thứ 7 18:00, làm tới 18:30
    assert secmon.add_business_minutes(sat, 60, biz) == datetime(2026, 11, 9, 8, 0, tzinfo=TZ)   # CN nghỉ → T2 08:00
    a = models.Alert(severity="critical", title="x", opened_at=datetime(2026, 11, 7, 15, 0))     # 22:00 hours VN → ngoài hours
    assert secmon.sla_due(a, cfg) == datetime(2026, 11, 7, 15, 30)
    a2 = models.Alert(severity="critical", title="x", opened_at=datetime(2026, 11, 5, 3, 0))     # 10:00 hours VN → trong hours
    assert secmon.sla_due(a2, cfg) == datetime(2026, 11, 5, 3, 15)
    a3 = models.Alert(severity="warning", title="x", opened_at=datetime(2026, 11, 7, 11, 0))     # 18:00 T7, Trouble theo business hours
    assert secmon.sla_due(a3, cfg) == datetime(2026, 11, 9, 1, 0)


def test_sla_breach_flagged_once(client, admin, clean):
    with SessionLocal() as db:
        db.add(models.Alert(severity="critical", title="old", opened_at=now() - timedelta(hours=2)))
        db.commit()
        cfg = secmon.get_settings(db)
        assert len(secmon.check_sla(db, cfg)) == 1
        db.commit()
        assert secmon.check_sla(db, cfg) == []
    a = next(x for x in _alerts(client, admin) if x["title"] == "old")
    assert a["sla_overdue"] is True and a["sla_breached"] is True


# ---------------------------------------------------------------- UC-13
def test_silent_log_source(client, admin, clean):
    fw = client.post("/api/assets", json={"name": "FW-T", "type": "firewall", "ip": "10.1.1.1"}, headers=admin).json()
    sw = client.post("/api/assets", json={"name": "SW-T", "type": "switch", "ip": "10.1.1.2"}, headers=admin).json()
    with SessionLocal() as db:
        db.add(models.Event(asset_id=fw["id"], ts=now() - timedelta(minutes=45), message="x"))
        db.add(models.Event(asset_id=sw["id"], ts=now() - timedelta(hours=2), message="x"))   # switch threshold 24h → chưa báo
        db.add(models.Check(name="ping fw", type="ping", target="10.1.1.1", asset_id=fw["id"], status="ok"))
        db.commit()
        notes = secmon.check_silence(db, secmon.get_settings(db))
        db.commit()
    assert len(notes) == 1 and "FW-T" in notes[0][0]
    with SessionLocal() as db:
        db.add(models.Event(asset_id=fw["id"], ts=now(), message="back"))
        db.commit()
        notes = secmon.check_silence(db, secmon.get_settings(db))
        db.commit()
    assert notes and notes[0][2] == "resolved"


def test_silent_but_device_down_is_not_silence(client, admin, clean):
    fw = client.post("/api/assets", json={"name": "FW-D", "type": "firewall", "ip": "10.1.1.3"}, headers=admin).json()
    with SessionLocal() as db:
        db.add(models.Event(asset_id=fw["id"], ts=now() - timedelta(hours=3), message="x"))
        db.add(models.Check(name="ping", type="ping", target="10.1.1.3", asset_id=fw["id"], status="fail", severity="down"))
        db.commit()
        assert secmon.check_silence(db, secmon.get_settings(db)) == []


# ---------------------------------------------------------------- B7/B8
def test_archive_and_hash_chain(client, admin, clean, tmp_path):
    client.put("/api/secmon", json={"archive": {"dir": str(tmp_path)}}, headers=admin)
    from app.automation.engine import to_utc_naive, TZ
    d1, d2 = date(2026, 10, 1), date(2026, 10, 2)
    with SessionLocal() as db:
        db.add(models.Event(ts=to_utc_naive(datetime(2026, 10, 1, 9, 0, tzinfo=TZ)), message="day1"))
        db.add(models.Event(ts=to_utc_naive(datetime(2026, 10, 2, 23, 59, tzinfo=TZ)), message="day2"))
        db.commit()
        cfg = secmon.get_settings(db)
        r1 = secmon.archive_day(db, cfg, d1)
        r2 = secmon.archive_day(db, cfg, d2)
        assert secmon.archive_day(db, cfg, d1) is None, "không ghi đè days đã lưu"
    assert r1["rows"] >= 1 and r2["rows"] >= 1
    res = client.get("/api/secmon/archive", headers=admin).json()
    assert res["ok"] and len(res["days"]) == 2
    import gzip
    p = tmp_path / r1["file"]
    with gzip.open(p, "at") as f:
        f.write('{"_t":"event","message":"chen them"}\n')
    res = client.get("/api/secmon/archive", headers=admin).json()
    assert not res["ok"] and any(not d["file_ok"] for d in res["days"]), "sửa file archive phải bị phát hiện"
    client.put("/api/secmon", json={"archive": {"dir": "archive"}}, headers=admin)


# ---------------------------------------------------------------- B9 / C14 / C15
def test_winevents_cursor_and_events():
    first = "##LOG Security 500 1\n##LOG System 900 1\n"
    cur, evs, notes = W.parse_output(first, {})
    assert cur == {"Security": 500, "System": 900} and evs == [], "lần đầu chỉ ghi nhận vị trí"
    out = "\n".join([
        "##LOG Security 510 1", "##LOG System 905 1",
        '##EV {"log":"Security","id":4720,"rec":503,"t":"2026-11-05T03:00:00Z","p":["eve","DOM","S-1","admin","IT"],"m":"A user account was created."}',
        '##EV {"log":"Security","id":4732,"rec":504,"t":"2026-11-05T03:01:00Z","p":["CN=eve","S-1","Administrators","BUILTIN","S","admin"],"m":"A member was added"}',
        '##EV {"log":"System","id":104,"rec":903,"t":"2026-11-05T03:02:00Z","p":["admin","DOM","System"],"m":"The System log file was cleared."}',
        '##EV {"log":"Security","id":1100,"rec":508,"t":"2026-11-05T04:00:00Z","p":[],"m":"The event logging service has shut down."}',
        '##EV {"log":"System","id":1074,"rec":904,"t":"2026-11-05T03:59:30Z","p":[],"m":"restart"}',
    ])
    cur, evs, notes = W.parse_output(out, cur)
    assert cur == {"Security": 510, "System": 905}
    msgs = [e["message"] for e in evs]
    assert any(m.startswith("EventID=4720") and "target=eve" in m for m in msgs)
    assert any("EventID=1100" in m and "planned=1" in m for m in msgs), "1100 có 1074 đi kèm = tắt machines có kế hoạch"
    assert not any("EventID=1074" in m for m in msgs)
    cur2, evs2, _ = W.parse_output("##LOG Security 3 1\n##LOG System 905 1", cur)
    assert any("RecordId decreased" in e["message"] for e in evs2) and cur2["Security"] == 3
    _, evs3, _ = W.parse_output("##LOG Security 700 600\n##LOG System 905 1", cur)
    assert any("RecordId has a gap" in e["message"] for e in evs3)
    assert "EventRecordID>510" not in W.build_command(cur)   # lệnh được base64-encoded
    import base64
    ps = base64.b64decode(W.build_command(cur).split()[-1]).decode("utf-16-le")
    assert '"Security": 510' in ps and "4720" in ps


def test_winevents_rules_raise_alerts(client, admin, clean):
    _, evs, _ = W.parse_output("\n".join([
        "##LOG Security 20 1", "##LOG System 20 1",
        '##EV {"log":"Security","id":1102,"rec":11,"t":"2026-11-05T03:00:00Z","p":["S","admin"],"m":"The audit log was cleared."}',
        '##EV {"log":"Security","id":1100,"rec":12,"t":"2026-11-05T03:00:00Z","p":[],"m":"shut down"}',
        '##EV {"log":"Security","id":4732,"rec":13,"t":"2026-11-05T03:00:00Z","p":["CN=x","S","Administrators","B","S","adm"],"m":"added"}',
        '##EV {"log":"Security","id":4732,"rec":14,"t":"2026-11-05T03:00:00Z","p":["CN=x","S","Print Operators","B","S","adm"],"m":"added"}',
    ]), {"Security": 10, "System": 10})
    batch = [{"kind": "winlog", "source_ip": "10.5.5.5", "severity": e["severity"], "facility": None, "host": "SRV1",
              "app": "WinEvent", "message": e["message"], "device_ts": e["t"], "data": {}} for e in evs]
    ev_mod.invalidate_caches()
    ev_mod.process_batch(batch)
    titles = [a["title"] for a in _alerts(client, admin)]
    assert any(t.startswith("Windows: event log cleared") for t in titles)
    assert any(t.startswith("Windows: event logging service stopped unexpectedly") for t in titles)
    assert sum(t.startswith("Windows: added to administrators group") for t in titles) == 1, "chỉ nhóm đặc quyền"


# ---------------------------------------------------------------- D
def test_receiver_sources_show_blocked(client, admin):
    ev_mod.submit({"kind": "syslog", "raw": b"<13>x", "source_ip": "8.8.4.4"})
    src = client.get("/api/receivers/sources", headers=admin).json()["sources"]
    s = next(x for x in src if x["ip"] == "8.8.4.4")
    assert s["blocked"] is True and s["count"] >= 1
