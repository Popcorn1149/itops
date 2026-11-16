"""Demo data có log "như thật": lịch sử 24h đi qua pipeline thật, có sự cố đã đóng and remaining mở, do not send thông báo."""
from datetime import timedelta

from app import demo_logs, models
from app.db import SessionLocal
from tests import simulators


def test_demo_history_realistic(client, admin, clean):
    from app.seed import seed_demo
    with SessionLocal() as db:
        seed_demo(db)
    try:
        out = demo_logs.seed_history(hours=24)
        assert out["events"] > 2000 and out["alerts_open"] >= 5 and out["alerts_resolved"] >= 5
        with SessionLocal() as db:
            evs = db.query(models.Event)
            assert evs.filter(models.Event.asset_id.is_(None)).count() == 0          # mọi log gắn đúng devices mẫu
            first, last = db.query(models.Event.ts).order_by(models.Event.ts).first()[0], db.query(models.Event.ts).order_by(models.Event.ts.desc()).first()[0]
            assert last - first > timedelta(hours=20)                                  # trải đều 24 hours
            kinds = {k for (k,) in db.query(models.Event.kind).distinct()}
            assert {"syslog", "trap", "winlog"} <= kinds
            titles = {a.title for a in db.query(models.Alert).filter_by(source="event")}
            for must in ("Gateway WAN down", "Switch port down", "Datastore connection lost", "UPS switched to battery",
                         "Repeated failed sign-ins", "Disk / RAID failure", "Windows: added to administrators group", "IP-to-MAC address change"):
                assert any(t.startswith(must) for t in titles), must
            wan = db.query(models.Alert).filter(models.Alert.title.like("Gateway WAN down%"), models.Alert.status == "resolved").first()
            assert wan and wan.resolved_at > wan.opened_at and (wan.resolved_at - wan.opened_at) < timedelta(minutes=15)
            trap = db.query(models.Alert).filter(models.Alert.title.like("Port down (SNMP trap)%")).first()
            assert "(1/1/" in trap.title                                             # khoá theo tên cổng, không phải ifIndex
        assert simulators.STATE["telegram"] == [] and simulators.STATE["webhook"] == []   # lịch sử do not send thông báo
        # trang Log devices and Warning có dữ liệu
        assert len(client.get("/api/events?limit=50", headers=admin).json()) == 50
        assert any(a["source"] == "event" for a in client.get("/api/alerts?status=active&limit=500", headers=admin).json())
    finally:
        client.post("/api/reset-data", json={"confirm": "XOA"}, headers=admin)
        with SessionLocal() as db:        # trả rule UC-10 về mặc định (dữ liệu mẫu đã bật nó) – không ảnh hưởng test khác
            r = db.query(models.EventRule).filter(models.EventRule.name.like("IP-to-MAC address change%")).first()
            r.enabled, r.key_filter = False, ""
            db.commit()
        from app import events
        events.invalidate_caches()


def test_demo_logs_off_by_default(monkeypatch):
    monkeypatch.delenv("DEMO_DATA", raising=False)
    assert demo_logs.enabled() is False
    monkeypatch.setenv("DEMO_DATA", "true")
    assert demo_logs.enabled() is True
    monkeypatch.setenv("DEMO_LOGS", "0")
    assert demo_logs.enabled() is False


def test_live_incident_scenarios_build_valid_events():
    """Mọi kịch bản sự cố dùng cho log trực tiếp đều tạo được sự kiện hợp lệ cho devices mẫu có trong CSDL."""
    import random
    from datetime import datetime
    dev = demo_logs.Devices()
    dev.by_name = {"SW-TANG3": "10.0.0.3", "pfSense-HQ": "10.0.0.1", "ESXi-02": "10.0.10.12", "UPS-RACK": "10.0.10.60",
                   "SW-CORE": "10.0.0.2", "AP-HN": "10.1.0.21"}
    now = datetime(2026, 11, 8, 3, 0, 0)
    for name, steps in demo_logs.incidents(random.Random(1)).items():
        evs = [fn(dev, now) for _, fn in steps]
        assert evs and all(e and e["source_ip"] and e["message"] for e in evs), name


def test_tried_usernames_extracted_from_common_formats():
    """Error tìm ra nhờ log mẫu: pfSense ghi "for user 'x'" → trước đây bắt nhầm chữ "user"."""
    from app.events import USER_RE
    skip = ("from", "port", "ssh2", "failed", "success")
    def users(m):
        return {u for u in USER_RE.findall(m) if u.lower() not in skip}
    assert users("/index.php: webConfigurator authentication error for user 'oracle' from: 92.63.197.153") == {"oracle"}
    assert users("Failed password for invalid user admin from 45.1.2.3 port 5222 ssh2") == {"admin"}
    assert users("Failed password for root from 45.1.2.3 port 5222 ssh2") == {"root"}
    assert users("User [admin] from [45.1.2.3] failed to log in via [DSM] due to authorization failure") == {"admin"}
    assert users("pam_unix(sshd:auth): authentication failure; ruser= rhost=45.1.2.3  user=oracle") == {"oracle"}
    assert users("%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: backup] [Source: 45.1.2.3]") == {"backup"}
