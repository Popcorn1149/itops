"""Tự động hoá: cron, kiểm tra kịch bản, từng template trong thư viện, kịch bản tự tạo, API.

Mỗi template có ít nhất 1 test chạy trên dữ liệu dựng giống thực tế (site → firewall → switch → server, check, cảnh báo, log,
lịch sử số liệu). Tin nhắn không gửi thật: send_to / notify được thay bằng hàm ghi lại.
"""
import asyncio
from datetime import datetime, timedelta

import pytest

from app import models, scheduler
from app.automation import engine as E
from app.collectors import COLLECTORS
from app.collectors.base import Result
from app.db import SessionLocal
from app.models import now


# ---------------------------------------------------------------- tiện ích
@pytest.fixture()
def sent(monkeypatch):
    """Ghi lại mọi tin: qua kịch bản (send_to) và qua kênh mặc định (notify)."""
    box = []

    async def fake_send(targets, subject, text, severity="info"):
        box.append({"via": "automation", "targets": targets, "subject": subject, "text": text, "severity": severity})
        return {"fake": "ok"}

    async def fake_notify(subject, text, severity="critical", only=None):
        box.append({"via": "notify", "subject": subject, "text": text, "severity": severity})
        return {"fake": "ok"}
    monkeypatch.setattr(E, "send_to", fake_send)
    import app.notify as nt
    monkeypatch.setattr(nt, "notify", fake_notify)
    return box


@pytest.fixture()
def autoclean(clean):
    db = SessionLocal()
    db.query(models.AutomationRun).delete()
    db.query(models.Automation).delete()
    db.commit()
    db.close()
    yield


def mk_auto(client, admin, code, spec=None, enabled=True, **kw):
    r = client.post("/api/automations", headers=admin, json={"code": code, "spec": spec or {}, "enabled": enabled, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def run(aid, trigger="manual", dry=False):
    return asyncio.run(E.run_automation(aid, trigger, dry_run=dry))


def at(h=8, m=0, days=0):
    """Giờ VN hôm nay ± ngày."""
    return E.local_now().replace(hour=h, minute=m) + timedelta(days=days)


@pytest.fixture()
def world(client, admin, autoclean):
    """Hạ tầng mẫu: HQ (FW01 → SW-CORE → SRV-APP, SRV-DB), Chi nhánh (FW-CN). Check, cảnh báo, log, hệ thống trọng yếu."""
    db = SessionLocal()
    hq, cn = models.Site(name="HQ"), models.Site(name="Chi nhánh")
    db.add_all([hq, cn]); db.flush()
    fw = models.Asset(name="FW01", type="firewall", site_id=hq.id, ip="10.0.0.1", owner="An", status="up", last_seen=now())
    db.add(fw); db.flush()
    sw = models.Asset(name="SW-CORE", type="switch", site_id=hq.id, parent_id=fw.id, ip="10.0.0.2", owner="An", status="up", last_seen=now())
    db.add(sw); db.flush()
    app_ = models.Asset(name="SRV-APP", type="server", site_id=hq.id, parent_id=sw.id, ip="10.0.0.10", status="up", last_seen=now())
    dbs = models.Asset(name="SRV-DB", type="server", site_id=hq.id, parent_id=sw.id, ip="10.0.0.11", owner="Bình", status="up", last_seen=now())
    fwcn = models.Asset(name="FW-CN", type="firewall", site_id=cn.id, ip="10.1.0.1", owner="An", status="up", last_seen=now())
    old = models.Asset(name="PRINTER-OLD", type="printer", site_id=hq.id, ip="10.0.0.99", owner="An", status="down",
                       last_seen=now() - timedelta(days=45), created_at=now() - timedelta(days=200))
    new = models.Asset(name="NAS-NEW", type="nas", site_id=hq.id, ip="10.0.0.50", status="unknown", created_at=now() - timedelta(days=1))
    db.add_all([app_, dbs, fwcn, old, new]); db.flush()

    def C(name, typ, target, asset, **kw):
        c = models.Check(name=name, type=typ, target=target, asset_id=asset.id, site_id=asset.site_id, interval=60, enabled=True,
                         status=kw.pop("status", "ok"), last_checked=now(), **kw)
        db.add(c); db.flush()
        return c
    c_fw = C("FW01 ping", "ping", "10.0.0.1", fw)
    c_sw = C("SW-CORE ping", "ping", "10.0.0.2", sw)
    c_app = C("SRV-APP ping", "ping", "10.0.0.10", app_)
    c_db = C("SRV-DB SSH", "ssh", "10.0.0.11", dbs, last_data={"res": {"cpu": 30, "mem": 93, "disk": 86, "disk_name": "/data",
                                                                       "levels": {"cpu": "ok", "mem": "trouble", "disk": "attention"}, "level": "trouble"}})
    C("FW-CN ping", "ping", "10.1.0.1", fwcn)
    C("Line VNPT", "ping", "113.161.119.25", fw, config={"map_role": "wan"}, last_latency=3.0)
    C("Portal", "http", "https://portal.congty.vn", app_, last_data={"code": 200, "cert_days": 9})
    C("Printer", "ping", "10.0.0.99", old, status="fail", severity="down")
    crit = models.CriticalSystem(name="ERP", level="High", asset_id=dbs.id, check_ids=[c_db.id], backup=False, owner="",
                                 runbook="Kiểm tra dịch vụ ERP\nXem log ứng dụng\nGọi nhà cung cấp ERP")
    db.add(crit)
    db.add(models.Alert(check_id=c_db.id, asset_id=dbs.id, site_id=hq.id, severity="trouble", metric="mem", source="resource",
                        title="SRV-DB: RAM 93% · Trouble", message="RAM 93%", opened_at=now() - timedelta(hours=2)))
    for i in range(5):
        db.add(models.Event(source_ip="10.9.9.9", severity=3, host="unknown-box", message=f"err {i}", ts=now() - timedelta(hours=3)))
    db.commit()
    ids = dict(hq=hq.id, cn=cn.id, fw=fw.id, sw=sw.id, app=app_.id, dbs=dbs.id, fwcn=fwcn.id, old=old.id, new=new.id,
               c_fw=c_fw.id, c_sw=c_sw.id, c_app=c_app.id, c_db=c_db.id, crit=crit.id)
    db.close()
    return ids


# ---------------------------------------------------------------- cron
def test_cron_match_and_next():
    t = datetime(2026, 11, 2, 8, 0, tzinfo=E.TZ)          # Thứ Hai
    assert E.cron_match("0 8 * * 1", t) and not E.cron_match("0 8 * * 2", t)
    assert E.cron_match("*/15 8-9 * * 1-5", t) and E.cron_match("0 8 2 * *", t)
    assert E.cron_match("0 8 1 * 1", t)                   # ngày & thứ đều giới hạn → một trong hai
    assert E.cron_match("0 8 * * 7", datetime(2026, 11, 1, 8, 0, tzinfo=E.TZ))      # 7 = Chủ nhật
    assert E.next_run("30 7 * * *", t) == t.replace(day=3, hour=7, minute=30)
    assert E.next_run("0 9 1 1,4,7,10 *", t).strftime("%d/%m/%Y %H:%M") == "01/01/2027 09:00"
    for bad in ("", "* * *", "60 * * * *", "* 24 * * *", "a b c d e", "*/0 * * * *", "5-1 * * * *"):
        with pytest.raises(ValueError):
            E.parse_cron(bad)
    assert E.describe_cron("30 7 * * *") == "07:30 hằng ngày" and E.describe_cron("0 8 * * 1") == "08:00 Thứ Hai hằng tuần"


def test_validate_spec_errors():
    with pytest.raises(ValueError, match="cron"):
        E.validate_spec("RPT-01", {"trigger": {"type": "schedule", "cron": "bad"}})
    with pytest.raises(ValueError, match="L2/L3"):
        E.validate_spec("RPT-01", {"level": "L3"})
    with pytest.raises(ValueError, match="Email"):
        E.validate_spec("RPT-01", {"actions": [{"type": "email", "to": "khong-phai-email"}]})
    with pytest.raises(ValueError, match="trigger.type"):
        E.validate_spec("INC-01", {"trigger": {"type": "schedule", "cron": "* * * * *"}})
    with pytest.raises(ValueError, match="Khối không tồn tại"):
        E.validate_spec("CUSTOM", {"content": {"blocks": ["khong-co"]}})
    with pytest.raises(ValueError, match="assets hoặc sites"):
        E.validate_spec("LCM-01", {"params": {"windows": [{"name": "x", "cron": "0 22 * * 6", "duration_min": 60}]}})
    ok = E.validate_spec("RPT-02", {"actions": [{"type": "email", "to": ["a@congty.vn", "b@congty.vn"]}]})
    assert ok["actions"][0]["to"] == "a@congty.vn, b@congty.vn"


# ---------------------------------------------------------------- API + YAML trong tài liệu
DOC_YAML = """id: RPT-02
name: Báo cáo tuần vận hành
enabled: true
trigger: { type: schedule, cron: "0 8 * * 1", tz: Asia/Ho_Chi_Minh }
scope: { sites: all, criticality: [high, medium] }
params: { uptime_target: 99.5, top_n: 5 }
actions:
  - { type: email, to: [it-manager@congty.vn], format: html+pdf }
  - { type: telegram, chat: it-ops, format: summary }
level: L0
kpi: "Quản lý đọc trong 24h; không cần hỏi thêm số liệu"
"""


def test_api_catalog_yaml_roundtrip_and_permissions(client, admin, autoclean):
    cat = client.get("/api/automation/catalog", headers=admin).json()
    codes = {t["code"] for t in cat["templates"]}
    assert {"RPT-01", "RPT-02", "RPT-03", "RPT-04", "RPT-06", "INC-01", "INC-02", "INC-03", "INC-05", "INC-08",
            "PRE-01", "PRE-02", "PRE-04", "PRE-08", "LCM-01", "LCM-02", "LCM-03", "LCM-06", "CUSTOM"} == codes
    assert len(cat["unsupported"]) == 12 and all(u["reason"] for u in cat["unsupported"])
    # dán nguyên mẫu YAML trong tài liệu
    r = client.post("/api/automations", headers=admin, json={"code": "RPT-02", "yaml": DOC_YAML})
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["enabled"] is True and a["when"] == "08:00 Thứ Hai hằng tuần" and a["next_run"]
    assert a["effective"]["actions"][0] == {"type": "email", "to": "it-manager@congty.vn", "format": "html+pdf"}
    assert client.post("/api/automations", headers=admin, json={"code": "RPT-02"}).status_code == 400      # mỗi template 1 bản
    y = client.get(f"/api/automations/{a['id']}/yaml", headers=admin).json()["yaml"]
    assert "id: RPT-02" in y and "uptime_target: 99.5" in y
    r = client.put(f"/api/automations/{a['id']}", headers=admin, json={"yaml": y.replace("99.5", "99.9")})
    assert r.json()["effective"]["params"]["uptime_target"] == 99.9
    r = client.put(f"/api/automations/{a['id']}", headers=admin, json={"yaml": "trigger: [không đúng"})
    assert r.status_code == 400 and "YAML lỗi" in r.json()["detail"]
    assert client.put(f"/api/automations/{a['id']}", headers=admin, json={"enabled": False}).json()["enabled"] is False
    # người xem chỉ được đọc
    client.post("/api/users", headers=admin, json={"username": "viewer1", "password": "Viewer@12345", "role": "viewer", "full_name": "V"})
    tok = client.post("/api/auth/login", json={"username": "viewer1", "password": "Viewer@12345"}).json()["token"]
    vh = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/automations", headers=vh).status_code == 200
    assert client.post("/api/automations", headers=vh, json={"code": "RPT-01"}).status_code == 403
    assert client.post(f"/api/automations/{a['id']}/run", headers=vh).status_code == 403
    assert client.delete(f"/api/automations/{a['id']}", headers=admin).json()["ok"]


# ---------------------------------------------------------------- RPT
def test_rpt01_morning_digest(client, admin, world, sent):
    a = mk_auto(client, admin, "RPT-01", {"actions": [{"type": "telegram", "chat": "-100123"}]})
    r = run(a["id"])
    assert r["status"] == "ok" and len(sent) == 1
    m = sent[0]
    assert "Bản tin IT" in m["subject"] and m["targets"] == [{"type": "telegram", "chat": "-100123"}]
    assert "SRV-DB: RAM 93% · Trouble" in m["text"] and "SSL portal.congty.vn: còn 9 ngày" in m["text"]
    assert "HQ: 1/1 line" in m["text"] and "Tài sản:" in m["text"]
    # chạy thử: có bản xem trước, không gửi, có lịch sử đánh dấu dry_run
    sent.clear()
    r = client.post(f"/api/automations/{a['id']}/run?dry=true", headers=admin).json()
    assert r["status"] == "ok" and "Bản tin IT" in r["output"] and sent == []
    runs = client.get(f"/api/automation/runs?automation_id={a['id']}", headers=admin).json()
    assert runs[0]["dry_run"] is True and runs[1]["dry_run"] is False and runs[1]["sent"] == {"fake": "ok"}


def _results(db, cid, days, every_min=60, down_at=(), metric=None, latency=None):
    """Bản ghi check_results giả: mỗi every_min phút trong `days` ngày qua."""
    t = now() - timedelta(days=days)
    i = 0
    while t < now():
        d = i in down_at
        db.add(models.CheckResult(check_id=cid, ts=t, status="fail" if d else "ok", down=d,
                                  metrics=(metric(i) if metric else None), latency=(latency(i) if latency else 1.0)))
        t += timedelta(minutes=every_min)
        i += 1


def test_rpt02_weekly_report(client, admin, world, sent):
    db = SessionLocal()
    _results(db, world["c_fw"], 8, down_at=range(48, 51))            # 3 giờ DOWN, ~6 ngày trước
    _results(db, world["c_app"], 8)
    al = models.Alert(check_id=world["c_fw"], asset_id=world["fw"], site_id=world["hq"], severity="down", title="FW01 ping DOWN",
                      opened_at=now() - timedelta(days=3), acked_at=now() - timedelta(days=3) + timedelta(minutes=12),
                      resolved_at=now() - timedelta(days=3) + timedelta(minutes=50), status="resolved")
    db.add(al)
    db.query(models.Check).filter_by(id=world["c_fw"]).update({"interval": 3600})     # mỗi bản ghi = 1 giờ
    db.commit(); db.close()
    a = mk_auto(client, admin, "RPT-02", {"params": {"uptime_target": 99.9}})
    r = run(a["id"])
    assert r["status"] == "ok"
    t = sent[0]["text"]
    assert "Báo cáo tuần vận hành" in sent[0]["subject"]
    for sec in ("Tóm tắt:", "Số liệu chính:", "Sự cố đáng chú ý:", "Việc cần quyết định:"):
        assert sec in t
    assert "KHÔNG đạt mục tiêu 99.9%" in t and "HQ:" in t and "DOWN 3 giờ" in t
    assert "MTTA (thời gian tới khi có người nhận): 12 phút" in t and "MTTR (thời gian tới khi đóng): 50 phút" in t
    assert "FW01: " in t                                               # top thiết bị nhiều sự cố


def test_rollup_and_rpt03_monthly_sla(client, admin, world, sent):
    db = SessionLocal()
    first = E.local_now().replace(day=1, hour=0, minute=0)
    prev = (first - timedelta(days=1)).replace(day=1)
    pp = (prev - timedelta(days=1)).replace(day=1)
    d = prev
    while d < first:                                                     # tháng trước: 1 ngày có 60 phút DOWN
        db.merge(models.DailyUptime(check_id=world["c_fw"], day=d.strftime("%Y-%m-%d"), total=1440,
                                    down=60 if d.day == 5 else 0, down_minutes=60 if d.day == 5 else 0))
        d += timedelta(days=1)
    d = pp
    while d < prev:                                                      # tháng trước nữa: không DOWN
        db.merge(models.DailyUptime(check_id=world["c_fw"], day=d.strftime("%Y-%m-%d"), total=1440, down=0, down_minutes=0))
        d += timedelta(days=1)
    db.query(models.CriticalSystem).filter_by(id=world["crit"]).update({"check_ids": [world["c_fw"]]})
    db.commit(); db.close()
    a = mk_auto(client, admin, "RPT-03", {"params": {"uptime_target": 99.9}})
    run(a["id"])
    t = sent[0]["text"]
    days = (first - prev).days
    pct = (1440 * days - 60) / (1440 * days) * 100
    assert f"Báo cáo SLA tháng {prev.strftime('%m/%Y')}" == sent[0]["subject"]
    assert f"✗ HQ: {pct:.3f}% · DOWN 1 giờ (tháng trước 100.00%)" in t
    assert "✗ ERP:" in t and "Tìm nguyên nhân gốc" in t


def test_rollup_uptime_from_raw_results(world):
    db = SessionLocal()
    yday = E.local_now().replace(hour=0, minute=0) - timedelta(days=1)
    for i in range(24 * 60):
        ts = E.to_utc_naive(yday + timedelta(minutes=i))
        db.add(models.CheckResult(check_id=world["c_sw"], ts=ts, status="fail" if i < 30 else "ok", down=i < 30))
    db.commit()
    E.rollup_uptime(force=True)
    row = db.get(models.DailyUptime, (world["c_sw"], yday.strftime("%Y-%m-%d")))
    assert row.total == 1440 and row.down == 30 and row.down_minutes == 30
    up = E.uptime_between(db, [world["c_sw"]], yday, yday + timedelta(days=1))
    assert up[world["c_sw"]][:2] == (1440, 30)
    db.close()


def test_rpt04_backup_risks(client, admin, world, sent):
    a = mk_auto(client, admin, "RPT-04")
    r = run(a["id"])
    assert r["status"] == "ok" and "ERP" in sent[0]["text"]


def test_rpt06_asset_changes(client, admin, world, sent):
    a = mk_auto(client, admin, "RPT-06")
    run(a["id"])
    t = sent[0]["text"]
    assert "Tài sản mới (30 ngày): " in t and "NAS-NEW" in t
    assert "Nguồn lạ gửi log chưa xử lý: 1 – 10.9.9.9" in t
    assert "Im lặng > 7 ngày: 1 – PRINTER-OLD" in t and "Thiếu người phụ trách:" in t and "SRV-APP" in t


# ---------------------------------------------------------------- INC (hook trên luồng cảnh báo thật)
def _fake_collector(monkeypatch, states):
    """states: {target: 'up'|'down'} – ping giả."""
    async def fake(target, cfg):
        if states.get(target, "up") == "down":
            return Result("fail", "Không phản hồi", None, 100.0, {"loss": 100.0}, down=True)
        return Result("ok", "1 ms", 1.0, 0.0, {"loss": 0.0})
    monkeypatch.setitem(COLLECTORS, "ping", fake)


def _run_checks(ids, times=1):
    for _ in range(times):
        for cid in ids:
            asyncio.run(scheduler.run_check(cid))


def test_inc01_root_cause_grouping(client, admin, world, sent, monkeypatch):
    a = mk_auto(client, admin, "INC-01")
    states = {"10.0.0.2": "down", "10.0.0.10": "down"}               # switch + server phía sau đều mất
    _fake_collector(monkeypatch, states)
    _run_checks([world["c_sw"], world["c_app"]], times=2)
    subj = [m["subject"] for m in sent]
    assert "SW-CORE ping DOWN" in subj and "SRV-APP ping DOWN" not in subj
    sw_msg = next(m for m in sent if m["subject"] == "SW-CORE ping DOWN")
    assert "2 thiết bị phía sau bị ảnh hưởng" in sw_msg["text"]       # SRV-APP, SRV-DB
    db = SessionLocal()
    child = db.query(models.Alert).filter_by(check_id=world["c_app"]).first()
    assert child.suppressed and "SW-CORE (cha) đang DOWN" in child.suppress_reason   # vẫn ghi nhận, chỉ không gửi
    db.close()
    runs = client.get(f"/api/automation/runs?automation_id={a['id']}", headers=admin).json()
    assert any("Chặn: SRV-APP ping DOWN" in r["summary"] for r in runs)
    pv = client.post(f"/api/automations/{a['id']}/run?dry=true", headers=admin).json()
    assert "SW-CORE ping DOWN: 2 thiết bị phía sau · 2 cảnh báo con sẽ bị gom" in pv["output"]


def test_inc02_flapping(client, admin, world, sent, monkeypatch):
    mk_auto(client, admin, "INC-02", {"params": {"changes": 3, "window_min": 10, "quiet_min": 60}})
    states = {}
    _fake_collector(monkeypatch, states)
    db = SessionLocal()
    db.query(models.Check).filter_by(id=world["c_app"]).update({"config": {"alert_after": 1}})
    db.commit(); db.close()
    for st in ["down", "up", "down", "up", "down", "up"]:
        states["10.0.0.10"] = st
        _run_checks([world["c_app"]])
    subj = [m["subject"] for m in sent]
    # 3 tin đầu bình thường (mới 2 lần đổi), lần đổi thứ 3 → gộp 1 tin "chập chờn", sau đó không còn tin lẻ
    assert subj == ["SRV-APP ping DOWN", "SRV-APP ping đã hoạt động lại", "SRV-APP ping DOWN", "SRV-APP ping chập chờn"]


def test_inc03_escalation(client, admin, world, sent):
    a = mk_auto(client, admin, "INC-03", {"params": {"steps": [
        {"label": "Trưởng nhóm", "after_min": 15, "severities": ["High"], "targets": [{"type": "telegram", "chat": "111"}]},
        {"label": "Quản lý", "after_min": 60, "severities": ["High"], "targets": [{"type": "email", "to": "boss@congty.vn"}]},
        {"label": "Nhóm IT", "after_min": 30, "severities": ["Medium"], "targets": []}]}})
    db = SessionLocal()
    hi = models.Alert(check_id=world["c_fw"], asset_id=world["fw"], site_id=world["hq"], severity="down", title="FW01 DOWN",
                      opened_at=now() - timedelta(minutes=20))
    db.add(hi); db.commit()
    hid = hi.id
    db.close()
    run(a["id"], "interval")
    # FW01 (High, 20′) → bước 1; RAM SRV-DB (Medium, 2 giờ) → bước 3. Chưa tới bước 2.
    got = sorted((m["subject"], str(m["targets"])) for m in sent)
    assert got == sorted([("[Leo thang – Trưởng nhóm] FW01 DOWN", str([{"type": "telegram", "chat": "111"}])),
                          ("[Leo thang – Nhóm IT] SRV-DB: RAM 93% · Trouble", str([{"type": "default"}]))])
    sent.clear()
    run(a["id"], "interval")
    assert sent == []                                                  # không báo lặp
    db = SessionLocal()
    db.query(models.Alert).filter_by(id=hid).update({"opened_at": now() - timedelta(minutes=61)})
    db.commit(); db.close()
    run(a["id"], "interval")
    assert [m["subject"] for m in sent] == ["[Leo thang – Quản lý] FW01 DOWN"]
    sent.clear()
    client.post(f"/api/alerts/{hid}/ack", headers=admin)              # có người nhận → dừng
    db = SessionLocal()
    al = db.get(models.Alert, hid)
    assert al.acked_at and al.escalation_level == 2
    db.close()
    run(a["id"], "interval")
    assert sent == []


def test_inc05_runbook(client, admin, world, sent, monkeypatch):
    mk_auto(client, admin, "INC-05", {"params": {"rules": [{"contains": "VNPT", "steps": ["Gọi 18001166", "Đọc mã HĐ 0123"]}]}})
    _fake_collector(monkeypatch, {"10.0.0.10": "down", "113.161.119.25": "down"})
    db = SessionLocal()
    vnpt = db.query(models.Check).filter_by(name="Line VNPT").first().id
    db.close()
    _run_checks([world["c_app"], vnpt], times=2)
    app_msg = next(m for m in sent if m["subject"] == "SRV-APP ping DOWN")
    assert "Cách xử lý:\n1. Ping lại từ máy khác" in app_msg["text"]
    vn = next(m for m in sent if m["subject"] == "Line VNPT DOWN")
    assert "1. Gọi 18001166\n2. Đọc mã HĐ 0123" in vn["text"]


def test_inc05_runbook_from_critical_system(client, admin, world, sent, monkeypatch):
    mk_auto(client, admin, "INC-05")
    async def fake(target, cfg):
        return Result("fail", "SSH lỗi: timeout")
    monkeypatch.setitem(COLLECTORS, "ssh", fake)
    _run_checks([world["c_db"]], times=2)
    m = next(m for m in sent if m["subject"] == "SRV-DB SSH DOWN")
    assert "1. Kiểm tra dịch vụ ERP\n2. Xem log ứng dụng\n3. Gọi nhà cung cấp ERP" in m["text"]


def test_inc08_user_notice(client, admin, world, sent):
    a = mk_auto(client, admin, "INC-08", {"params": {"down_minutes": 10}, "actions": [{"type": "telegram", "chat": "-100all"}]})
    db = SessionLocal()
    al = models.Alert(check_id=world["c_db"], asset_id=world["dbs"], severity="down", title="SRV-DB SSH DOWN", opened_at=now() - timedelta(minutes=5))
    db.add(al); db.commit()
    aid = al.id
    db.close()
    run(a["id"], "interval")
    assert sent == []                                                   # mới 5 phút
    db = SessionLocal()
    db.query(models.Alert).filter_by(id=aid).update({"opened_at": now() - timedelta(minutes=12)})
    db.commit(); db.close()
    run(a["id"], "interval")
    assert sent[0]["subject"] == "ERP đang gián đoạn" and "IT đã nhận thông tin" in sent[0]["text"]
    assert sent[0]["targets"] == [{"type": "telegram", "chat": "-100all"}]
    run(a["id"], "interval")
    assert len(sent) == 1
    db = SessionLocal()
    db.query(models.Alert).filter_by(id=aid).update({"status": "resolved", "resolved_at": now()})
    db.commit(); db.close()
    run(a["id"], "interval")
    assert sent[1]["subject"] == "ERP đã hoạt động trở lại" and "khoảng 12 phút" in sent[1]["text"]


# ---------------------------------------------------------------- PRE
def test_pre01_disk_forecast(client, admin, world, sent):
    db = SessionLocal()
    # 5 ngày, tăng 1%/ngày từ 80% → hôm nay ~85% → chạm 90% sau ~5 ngày
    _results(db, world["c_db"], 5, every_min=120, metric=lambda i: {"disk": round(80 + i * (2 / 24), 2), "cpu": 20, "mem": 50})
    db.commit(); db.close()
    a = mk_auto(client, admin, "PRE-01")
    r = run(a["id"])
    assert r["status"] == "ok"
    t = sent[0]["text"]
    assert "SRV-DB (/data): " in t and "→ chạm 90% khoảng" in t and "(còn ~5 ngày, tăng 1.00%/ngày)" in t


def test_pre01_not_enough_data(client, admin, world, sent):
    db = SessionLocal()
    _results(db, world["c_db"], 0.2, every_min=60, metric=lambda i: {"disk": 80 + i})
    db.commit(); db.close()
    a = mk_auto(client, admin, "PRE-01")
    assert run(a["id"])["status"] == "skipped" and sent == []


def test_pre02_ssl_reminders(client, admin, world, sent):
    a = mk_auto(client, admin, "PRE-02")
    run(a["id"])
    assert sent[0]["subject"] == "SSL portal.congty.vn còn 9 ngày" and sent[0]["severity"] == "warning"   # mốc 14
    run(a["id"])
    assert len(sent) == 1                                               # không nhắc lại cùng mốc
    db = SessionLocal()
    c = db.query(models.Check).filter_by(name="Portal").first()
    c.last_data = {"cert_days": 6}
    db.commit()
    run(a["id"])
    assert sent[1]["severity"] == "critical" and "lần nhắc cuối" in sent[1]["text"]
    c = db.query(models.Check).filter_by(name="Portal").first()
    c.last_data = {"cert_days": 365}                                    # gia hạn
    db.commit(); db.close()
    run(a["id"])
    db = SessionLocal()
    assert db.get(models.Automation, a["id"]).state["sent"] == {}
    db.close()


def test_pre04_latency_anomaly(client, admin, world, sent):
    db = SessionLocal()
    _results(db, world["c_fw"], 3, every_min=10, latency=lambda i: 2.0 + (i % 3) * 0.2)
    for k in range(5):
        db.add(models.CheckResult(check_id=world["c_fw"], ts=now() - timedelta(minutes=k * 2), status="ok", down=False, latency=40.0))
    db.commit(); db.close()
    a = mk_auto(client, admin, "PRE-04")
    run(a["id"], "interval")
    assert "FW01 ping: " in sent[0]["text"] and "ms trong 15 phút (bình thường 2.2 ± 0.2 ms)" in sent[0]["text"]
    run(a["id"], "interval")
    assert len(sent) == 1                                               # nghỉ 6 giờ trước khi nhắc lại


def test_pre08_log_anomaly(client, admin, world, sent):
    db = SessionLocal()
    for d in range(1, 8):
        for i in range(5):
            db.add(models.Event(source_ip="10.0.0.1", severity=3, host="FW01", message="x", ts=now() - timedelta(days=d, minutes=10 + i)))
    for i in range(60):
        db.add(models.Event(source_ip="10.0.0.1", severity=3, host="FW01", message=f"kernel: em0 link flap {i}", ts=now() - timedelta(minutes=i % 50)))
    db.commit(); db.close()
    a = mk_auto(client, admin, "PRE-08")
    run(a["id"], "interval")
    t = sent[0]["text"]
    assert "FW01 (10.0.0.1): 60 log lỗi/cảnh báo trong 1 giờ (bình thường ~5)" in t and "kernel: em0 link flap" in t


# ---------------------------------------------------------------- LCM
def test_lcm01_maintenance_window(client, admin, world, sent, monkeypatch):
    t0 = E.local_now()
    start = t0 - timedelta(minutes=10)
    w = {"name": "Nâng cấp switch", "cron": f"{start.minute} {start.hour} * * *", "duration_min": 60, "assets": [world["sw"]]}
    a = mk_auto(client, admin, "LCM-01", {"params": {"windows": [w]}})
    _fake_collector(monkeypatch, {"10.0.0.2": "down", "10.0.0.10": "down", "10.1.0.1": "down"})
    _run_checks([world["c_sw"], world["c_app"], world["c_fw"] + 0], times=2)
    db = SessionLocal()
    fwcn = db.query(models.Check).filter_by(name="FW-CN ping").first().id
    db.close()
    _run_checks([fwcn], times=2)
    subj = [m["subject"] for m in sent]
    assert "SW-CORE ping DOWN" not in subj and "SRV-APP ping DOWN" not in subj    # trong bảo trì (gồm thiết bị phía sau)
    assert "FW-CN ping DOWN" in subj                                              # ngoài phạm vi vẫn báo
    pv = client.post(f"/api/automations/{a['id']}/run?dry=true", headers=admin).json()
    assert "Nâng cấp switch: ĐANG DIỄN RA · 60 phút · 3 thiết bị" in pv["output"]
    # nhắc trước 24 giờ và tổng kết sau bảo trì
    sent.clear()
    tomorrow = t0 + timedelta(hours=24)
    db = SessionLocal()
    db.query(models.Automation).filter_by(id=a["id"]).update({"spec": {"params": {"windows": [
        {**w, "cron": f"{tomorrow.minute} {tomorrow.hour} * * *"},
        {"name": "Vừa xong", "cron": f"{(t0 - timedelta(minutes=30)).minute} {(t0 - timedelta(minutes=30)).hour} * * *", "duration_min": 30,
         "sites": [world["cn"]]}]}}})
    db.commit(); db.close()
    run(a["id"], "tick")
    subj = [m["subject"] for m in sent]
    assert "Nhắc lịch bảo trì: Nâng cấp switch" in subj
    assert any(s.startswith("Sau bảo trì 'Vừa xong': 0/1 xanh") for s in subj)


def test_lcm02_onboard(client, admin, world, sent):
    a = mk_auto(client, admin, "LCM-02")
    run(a["id"])
    t = sent[0]["text"]
    assert "NAS-NEW (nas): nên thêm Ping + SNMP · thiếu người phụ trách" in t and "Nguồn lạ 10.9.9.9: 5 log" in t


def test_lcm03_offboard(client, admin, world, sent):
    a = mk_auto(client, admin, "LCM-03")
    run(a["id"])
    assert "PRINTER-OLD (10.0.0.99): không phản hồi từ" in sent[0]["text"] and "không tự xoá" in sent[0]["text"]
    db = SessionLocal()
    assert db.get(models.Asset, world["old"]) is not None                 # không xoá gì
    db.close()


def test_lcm06_quarterly_review(client, admin, world, sent):
    db = SessionLocal()
    db.add(models.Check(name="Check cũ", type="ping", target="1.2.3.4", enabled=False, last_checked=now() - timedelta(days=30)))
    db.commit(); db.close()
    a = mk_auto(client, admin, "LCM-06")
    run(a["id"])
    t = sent[0]["text"]
    assert "Tài sản thiếu người phụ trách: " in t and "SRV-APP" in t and "Check tắt > 14 ngày: 1 – Check cũ" in t
    assert "Hệ thống trọng yếu thiếu người phụ trách: 1 – ERP" in t


# ---------------------------------------------------------------- kịch bản tự tạo
def test_custom_schedule_blocks_and_send_when(client, admin, world, sent):
    a = mk_auto(client, admin, "CUSTOM", {"trigger": {"type": "schedule", "cron": "0 17 * * 1-5"},
                                          "content": {"title": "Cuối ngày {time}", "blocks": ["open_alerts", "resources_top"]},
                                          "scope": {"sites": [world["hq"]]}, "send_when": "has_items"}, name="Tổng kết cuối ngày")
    assert a["when"] == "17:00 Thứ Hai–Thứ Sáu"
    run(a["id"])
    assert sent[0]["subject"].startswith("Cuối ngày ") and "SRV-DB: RAM 93% · Trouble" in sent[0]["text"]
    assert "SRV-DB SSH: RAM 93%, Disk 86% (Trouble)" in sent[0]["text"]
    b = mk_auto(client, admin, "CUSTOM", {"trigger": {"type": "interval", "minutes": 30}, "content": {"blocks": ["ssl_expiring"],
                                          "block_params": {"days": 3}}, "send_when": "has_items"}, name="SSL gấp")
    assert run(b["id"])["status"] == "skipped"                        # còn 9 ngày > 3 → không gửi


def test_custom_event_trigger_with_scope(client, admin, world, sent, monkeypatch):
    mk_auto(client, admin, "CUSTOM", {"trigger": {"type": "event", "on": ["alert_opened"]},
                                      "scope": {"sites": [world["cn"]], "severities": ["High"]},
                                      "content": {"title": "[CN] {title}", "message": "{asset} tại {site} – {severity} lúc {time}"},
                                      "actions": [{"type": "telegram", "chat": "-100cn"}]}, name="Báo riêng chi nhánh")
    _fake_collector(monkeypatch, {"10.1.0.1": "down", "10.0.0.10": "down"})
    db = SessionLocal()
    fwcn = db.query(models.Check).filter_by(name="FW-CN ping").first().id
    db.close()
    _run_checks([fwcn, world["c_app"]], times=2)
    cn = [m for m in sent if m["via"] == "automation"]
    assert len(cn) == 1 and cn[0]["subject"] == "[CN] FW-CN ping DOWN" and cn[0]["targets"] == [{"type": "telegram", "chat": "-100cn"}]
    assert cn[0]["text"].startswith("FW-CN tại Chi nhánh – DOWN lúc ")
    assert any(m["subject"] == "SRV-APP ping DOWN" and m["via"] == "notify" for m in sent)     # HQ vẫn qua kênh mặc định


def test_preview_unsaved_and_tick_schedule(client, admin, world, sent):
    r = client.post("/api/automations/preview", headers=admin, json={"code": "CUSTOM", "spec": {
        "trigger": {"type": "schedule", "cron": "0 8 * * *"}, "content": {"blocks": ["overview"]}}})
    assert r.status_code == 200 and "Tài sản:" in r.json()["output"] and sent == []
    db = SessionLocal()
    assert db.query(models.Automation).count() == 0                  # bản xem trước không lưu lại
    db.close()
    t = E.local_now()
    a = mk_auto(client, admin, "CUSTOM", {"trigger": {"type": "schedule", "cron": f"{t.minute} {t.hour} * * *"},
                                          "content": {"blocks": ["overview"]}})
    asyncio.run(E.tick(t))
    asyncio.run(E.tick(t))                                             # cùng phút → không chạy lần 2
    assert len(sent) == 1
    asyncio.run(E.tick(t + timedelta(minutes=1)))
    assert len(sent) == 1
    off = mk_auto(client, admin, "RPT-01", {"trigger": {"type": "schedule", "cron": f"{t.minute} {t.hour} * * *"}}, enabled=False)
    asyncio.run(E.tick(t + timedelta(days=1)))
    assert len(sent) == 2 and sent[1]["subject"] == "Kịch bản tự tạo"     # ngày hôm sau chạy lại (tiêu đề = tên kịch bản); RPT-01 đang tắt không chạy
    lst = {x["id"]: x for x in client.get("/api/automations", headers=admin).json()}
    assert lst[a["id"]]["last_status"] == "ok" and lst[off["id"]]["last_run_at"] is None
