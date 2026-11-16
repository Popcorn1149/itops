"""Đăng ký ĐÈ lên máy đã có phải chờ IT duyệt; MAC của card mạng được lưu và hiển thị."""
import uuid

import pytest

from app import agents as ag
from app import models
from app.db import SessionLocal
from tests.test_agents import report, token
from tests.test_cve_p1 import enroll


@pytest.fixture(autouse=True)
def _clean():
    ag._enroll_fail.clear()
    yield
    ag._enroll_fail.clear()


def pending(r):
    assert r.status_code == 429, r.text
    d = r.json()["detail"]
    assert d["pending"] is True and d["retry_seconds"] == 300 and r.headers["retry-after"] == "300"
    return d["request_id"]


def reqs(client, admin, **q):
    return client.get("/api/agent-enroll-requests", params=q, headers=admin).json()


def test_takeover_waits_and_real_agent_keeps_working(client, admin):
    tok = token(client, admin, max_uses=10)
    real = enroll(client, tok, host="PC-KETOAN01", machine_id="guid-kt01", serial="5CD0001AAA", macs=["aa-bb-cc-00-00-01"]).json()
    assert report(client, real, metrics={"cpu": 3, "mem": 30, "disks": []}).status_code == 200
    # kẻ biết tên máy + serial (đăng ký mở, không cần gì khác) → KHÔNG chiếm được ngay
    uid = str(uuid.uuid4())
    rid = pending(enroll(client, tok, uid=uid, host="PC-KETOAN01", serial="5CD0001AAA", macs=["DE:AD:BE:EF:00:99"]))
    assert report(client, real, metrics={"cpu": 4, "mem": 31, "disks": []}).status_code == 200, "agent thật vẫn chạy"
    # hỏi lại nhiều lần → vẫn 1 yêu cầu, đếm số lần
    assert pending(enroll(client, tok, uid=uid, host="PC-KETOAN01", serial="5CD0001AAA", macs=["DE:AD:BE:EF:00:99"])) == rid
    lst = reqs(client, admin)
    r = next(x for x in lst if x["id"] == rid)
    assert r["attempts"] == 2 and r["matched_by"] == "serial"
    assert r["current"]["macs"] == ["AA:BB:CC:00:00:01"] and r["new"]["macs"] == ["DE:AD:BE:EF:00:99"]
    assert r["current"]["status"] == "online"
    # có cảnh báo + audit
    with SessionLocal() as db:
        al = db.query(models.Alert).filter_by(dedupe_key=f"agent-enroll:{real['agent_id']}").one()
        assert al.status != "resolved" and "PC-KETOAN01" in al.title
        assert db.query(models.AuditLog).filter_by(action="enroll_pending").count() >= 1
    assert client.get("/api/agent-summary", headers=admin).json()["pending_enroll"] >= 1
    # IT từ chối → agent giả nhận 403, agent thật vẫn chạy, cảnh báo đóng
    assert client.post(f"/api/agent-enroll-requests/{rid}/reject", json={"reason": "không ai cài lại máy này"}, headers=admin).status_code == 200
    r = enroll(client, tok, uid=uid, host="PC-KETOAN01", serial="5CD0001AAA")
    assert r.status_code == 403 and "rejected" in r.json()["detail"]
    assert report(client, real, metrics={"cpu": 5, "mem": 32, "disks": []}).status_code == 200
    with SessionLocal() as db:
        assert db.query(models.Alert).filter_by(dedupe_key=f"agent-enroll:{real['agent_id']}").one().status == "resolved"
        assert db.get(models.Agent, real["agent_id"]).macs == ["AA:BB:CC:00:00:01"]


def test_approve_then_new_agent_takes_over(client, admin):
    tok = token(client, admin, max_uses=10)
    old = enroll(client, tok, host="PC-NS02", machine_id="guid-ns02").json()
    uid = str(uuid.uuid4())
    rid = pending(enroll(client, tok, uid=uid, host="PC-NS02", machine_id="guid-ns02", macs=["00:11:22:33:44:55"]))
    other = pending(enroll(client, tok, host="PC-NS02", machine_id="guid-ns02"))         # yêu cầu thứ hai cho cùng máy
    assert client.post(f"/api/agent-enroll-requests/{rid}/approve", headers=admin).status_code == 200
    assert client.post(f"/api/agent-enroll-requests/{rid}/approve", headers=admin).status_code == 400   # không duyệt 2 lần
    st = {x["id"]: x["status"] for x in reqs(client, admin, all=1)}
    assert st[rid] == "approved" and st[other] == "rejected"                              # chỉ một agent được thay
    new = enroll(client, tok, uid=uid, host="PC-NS02", machine_id="guid-ns02", macs=["00:11:22:33:44:55"]).json()
    assert new["agent_id"] == old["agent_id"]
    assert report(client, old).status_code == 401 and report(client, new).status_code == 200
    a = client.get(f"/api/agents/{new['agent_id']}", headers=admin).json()
    assert a["macs"] == ["00:11:22:33:44:55"]
    assert next(x for x in reqs(client, admin, all=1) if x["id"] == rid)["status"] == "completed"
    assert reqs(client, admin) == [] or all(x["agent_id"] != old["agent_id"] for x in reqs(client, admin))


def test_same_uid_and_new_machines_need_no_approval(client, admin):
    tok = token(client, admin, max_uses=10)
    uid = str(uuid.uuid4())
    a1 = enroll(client, tok, uid=uid, host="PC-GPO01", machine_id="guid-gpo01").json()
    a2 = enroll(client, tok, uid=uid, host="PC-GPO01", machine_id="guid-gpo01")      # chính bản cài đó, GPO chạy lại
    assert a2.status_code == 200 and a2.json()["agent_id"] == a1["agent_id"]
    assert enroll(client, tok, host="PC-MOI99", machine_id="guid-moi99").status_code == 200   # máy mới
    assert all(x["hostname"] not in ("PC-GPO01", "PC-MOI99") for x in reqs(client, admin))


def test_pending_list_admin_only(client, admin, viewer):
    tok = token(client, admin, max_uses=10)
    enroll(client, tok, host="PC-TK01", machine_id="guid-tk01")
    rid = pending(enroll(client, tok, host="PC-TK01", machine_id="guid-tk01"))
    assert client.get("/api/agent-enroll-requests", headers=viewer).status_code == 403
    assert client.post(f"/api/agent-enroll-requests/{rid}/approve", headers=viewer).status_code == 403


def test_mac_normalized_and_updated_by_report(client, admin):
    assert ag.normalize_macs(["aa-bb-cc-dd-ee-ff", "AABB.CCDD.EEFF", "00:00:00:00:00:00", "rác", "11:22:33:44:55:66"]) == \
        ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
    a = enroll(client, token(client, admin), host="PC-MAC01", macs=["aa:bb:cc:dd:ee:01"]).json()
    report(client, a, system={"hostname": "PC-MAC01", "macs": ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"]})
    row = next(x for x in client.get("/api/agents", headers=admin).json() if x["id"] == a["agent_id"])
    assert row["macs"] == ["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:01"]
    report(client, a, system={"hostname": "PC-MAC01"})                                       # agent cũ không gửi MAC → giữ nguyên
    assert client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()["macs"] == ["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:01"]


def test_old_requests_expire(client, admin):
    from datetime import timedelta
    tok = token(client, admin, max_uses=10)
    enroll(client, tok, host="PC-HH01", machine_id="guid-hh01")
    uid = str(uuid.uuid4())
    rid = pending(enroll(client, tok, uid=uid, host="PC-HH01", machine_id="guid-hh01"))
    with SessionLocal() as db:
        r = db.get(models.AgentEnrollRequest, rid)
        r.last_attempt_at = r.last_attempt_at - timedelta(days=8)
        db.commit()
    assert all(x["id"] != rid for x in reqs(client, admin))                   # quá 7 ngày → hết hạn
    rid2 = pending(enroll(client, tok, uid=uid, host="PC-HH01", machine_id="guid-hh01"))   # hỏi lại → yêu cầu mới
    assert rid2 != rid
