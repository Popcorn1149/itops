"""Module agent phía server (ADR 0004): đăng ký, xác thực từng máy, nhận báo cáo, lọc + dịch sự kiện, cảnh báo."""
import gzip
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import agents as ag
from app import models
from app.db import SessionLocal

NOW = lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()   # noqa: E731


def token(client, admin, **kw):
    r = client.post("/api/agent-tokens", json={"name": kw.pop("name", "test"), **kw}, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()["token"]


def enroll(client, tok, host="PC-KT01", os_family="windows", os_kind="client", uid=None):
    r = client.post("/api/agent/v1/enroll", json={
        "token": tok, "uid": uid or str(uuid.uuid4()), "os_family": os_family, "agent_version": "1.0.0",
        "system": {"hostname": host, "os_name": "Windows 11 Pro" if os_family == "windows" else "Ubuntu 24.04",
                   "os_kind": os_kind, "ips": ["10.10.5.21"], "ram_mb": 16384, "cpu_cores": 8}})
    return r


def H(res):
    return {"Authorization": f"Agent {res['agent_id']}.{res['key']}"}


def report(client, res, **body):
    return client.post("/api/agent/v1/report", json={"seq": 1, "agent_version": "1.0.0", **body}, headers=H(res))


def ev(eid, data, channel="Security", provider="Microsoft-Windows-Security-Auditing", rec=0, ts=None):
    return {"channel": channel, "provider": provider, "event_id": eid, "record_id": rec, "ts": ts or NOW(), "data": data,
            "message": f"msg {eid}"}


def alerts(prefix):
    with SessionLocal() as db:
        return [(a.title, a.severity, a.status) for a in db.query(models.Alert).filter(models.Alert.dedupe_key.like(prefix))]


@pytest.fixture
def agent(client, admin):
    return enroll(client, token(client, admin)).json()


def test_token_stored_hashed_and_enroll_rules(client, admin, viewer):
    assert client.post("/api/agent-tokens", json={"name": "x"}, headers=viewer).status_code == 403
    tok = token(client, admin, name="GPO Kế toán", max_uses=2)
    with SessionLocal() as db:
        t = db.query(models.AgentEnrollToken).filter_by(name="GPO Kế toán").one()
        assert t.token_hash == ag.sha256(tok) and tok not in json.dumps([t.token_hash, t.prefix])
    assert enroll(client, "itk_sai-token-khong-ton-tai-123").status_code == 403
    a1, a2 = enroll(client, tok), enroll(client, tok)
    assert a1.status_code == a2.status_code == 200
    assert enroll(client, tok).status_code == 403                     # hết lượt
    lst = client.get("/api/agent-tokens", headers=admin).json()
    assert next(t for t in lst if t["name"] == "GPO Kế toán")["state"] == "used_up"
    with SessionLocal() as db:                                          # khoá máy chỉ lưu dạng băm
        a = db.get(models.Agent, a1.json()["agent_id"])
        assert a.key_hash == ag.sha256(a1.json()["key"]) and a.asset_id
        assert db.get(models.Asset, a.asset_id).type == "workstation"
        assert any(x.action == "enroll" for x in db.query(models.AuditLog).filter_by(entity="agent"))


def test_agent_auth(client, admin, agent):
    assert client.post("/api/agent/v1/report", json={}).status_code == 401
    bad = {"Authorization": f"Agent {agent['agent_id']}.{'x' * 43}"}
    assert client.post("/api/agent/v1/report", json={}, headers=bad).status_code == 401
    assert report(client, agent).status_code == 200
    # khoá agent không dùng được cho API giao diện, và ngược lại
    assert client.get("/api/agents", headers=H(agent)).status_code == 401
    assert client.post("/api/agent/v1/report", json={}, headers=admin).status_code == 401
    # thu hồi → agent nhận "revoked"; đăng ký lại cùng uid bị từ chối tới khi xoá máy
    assert client.post(f"/api/agents/{agent['agent_id']}/revoke", headers=admin).status_code == 200
    r = report(client, agent)
    assert r.status_code == 401 and r.json()["detail"] == "revoked"


def test_reenroll_same_uid_rotates_key(client, admin):
    tok, uid = token(client, admin), str(uuid.uuid4())
    a1 = enroll(client, tok, uid=uid).json()
    a2 = enroll(client, tok, uid=uid).json()
    assert a1["agent_id"] == a2["agent_id"]
    assert report(client, a1).status_code == 401 and report(client, a2).status_code == 200


def test_report_inventory_and_software_search(client, admin, agent):
    r = report(client, agent,
               system={"hostname": "PC-KT01", "os_name": "Windows 11 Pro", "os_version": "10.0.26100", "logged_user": "CTY\\lan.nt",
                       "manufacturer": "Dell Inc.", "model": "Latitude 5440", "serial": "ABC123", "ips": ["10.10.5.21"]},
               metrics={"cpu": 12.5, "mem": 61, "disks": [{"mount": "C:", "fs": "NTFS", "total_gb": 237, "used_pct": 71}]},
               defender={"realtime": True, "antivirus_enabled": True, "signature_age_days": 0, "signature_version": "1.421.1"},
               services=[{"name": "Spooler", "display": "Print Spooler", "state": "running", "start": "auto"},
                         {"name": "wuauserv", "display": "Windows Update", "state": "stopped", "start": "auto"}],
               software=[{"name": "Google Chrome", "version": "130.0.6723.92", "publisher": "Google LLC"},
                         {"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"}],
               updates={"reboot_pending": True})
    assert r.status_code == 200, r.text
    aid = agent["agent_id"]
    d = client.get(f"/api/agents/{aid}", headers=admin).json()
    assert d["status"] == "online" and d["logged_user"] == "CTY\\lan.nt" and d["model"] == "Latitude 5440"
    assert d["cpu"] == 12.5 and d["disks"][0]["mount"] == "C:" and d["defender"]["realtime"] is True
    assert d["reboot_pending"] is True and d["services_stopped_auto"] == 1 and d["software_count"] == 2
    assert len(client.get(f"/api/agents/{aid}/services", headers=admin).json()["items"]) == 2
    assert len(client.get(f"/api/agents/{aid}/metrics", headers=admin).json()) == 1
    hit = client.get("/api/agent-software?q=chrome", headers=admin).json()
    assert hit[0]["name"] == "Google Chrome" and "PC-KT01" in hit[0]["hosts"]
    # gửi lại cùng danh sách → không ghi lại; danh sách đổi → thay hết
    report(client, agent, software=[{"name": "Google Chrome", "version": "131.0", "publisher": "Google LLC"}])
    sw = client.get(f"/api/agents/{aid}/software", headers=admin).json()
    assert [s["version"] for s in sw] == ["131.0"]


def test_events_filtered_translated_grouped(client, admin, agent):
    aid = agent["agent_id"]
    noise = [ev(4624, {"TargetUserName": "lan.nt"}), ev(4634, {}), ev(4672, {}),                    # đăng nhập thường ngày
             ev(4625, {"TargetUserName": "PC-KT01$", "IpAddress": "10.0.0.1"}),                      # tài khoản máy
             ev(9999, {}), ev(4625, {"TargetUserName": "x"}, provider="Fake-Provider")]               # ngoài danh mục
    r = report(client, agent, events=noise)
    assert r.json()["events_stored"] == 0 and r.json()["events_dropped"] == 6
    fails = [ev(4625, {"TargetUserName": "lan.nt", "TargetDomainName": "CTY", "IpAddress": "10.10.9.99",
                       "WorkstationName": "PC-LA", "LogonType": "10", "SubStatus": "0xC000006A"}, rec=100 + i) for i in range(12)]
    report(client, agent, events=fails)
    report(client, agent, events=fails[-1:])                               # agent gửi lại (mất mạng) → không đếm trùng
    rows = client.get(f"/api/agent-events?agent_id={aid}", headers=admin).json()
    assert len(rows) == 1
    e = rows[0]
    assert e["count"] == 12 and e["title"] == "Đăng nhập thất bại" and e["who"] == "CTY\\lan.nt"
    assert "PC-LA" in e["where"] and "10.10.9.99" in e["where"]
    assert "sai mật khẩu" in e["what"] and "Remote Desktop" in e["what"] and e["advice"]
    al = alerts(f"agent-ev:{aid}:win:4625:%")
    assert len(al) == 1 and al[0][0].startswith("Nghi dò mật khẩu: PC-KT01") and al[0][1] == "trouble"


def test_event_alerts_admin_group_log_cleared_defender(client, admin, agent):
    aid = agent["agent_id"]
    report(client, agent, events=[
        ev(4732, {"TargetUserName": "Administrators", "MemberName": "CN=Tran Van B,OU=Users,DC=cty,DC=local",
                  "SubjectUserName": "it.admin", "SubjectDomainName": "CTY"}),
        ev(4732, {"TargetUserName": "Print Operators-x", "MemberName": "CN=C"}),
        ev(1102, {"SubjectUserName": "hacker"}, provider="Microsoft-Windows-Eventlog"),
        ev(5001, {}, channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender"),
        ev(7031, {"param1": "Print Spooler", "param2": "1"}, channel="System", provider="Service Control Manager"),
        ev(55, {}, channel="System", provider="Microsoft-Windows-Ntfs"),       # tên provider kiểu mới vẫn khớp
    ])
    rows = {e["title"]: e for e in client.get(f"/api/agent-events?agent_id={aid}", headers=admin).json()}
    assert rows["Thêm vào nhóm QUẢN TRỊ"]["severity"] == "critical" and "Tran Van B" in rows["Thêm vào nhóm QUẢN TRỊ"]["what"]
    assert rows["Thêm thành viên vào nhóm"]["severity"] == "attention"
    assert "Hệ thống file bị hỏng" in rows
    titles = {t: s for t, s, _ in alerts(f"agent-ev:{aid}:%")}
    assert titles.get("Thêm tài khoản vào nhóm quản trị: PC-KT01 (CTY\\it.admin)") == "critical"
    assert titles.get("Nhật ký bảo mật bị xoá: PC-KT01 (hacker)") == "critical"
    assert any(t.startswith("Defender bị tắt bảo vệ thời gian thực") for t in titles)
    assert any(t.startswith("Dịch vụ dừng bất thường") for t in titles)
    assert len([t for t in titles if "nhóm quản trị" in t]) == 1           # nhóm thường không cảnh báo


def test_linux_events(client, admin):
    a = enroll(client, token(client, admin), host="srv-web01", os_family="linux", os_kind="server").json()
    r = report(client, a, events=[
        {"kind": "auth_fail", "channel": "journal", "provider": "sshd", "ts": NOW(), "data": {"user": "root", "src": "45.1.2.3", "service": "SSH"}},
        {"kind": "group_admin", "channel": "journal", "provider": "usermod", "ts": NOW(), "data": {"user": "bob", "group": "sudo"}},
        {"kind": "khong-co", "channel": "journal", "ts": NOW(), "data": {}}])
    assert r.json()["events_stored"] == 2 and r.json()["events_dropped"] == 1
    assert any(s == "critical" for _, s, _ in alerts(f"agent-ev:{a['agent_id']}:unix:admin-add:%"))


def test_state_alerts_disk_and_defender(client, admin, agent):
    aid = agent["agent_id"]
    report(client, agent, metrics={"disks": [{"mount": "C:", "total_gb": 237, "used_pct": 96.4}]},
           defender={"realtime": False, "signature_age_days": 9})
    got = {t: (s, st) for t, s, st in alerts(f"agent:{aid}:%")}
    assert got["Ổ C: sắp đầy: PC-KT01"] == ("critical", "open")
    assert got["Defender tắt bảo vệ thời gian thực: PC-KT01"][0] == "critical"
    assert got["Mẫu nhận diện virus cũ: PC-KT01"][0] == "trouble"
    report(client, agent, metrics={"disks": [{"mount": "C:", "total_gb": 237, "used_pct": 50}]},
           defender={"realtime": True, "signature_age_days": 0})
    assert all(st == "resolved" for _, _, st in alerts(f"agent:{aid}:%"))
    # ổ USB đầy rồi bị rút ra → cảnh báo tự đóng
    report(client, agent, metrics={"disks": [{"mount": "E:", "total_gb": 32, "used_pct": 99}]})
    assert ("Ổ E: sắp đầy: PC-KT01", "critical", "open") in alerts(f"agent:{aid}:disk:%")
    report(client, agent, metrics={"disks": [{"mount": "C:", "total_gb": 237, "used_pct": 50}]})
    assert all(st == "resolved" for _, _, st in alerts(f"agent:{aid}:disk:%"))
    # có phần mềm diệt virus khác làm chính (Defender chạy thụ động) → không báo
    report(client, agent, defender={"realtime": False, "running_mode": "Passive Mode", "signature_age_days": 30})
    assert all(st == "resolved" for _, _, st in alerts(f"agent:{aid}:av-%"))


def test_offline_only_for_servers(client, admin):
    tok = token(client, admin)
    srv = enroll(client, tok, host="SRV-FILE01", os_kind="server").json()
    pc = enroll(client, tok, host="PC-NV05").json()
    with SessionLocal() as db:
        for aid in (srv["agent_id"], pc["agent_id"]):
            db.get(models.Agent, aid).last_seen = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        db.commit()
    ag._offline_pass()
    assert alerts(f"agent:{srv['agent_id']}:offline") == [("Mất kết nối agent: SRV-FILE01", "down", "open")]
    assert alerts(f"agent:{pc['agent_id']}:offline") == []                 # máy trạm tắt buổi tối là bình thường
    report(client, srv)
    assert alerts(f"agent:{srv['agent_id']}:offline")[0][2] == "resolved"


def test_config_policy_and_gzip(client, admin, agent):
    c1 = client.get("/api/agent/v1/config", headers=H(agent)).json()
    sec = next(q for q in c1["windows_events"] if q["channel"] == "Security")
    assert 4625 in sec["ids"] and 4624 not in sec["ids"] and 4634 not in sec["ids"]
    r = client.put("/api/agent-policy", json={"disabled_keys": ["win:4625"], "report_seconds": 120}, headers=admin)
    assert r.status_code == 200
    c2 = client.get("/api/agent/v1/config", headers=H(agent)).json()
    assert c2["version"] != c1["version"] and c2["report_seconds"] == 120
    assert 4625 not in next(q for q in c2["windows_events"] if q["channel"] == "Security")["ids"]
    body = gzip.compress(json.dumps({"seq": 2, "metrics": {"cpu": 5}}).encode())
    r = client.post("/api/agent/v1/report", content=body, headers={**H(agent), "Content-Encoding": "gzip",
                                                                       "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["config_version"] == c2["version"]
    client.put("/api/agent-policy", json={"disabled_keys": [], "report_seconds": 60}, headers=admin)
    assert client.get("/api/agent/v1/update", headers=H(agent)).status_code == 204     # tự cập nhật đang tắt


def test_invalid_payload_rejected(client, agent):
    assert report(client, agent, events=None).status_code == 200            # agent cũ gửi null khi không có sự kiện
    assert report(client, agent, metrics={"cpu": 500}).status_code == 422
    assert report(client, agent, events=[{"ts": "khong-phai-ngay"}]).status_code == 422
    big = {"Authorization": H(agent)["Authorization"], "Content-Length": str(ag.MAX_BODY + 1)}
    assert client.post("/api/agent/v1/report", content=b"{}", headers=big).status_code in (400, 413)


def test_delete_agent_removes_auto_asset(client, admin, agent):
    aid = agent["agent_id"]
    with SessionLocal() as db:
        asset_id = db.get(models.Agent, aid).asset_id
    assert client.delete(f"/api/agents/{aid}", headers=admin).status_code == 200
    with SessionLocal() as db:
        assert db.get(models.Agent, aid) is None and db.get(models.Asset, asset_id) is None


def test_enroll_bruteforce_limited(client, admin):
    ag._enroll_fail.clear()
    for _ in range(10):
        assert enroll(client, "itk_doan-mo-token-sai-000000").status_code == 403
    assert enroll(client, token(client, admin)).status_code == 429        # khoá IP sau 10 lần sai
    ag._enroll_fail.clear()


def test_resend_dropped_but_log_renumbering_accepted(client, admin, agent):
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    batch = [ev(4740, {"TargetUserName": f"u{i}"}, rec=500 + i, ts=(t0 + timedelta(seconds=i)).isoformat()) for i in range(3)]
    assert report(client, agent, events=batch).json()["events_stored"] == 3
    assert report(client, agent, events=batch).json()["events_stored"] == 0          # gửi lại nguyên lô
    # log bị xoá → Windows đánh số lại từ nhỏ, nhưng thời điểm mới hơn → vẫn nhận
    later = ev(4740, {"TargetUserName": "u9"}, rec=3, ts=(t0 + timedelta(minutes=2)).isoformat())
    assert report(client, agent, events=[later]).json()["events_stored"] == 1
