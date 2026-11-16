"""Module CVE – part 1: chuẩn hoá dữ liệu tài sản (build/UBR, người dùng gần nhất, gộp machines cài lại, tên phần mềm)."""
import uuid

from app import inventory as inv
from tests.test_agents import H, report, token


def enroll(client, tok, host="PC-KT09", uid=None, machine_id="", serial="", os_family="windows", macs=None):
    return client.post("/api/agent/v1/enroll", json={
        "token": tok, "uid": uid or str(uuid.uuid4()), "os_family": os_family, "agent_version": "1.0.2",
        "system": {"hostname": host, "os_name": "Windows 11 Pro", "os_version": "23H2 (build 22631.4317)",
                   "machine_id": machine_id, "serial": serial, "logged_user": "CTY\\lan", "user_source": "console",
                   "macs": macs or []}})


def test_parse_os_and_software_normalize():
    assert inv.parse_os("windows", "Windows 11 Pro", "23H2 (build 22631.4317)") == \
        {"os_release": "23H2", "os_build": "22631", "os_ubr": 4317}
    assert inv.parse_os("windows", "Windows Server 2019", "1809 (build 17763.)")["os_ubr"] is None
    assert inv.parse_os("linux", "Ubuntu 22.04.4 LTS", "")["os_release"] == "22.04"
    assert inv.parse_os("darwin", "macOS 15.1", "24B83") == {"os_release": "15.1", "os_build": "24B83", "os_ubr": None}
    rows = inv.normalize_software([
        {"name": "7-Zip 23.01 (x64)", "publisher": "Igor Pavlov", "version": "23.01"},
        {"name": "Google Chrome", "publisher": "Google LLC", "version": "v130.0.6723.92"},
        {"name": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", "publisher": "Microsoft Corporation", "version": "14.38.33135.0"},
        {"name": "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33135", "publisher": "Microsoft Corporation", "version": "14.38.33135.0"},
        {"name": "libssl3", "publisher": "Ubuntu Developers <x@y>", "version": "3.0.2-0ubuntu1.18", "source_pkg": "openssl"},
    ])
    assert len(rows) == 5                                    # khi lưu: giữ đủ dòng gốc
    assert [(r["norm_name"], r["norm_vendor"], r["norm_version"]) for r in rows[:2]] == \
        [("7-zip", "7-zip", "23.01"), ("chrome", "google", "130.0.6723.92")]
    assert rows[4]["norm_vendor"] == "canonical"
    assert len(inv.normalize_software(rows, dedupe=True)) == 4   # x64 + x86 cùng sessions bản → 1 khi khớp CVE
    assert not inv.valid_serial("To be filled by O.E.M.") and not inv.valid_serial("0") and inv.valid_serial("5CD1234XYZ")


def test_build_ubr_and_last_user(client, admin):
    a = enroll(client, token(client, admin), machine_id="1111-aaaa").json()
    d = client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()
    assert (d["os_release"], d["os_build"], d["os_ubr"]) == ("23H2", "22631", 4317)
    assert d["logged_user"] == d["last_user"] == "CTY\\lan" and d["user_source"] == "console"
    # sign-out: không ai sign-in nhưng vẫn biết người dùng gần nhất
    report(client, a, system={"hostname": "PC-KT09", "logged_user": ""})
    d = client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()
    assert d["logged_user"] == "" and d["last_user"] == "CTY\\lan" and d["user_source"] == ""
    # RDP
    report(client, a, system={"hostname": "PC-KT09", "logged_user": "CTY\\admin.it", "user_source": "rdp"})
    d = client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()
    assert d["last_user"] == "CTY\\admin.it" and d["user_source"] == "rdp"
    # báo cáo rút gọn cùng người dùng, không kèm user_source → giữ "rdp"
    report(client, a, system={"hostname": "PC-KT09", "logged_user": "CTY\\admin.it"})
    assert client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()["user_source"] == "rdp"


def _approve_and_retry(client, admin, tok, **kw):
    """Cài lại máy đã có → máy chủ trả 429 "chờ duyệt"; IT duyệt → agent hỏi lại (cùng uid) thì nhận khoá."""
    uid = str(uuid.uuid4())
    r = enroll(client, tok, uid=uid, **kw)
    assert r.status_code == 429 and r.json()["detail"]["pending"] is True, r.text
    rid = r.json()["detail"]["request_id"]
    assert client.post(f"/api/agent-enroll-requests/{rid}/approve", headers=admin).status_code == 200
    r = enroll(client, tok, uid=uid, **kw)
    assert r.status_code == 200, r.text
    return r.json()


def test_reinstall_merges_same_machine_not_others(client, admin):
    tok = token(client, admin, max_uses=10)
    first = enroll(client, tok, host="PC-KT10", machine_id="guid-10").json()
    report(client, first, metrics={"cpu": 5, "mem": 40, "disks": []})
    # cài lại agent (uid mới, xoá thư mục agent) – cùng tên + cùng MachineGuid → IT duyệt → dùng lại bản ghi cũ
    again = _approve_and_retry(client, admin, tok, host="PC-KT10", machine_id="guid-10")
    assert again["agent_id"] == first["agent_id"]
    assert report(client, first, metrics={"cpu": 1, "mem": 1, "disks": []}).status_code == 401     # khoá cũ hết hiệu lực
    assert report(client, again, metrics={"cpu": 1, "mem": 1, "disks": []}).status_code == 200
    # cài lại Windows: MachineGuid mới, serial phần cứng giữ nguyên → vẫn gộp (sau khi duyệt)
    s1 = enroll(client, tok, host="PC-KT11", machine_id="old", serial="5CD1234XYZ").json()
    s2 = _approve_and_retry(client, admin, tok, host="PC-KT11", machine_id="new", serial="5CD1234XYZ")
    assert s1["agent_id"] == s2["agent_id"]
    # serial mặc định of bo mạch, khác tên machines, hoặc không có định danh → KHÔNG gộp (máy mới, không cần duyệt)
    b1 = enroll(client, tok, host="PC-KT12", serial="To be filled by O.E.M.").json()
    b2 = enroll(client, tok, host="PC-KT12", serial="To be filled by O.E.M.").json()
    c = enroll(client, tok, host="PC-KHAC", machine_id="guid-10").json()
    assert len({b1["agent_id"], b2["agent_id"], c["agent_id"], first["agent_id"]}) == 4
    hosts = [x["hostname"] for x in client.get("/api/agents", headers=admin).json()]
    assert hosts.count("PC-KT10") == 1 and hosts.count("PC-KT11") == 1


def test_software_normalized_quality_and_duplicates(client, admin):
    a = enroll(client, token(client, admin), host="PC-KT13", machine_id="g13").json()
    report(client, a, software=[{"name": "7-Zip 23.01 (x64)", "version": "23.01", "publisher": "Igor Pavlov"},
                                {"name": "Google Chrome", "version": "130.0.6723.92", "publisher": "Google LLC"}])
    sw = client.get(f"/api/agents/{a['agent_id']}/software", headers=admin).json()
    assert {s["norm_name"] for s in sw} == {"7-zip", "chrome"}
    q = client.get(f"/api/agents/{a['agent_id']}", headers=admin).json()["quality"]
    by = {c["key"]: c["ok"] for c in q["checks"]}
    assert by["os_build"] and by["user"] and by["software"] and by["identity"] and q["score"] == 100
    # agent cũ (không machine-id, không serial) → nêu rõ missing định danh
    old = client.post("/api/agent/v1/enroll", json={"token": token(client, admin), "uid": str(uuid.uuid4()), "os_family": "windows",
                                                    "system": {"hostname": "PC-CU01"}}).json()
    q = client.get(f"/api/agents/{old['agent_id']}", headers=admin).json()["quality"]
    assert not {c["key"]: c["ok"] for c in q["checks"]}["identity"] and q["score"] < 100
    assert all(x["duplicates"] == [] for x in client.get("/api/agents", headers=admin).json())
