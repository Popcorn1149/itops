"""API: sign-in, phân quyền, CRUD, mã hoá bí mật, xuất/nhập, bản đồ, rủi ro."""

from tests.pgtest import sql


def mk(client, h, _kind, **body):
    r = client.post(f"/api/{_kind}", json=body, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------- auth ----------------
def test_login_ok_and_wrong(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "sai"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "khongco", "password": "x"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "Admin@12345"}).status_code == 200


def test_all_endpoints_require_auth(client):
    for path in ["/api/dashboard", "/api/sites", "/api/assets", "/api/checks", "/api/critical", "/api/alerts",
                 "/api/topology", "/api/risks", "/api/audit", "/api/search?q=a", "/api/assets/1", "/api/settings/notify", "/api/export"]:
        assert client.get(path).status_code == 401, path
    assert client.post("/api/sites", json={"name": "x"}).status_code == 401
    assert client.get("/api/health").status_code == 200  # health công khai


def test_tampered_token_rejected(client, admin):
    tok = admin["Authorization"][7:]
    bad = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    assert client.get("/api/dashboard", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_viewer_is_read_only(client, admin, viewer, clean):
    s = mk(client, admin, "sites", name="HQ")
    assert client.get("/api/sites", headers=viewer).status_code == 200
    assert client.post("/api/sites", json={"name": "X"}, headers=viewer).status_code == 403
    assert client.put(f"/api/sites/{s['id']}", json={"name": "Y"}, headers=viewer).status_code == 403
    assert client.delete(f"/api/sites/{s['id']}", headers=viewer).status_code == 403
    assert client.get("/api/settings/notify", headers=viewer).status_code == 403
    assert client.get("/api/users", headers=viewer).status_code == 403
    assert client.post("/api/checks-test", json={"type": "ping", "target": "127.0.0.1"}, headers=viewer).status_code == 403
    assert client.post("/api/reset-data", json={"confirm": "XOA"}, headers=viewer).status_code == 403
    assert client.get("/api/export", headers=viewer).status_code == 403


def test_password_change_rules(client):
    client.post("/api/users", json={"username": "u2", "password": "Passw0rd!", "role": "viewer"},
                headers={"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "admin", "password": "Admin@12345"}).json()["token"]})
    t = client.post("/api/auth/login", json={"username": "u2", "password": "Passw0rd!"}).json()["token"]
    h = {"Authorization": f"Bearer {t}"}
    assert client.post("/api/auth/password", json={"old_password": "sai", "new_password": "12345678"}, headers=h).status_code == 400
    assert client.post("/api/auth/password", json={"old_password": "Passw0rd!", "new_password": "ngan"}, headers=h).status_code == 400
    assert client.post("/api/auth/password", json={"old_password": "Passw0rd!", "new_password": "MoiMoi123"}, headers=h).status_code == 200
    assert client.post("/api/auth/login", json={"username": "u2", "password": "MoiMoi123"}).status_code == 200


def test_user_management_guards(client, admin):
    me = client.get("/api/auth/me", headers=admin).json()
    assert client.delete(f"/api/users/{me['id']}", headers=admin).status_code == 400
    assert client.put(f"/api/users/{me['id']}", json={"role": "viewer"}, headers=admin).status_code == 400
    assert client.post("/api/users", json={"username": "admin", "password": "12345678"}, headers=admin).status_code == 400
    assert client.post("/api/users", json={"username": "x", "password": "123"}, headers=admin).status_code == 400
    assert client.put("/api/users/99999", json={"full_name": "a"}, headers=admin).status_code == 404


# ---------------- CRUD ----------------
def test_crud_and_validation(client, admin, clean):
    assert client.post("/api/sites", json={"name": "  "}, headers=admin).status_code == 400
    assert client.post("/api/unknown", json={"name": "x"}, headers=admin).status_code == 404
    assert client.post("/api/checks", json={"name": "x", "type": "telnet"}, headers=admin).status_code == 400
    s = mk(client, admin, "sites", name="HQ", kind="datacenter")
    fw = mk(client, admin, "assets", name="fw", type="firewall", site_id=s["id"], ip="10.0.0.1")
    sw = mk(client, admin, "assets", name="sw", type="switch", site_id=s["id"], parent_id=fw["id"])
    assert client.put(f"/api/assets/{sw['id']}", json={"parent_id": sw["id"]}, headers=admin).status_code == 400
    r = client.put(f"/api/assets/{sw['id']}", json={"name": "SW-CORE", "site_id": ""}, headers=admin)
    assert r.status_code == 200 and r.json()["name"] == "SW-CORE" and r.json()["site_id"] is None
    assert client.get("/api/assets/99999", headers=admin).status_code == 404
    # check kế thừa site từ tài sản
    c = mk(client, admin, "checks", name="fw ping", type="ping", target="10.0.0.1", asset_id=fw["id"], enabled=False)
    assert c["site_id"] == s["id"]
    # xoá firewall → switch mất cha nhưng không bị xoá
    assert client.delete(f"/api/assets/{fw['id']}", headers=admin).status_code == 200
    sw2 = client.get(f"/api/assets/{sw['id']}", headers=admin).json()
    assert sw2["parent_id"] is None
    # xoá site → tài sản về "chưa gán"
    client.delete(f"/api/sites/{s['id']}", headers=admin)
    assert client.get(f"/api/assets/{sw['id']}", headers=admin).json()["site_id"] is None


def test_parent_cycle_rejected(client, admin, clean):
    a = mk(client, admin, "assets", name="A", type="switch")
    b = mk(client, admin, "assets", name="B", type="switch", parent_id=a["id"])
    c = mk(client, admin, "assets", name="C", type="switch", parent_id=b["id"])
    r = client.put(f"/api/assets/{a['id']}", json={"parent_id": c["id"]}, headers=admin)
    assert r.status_code == 400, "Vòng lặp A→C→B→A phải bị chặn"


def test_secrets_encrypted_and_masked(client, admin, clean):
    c = mk(client, admin, "checks", name="esx", type="esxi", target="10.0.0.5", enabled=False,
           config={"username": "ro", "password": "SieuBiMat!", "verify_ssl": False})
    assert c["config"]["password"] == "__SECRET__"
    for path in ["/api/checks", f"/api/checks/{c['id']}", "/api/export", "/api/dashboard"]:
        assert "SieuBiMat" not in client.get(path, headers=admin).text, path
    raw = sql("select config::text from checks where id=%s", (c["id"],))[0][0]
    assert "SieuBiMat" not in raw and "enc2:" in raw and '"enc:' not in raw     # AES-256-GCM, không remaining Fernet
    # sửa check gửi lại MASK → giữ password cũ
    client.put(f"/api/checks/{c['id']}", json={"config": {"username": "ro2", "password": "__SECRET__"}}, headers=admin)
    raw2 = sql("select config::text from checks where id=%s", (c["id"],))[0][0]
    assert "enc2:" in raw2 and "ro2" in raw2
    audit_rows = " ".join(str(r) for r in sql("select detail, changes::text from audit_logs where entity='checks'"))
    assert "SieuBiMat" not in audit_rows and "enc2:" not in audit_rows and "ro2" in audit_rows   # trước/sau có, bí mật bị che
    from app.security import open_config
    import json
    assert open_config(json.loads(raw2))["password"] == "SieuBiMat!"


def test_notify_settings_masked(client, admin):
    client.put("/api/settings/notify", json={"telegram": {"enabled": True, "bot_token": "123:ABC", "chat_id": "-1"}, "email": {}, "webhook": {}}, headers=admin)
    r = client.get("/api/settings/notify", headers=admin).json()
    assert r["telegram"]["bot_token"] == "__SECRET__" and r["telegram"]["chat_id"] == "-1"
    client.put("/api/settings/notify", json={**r, "telegram": {**r["telegram"], "chat_id": "-2"}}, headers=admin)
    from app.notify import load_notify_settings
    assert load_notify_settings()["telegram"]["bot_token"] == "123:ABC"
    client.put("/api/settings/notify", json={"telegram": {}, "email": {}, "webhook": {}}, headers=admin)


def test_export_reset_import_roundtrip(client, admin, clean):
    s = mk(client, admin, "sites", name="HQ")
    a = mk(client, admin, "assets", name="srv", type="server", site_id=s["id"])
    mk(client, admin, "critical", name="ERP", asset_id=a["id"], level="High")
    mk(client, admin, "checks", name="p", type="ping", target="127.0.0.1", asset_id=a["id"], enabled=False)
    exp = client.get("/api/export", headers=admin).json()
    assert client.post("/api/reset-data", json={"confirm": "khong"}, headers=admin).status_code == 400
    client.post("/api/reset-data", json={"confirm": "XOA"}, headers=admin)
    assert client.get("/api/assets", headers=admin).json() == []
    assert client.post("/api/import", json=exp, headers=admin).json()["imported"] == 4
    crit = client.get("/api/critical", headers=admin).json()
    assert crit[0]["asset"]["name"] == "srv"


def test_search_and_sql_injection(client, admin, clean):
    mk(client, admin, "assets", name="DC01", type="vm", ip="10.0.20.10")
    assert client.get("/api/search?q=10.0.20", headers=admin).json()[0]["title"] == "DC01"
    r = client.get("/api/search?q=' OR 1=1 --", headers=admin)
    assert r.status_code == 200 and r.json() == []
    assert client.get("/api/assets?q=%25", headers=admin).status_code == 200


def test_audit_log_records_changes(client, admin, clean):
    s = mk(client, admin, "sites", name="Audit-site")
    client.put(f"/api/sites/{s['id']}", json={"wan": "FPT"}, headers=admin)
    client.delete(f"/api/sites/{s['id']}", headers=admin)
    logs = client.get("/api/audit", headers=admin).json()
    acts = [(l["action"], l["entity"]) for l in logs[:5]]
    assert ("delete", "sites") in acts and ("update", "sites") in acts and ("create", "sites") in acts
    assert any("wan" in l["detail"] for l in logs[:5])


# ---------------- topology / critical / risks ----------------
def test_topology_and_risks(client, admin, clean):
    s = mk(client, admin, "sites", name="HQ")
    fw = mk(client, admin, "assets", name="fw", type="firewall", site_id=s["id"])
    sw = mk(client, admin, "assets", name="sw", type="switch", site_id=s["id"])  # không khai báo cha → tự nằm sau firewall
    host = mk(client, admin, "assets", name="esx", type="host", site_id=s["id"], parent_id=sw["id"])
    vm1 = mk(client, admin, "assets", name="dc01", type="vm", site_id=s["id"], parent_id=host["id"], backup=True)
    vm2 = mk(client, admin, "assets", name="erp", type="vm", site_id=s["id"], parent_id=host["id"])
    loose = mk(client, admin, "assets", name="lonely", type="printer")
    ad = mk(client, admin, "critical", name="AD", asset_id=vm1["id"], level="High")
    mk(client, admin, "critical", name="ERP", asset_id=vm2["id"], level="High", depends_on=[ad["id"]])
    mk(client, admin, "critical", name="Chấm công", level="Low")
    mk(client, admin, "critical", name="M365", hosted_externally=True, external_note="Microsoft")

    t = client.get("/api/topology", headers=admin).json()
    root = t["tree"]
    assert root["name"] == "Internet"
    hq = next(c for c in root["children"] if c["name"] == "HQ")
    assert [c["name"] for c in hq["children"]] == ["fw"]
    assert hq["children"][0]["children"][0]["name"] == "sw"
    assert {c["name"] for c in hq["children"][0]["children"][0]["children"][0]["children"]} == {"dc01", "erp"}
    names = {c["name"] for c in root["children"]}
    assert "No site assigned" in names and "External service" in names
    assert hq["count"] == 6  # site + 5 tài sản
    edges = {(e["source"], e["target"], e["label"]) for e in t["flow"]["edges"]}
    assert any(l == "depends on" for *_, l in edges) and any(l == "runs on" for *_, l in edges)

    risks = client.get("/api/risks", headers=admin).json()
    kinds = {(r["kind"], r["title"]) for r in risks}
    assert ("No backup", "ERP") in kinds
    assert ("No server mapped", "Chấm công") in kinds
    assert ("Concentration risk", "esx") in kinds  # 2 hệ thống High trên cùng host
    assert not any(k == "No backup" and t_ == "M365" for k, t_ in kinds)
    assert not any(k == "No backup" and t_ == "AD" for k, t_ in kinds)
    assert risks == sorted(risks, key=lambda r: {"high": 0, "medium": 1, "low": 2}[r["severity"]])

    d = client.get("/api/dashboard", headers=admin).json()
    assert d["critical_total"] == 4 and d["critical_unmapped"] == 1 and d["critical_no_backup"] == 2
    _ = loose


def test_demo_seed_loads(client, admin, clean):
    from app.db import SessionLocal
    from app.seed import seed_demo
    db = SessionLocal()
    seed_demo(db)
    db.close()
    d = client.get("/api/dashboard", headers=admin).json()
    assert d["assets_total"] >= 25 and d["critical_total"] == 11 and d["checks_total"] >= 20
    assert client.get("/api/topology", headers=admin).status_code == 200
    assert len(client.get("/api/risks", headers=admin).json()) > 5


def test_spa_and_static(client):
    r = client.get("/api/health")
    assert r.json()["ok"] is True
    assert client.get("/api/khong-ton-tai-xyz", headers={}).status_code in (401, 404, 405)
