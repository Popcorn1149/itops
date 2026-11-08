"""Đợt bảo mật P1 (bản v2): phiên + cookie HttpOnly + CSRF, 2FA (TOTP) bắt buộc với admin, khoá theo IP,
audit 5W1H chỉ ghi thêm, tách khoá ký / khoá mã hoá (AES-256-GCM), khoá lệnh SSH tuỳ chỉnh."""
import asyncio
import os
import time
from datetime import timedelta

import pytest

from app import main as M
from app import models
from app import security as sec
from app.db import SessionLocal

WEB = {"X-Requested-With": "itops"}        # header giao diện web luôn gửi


from tests.pgtest import head_revision, sql  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_ip_lock():
    M._FAILED.clear(); M._FAILED_IP.clear()
    yield
    M._FAILED.clear(); M._FAILED_IP.clear()


def mkuser(client, admin, name, role="viewer", pw="Matkhau@123"):
    r = client.post("/api/users", json={"username": name, "password": pw, "role": role}, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def login(client, name, pw="Matkhau@123", **extra):
    return client.post("/api/auth/login", json={"username": name, "password": pw, **extra})


def bearer(r):
    return {"Authorization": f"Bearer {r.json()['token']}"}


def secret_of(name):
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(username=name).first()
        return sec.decrypt(u.totp_secret or u.totp_pending or "")


def next_code(secret):
    """Mã của bước 30s KẾ TIẾP (vẫn hợp lệ nhờ cửa sổ ±1) – tránh trùng bước vừa dùng khi bật 2FA."""
    return sec.totp_now(secret, time.time() + sec.TOTP_STEP)


def enable_2fa(client, h):
    st = client.post("/api/auth/2fa/setup", headers=h)
    assert st.status_code == 200, st.text
    secret = st.json()["secret"]
    assert client.post("/api/auth/2fa/enable", json={"code": sec.totp_now(secret)}, headers=h).status_code == 200
    return secret


# ---------------------------------------------------------------- cookie, CSRF, query token
def test_web_login_uses_httponly_cookie_not_token(client, admin):
    mkuser(client, admin, "web1")
    r = client.post("/api/auth/login", json={"username": "web1", "password": "Matkhau@123"}, headers=WEB)
    assert r.status_code == 200 and "token" not in r.json(), "giao diện web không được nhận token"
    sc = r.headers["set-cookie"].lower()
    assert sec.COOKIE_NAME in sc and "httponly" in sc and "samesite=strict" in sc
    assert client.get("/api/auth/me").json()["username"] == "web1"            # cookie tự gửi kèm
    # ghi bằng cookie mà thiếu header chống CSRF → chặn; có header → được
    assert client.post("/api/auth/password", json={"old_password": "x", "new_password": "y" * 8}).status_code == 403
    assert client.post("/api/auth/password", json={"old_password": "x", "new_password": "y" * 8}, headers=WEB).status_code == 400


def test_token_in_query_string_rejected(client, admin):
    tok = admin["Authorization"][7:]
    assert client.get(f"/api/dashboard?token={tok}").status_code == 401


def test_logout_revokes_session(client, admin):
    mkuser(client, admin, "lo1")
    h = bearer(login(client, "lo1"))
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401


# ---------------------------------------------------------------- phiên: liệt kê, thu hồi, idle, đổi mật khẩu
def test_sessions_list_and_revoke(client, admin):
    mkuser(client, admin, "ss1")
    h1, h2 = bearer(login(client, "ss1")), bearer(login(client, "ss1"))
    mine = client.get("/api/auth/sessions", headers=h1).json()
    assert len(mine) == 2 and sum(s["current"] for s in mine) == 1 and all(s["username"] == "ss1" for s in mine)
    other = [s for s in mine if not s["current"]][0]
    assert client.delete(f"/api/auth/sessions/{other['id']}", headers=h1).status_code == 200
    assert client.get("/api/auth/me", headers=h2).status_code == 401 and client.get("/api/auth/me", headers=h1).status_code == 200
    # admin thấy phiên của mọi người; người thường không thu hồi được phiên người khác
    allp = client.get("/api/auth/sessions?all=1", headers=admin).json()
    assert {"ss1", "admin"} <= {s["username"] for s in allp}
    adm_sid = [s for s in allp if s["username"] == "admin"][0]["id"]
    assert client.delete(f"/api/auth/sessions/{adm_sid}", headers=h1).status_code == 404


def test_idle_timeout_and_background_requests(client, admin):
    mkuser(client, admin, "idle1")
    h = bearer(login(client, "idle1"))
    sid = client.get("/api/auth/sessions", headers=h).json()[0]["id"]

    def age(minutes):
        with SessionLocal() as db:
            s = db.get(models.LoginSession, sid)
            s.last_seen = sec.now() - timedelta(minutes=minutes)
            db.commit()

    def last_seen():
        with SessionLocal() as db:
            return db.get(models.LoginSession, sid).last_seen

    age(5)
    before = last_seen()
    assert client.get("/api/dashboard", headers={**h, "X-Background": "1"}).status_code == 200
    assert last_seen() == before, "request nền không được tính là đang thao tác"
    assert client.get("/api/dashboard", headers=h).status_code == 200
    assert last_seen() > before
    age(sec.IDLE_MINUTES + 1)
    r = client.get("/api/dashboard", headers=h)
    assert r.status_code == 401 and "không thao tác" in r.text
    assert client.get("/api/auth/me", headers=h).status_code == 401      # đã bị thu hồi hẳn


def test_password_change_revokes_other_sessions(client, admin):
    mkuser(client, admin, "pw1")
    h1, h2 = bearer(login(client, "pw1")), bearer(login(client, "pw1"))
    assert client.post("/api/auth/password", json={"old_password": "Matkhau@123", "new_password": "MoiMoi@456"}, headers=h1).status_code == 200
    assert client.get("/api/auth/me", headers=h1).status_code == 200 and client.get("/api/auth/me", headers=h2).status_code == 401
    # admin đặt lại mật khẩu → mọi phiên của người đó bị thu hồi
    uid = client.get("/api/auth/me", headers=h1).json()["id"]
    assert client.put(f"/api/users/{uid}", json={"password": "Admin@Reset1"}, headers=admin).status_code == 200
    assert client.get("/api/auth/me", headers=h1).status_code == 401


# ---------------------------------------------------------------- 2FA
def test_totp_rfc6238_vector():
    # RFC 6238 phụ lục B: khoá "12345678901234567890", T=59 → 94287082 (8 số) → 6 số cuối 287082
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert sec.totp_now(secret, 59) == "287082"
    assert sec.totp_match(secret, "287082", 0, at=59) == 1
    assert sec.totp_match(secret, "287082", 1, at=59) is None          # bước đã dùng → chống replay
    assert sec.totp_match(secret, "000000", 0, at=59) is None


def test_2fa_setup_enable_login_and_replay(client, admin):
    mkuser(client, admin, "tf1")
    h = bearer(login(client, "tf1"))
    st = client.post("/api/auth/2fa/setup", headers=h).json()
    assert st["otpauth_uri"].startswith("otpauth://totp/") and st["qr_svg"].lstrip().startswith("<svg")
    assert client.post("/api/auth/2fa/enable", json={"code": "123456"}, headers=h).status_code == 400
    assert client.post("/api/auth/2fa/enable", json={"code": sec.totp_now(st["secret"])}, headers=h).status_code == 200
    me = client.get("/api/auth/me", headers=h).json()
    assert me["totp_enabled"] is True and "totp_secret" not in me and "totp_pending" not in me
    assert "totp_secret" not in client.get("/api/users", headers=admin).text
    # bí mật lưu đã mã hoá
    raw = sql("select totp_secret from users where username='tf1'")[0][0]
    assert raw.startswith("enc2:") and st["secret"] not in raw
    # đăng nhập: thiếu mã → yêu cầu mã (không tính là sai); sai mã → 401; đúng mã → vào được
    r = login(client, "tf1")
    assert r.status_code == 401 and r.json()["detail"]["need_otp"] is True
    assert login(client, "tf1", otp="000000").status_code == 401
    code = next_code(st["secret"])
    r = login(client, "tf1", otp=code)
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=bearer(r)).json()["session"]["mfa"] is True
    assert login(client, "tf1", otp=code).status_code == 401, "mã đã dùng không được dùng lại"
    # viewer tự tắt 2FA được (cần mật khẩu + mã)
    assert client.post("/api/auth/2fa/disable", json={"password": "sai", "code": "1"}, headers=bearer(r)).status_code == 400


def test_admin_must_enroll_2fa(client, admin, monkeypatch):
    mkuser(client, admin, "adm2", role="admin")
    mkuser(client, admin, "view2")
    monkeypatch.setattr(sec, "REQUIRE_2FA_ADMIN", True)
    r = login(client, "adm2")
    assert r.status_code == 200 and r.json()["user"]["need_2fa_setup"] is True
    h = bearer(r)
    blocked = client.get("/api/dashboard", headers=h)
    assert blocked.status_code == 403 and blocked.json()["detail"]["code"] == "2fa_required"
    assert client.get("/api/auth/me", headers=h).status_code == 200            # vẫn vào được màn hình bật 2FA
    secret = enable_2fa(client, h)
    assert client.get("/api/dashboard", headers=h).status_code == 200
    # admin không tự tắt được khi bắt buộc
    assert client.post("/api/auth/2fa/disable", json={"password": "Matkhau@123", "code": next_code(secret)}, headers=h).status_code == 400
    # viewer không bị bắt buộc
    assert client.get("/api/dashboard", headers=bearer(login(client, "view2"))).status_code == 200


def test_admin_reset_2fa_of_other_user(client, admin):
    u = mkuser(client, admin, "lost1")
    h = bearer(login(client, "lost1"))
    enable_2fa(client, h)
    assert client.post(f"/api/users/{u['id']}/reset-2fa", headers=admin).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401           # phiên cũ bị thu hồi
    assert login(client, "lost1").status_code == 200                          # đăng nhập lại không cần mã
    me_id = client.get("/api/auth/me", headers=admin).json()["id"]
    assert client.post(f"/api/users/{me_id}/reset-2fa", headers=admin).status_code == 400


# ---------------------------------------------------------------- khoá theo IP
def test_lockout_per_ip_across_usernames(client, admin, monkeypatch):
    monkeypatch.setattr(M, "MAX_FAILS_IP", 4)
    for i in range(4):
        assert login(client, f"khongco{i}", pw="sai").status_code == 401
    r = login(client, "admin", pw="Admin@12345")
    assert r.status_code == 429 and "testclient" in r.text      # cả tài khoản đúng cũng bị chặn từ IP này


# ---------------------------------------------------------------- audit 5W1H + chỉ ghi thêm
def test_audit_5w1h_fields(client, admin, clean):
    s = client.post("/api/sites", json={"name": "HQ-cu", "kind": "hq"}, headers=admin).json()
    r = client.put(f"/api/sites/{s['id']}", json={"name": "HQ-moi"},
                   headers={**admin, "X-Audit-Reason": "%C4%90%E1%BB%95i%20t%C3%AAn%20theo%20phi%E1%BA%BFu%20CR-12", "User-Agent": "pytest-ua"})
    assert r.status_code == 200
    row = [a for a in client.get("/api/audit", headers=admin).json() if a["entity"] == "sites" and a["action"] == "update"][0]
    assert row["user"] == "admin" and row["ip"] == "testclient" and row["user_agent"] == "pytest-ua"
    assert row["reason"] == "Đổi tên theo phiếu CR-12"
    assert row["changes"] == {"before": {"name": "HQ-cu"}, "after": {"name": "HQ-moi"}}


def test_audit_append_only(client, admin):
    import psycopg
    n = sql("select count(*) from audit_logs")[0][0]
    assert n > 0
    for q in ("update audit_logs set detail='sua'", "delete from audit_logs", "truncate audit_logs"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="chi duoc ghi them"):
            sql(q)
    assert sql("select count(*) from audit_logs")[0][0] >= n
    trig = {r[0] for r in sql("select tgname from pg_trigger where tgrelid='audit_logs'::regclass and not tgisinternal")}
    assert {"audit_logs_no_update_delete", "audit_logs_no_truncate"} <= trig
    # ORM cũng bị chặn (vd. code lỗi gọi db.delete trên bản ghi audit)
    from sqlalchemy.exc import DBAPIError
    db = SessionLocal()
    try:
        with pytest.raises(DBAPIError, match="chi duoc ghi them"):
            db.query(models.AuditLog).filter(models.AuditLog.id > 0).update({"detail": "x"})
    finally:
        db.rollback(); db.close()


# ---------------------------------------------------------------- khoá
def test_signing_and_encryption_keys_are_separate():
    d = os.environ["DATA_DIR"]
    sk, ek = open(os.path.join(d, ".secret_key")).read().strip(), open(os.path.join(d, ".enc_key")).read().strip()
    assert sk and ek and sk != ek
    import base64
    assert len(base64.urlsafe_b64decode(ek)) == 32                    # AES-256
    v = sec.encrypt("abc")
    assert v.startswith("enc2:") and sec.decrypt(v) == "abc" and sec.encrypt("abc") != v   # nonce ngẫu nhiên
    tampered = v[:-4] + ("AAAA" if not v.endswith("AAAA") else "BBBB")
    assert sec.decrypt(tampered) == ""                                  # GCM phát hiện bị sửa


def test_legacy_fernet_values_reencrypted(client, admin, clean):
    legacy = "enc:" + sec._legacy_fernet.encrypt(b"MatKhauCuV1").decode()
    with SessionLocal() as db:
        chk = models.Check(name="legacy", type="tcp", target="127.0.0.1", enabled=False, config={"password": legacy, "port": 22})
        db.add(chk)
        st = db.get(models.Setting, "notify") or models.Setting(key="notify", value={})
        st.value = {**(st.value or {}), "telegram": {"bot_token": "enc:" + sec._legacy_fernet.encrypt(b"123:TOKENCU").decode()}}
        db.merge(st)
        db.commit()
        cid = chk.id
        assert sec.open_config(chk.config)["password"] == "MatKhauCuV1"      # vẫn đọc được
        assert sec.reencrypt_all(db) >= 2
        assert sec.reencrypt_all(db) == 0                                     # chạy lại không làm gì
        chk = db.get(models.Check, cid)
        assert chk.config["password"].startswith("enc2:") and sec.open_config(chk.config)["password"] == "MatKhauCuV1"
        tg = db.get(models.Setting, "notify").value["telegram"]["bot_token"]
        assert tg.startswith("enc2:") and sec.decrypt(tg) == "123:TOKENCU"


# ---------------------------------------------------------------- lệnh SSH tuỳ chỉnh
def test_ssh_custom_command_locked_by_default(client, admin, clean, monkeypatch):
    monkeypatch.delenv("ALLOW_SSH_COMMAND", raising=False)
    body = {"name": "ssh-cmd", "type": "ssh", "target": "127.0.0.1", "enabled": False, "config": {"username": "u", "command": "rm -rf /tmp/x"}}
    r = client.post("/api/checks", json=body, headers=admin)
    assert r.status_code == 400 and "chỉ để đọc" in r.text
    assert client.post("/api/checks-test", json=body, headers=admin).status_code == 400
    ok = client.post("/api/checks", json={**body, "config": {"username": "u"}}, headers=admin)
    assert ok.status_code == 200
    assert client.put(f"/api/checks/{ok.json()['id']}", json={"config": {"username": "u", "command": "id"}}, headers=admin).status_code == 400
    from app.collectors.ssh import ssh
    res = asyncio.run(ssh("127.0.0.1", {"username": "u", "command": "id"}))
    assert res.status == "fail" and "bị khoá" in res.message                  # chặn cả ở collector (check cũ đã lưu)
    monkeypatch.setenv("ALLOW_SSH_COMMAND", "1")
    assert client.post("/api/checks-test", json={**body, "config": {"username": "u", "command": "id", "timeout": 1}, "target": "127.0.0.1"},
                       headers=admin).status_code == 200


# ---------------------------------------------------------------- sao lưu
def test_backup_contains_db_and_keys_and_restores(client, admin, clean, tmp_path, monkeypatch):
    import base64
    import json
    import zipfile
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker
    from app import admin_tools
    from tests.pgtest import scratch_db
    c = client.post("/api/checks", json={"name": "bk", "type": "tcp", "target": "127.0.0.1", "enabled": False,
                                         "config": {"port": 22, "password": "BiMatSaoLuu"}}, headers=admin).json()
    out = admin_tools.backup(str(tmp_path / "bk"), "test")
    z = zipfile.ZipFile(out)
    names = set(z.namelist())
    assert {"db/manifest.json", "db/checks.jsonl", "db/audit_logs.jsonl", ".secret_key", ".enc_key", "KHOI-PHUC.txt"} <= names
    man = json.loads(z.read("db/manifest.json"))
    assert man["revision"] == head_revision() and man["tables"]["checks"] >= 1 and man["tables"]["users"] >= 1
    assert not list((tmp_path / "bk").glob("*.part")), "không để lại file dở"
    # bí mật trong bản sao lưu vẫn ở dạng mã hoá, giải được bằng .enc_key đi kèm
    rows = [json.loads(line) for line in z.read("db/checks.jsonl").splitlines()]
    raw = next(r for r in rows if r["id"] == c["id"])["config"]["password"]
    assert raw.startswith("enc2:") and "BiMatSaoLuu" not in z.read("db/checks.jsonl").decode()
    key = base64.urlsafe_b64decode(z.read(".enc_key").decode().strip())
    blob = base64.urlsafe_b64decode(raw[5:])
    assert AESGCM(key).decrypt(blob[:12], blob[12:], b"itops-v2").decode() == "BiMatSaoLuu"
    assert any(a["action"] == "backup" for a in client.get("/api/audit", headers=admin).json())
    # khôi phục sang CSDL trống khác → đủ bản ghi, đúng kiểu, sequence nối tiếp, audit vẫn chỉ-ghi-thêm
    with scratch_db() as eng:
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        monkeypatch.setattr(admin_tools, "engine", eng)
        monkeypatch.setattr(admin_tools, "SessionLocal", sessionmaker(bind=eng))
        monkeypatch.setattr(admin_tools, "DATA_DIR", str(keys_dir))
        msg = admin_tools.restore(str(out))
        assert "Đã khôi phục" in msg
        assert (keys_dir / ".enc_key").read_bytes() == z.read(".enc_key")
        with eng.connect() as conn:
            for t, n in man["tables"].items():
                got = conn.execute(text(f'select count(*) from "{t}"')).scalar()
                assert got == n + (1 if t == "audit_logs" else 0), t      # +1 = dòng audit "restore"
            cfg = conn.execute(text("select config from checks where id=:i"), {"i": c["id"]}).scalar()
            assert cfg["password"] == raw and cfg["port"] == 22                       # json → dict
            assert conn.execute(text("select pg_typeof(config)::text from checks limit 1")).scalar() == "json"
            assert conn.execute(text("select version_num from alembic_version")).scalar() == head_revision()
            nid = conn.execute(text("select nextval(pg_get_serial_sequence('checks','id'))")).scalar()
            assert nid > max(r["id"] for r in rows), "sequence phải nối tiếp id lớn nhất đã nạp"
        with pytest.raises(SystemExit, match="đang có dữ liệu"):
            admin_tools.restore(str(out))                       # không ghi đè khi chưa --wipe
        assert "Đã khôi phục" in admin_tools.restore(str(out), wipe=True)
        # bản sao lưu hỏng + --wipe → báo lỗi, dữ liệu đang có KHÔNG bị xoá (wipe và nạp chung một transaction)
        bad = tmp_path / "hong.zip"
        with zipfile.ZipFile(bad, "w") as zb:
            for n in z.namelist():
                zb.writestr(n, z.read(n) if n != "db/checks.jsonl" else b"")
        with pytest.raises(SystemExit, match="không khớp"):
            admin_tools.restore(str(bad), wipe=True)
        with eng.connect() as conn:
            assert conn.execute(text("select count(*) from checks")).scalar() == man["tables"]["checks"]
    for i in range(3):
        (tmp_path / "bk" / f"itops-backup-2000010{i}-000000.zip").write_bytes(b"x")
    assert admin_tools.prune_backups(str(tmp_path / "bk"), keep=2) == 2


def test_cli_reset_password(client, admin):
    from app import admin_tools
    mkuser(client, admin, "quenmk")
    out = admin_tools.reset_password("quenmk")
    pw = out.split(": ", 1)[1].split("\n")[0]
    assert login(client, "quenmk", pw="Matkhau@123").status_code == 401
    assert login(client, "quenmk", pw=pw).status_code == 200
    with pytest.raises(SystemExit, match="Tài khoản đang có"):
        admin_tools.reset_password("khong-ton-tai")
