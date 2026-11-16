"""Bước nhập mã 2FA có hạn (mặc định 3 phút): mật khẩu đúng → vé bước 2; hết hạn → phải nhập lại mật khẩu."""
import time

import pytest

from app import main as M
from app import security as sec
from tests.test_security_p1 import WEB, mkuser, login, bearer, enable_2fa, next_code


@pytest.fixture(autouse=True)
def _reset():
    M._FAILED.clear(); M._FAILED_IP.clear(); sec._USED_TICKETS.clear()
    yield
    M._FAILED.clear(); M._FAILED_IP.clear(); sec._USED_TICKETS.clear()


def step1(client, name, pw="Matkhau@123"):
    r = client.post("/api/auth/login", json={"username": name, "password": pw}, headers=WEB)
    assert r.status_code == 401, r.text
    d = r.json()["detail"]
    assert d["need_otp"] is True and d["mfa_ticket"] and d["expires_in"] == sec.MFA_STEP_SECONDS
    return d["mfa_ticket"]


def step2(client, ticket, otp):
    return client.post("/api/auth/login", json={"mfa_ticket": ticket, "otp": otp}, headers=WEB)


def test_default_is_3_minutes():
    assert sec.MFA_STEP_SECONDS == 180


def test_ticket_login_without_resending_password(client, admin):
    mkuser(client, admin, "mt1")
    secret = enable_2fa(client, bearer(login(client, "mt1")))
    tk = step1(client, "mt1")
    bad = step2(client, tk, "000000")
    assert bad.status_code == 401 and bad.json()["detail"]["need_otp"] is True       # mã sai: vẫn ở bước 2, vé còn dùng được
    ok = step2(client, tk, next_code(secret))
    assert ok.status_code == 200 and ok.json()["user"]["username"] == "mt1"
    assert client.get("/api/auth/me").json()["session"]["mfa"] is True
    # vé đã đăng nhập thành công → không dùng lại được, kể cả với mã mới
    again = step2(client, tk, sec.totp_now(secret, time.time() + 2 * sec.TOTP_STEP))
    assert again.status_code == 401 and again.json()["detail"]["mfa_expired"] is True


def test_wrong_password_gets_no_ticket(client, admin):
    mkuser(client, admin, "mt2")
    enable_2fa(client, bearer(login(client, "mt2")))
    r = client.post("/api/auth/login", json={"username": "mt2", "password": "sai"}, headers=WEB)
    assert r.status_code == 401 and "mfa_ticket" not in str(r.json())


def test_ticket_expires_after_3_minutes(client, admin, monkeypatch):
    mkuser(client, admin, "mt3")
    secret = enable_2fa(client, bearer(login(client, "mt3")))
    tk = step1(client, "mt3")
    import calendar
    import jose.jwt as jj
    monkeypatch.setattr(jj, "timegm", lambda t: calendar.timegm(t) + 181)     # đồng hồ kiểm tra hạn vé nhảy +181 giây
    r = step2(client, tk, next_code(secret))
    assert r.status_code == 401
    d = r.json()["detail"]
    assert d["mfa_expired"] is True and "3 minutes" in d["msg"]
    assert "2FA step expired" in client.get("/api/audit?limit=5", headers=admin).text


def test_forged_or_reused_ticket_rejected(client, admin):
    mkuser(client, admin, "mt4")
    secret = enable_2fa(client, bearer(login(client, "mt4")))
    tk = step1(client, "mt4")
    assert step2(client, tk[:-3] + "abc", next_code(secret)).json()["detail"]["mfa_expired"] is True
    # vé không phải phiên đăng nhập
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tk}"}).status_code == 401
    # đổi mật khẩu giữa chừng → vé cũ vô hiệu
    tk2 = step1(client, "mt4")
    h = bearer(login(client, "mt4", otp=next_code(secret)))
    assert client.post("/api/auth/password", json={"old_password": "Matkhau@123", "new_password": "Moi@123456"}, headers=h).status_code == 200
    r = step2(client, tk2, sec.totp_now(secret, time.time() + 2 * sec.TOTP_STEP))
    assert r.status_code == 401 and r.json()["detail"]["mfa_expired"] is True


def test_ticket_bound_to_ip(client, admin, monkeypatch):
    mkuser(client, admin, "mt5")
    secret = enable_2fa(client, bearer(login(client, "mt5")))
    tk = step1(client, "mt5")
    monkeypatch.setattr(M, "client_ip", lambda req: "10.9.9.9")
    r = step2(client, tk, next_code(secret))
    assert r.status_code == 401 and r.json()["detail"]["mfa_expired"] is True


def test_script_single_request_still_works(client, admin):
    mkuser(client, admin, "mt6")
    secret = enable_2fa(client, bearer(login(client, "mt6")))
    assert login(client, "mt6", otp=next_code(secret)).status_code == 200
