"""Bảo mật API: chống dò password, path traversal, header, ẩn tài liệu API."""
import os

import pytest


def test_login_lockout_after_5_failures(client, admin):
    client.post("/api/users", json={"username": "victim", "password": "Victim@123", "role": "viewer"}, headers=admin)
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "victim", "password": "doan-sai"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": "victim", "password": "Victim@123"})
    assert r.status_code == 429 and "Try again" in r.json()["detail"], "Mật khẩu đúng cũng bị chặn khi đang khoá"
    assert client.post("/api/auth/login", json={"username": "admin", "password": "Admin@12345"}).status_code == 200, "Khoá theo từng account, không khoá admin"
    logs = client.get("/api/audit", headers=admin).json()
    assert sum(1 for l in logs if l["action"] == "login_failed" and l["user"] == "victim") == 5
    from app import main
    main._FAILED.clear()
    assert client.post("/api/auth/login", json={"username": "victim", "password": "Victim@123"}).status_code == 200


@pytest.mark.parametrize("path", [
    "/../app/security.py", "/%2e%2e/app/security.py", "/..%2fapp%2fsecurity.py", "/assets/../../app/main.py",
    "/%2e%2e/%2e%2e/etc/passwd", "/....//app/db.py",
])
def test_static_path_traversal_blocked(client, path):
    static = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(__file__), "..", "static"))
    if not os.path.isdir(static):
        pytest.skip("chưa build frontend")
    r = client.get(path)
    body = r.text
    assert "SECRET_KEY" not in body and "def " not in body and "root:" not in body, f"{path} lộ file ngoài thư items static"


def test_security_headers_and_no_api_docs(client, admin):
    r = client.get("/api/dashboard", headers=admin)
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
    for p in ["/docs", "/redoc", "/openapi.json"]:
        assert "swagger" not in client.get(p).text.lower() and '"openapi"' not in client.get(p).text


def test_password_hashes_never_returned(client, admin):
    for p in ["/api/users", "/api/auth/me"]:
        assert "password_hash" not in client.get(p, headers=admin).text and "$2b$" not in client.get(p, headers=admin).text


def test_secret_key_file_permissions():
    path = os.path.join(os.environ["DATA_DIR"], ".secret_key")
    if os.path.exists(path):
        assert oct(os.stat(path).st_mode)[-3:] == "600"
