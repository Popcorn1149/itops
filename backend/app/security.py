"""Đăng nhập, phiên, 2FA (TOTP) và mã hoá bí mật trong cấu hình.

Hai khoá TÁCH RIÊNG (data/ hoặc biến môi trường):
  * .secret_key (SECRET_KEY)      – chỉ để KÝ phiên đăng nhập (JWT HS256). Mất/đổi → mọi người phải đăng nhập lại.
  * .enc_key    (ENCRYPTION_KEY)  – chỉ để MÃ HOÁ mật khẩu/community/token thiết bị (AES-256-GCM, tiền tố "enc2:").
                                     Mất khoá này → KHÔNG giải mã lại được bí mật đã lưu → phải backup cùng CSDL.
Dữ liệu cũ dạng "enc:" (Fernet, khoá suy ra từ SECRET_KEY của bản v1) vẫn đọc được và được mã hoá lại sang enc2
khi app khởi động (reencrypt_all).
"""
import base64
import contextvars
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException, Request
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from .db import get_db, DATA_DIR
from . import models


def _env_flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _load_or_create(env: str, filename: str, make) -> str:
    v = os.environ.get(env)
    if v:
        return v.strip()
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        return open(path).read().strip()
    key = make()
    with open(path, "w") as f:
        f.write(key)
    os.chmod(path, 0o600)
    return key


# ---------------------------------------------------------------- khoá
SECRET_KEY = _load_or_create("SECRET_KEY", ".secret_key", lambda: secrets.token_urlsafe(48))            # ký JWT
_ENC_KEY_B64 = _load_or_create("ENCRYPTION_KEY", ".enc_key", lambda: base64.urlsafe_b64encode(os.urandom(32)).decode())
_ENC_KEY = base64.urlsafe_b64decode(_ENC_KEY_B64)
if len(_ENC_KEY) != 32:
    raise RuntimeError("ENCRYPTION_KEY / .enc_key phải là 32 byte mã hoá base64 (AES-256)")
_aes = AESGCM(_ENC_KEY)
_AAD = b"itops-v2"
_legacy_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))   # chỉ để ĐỌC dữ liệu v1

ALGO = "HS256"
TOKEN_HOURS = int(os.environ.get("TOKEN_HOURS", "12"))
IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", "30"))
COOKIE_NAME = "itops_session"
CSRF_HEADER = "X-Requested-With"          # giao diện luôn gửi X-Requested-With: itops
REQUIRE_2FA_ADMIN = _env_flag("REQUIRE_2FA_ADMIN", "1")   # bắt buộc 2FA với admin – chỉ đổi được bằng biến môi trường
ISSUER = os.environ.get("APP_NAME", "IT Ops Workspace")

SECRET_FIELDS = {"password", "community", "api_key", "token", "private_key", "bot_token", "auth_key", "priv_key", "client_secret",
                 "cli_password", "cli_private_key", "token_secret", "esxi_password"}
MASK = "__SECRET__"

# Bối cảnh request (cho audit 5W1H) – middleware đặt, audit() đọc
REQ_CTX: contextvars.ContextVar[dict | None] = contextvars.ContextVar("itops_req", default=None)


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- mật khẩu
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except ValueError:
        return False


# ---------------------------------------------------------------- TOTP (RFC 6238, không cần thư viện ngoài)
TOTP_STEP, TOTP_DIGITS = 30, 6


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // TOTP_STEP))


def totp_match(secret_b32: str, code: str, last_step: int = 0, at: float | None = None) -> int | None:
    """Trả về bước thời gian khớp (cho phép lệch ±1 bước = ±30s), None nếu sai hoặc mã đã dùng (chống replay)."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS or not secret_b32:
        return None
    cur = int((at or time.time()) // TOTP_STEP)
    for step in (cur - 1, cur, cur + 1):
        if step > (last_step or 0) and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, username: str) -> str:
    from urllib.parse import quote
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"


def qr_svg(text: str) -> str:
    import io
    import segno
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, dark="#111111", light="#ffffff", xmldecl=False)
    return buf.getvalue().decode()


# ---------------------------------------------------------------- phiên đăng nhập
def create_session(db: Session, user: models.User, request: Request, mfa: bool) -> tuple[str, models.LoginSession]:
    sid = secrets.token_hex(16)
    t = now()
    s = models.LoginSession(id=sid, username=user.username, created_at=t, last_seen=t,
                            expires_at=t + timedelta(hours=TOKEN_HOURS), mfa=mfa,
                            ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:255])
    db.add(s)
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    token = jwt.encode({"sub": user.username, "role": user.role, "jti": sid, "exp": exp}, SECRET_KEY, algorithm=ALGO)
    return token, s


def revoke_sessions(db: Session, username: str, by: str, keep: str | None = None) -> int:
    n = 0
    for s in db.query(models.LoginSession).filter_by(username=username, revoked_at=None):
        if s.id != keep:
            s.revoked_at, s.revoked_by = now(), by
            n += 1
    return n


def set_session_cookie(resp, request: Request, token: str):
    secure = _env_flag("COOKIE_SECURE", "0") or request.url.scheme == "https"
    resp.set_cookie(COOKIE_NAME, token, max_age=TOKEN_HOURS * 3600, httponly=True, samesite="strict", secure=secure, path="/")


def clear_session_cookie(resp):
    resp.delete_cookie(COOKIE_NAME, path="/")


def client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "-"


# Khi admin chưa bật 2FA mà hệ thống bắt buộc: chỉ cho gọi các API để tự bật 2FA
_2FA_SETUP_PATHS = ("/api/auth/me", "/api/auth/logout", "/api/auth/2fa/", "/api/auth/sessions")


def current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    auth = request.headers.get("Authorization", "")
    from_cookie = False
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    else:
        token = request.cookies.get(COOKIE_NAME, "")
        from_cookie = True
    # KHÔNG nhận token qua query string (?token=) – dễ lộ qua log, lịch sử trình duyệt, Referer.
    if not token:
        raise HTTPException(401, "Chưa đăng nhập")
    if from_cookie and request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != "itops":
        raise HTTPException(403, "Thiếu header chống CSRF")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(401, "Phiên đăng nhập hết hạn") from None
    sess = db.get(models.LoginSession, str(payload.get("jti") or ""))
    t = now()
    if not sess or sess.revoked_at is not None or sess.username != payload.get("sub") or sess.expires_at < t:
        raise HTTPException(401, "Phiên đăng nhập đã kết thúc – vui lòng đăng nhập lại")
    if IDLE_MINUTES > 0 and (t - sess.last_seen) > timedelta(minutes=IDLE_MINUTES):
        sess.revoked_at, sess.revoked_by = t, "idle-timeout"
        db.commit()
        raise HTTPException(401, f"Phiên đã hết hạn do không thao tác quá {IDLE_MINUTES} phút")
    # Request nền (giao diện tự làm mới số liệu) không tính là "đang thao tác"
    if request.headers.get("X-Background") != "1" and (t - sess.last_seen) > timedelta(seconds=30):
        sess.last_seen = t
        db.commit()
    user = db.query(models.User).filter_by(username=payload.get("sub")).first()
    if not user:
        raise HTTPException(401, "Tài khoản không tồn tại")
    request.state.session = sess
    if need_2fa_setup(user) and not request.url.path.startswith(_2FA_SETUP_PATHS):
        raise HTTPException(403, {"code": "2fa_required", "msg": "Tài khoản quản trị phải bật xác thực 2 lớp (2FA) trước khi sử dụng"})
    return user


def need_2fa_setup(user: models.User) -> bool:
    return REQUIRE_2FA_ADMIN and user.role == "admin" and not user.totp_enabled


def admin_user(user: models.User = Depends(current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "Chỉ admin mới được thay đổi")
    return user


# ---------------------------------------------------------------- bí mật trong cấu hình
def encrypt(v: str) -> str:
    nonce = os.urandom(12)
    return "enc2:" + base64.urlsafe_b64encode(nonce + _aes.encrypt(nonce, v.encode(), _AAD)).decode()


def decrypt(v):
    if isinstance(v, str) and v.startswith("enc2:"):
        try:
            raw = base64.urlsafe_b64decode(v[5:].encode())
            return _aes.decrypt(raw[:12], raw[12:], _AAD).decode()
        except (InvalidTag, ValueError):
            return ""
    if isinstance(v, str) and v.startswith("enc:"):          # dữ liệu bản v1
        try:
            return _legacy_fernet.decrypt(v[4:].encode()).decode()
        except InvalidToken:
            return ""
    return v


def seal_config(new: dict, old: dict | None = None) -> dict:
    """Mã hoá các trường bí mật; giữ giá trị cũ nếu client gửi lại MASK."""
    old = old or {}
    out = {}
    for k, v in (new or {}).items():
        if k in SECRET_FIELDS and isinstance(v, str):
            if v == MASK:
                if k in old:
                    out[k] = old[k]
            elif v == "":
                out[k] = ""
            else:
                out[k] = encrypt(v)
        else:
            out[k] = v
    return out


def mask_config(cfg: dict) -> dict:
    return {k: (MASK if k in SECRET_FIELDS and v else v) for k, v in (cfg or {}).items()}


def open_config(cfg: dict) -> dict:
    return {k: decrypt(v) if k in SECRET_FIELDS else v for k, v in (cfg or {}).items()}


def _reseal(v):
    """enc: (v1) → enc2:. Giá trị không giải mã được giữ nguyên để không mất dữ liệu."""
    if isinstance(v, str) and v.startswith("enc:"):
        plain = decrypt(v)
        return encrypt(plain) if plain else v
    if isinstance(v, dict):
        return {k: _reseal(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_reseal(x) for x in v]
    return v


def reencrypt_all(db: Session) -> int:
    """Mã hoá lại mọi bí mật dạng cũ (enc:) sang AES-256-GCM (enc2:). Chạy lúc khởi động, an toàn khi chạy lại."""
    n = 0
    for chk in db.query(models.Check):
        new = _reseal(chk.config or {})
        if new != (chk.config or {}):
            chk.config, n = new, n + 1
    for st in db.query(models.Setting):
        new = _reseal(st.value)
        if new != st.value:
            st.value, n = new, n + 1
    db.commit()
    return n
