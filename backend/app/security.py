"""Sign-in, sessions, 2FA (TOTP), and encryption of configuration secrets.

Two SEPARATE keys (data/ or environment variables):
  * .secret_key (SECRET_KEY)      – used only to SIGN sign-in sessions (JWT HS256). Lost/changed → everyone must sign in again.
  * .enc_key    (ENCRYPTION_KEY)  – used only to ENCRYPT device passwords/community strings/tokens (AES-256-GCM, prefix "enc2:").
                                     If this key is lost → stored secrets CANNOT be decrypted → back it up with the database.
Legacy data using "enc:" (Fernet, key derived from the v1 SECRET_KEY) remains readable and is re-encrypted to enc2
when the app starts (reencrypt_all)."""
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
from jose.exceptions import ExpiredSignatureError
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
    raise RuntimeError("ENCRYPTION_KEY / .enc_key must be 32 byte base64-encoded (AES-256)")
_aes = AESGCM(_ENC_KEY)
_AAD = b"itops-v2"
_legacy_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))   # chỉ để ĐỌC dữ liệu v1

ALGO = "HS256"
TOKEN_HOURS = int(os.environ.get("TOKEN_HOURS", "12"))
IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", "30"))
COOKIE_NAME = "itops_session"
CSRF_HEADER = "X-Requested-With"          # giao diện luôn gửi X-Requested-With: itops
REQUIRE_2FA_ADMIN = _env_flag("REQUIRE_2FA_ADMIN", "1")   # required 2FA với admin – chỉ đổi được bằng biến môi trường
ISSUER = os.environ.get("APP_NAME", "IT Ops Workspace")

SECRET_FIELDS = {"password", "community", "api_key", "token", "private_key", "bot_token", "auth_key", "priv_key", "client_secret",
                 "cli_password", "cli_private_key", "token_secret", "esxi_password",
                 "indexer_password"}
MASK = "__SECRET__"

# Bối cảnh request (cho audit 5W1H) – middleware đặt, audit() đọc
REQ_CTX: contextvars.ContextVar[dict | None] = contextvars.ContextVar("itops_req", default=None)


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- password
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except ValueError:
        return False


# ---------------------------------------------------------------- TOTP (RFC 6238, without requiring thư viện ngoài)
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
    """Trả về step thời gian khớp (cho phép lệch ±1 step = ±30s), None nếu sai hoặc mã đã dùng (chống replay)."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS or not secret_b32:
        return None
    cur = int((at or time.time()) // TOTP_STEP)
    for step in (cur - 1, cur, cur + 1):
        if step > (last_step or 0) and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


# ---------------------------------------------------------------- vé bước 2FA (mật khẩu đúng → có N giây để nhập mã)
# Sau khi mật khẩu đúng, server cấp "vé" ký HMAC có hạn MFA_STEP_SECONDS (mặc định 180s = 3 phút).
# Bước nhập mã chỉ gửi vé + mã (không gửi lại mật khẩu). Hết hạn → phải nhập lại mật khẩu.
# Vé gắn với: tài khoản, IP, dấu vân tay mật khẩu (đổi mật khẩu → vé cũ vô hiệu) và chỉ dùng thành công 1 lần.
MFA_STEP_SECONDS = max(30, int(os.environ.get("MFA_STEP_SECONDS", "180")))
_MFA_TYP = "itops-mfa-pending"
_USED_TICKETS: dict[str, float] = {}       # jti → hạn; vé đã đăng nhập thành công thì không dùng lại được


def mfa_step_label(sec_: int | None = None) -> str:
    n = MFA_STEP_SECONDS if sec_ is None else sec_
    if n % 60:
        return f"{n} seconds"
    return "1 minute" if n == 60 else f"{n // 60} minutes"


class MfaTicketError(Exception):
    def __init__(self, expired: bool):
        super().__init__("expired" if expired else "invalid")
        self.expired = expired


def _pw_fp(user: models.User) -> str:
    return hmac.new(SECRET_KEY.encode(), (user.password_hash or "").encode(), hashlib.sha256).hexdigest()[:16]


def create_mfa_ticket(user: models.User, ip: str) -> tuple[str, int]:
    exp = int(time.time()) + MFA_STEP_SECONDS
    tok = jwt.encode({"typ": _MFA_TYP, "sub": user.username, "ip": ip, "pw": _pw_fp(user),
                      "jti": secrets.token_hex(12), "exp": exp}, SECRET_KEY, algorithm=ALGO)
    return tok, MFA_STEP_SECONDS


def read_mfa_ticket(ticket: str, ip: str) -> dict:
    """Trả payload của vé hợp lệ; MfaTicketError(expired=True) nếu quá hạn, expired=False nếu giả/sai."""
    try:
        p = jwt.decode(str(ticket or ""), SECRET_KEY, algorithms=[ALGO])
    except ExpiredSignatureError:
        raise MfaTicketError(True) from None
    except JWTError:
        raise MfaTicketError(False) from None
    if p.get("typ") != _MFA_TYP or p.get("ip") != ip or not p.get("sub") or p.get("jti") in _USED_TICKETS:
        raise MfaTicketError(False)
    return p


def check_mfa_ticket_user(p: dict, user: models.User | None) -> None:
    if not user or not user.totp_enabled or not hmac.compare_digest(p.get("pw", ""), _pw_fp(user)):
        raise MfaTicketError(False)


def burn_mfa_ticket(p: dict) -> None:
    t = time.time()
    for k in [k for k, v in _USED_TICKETS.items() if v < t]:
        _USED_TICKETS.pop(k, None)
    _USED_TICKETS[p["jti"]] = float(p.get("exp", t + MFA_STEP_SECONDS))


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


# ---------------------------------------------------------------- sessions sign-in
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


HINT_COOKIE = "itops_auth"   # cookie "gợi ý" KHÔNG chứa bí mật (value "1"), JS đọc được → biết có nên hỏi /auth/me


def set_session_cookie(resp, request: Request, token: str):
    secure = _env_flag("COOKIE_SECURE", "0") or request.url.scheme == "https"
    resp.set_cookie(COOKIE_NAME, token, max_age=TOKEN_HOURS * 3600, httponly=True, samesite="strict", secure=secure, path="/")
    resp.set_cookie(HINT_COOKIE, "1", max_age=TOKEN_HOURS * 3600, httponly=False, samesite="strict", secure=secure, path="/")


def clear_session_cookie(resp):
    resp.delete_cookie(COOKIE_NAME, path="/")
    resp.delete_cookie(HINT_COOKIE, path="/")


def client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "-"


# Khi admin chưa enabled 2FA mà hệ thống required: chỉ cho gọi các API để tự enabled 2FA
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
        raise HTTPException(401, "Not logged in")
    if from_cookie and request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != "itops":
        raise HTTPException(403, "Missing CSRF protection header")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(401, "Login session expired") from None
    sess = db.get(models.LoginSession, str(payload.get("jti") or ""))
    t = now()
    if sess and sess.revoked_by == "idle-timeout":
        raise HTTPException(401, f"Session expired after being idle for {IDLE_MINUTES} minutes")
    if not sess or sess.revoked_at is not None or sess.username != payload.get("sub") or sess.expires_at < t:
        raise HTTPException(401, "The login session has ended. Please sign in again.")
    if IDLE_MINUTES > 0 and (t - sess.last_seen) > timedelta(minutes=IDLE_MINUTES):
        sess.revoked_at, sess.revoked_by = t, "idle-timeout"
        db.commit()
        raise HTTPException(401, f"Session expired after being idle for {IDLE_MINUTES} minutes")
    # Background requests (the UI refreshes data automatically) do not count as user activity
    if request.headers.get("X-Background") != "1" and (t - sess.last_seen) > timedelta(seconds=30):
        sess.last_seen = t
        db.commit()
    user = db.query(models.User).filter_by(username=payload.get("sub")).first()
    if not user:
        raise HTTPException(401, "Account does not exist")
    request.state.session = sess
    if need_2fa_setup(user) and not request.url.path.startswith(_2FA_SETUP_PATHS):
        raise HTTPException(403, {"code": "2fa_required", "msg": "Administrator accounts must enable two-factor authentication (2FA) before use"})
    return user


def need_2fa_setup(user: models.User) -> bool:
    return REQUIRE_2FA_ADMIN and user.role == "admin" and not user.totp_enabled


def admin_user(user: models.User = Depends(current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "Only administrators can make changes")
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
    """Encrypt secret fields; preserve existing values when the client sends MASK."""
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
    """enc: (v1) → enc2:. Values that cannot be decrypted are preserved to prevent data loss."""
    if isinstance(v, str) and v.startswith("enc:"):
        plain = decrypt(v)
        return encrypt(plain) if plain else v
    if isinstance(v, dict):
        return {k: _reseal(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_reseal(x) for x in v]
    return v


def reencrypt_all(db: Session) -> int:
    """Mã hoá lại mọi bí mật dạng cũ (enc:) sang AES-256-GCM (enc2:). Runs at startup and is safe to repeat."""
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
