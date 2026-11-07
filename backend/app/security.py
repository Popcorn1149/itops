"""Đăng nhập (JWT) và mã hoá mật khẩu/community lưu trong cấu hình check."""
import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from .db import get_db, DATA_DIR
from . import models


def _load_secret() -> str:
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(DATA_DIR, ".secret_key")
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_urlsafe(48)
    with open(path, "w") as f:
        f.write(key)
    os.chmod(path, 0o600)
    return key


SECRET_KEY = _load_secret()
ALGO = "HS256"
TOKEN_HOURS = int(os.environ.get("TOKEN_HOURS", "12"))
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))

SECRET_FIELDS = {"password", "community", "api_key", "token", "private_key", "bot_token", "auth_key", "priv_key", "client_secret",
                 "cli_password", "cli_private_key", "token_secret", "esxi_password"}
MASK = "__SECRET__"


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except ValueError:
        return False


def create_token(user: models.User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, SECRET_KEY, algorithm=ALGO)


def current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else request.query_params.get("token", "")
    if not token:
        raise HTTPException(401, "Chưa đăng nhập")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(401, "Phiên đăng nhập hết hạn") from None
    user = db.query(models.User).filter_by(username=payload.get("sub")).first()
    if not user:
        raise HTTPException(401, "Tài khoản không tồn tại")
    return user


def admin_user(user: models.User = Depends(current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "Chỉ admin mới được thay đổi")
    return user


# ---- secrets in config dicts -------------------------------------------------
def encrypt(v: str) -> str:
    return "enc:" + _fernet.encrypt(v.encode()).decode()


def decrypt(v):
    if isinstance(v, str) and v.startswith("enc:"):
        try:
            return _fernet.decrypt(v[4:].encode()).decode()
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
