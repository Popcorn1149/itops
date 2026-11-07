import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, Body, Query, BackgroundTasks, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect as sa_inspect, func
from sqlalchemy.orm import Session

from .db import engine, get_db, SessionLocal, run_migrations
from . import models
from .models import now
from .security import (current_user, admin_user, verify_password, hash_password,
                       seal_config, mask_config, MASK, SECRET_FIELDS, REQ_CTX, client_ip)
from . import security as sec
from . import scheduler
from .scheduler import run_check
from .collectors import COLLECTORS
from .notify import notify, CHANNELS
from .topology import build_topology, build_risks, critical_view
from . import events as ev_mod, receivers, secmon, virt
from .security import open_config

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("itops")
VERSION = "1.0.0"


def init_db():
    m = run_migrations()
    if m["from"] != m["to"]:
        log.warning("Đã nâng cấp CSDL: %s → %s", m["from"] or "(trống)", m["to"])
    db = SessionLocal()
    try:
        n = sec.reencrypt_all(db)
        if n:
            log.warning("Đã mã hoá lại %d cấu hình sang AES-256-GCM (khoá riêng .enc_key)", n)
        ev_mod.seed_rules(db)
        if not db.query(models.User).first():
            u = os.environ.get("ADMIN_USER", "admin")
            p = os.environ.get("ADMIN_PASSWORD", "").strip()
            if not p:
                import secrets as _s
                p = _s.token_urlsafe(9)
                log.warning("ADMIN_PASSWORD chưa đặt → đã sinh mật khẩu ngẫu nhiên cho '%s': %s", u, p)
            db.add(models.User(username=u, full_name="Quản trị viên", password_hash=hash_password(p), role="admin"))
            db.commit()
            log.warning("Đã tạo tài khoản %s – hãy đổi mật khẩu sau khi đăng nhập!", u)
        if os.environ.get("DEMO_DATA", "false").lower() in ("1", "true", "yes") and not db.query(models.Site).first():
            from .seed import seed_demo
            seed_demo(db)
            from . import demo_logs
            if demo_logs.enabled():
                demo_logs.seed_history()          # 24 giờ log/trap "như thật" cho dữ liệu mẫu
    finally:
        db.close()


def _receiver_cfg(raw: bool = False) -> dict:
    db = SessionLocal()
    try:
        st = db.get(models.Setting, "receivers")
        v = dict((st.value if st else {}) or {})
    finally:
        db.close()
    v.setdefault("communities", ["public"])
    v.setdefault("v3_users", [])
    v.setdefault("allowed_sources", list(ev_mod.DEFAULT_ALLOWED))
    if not raw:
        v["communities"] = [open_config({"community": c})["community"] for c in v["communities"]]
        v["v3_users"] = [open_config(u) for u in v["v3_users"]]
    return v


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    tasks = []
    if os.environ.get("DISABLE_SCHEDULER", "").lower() not in ("1", "true"):
        tasks.append(asyncio.create_task(scheduler.loop()))
        from .automation import engine as auto_engine
        tasks.append(asyncio.create_task(auto_engine.loop()))      # tự động hoá chạy cùng bộ lập lịch
        tasks.append(asyncio.create_task(secmon.loop()))           # SLA, log source im lặng, archive + hash, cảnh báo audit
    tasks += [asyncio.create_task(ev_mod.consumer()), asyncio.create_task(ev_mod.housekeeping())]
    if os.environ.get("DISABLE_SCHEDULER", "").lower() not in ("1", "true"):
        from .admin_tools import backup_loop
        tasks.append(asyncio.create_task(backup_loop()))            # sao lưu CSDL + khoá mỗi ngày
        from . import demo_logs
        if demo_logs.enabled():
            tasks.append(asyncio.create_task(demo_logs.live_loop()))   # dữ liệu mẫu: log trực tiếp + sự cố định kỳ
    ev_mod.set_allowed(_receiver_cfg()["allowed_sources"])
    if os.environ.get("DISABLE_RECEIVERS", "").lower() not in ("1", "true"):
        await receivers.start_all(_receiver_cfg())
    yield
    await receivers.stop_all()
    for t in tasks:
        t.cancel()


app = FastAPI(title="IT Ops Workspace", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    from urllib.parse import unquote
    tok = REQ_CTX.set({"ip": client_ip(request), "ua": (request.headers.get("user-agent") or "")[:255],
                       "reason": unquote(request.headers.get("X-Audit-Reason", ""))[:500]})
    try:
        resp = await call_next(request)
    finally:
        REQ_CTX.reset(tok)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- helpers
def to_dict(obj) -> dict:
    d = {c.key: getattr(obj, c.key) for c in sa_inspect(obj).mapper.column_attrs}
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat() + "Z"
    for k in ("password_hash", "totp_secret", "totp_pending", "totp_last_step"):
        d.pop(k, None)
    return d


def _audit_safe(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: (MASK if k in SECRET_FIELDS and x else _audit_safe(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [_audit_safe(x) for x in v]
    return v


def audit(db: Session, user: str, action: str, entity: str, entity_id=None, detail: str = "", changes: dict | None = None):
    """Ghi nhật ký 5W1H: Ai (user) · Cái gì (action/entity/detail) · Khi nào (ts) · Ở đâu (ip, user_agent)
    · Như thế nào (changes: trước → sau, bí mật được che) · Tại sao (reason – header X-Audit-Reason)."""
    ctx = REQ_CTX.get() or {}
    db.add(models.AuditLog(user=user, action=action, entity=entity, entity_id=entity_id, detail=detail[:2000],
                           ip=ctx.get("ip", ""), user_agent=ctx.get("ua", ""), reason=ctx.get("reason", ""),
                           changes=_audit_safe(changes) if changes else None))
    secmon.on_audit(db, user, action, entity, entity_id, detail)   # UC-14: thao tác nhạy cảm → cảnh báo người nhận riêng


EDITABLE = {
    "sites": ["name", "kind", "location", "wan", "vpn", "description", "sort"],
    "assets": ["name", "type", "site_id", "parent_id", "ip", "vendor", "model", "os", "serial", "owner", "location",
               "status", "backup", "backup_note", "notes", "meta"],
    "critical": ["name", "description", "layer", "level", "asset_id", "hosted_externally", "external_note", "backup",
                 "backup_note", "owner", "url", "depends_on", "check_ids", "runbook"],
    "checks": ["name", "type", "site_id", "asset_id", "target", "interval", "enabled", "config"],
    "event-rules": ["name", "description", "enabled", "action", "kind", "max_severity", "pattern", "app_pattern", "trap_oids",
                    "resolve_pattern", "resolve_trap_oids", "asset_id", "site_id", "alert_severity", "threshold", "window_min",
                    "auto_resolve_min", "sort", "group_by", "key_filter"],
}
MODEL = {"sites": models.Site, "assets": models.Asset, "critical": models.CriticalSystem, "checks": models.Check, "event-rules": models.EventRule}
LABEL = {"sites": "site", "assets": "tài sản", "critical": "hệ thống trọng yếu", "checks": "check giám sát", "event-rules": "rule log"}


def _validate_rule(body: dict):
    import re as _re
    for f in ("pattern", "app_pattern", "resolve_pattern"):
        if body.get(f):
            try:
                _re.compile(body[f])
            except _re.error as e:
                raise HTTPException(400, f"Biểu thức {f} không hợp lệ: {e}") from None
    if body.get("action", "alert") not in ("alert", "drop") or body.get("kind", "any") not in ("any", "syslog", "trap"):
        raise HTTPException(400, "action/kind không hợp lệ")
    if body.get("group_by", "") not in ("", "src_ip"):
        raise HTTPException(400, "group_by không hợp lệ")


def apply(obj, data: dict, fields: list[str]):
    for f in fields:
        if f in data:
            v = data[f]
            if f.endswith("_id") and v in ("", 0):
                v = None
            setattr(obj, f, v)


def _close_alerts(db: Session, check_id: int, reason: str):
    for a in db.query(models.Alert).filter(models.Alert.check_id == check_id, models.Alert.status != "resolved"):
        a.status, a.resolved_at = "resolved", now()
        a.message = f"{a.message} · {reason}"[:2000]


def serialize(kind: str, obj) -> dict:
    d = to_dict(obj)
    if kind == "checks":
        d["config"] = mask_config(d.get("config") or {})
        from .topology import is_public, wan_role
        d["wan_role"] = wan_role(obj)        # đang được tính là 1 Line Internet trên bản đồ (None = không)
        d["line_suggest"] = not d["wan_role"] and obj.type in ("ping", "tcp") and is_public(obj.target)
    return d


# ---------------------------------------------------------------- auth
_FAILED: dict[str, list[float]] = {}        # khoá theo IP + tài khoản
_FAILED_IP: dict[str, list[float]] = {}     # khoá theo IP (chặn dò nhiều tài khoản từ 1 máy)
MAX_FAILS, LOCK_SECONDS = int(os.environ.get("LOGIN_MAX_FAILS", "5")), int(os.environ.get("LOGIN_LOCK_SECONDS", "300"))
MAX_FAILS_IP = int(os.environ.get("LOGIN_MAX_FAILS_PER_IP", "20"))


def _lock_msg(fails, limit, what):
    return f"{what} sai quá {limit} lần. Thử lại sau {int((LOCK_SECONDS - (time.time() - fails[0])) // 60) + 1} phút."


def _user_out(u: models.User) -> dict:
    d = to_dict(u)
    d["require_2fa"] = sec.REQUIRE_2FA_ADMIN and u.role == "admin"
    d["need_2fa_setup"] = sec.need_2fa_setup(u)
    return d


@app.post("/api/auth/login")
def login(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    username = str(body.get("username", "")).strip()
    ip = client_ip(request)
    key = f"{ip}|{username.lower()}"
    t = time.time()
    fails = [x for x in _FAILED.get(key, []) if t - x < LOCK_SECONDS]
    ip_fails = [x for x in _FAILED_IP.get(ip, []) if t - x < LOCK_SECONDS]
    if len(fails) >= MAX_FAILS:
        raise HTTPException(429, _lock_msg(fails, MAX_FAILS, "Đăng nhập"))
    if len(ip_fails) >= MAX_FAILS_IP:
        raise HTTPException(429, _lock_msg(ip_fails, MAX_FAILS_IP, f"Máy {ip} đăng nhập"))

    def fail(why: str, msg: str, extra: dict | None = None):
        _FAILED[key] = fails + [t]
        _FAILED_IP[ip] = ip_fails + [t]
        audit(db, username or "?", "login_failed", "user", None, f"{why} từ {ip}")
        db.commit()
        raise HTTPException(401, {"msg": msg, **(extra or {})} if extra else msg)

    u = db.query(models.User).filter_by(username=username).first()
    if not u or not verify_password(str(body.get("password", "")), u.password_hash):
        fail("Đăng nhập sai", "Sai tài khoản hoặc mật khẩu")
    mfa = False
    if u.totp_enabled:
        otp = str(body.get("otp", "")).strip()
        if not otp:   # mật khẩu đúng, chưa nhập mã → yêu cầu bước 2 (không tính là sai)
            raise HTTPException(401, {"msg": "Nhập mã 6 số từ ứng dụng xác thực", "need_otp": True})
        step = sec.totp_match(sec.decrypt(u.totp_secret or ""), otp, u.totp_last_step)
        if step is None:
            fail("Sai mã 2FA", "Mã xác thực không đúng hoặc đã dùng", {"need_otp": True})
        u.totp_last_step, mfa = step, True
    _FAILED.pop(key, None)
    u.last_login = now()
    token, sess = sec.create_session(db, u, request, mfa)
    audit(db, u.username, "login", "user", u.id, "2FA" if mfa else "")
    db.commit()
    out = {"user": _user_out(u)}
    if request.headers.get(sec.CSRF_HEADER) != "itops":
        out["token"] = token          # chỉ cho script/API; giao diện web chỉ dùng cookie HttpOnly
    resp = JSONResponse(out)
    sec.set_session_cookie(resp, request, token)
    return resp


@app.post("/api/auth/logout")
def logout(request: Request, user=Depends(current_user), db: Session = Depends(get_db)):
    sess = request.state.session
    sess.revoked_at, sess.revoked_by = now(), user.username
    audit(db, user.username, "logout", "user", user.id)
    db.commit()
    resp = JSONResponse({"ok": True})
    sec.clear_session_cookie(resp)
    return resp


@app.get("/api/auth/me")
def me(request: Request, user=Depends(current_user)):
    d = _user_out(user)
    s = request.state.session
    d["session"] = {"id": s.id[:8], "mfa": s.mfa, "expires_at": s.expires_at.isoformat() + "Z", "idle_minutes": sec.IDLE_MINUTES}
    return d


@app.get("/api/auth/sessions")
def list_sessions(request: Request, all: bool = False, user=Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(models.LoginSession).filter(models.LoginSession.revoked_at.is_(None), models.LoginSession.expires_at > now())
    if not (all and user.role == "admin"):
        q = q.filter_by(username=user.username)
    cur = request.state.session.id
    return [{"id": s.id, "username": s.username, "created_at": s.created_at.isoformat() + "Z", "last_seen": s.last_seen.isoformat() + "Z",
             "ip": s.ip, "user_agent": s.user_agent, "mfa": s.mfa, "current": s.id == cur}
            for s in q.order_by(models.LoginSession.last_seen.desc()).limit(200)]


@app.delete("/api/auth/sessions/{sid}")
def revoke_session(sid: str, request: Request, user=Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(models.LoginSession, sid)
    if not s or (s.username != user.username and user.role != "admin"):
        raise HTTPException(404, "Không tìm thấy phiên")
    if s.revoked_at is None:
        s.revoked_at, s.revoked_by = now(), user.username
        audit(db, user.username, "revoke", "session", None, f"Thu hồi phiên của {s.username} ({s.ip})")
        db.commit()
    return {"ok": True, "current": s.id == request.state.session.id}


@app.post("/api/auth/2fa/setup")
def totp_setup(user=Depends(current_user), db: Session = Depends(get_db)):
    """Bước 1: sinh bí mật mới (chưa có hiệu lực) → trả mã QR để quét bằng Google Authenticator / Microsoft Authenticator…"""
    u = db.get(models.User, user.id)
    if u.totp_enabled:
        raise HTTPException(400, "2FA đã bật. Muốn đổi điện thoại: tắt rồi bật lại (hoặc nhờ admin đặt lại).")
    secret = sec.new_totp_secret()
    u.totp_pending = sec.encrypt(secret)
    db.commit()
    uri = sec.otpauth_uri(secret, u.username)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": sec.qr_svg(uri)}


@app.post("/api/auth/2fa/enable")
def totp_enable(request: Request, body: dict = Body(...), user=Depends(current_user), db: Session = Depends(get_db)):
    """Bước 2: nhập mã đang hiện trên điện thoại để xác nhận → 2FA có hiệu lực."""
    u = db.get(models.User, user.id)
    secret = sec.decrypt(u.totp_pending or "")
    if not secret:
        raise HTTPException(400, "Chưa tạo mã QR – bấm Bật 2FA lại")
    step = sec.totp_match(secret, body.get("code", ""))
    if step is None:
        raise HTTPException(400, "Mã không đúng. Kiểm tra giờ trên điện thoại và nhập mã mới nhất.")
    u.totp_secret, u.totp_pending, u.totp_enabled, u.totp_last_step = u.totp_pending, None, True, step
    request.state.session.mfa = True
    n = sec.revoke_sessions(db, u.username, "2fa-enabled", keep=request.state.session.id)
    audit(db, u.username, "enable_2fa", "user", u.id, "Bật xác thực 2 lớp" + (f", thu hồi {n} phiên khác" if n else ""))
    db.commit()
    return _user_out(u)


@app.post("/api/auth/2fa/disable")
def totp_disable(body: dict = Body(...), user=Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(models.User, user.id)
    if not u.totp_enabled:
        return _user_out(u)
    if sec.REQUIRE_2FA_ADMIN and u.role == "admin":
        raise HTTPException(400, "Tài khoản admin bắt buộc dùng 2FA – không thể tắt. Đổi điện thoại: nhờ admin khác đặt lại 2FA.")
    if not verify_password(str(body.get("password", "")), u.password_hash):
        raise HTTPException(400, "Mật khẩu không đúng")
    if sec.totp_match(sec.decrypt(u.totp_secret or ""), body.get("code", ""), u.totp_last_step) is None:
        raise HTTPException(400, "Mã xác thực không đúng")
    u.totp_enabled, u.totp_secret, u.totp_pending, u.totp_last_step = False, None, None, 0
    audit(db, u.username, "disable_2fa", "user", u.id, "Tắt xác thực 2 lớp")
    db.commit()
    return _user_out(u)


@app.post("/api/users/{uid}/reset-2fa")
def reset_user_2fa(uid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    """Admin đặt lại 2FA cho người khác (mất điện thoại). Người đó phải bật lại ở lần đăng nhập sau."""
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404, "Không tìm thấy người dùng")
    if u.id == user.id:
        raise HTTPException(400, "Không tự đặt lại 2FA của chính mình – nhờ admin khác, hoặc dùng lệnh admin_tools trên máy chủ")
    u.totp_enabled, u.totp_secret, u.totp_pending, u.totp_last_step = False, None, None, 0
    n = sec.revoke_sessions(db, u.username, user.username)
    audit(db, user.username, "reset_2fa", "user", uid, f"Đặt lại 2FA của {u.username}, thu hồi {n} phiên")
    db.commit()
    return _user_out(u)


@app.post("/api/auth/password")
def change_password(request: Request, body: dict = Body(...), user=Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(models.User, user.id)
    if not verify_password(body.get("old_password", ""), u.password_hash):
        raise HTTPException(400, "Mật khẩu cũ không đúng")
    if len(body.get("new_password", "")) < 8:
        raise HTTPException(400, "Mật khẩu mới tối thiểu 8 ký tự")
    u.password_hash = hash_password(body["new_password"])
    n = sec.revoke_sessions(db, u.username, u.username, keep=request.state.session.id)
    audit(db, u.username, "update", "user", u.id, "Đổi mật khẩu" + (f", thu hồi {n} phiên khác" if n else ""))
    db.commit()
    return {"ok": True}


@app.get("/api/users")
def list_users(user=Depends(admin_user), db: Session = Depends(get_db)):
    return [_user_out(u) for u in db.query(models.User).order_by(models.User.id)]


@app.post("/api/users")
def create_user(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    if not body.get("username") or len(body.get("password", "")) < 8:
        raise HTTPException(400, "Cần username và mật khẩu ≥ 8 ký tự")
    if db.query(models.User).filter_by(username=body["username"]).first():
        raise HTTPException(400, "Username đã tồn tại")
    u = models.User(username=body["username"], full_name=body.get("full_name", ""), role=body.get("role", "viewer"),
                    password_hash=hash_password(body["password"]))
    db.add(u)
    audit(db, user.username, "create", "user", None, f"{body['username']} role={u.role}")
    db.commit()
    return _user_out(u)


@app.put("/api/users/{uid}")
def update_user(uid: int, body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404, "Không tìm thấy người dùng")
    if "full_name" in body:
        u.full_name = body["full_name"]
    role_note, revoke = "", False
    if body.get("role") in ("admin", "viewer"):
        if u.id == user.id and body["role"] != "admin":
            raise HTTPException(400, "Không tự hạ quyền chính mình")
        if u.role != body["role"]:
            role_note, revoke = f" role={body['role']} (trước: {u.role})", True
        u.role = body["role"]
    if body.get("password"):
        if len(body["password"]) < 8:
            raise HTTPException(400, "Mật khẩu tối thiểu 8 ký tự")
        u.password_hash = hash_password(body["password"])
        role_note, revoke = role_note + " (đặt lại mật khẩu)", True
    if revoke and u.id != user.id:
        n = sec.revoke_sessions(db, u.username, user.username)
        role_note += f", thu hồi {n} phiên" if n else ""
    audit(db, user.username, "update", "user", uid, u.username + role_note)
    db.commit()
    return _user_out(u)


@app.delete("/api/users/{uid}")
def delete_user(uid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    if uid == user.id:
        raise HTTPException(400, "Không thể xoá chính mình")
    u = db.get(models.User, uid)
    if u:
        sec.revoke_sessions(db, u.username, user.username)
        db.delete(u)
        audit(db, user.username, "delete", "user", uid, u.username)
        db.commit()
    return {"ok": True}


def _guard_ssh_command(ctype, cfg):
    from .collectors.ssh import custom_command_allowed
    if ctype == "ssh" and str((cfg or {}).get("command") or "").strip() and not custom_command_allowed():
        raise HTTPException(400, "Lệnh SSH tuỳ chỉnh đang bị khoá (nguyên tắc: tài khoản thiết bị chỉ để đọc). "
                                 "Bỏ trống ô lệnh để dùng bộ đo mặc định, hoặc bật ALLOW_SSH_COMMAND=1 nếu thật sự cần.")


# ---------------------------------------------------------------- generic CRUD
def _list(kind, db):
    q = db.query(MODEL[kind])
    order = {"sites": [models.Site.sort, models.Site.id]}.get(kind, [MODEL[kind].id])
    return q.order_by(*order).all()


@app.get("/api/sites")
def list_sites(user=Depends(current_user), db: Session = Depends(get_db)):
    sites = _list("sites", db)
    assets = db.query(models.Asset).all()
    checks = db.query(models.Check).all()
    alerts = db.query(models.Alert).filter(models.Alert.status != "resolved").all()
    from .topology import internet_lines
    lines = internet_lines(db)
    out = []
    for s in sites:
        d = to_dict(s)
        sa = [a for a in assets if a.site_id == s.id]
        sc = [c for c in checks if c.site_id == s.id or (c.asset_id and any(a.id == c.asset_id for a in sa))]
        vms = [a for a in sa if a.type == "vm"]
        d["stats"] = {
            "hosts": sum(1 for a in sa if a.type == "host"),
            "vms": len(vms), "vms_on": sum(1 for a in vms if a.status == "up"),
            "devices": sum(1 for a in sa if a.type not in ("host", "vm", "container", "firewall")),
            "checks": len(sc), "checks_bad": sum(1 for c in sc if c.status in ("fail", "warn")),
            "alerts": sum(1 for al in alerts if al.site_id == s.id or (al.asset_id and any(a.id == al.asset_id for a in sa))),
        }
        last = max([c.last_checked for c in sc if c.last_checked] or [None], key=lambda x: x or datetime.min)
        d["last_sync"] = last.isoformat() + "Z" if last else None
        on = [c for c in sc if c.enabled]
        d["internet"] = lines.get(s.id, [])
        # status site: chưa giám sát (không có check nào bật) / lỗi / cảnh báo / chưa chạy / hoạt động
        bad = [c.status for c in on]
        if not on:
            health = "unmonitored"
        elif "fail" in bad:
            health = "fail"
        elif "warn" in bad or d["stats"]["alerts"]:
            health = "warn"
        elif all(x == "unknown" for x in bad):
            health = "unknown"
        else:
            health = "ok"
        d["health"] = health
        d["firewalls"] = [{"id": a.id, "name": a.name, "status": a.status, "model": a.model, "vendor": a.vendor,
                           "live": (a.meta or {}).get("live", {})} for a in sa if a.type == "firewall"]
        d["assets"] = [{"id": a.id, "name": a.name, "type": a.type, "status": a.status} for a in sa if a.type not in ("vm", "container", "firewall", "device")]
        d["checks_list"] = [{"id": c.id, "name": c.name, "type": c.type, "status": c.status} for c in sc]
        out.append(d)
    return out


@app.get("/api/assets")
def list_assets(type: str | None = None, site_id: int | None = None, q: str | None = None,
                user=Depends(current_user), db: Session = Depends(get_db)):
    qry = db.query(models.Asset)
    if type:
        qry = qry.filter(models.Asset.type.in_(type.split(",")))
    if site_id:
        qry = qry.filter(models.Asset.site_id == site_id)
    if q:
        like = f"%{q}%"
        qry = qry.filter((models.Asset.name.ilike(like)) | (models.Asset.ip.ilike(like)) | (models.Asset.model.ilike(like)))
    assets = qry.order_by(models.Asset.site_id, models.Asset.type, models.Asset.name).all()
    checks = db.query(models.Check).all()
    crit = db.query(models.CriticalSystem).all()
    child_count = dict(db.query(models.Asset.parent_id, func.count()).group_by(models.Asset.parent_id).all())
    guests = virt.guest_counts(db)
    names = dict(db.query(models.Asset.id, models.Asset.name).all())
    out = []
    for a in assets:
        d = to_dict(a)
        d["checks"] = [{"id": c.id, "name": c.name, "type": c.type, "status": c.status, "last_message": c.last_message} for c in checks if c.asset_id == a.id]
        d["critical"] = [{"id": c.id, "name": c.name, "level": c.level} for c in crit if c.asset_id == a.id]
        d["children_count"] = child_count.get(a.id, 0)
        d["guests"] = guests.get(a.id)
        d["parent_name"] = names.get(a.parent_id, "") if a.parent_id else ""
        out.append(d)
    return out


@app.post("/api/assets/{aid}/esxi-credentials")
async def set_esxi_credentials(aid: int, body: dict = Body(...), user=Depends(admin_user)):
    """Lưu tài khoản ESXi chỉ đọc vào check SNMP của host rồi chạy lại ngay → có CPU/RAM/Disk từng VM."""
    from .security import seal_config, SECRET_FIELDS, MASK
    with SessionLocal() as db:
        a = db.get(models.Asset, aid)
        if not a:
            raise HTTPException(404)
        src = virt.perf_source(db, a)
        if not src:
            raise HTTPException(400, "Host này không có check SNMP đọc máy ảo ESXi")
        chk = db.get(models.Check, src["check_id"])
        u, pw = str(body.get("user", "")).strip(), str(body.get("password", ""))
        old_cfg = dict(chk.config or {})
        cfg = {k: (MASK if k in SECRET_FIELDS and isinstance(v, str) and v else v) for k, v in old_cfg.items()}  # giữ nguyên bí mật đã mã hoá
        if not u:
            cfg.pop("esxi_user", None); cfg.pop("esxi_password", None)
        else:
            if not pw and not cfg.get("esxi_password"):
                raise HTTPException(400, "Cần mật khẩu")
            cfg["esxi_user"] = u
            if pw:
                cfg["esxi_password"] = pw
        chk.config = seal_config(cfg, old_cfg)
        audit(db, user.username, "update", "checks", chk.id, f"Sửa check giám sát {chk.name}: tài khoản ESXi đọc hiệu năng VM" + ("" if u else " (xoá)"))
        db.commit()
        cid = chk.id
    res = None
    for _ in range(90):   # nếu check đang chạy theo lịch (cấu hình cũ) → chờ xong rồi chạy lại với tài khoản mới
        res = await run_check(cid)
        if res is not None:
            break
        await asyncio.sleep(0.5)
    with SessionLocal() as db:
        a = db.get(models.Asset, aid)
        return {"result": res, "perf": virt.perf_source(db, a)}


@app.get("/api/assets/{aid}/guests")
def asset_guests(aid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    """Máy ảo / container trên host ảo hoá: số lượng, cấp phát (vCPU, RAM so với host), hiệu năng từng máy."""
    a = db.get(models.Asset, aid)
    if not a:
        raise HTTPException(404)
    return virt.guests_view(db, a)


@app.get("/api/checks")
def list_checks(user=Depends(current_user), db: Session = Depends(get_db)):
    since = now() - timedelta(hours=24)
    # uptime = tỷ lệ lần chạy KHÔNG bị DOWN (mất kết nối). Vượt threshold CPU/RAM/Disk hay lỗi dịch vụ không trừ uptime.
    CR = models.CheckResult
    rows = db.query(CR.check_id, CR.down, CR.status, CR.metrics.is_(None), func.count()).filter(CR.ts >= since).group_by(
        CR.check_id, CR.down, CR.status, CR.metrics.is_(None)).all()
    up = {}
    for cid, down, st, no_metrics, n in rows:
        t = up.setdefault(cid, [0, 0])
        t[1] += n
        if down is None:          # bản ghi trước khi có cột "down": chỉ coi là DOWN nếu lỗi mà không đo được gì
            down = st == "fail" and no_metrics
        if not down:
            t[0] += n
    out = []
    for c in _list("checks", db):
        d = serialize("checks", c)
        u = up.get(c.id)
        d["uptime_24h"] = round(u[0] / u[1] * 100, 2) if u and u[1] else None
        out.append(d)
    return out


@app.get("/api/critical")
def list_critical(user=Depends(current_user), db: Session = Depends(get_db)):
    return critical_view(db)


def get_one(kind: str, oid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    if kind not in MODEL:
        raise HTTPException(404)
    obj = db.get(MODEL[kind], oid)
    if not obj:
        raise HTTPException(404, "Không tìm thấy")
    d = serialize(kind, obj)
    if kind == "assets":
        d["children"] = [to_dict(a) for a in db.query(models.Asset).filter_by(parent_id=oid).order_by(models.Asset.type, models.Asset.name)]
        d["checks"] = [serialize("checks", c) for c in db.query(models.Check).filter_by(asset_id=oid)]
        d["alerts"] = [to_dict(a) for a in db.query(models.Alert).filter_by(asset_id=oid).order_by(models.Alert.id.desc()).limit(20)]
        d["critical"] = [to_dict(c) for c in db.query(models.CriticalSystem).filter_by(asset_id=oid)]
        d["events"] = [to_dict(e) for e in db.query(models.Event).filter_by(asset_id=oid).order_by(models.Event.id.desc()).limit(15)]
        chain, p = [], obj.parent_id
        while p and len(chain) < 10:
            pa = db.get(models.Asset, p)
            if not pa:
                break
            chain.insert(0, {"id": pa.id, "name": pa.name, "type": pa.type})
            p = pa.parent_id
        d["path"] = chain
    return d


def create(kind: str, background: BackgroundTasks, body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    if kind not in MODEL:
        raise HTTPException(404)
    if not str(body.get("name", "")).strip():
        raise HTTPException(400, "Thiếu tên")
    obj = MODEL[kind]()
    if kind == "event-rules":
        _validate_rule(body)
    if kind == "checks":
        if body.get("type") not in COLLECTORS:
            raise HTTPException(400, "Loại check không hợp lệ")
        _guard_ssh_command(body.get("type"), body.get("config"))
        body = {**body, "config": seal_config(body.get("config") or {})}
        if not body.get("site_id") and body.get("asset_id"):
            a = db.get(models.Asset, int(body["asset_id"]))
            body["site_id"] = a.site_id if a else None
    apply(obj, body, EDITABLE[kind])
    db.add(obj)
    db.flush()
    audit(db, user.username, "create", kind, obj.id, f"Tạo {LABEL[kind]} {obj.name}")
    db.commit()
    ev_mod.invalidate_caches()
    if kind == "checks" and obj.enabled:
        background.add_task(run_check, obj.id)
    return serialize(kind, obj)


def update(kind: str, oid: int, background: BackgroundTasks, body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    if kind not in MODEL:
        raise HTTPException(404)
    obj = db.get(MODEL[kind], oid)
    if not obj:
        raise HTTPException(404)
    if kind == "checks" and "config" in body:
        _guard_ssh_command(body.get("type", obj.type), body["config"])
        body = {**body, "config": seal_config(body["config"] or {}, obj.config or {})}
    if kind == "event-rules":
        _validate_rule(body)
    if kind == "assets" and body.get("parent_id"):
        p, seen = int(body["parent_id"]), set()
        while p and p not in seen:
            if p == oid:
                raise HTTPException(400, "Không thể đặt cha: tạo vòng lặp (tài sản nằm dưới chính nó)")
            seen.add(p)
            pa = db.get(models.Asset, p)
            p = pa.parent_id if pa else None
    changed = [f for f in EDITABLE[kind] if f in body and f != "config" and body[f] != getattr(obj, f)]
    diff_fields = changed + (["config"] if "config" in body and body["config"] != getattr(obj, "config", None) else [])
    before = {f: getattr(obj, f) for f in diff_fields}
    old_type = obj.type if kind == "checks" else None
    apply(obj, body, EDITABLE[kind])
    after = {f: getattr(obj, f) for f in diff_fields}
    if "config" in before:   # chỉ ghi các khoá cấu hình thực sự đổi
        bc, ac = before["config"] or {}, after["config"] or {}
        keys = sorted(k for k in set(bc) | set(ac) if bc.get(k) != ac.get(k))
        before["config"], after["config"] = {k: bc.get(k) for k in keys}, {k: ac.get(k) for k in keys}
    changes = {"before": before, "after": after} if diff_fields else None
    if kind == "checks" and old_type and obj.type != old_type:
        # Đổi loại check: giữ lịch sử kết quả, đóng cảnh báo của loại cũ, đặt lại status để đo lại từ đầu
        if obj.type not in COLLECTORS:
            raise HTTPException(400, f"Loại check không hợp lệ: {obj.type}")
        _close_alerts(db, oid, f"Đổi loại check {old_type} → {obj.type}")
        obj.status, obj.severity, obj.fail_count = "unknown", None, 0
        obj.last_data, obj.last_message, obj.last_latency = {}, f"Đã đổi loại từ {old_type} sang {obj.type} – chờ lần chạy đầu", None
        changed = [c if c != "type" else f"loại {old_type} → {obj.type}" for c in changed]
    if kind == "checks" and body.get("enabled") is False:
        _close_alerts(db, oid, "Check đã tắt")
    if kind in ("checks", "event-rules") and body.get("enabled") is False and "enabled" in changed:
        audit(db, user.username, "disable", kind, oid, f"{LABEL[kind]} {obj.name}", changes)
    else:
        audit(db, user.username, "update", kind, oid, f"Sửa {LABEL[kind]} {obj.name}" + (f": {', '.join(changed)}" if changed else ""), changes)
    db.commit()
    ev_mod.invalidate_caches()
    if kind == "checks" and old_type and obj.type != old_type and obj.enabled:
        background.add_task(run_check, obj.id)
    return serialize(kind, obj)


def delete(kind: str, oid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    if kind not in MODEL:
        raise HTTPException(404)
    obj = db.get(MODEL[kind], oid)
    if obj:
        name = obj.name
        if kind == "checks":
            _close_alerts(db, oid, "Check đã bị xoá")
            db.query(models.CheckResult).filter_by(check_id=oid).delete()
            # tài sản do check này phát hiện → bỏ nguồn để giữ lại như tài sản thủ công
            for a in db.query(models.Asset).filter_by(source=f"check:{oid}"):
                a.source = "manual"
        db.delete(obj)
        audit(db, user.username, "delete", kind, oid, f"Xoá {LABEL[kind]} {name}")
        db.commit()
        ev_mod.invalidate_caches()
    return {"ok": True}


# ---------------------------------------------------------------- checks
@app.post("/api/checks/{cid}/run")
async def run_now(cid: int, user=Depends(current_user)):
    res = await run_check(cid)
    if res is None:
        raise HTTPException(409, "Check đang chạy, thử lại sau vài giây")
    return res


@app.post("/api/checks-test")
async def test_check(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    """Chạy thử cấu hình check mà không lưu (dùng trong form)."""
    fn = COLLECTORS.get(body.get("type"))
    if not fn:
        raise HTTPException(400, "Loại check không hợp lệ")
    _guard_ssh_command(body.get("type"), body.get("config"))
    cfg = dict(body.get("config") or {})
    if body.get("id"):
        old = db.get(models.Check, int(body["id"]))
        if old:
            from .security import open_config
            oldcfg = open_config(old.config or {})
            cfg = {k: (oldcfg.get(k, "") if v == MASK else v) for k, v in cfg.items()}
    res = await fn(body.get("target", ""), cfg)
    from .collectors.base import classify, max_sev, status_of
    avail, down = classify(res)
    lv = ((res.data or {}).get("res") or {}).get("level")
    sev = max_sev(avail, lv if lv != "ok" else None)
    return {"status": status_of(sev, res.status), "severity": sev, "down": down, "message": res.message, "latency": res.latency,
            "data": res.data, "discovered": len(res.discovered)}


@app.get("/api/checks/{cid}/history")
def history(cid: int, hours: int = 24, user=Depends(current_user), db: Session = Depends(get_db)):
    since = now() - timedelta(hours=min(hours, 24 * 30))
    rows = db.query(models.CheckResult).filter(models.CheckResult.check_id == cid, models.CheckResult.ts >= since).order_by(models.CheckResult.ts).all()
    return [{"ts": r.ts.isoformat() + "Z", "status": r.status, "latency": r.latency, "value": r.value, "message": r.message,
             "metrics": r.metrics, "severity": r.severity,
             "down": r.down if r.down is not None else (r.status == "fail" and r.metrics is None)} for r in rows]


# ---------------------------------------------------------------- tài nguyên CPU/RAM/Disk
RES_TYPES = ("firewall", "switch", "router", "ap", "host", "server", "vm", "nas")   # UPS/máy in/camera không có CPU/RAM


def resources_view(db: Session) -> dict:
    from .collectors.base import level_of, res_thresholds, worst_level, LEVEL_RANK
    checks = {c.id: c for c in db.query(models.Check).all()}
    sites = {s.id: s.name for s in db.query(models.Site).all()}
    rows, covered, uncovered = [], set(), []
    t_now = now()

    def build(name, r, cfg, chk, **extra):
        try:
            age = (t_now - datetime.fromisoformat(str(r.get("ts", "")).rstrip("Z"))).total_seconds()
        except ValueError:
            age = None
        interval = (chk.interval if chk else 300) or 300
        if chk and (chk.config or {}).get("demo") and chk.last_checked:   # dữ liệu mẫu: coi như vừa cập nhật theo check
            age = (t_now - chk.last_checked).total_seconds()
        lv = {k: level_of(cfg, k, r.get(k)) for k in ("cpu", "mem", "disk")}
        disks = [{**d, "level": level_of(cfg, "disk", d.get("pct"))} for d in (r.get("disks") or [])]
        worst_l = worst_level(lv.values())
        return {"name": name, "cpu": r.get("cpu"), "mem": r.get("mem"), "disk": r.get("disk"), "disk_name": r.get("disk_name"),
                "disks": disks, "mem_total_gb": r.get("mem_total_gb"), "cores": r.get("cores"), "swap": r.get("swap"), "mem_note": r.get("mem_note"), "source": r.get("source"),
                "levels": lv, "level": worst_l, "ts": r.get("ts"), "age_s": age,
                "stale": age is not None and age > max(interval * 3, 900),
                "check_id": chk.id if chk else None, "check_name": chk.name if chk else None, "via": chk.type if chk else None,
                "thresholds": res_thresholds(cfg),
                **extra}

    for a in db.query(models.Asset).all():
        r = (a.meta or {}).get("res")
        if r and any(r.get(k) is not None for k in ("cpu", "mem", "disk")):
            chk = checks.get(r.get("check_id") or r.get("via_check"))
            if chk and chk.enabled is False:
                continue
            rows.append(build(a.name, r, (chk.config if chk else {}) or {}, chk, asset_id=a.id, type=a.type, ip=a.ip,
                              status=a.status, site_id=a.site_id, site_name=sites.get(a.site_id, ""),
                              has_history=bool(r.get("check_id"))))
            covered.add(a.id)
            if r.get("check_id"):
                covered.add(("chk", r["check_id"]))
        elif a.type in RES_TYPES and not (a.type == "vm" and a.status != "up"):
            uncovered.append({"id": a.id, "name": a.name, "type": a.type, "ip": a.ip, "os": a.os, "site_id": a.site_id,
                              "site_name": sites.get(a.site_id, "")})
    # check có số liệu nhưng không gắn tài sản
    for c in checks.values():
        r = (c.last_data or {}).get("res")
        if c.enabled and r and ("chk", c.id) not in covered:
            rr = {**r, "ts": c.last_checked.isoformat() + "Z" if c.last_checked else None}
            rows.append(build(c.name, rr, c.config or {}, c, asset_id=None, type=c.type, ip=c.target, status=c.status,
                              site_id=c.site_id, site_name=sites.get(c.site_id, ""), has_history=True))
    rows.sort(key=lambda x: (-LEVEL_RANK[x["level"]], -max(x["cpu"] or 0, x["mem"] or 0, x["disk"] or 0)))
    summary = {k: {l: sum(1 for x in rows if x["levels"].get(k) == l) for l in ("attention", "trouble", "critical")} for k in ("cpu", "mem", "disk")}
    return {"rows": rows, "uncovered": uncovered, "summary": summary,
            "total": len(rows), "problems": sum(1 for x in rows if x["level"] != "ok"), "stale": sum(1 for x in rows if x["stale"])}


@app.get("/api/resources")
def resources(user=Depends(current_user), db: Session = Depends(get_db)):
    return resources_view(db)


@app.get("/api/resources/history")
def resources_history(check_id: int, hours: int = 24, user=Depends(current_user), db: Session = Depends(get_db)):
    since = now() - timedelta(hours=min(hours, 24 * 30))
    rows = db.query(models.CheckResult).filter(models.CheckResult.check_id == check_id, models.CheckResult.ts >= since,
                                               models.CheckResult.metrics.isnot(None)).order_by(models.CheckResult.ts).all()
    pts = [{"ts": r.ts.isoformat() + "Z", **(r.metrics or {})} for r in rows]
    # gom điểm khi khoảng dài (tối đa ~300 điểm cho biểu đồ)
    if len(pts) > 300:
        step = len(pts) / 300
        pts = [pts[int(i * step)] for i in range(300)]
    stats = {}
    for k in ("cpu", "mem", "disk"):
        vals = [p[k] for p in pts if p.get(k) is not None]
        if vals:
            stats[k] = {"avg": round(sum(vals) / len(vals), 1), "max": max(vals), "min": min(vals)}
    return {"points": pts, "stats": stats}


# ---------------------------------------------------------------- alerts
@app.get("/api/alerts")
def list_alerts(status: str = "active", limit: int = 200, user=Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(models.Alert)
    if status == "active":
        q = q.filter(models.Alert.status != "resolved")
    elif status != "all":
        q = q.filter(models.Alert.status == status)
    alerts = q.order_by(models.Alert.id.desc()).limit(limit).all()
    sm = secmon.get_settings(db)
    assets = {a.id: a for a in db.query(models.Asset).all()}
    sites = {s.id: s.name for s in db.query(models.Site).all()}
    out = []
    for a in alerts:
        d = to_dict(a)
        asset = assets.get(a.asset_id)
        d["asset_name"] = asset.name if asset else ""
        d["site_name"] = sites.get(a.site_id or (asset.site_id if asset else None), "")
        d.update(secmon.sla_info(a, sm))
        out.append(d)
    return out


@app.post("/api/alerts/{aid}/{action}")
def alert_action(aid: int, action: str, user=Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(models.Alert, aid)
    if not a:
        raise HTTPException(404)
    if a.source == "audit" and a.actor and a.actor == user.username and action in ("ack", "resolve"):
        raise HTTPException(403, "Không tự xử lý cảnh báo về thao tác của chính mình – người khác phải xem xét (tách nhiệm vụ)")
    if action == "ack":
        a.status, a.acked_by, a.acked_at = "acknowledged", user.username, now()
    elif action == "resolve":
        a.status, a.resolved_at = "resolved", now()
    else:
        raise HTTPException(400)
    audit(db, user.username, action, "alert", aid, a.title)
    db.commit()
    return to_dict(a)


# ---------------------------------------------------------------- tự động hoá
def _auto_dict(a: models.Automation) -> dict:
    from .automation.engine import describe_cron, effective_spec, next_run, to_local, local_now
    from .automation.templates import TEMPLATES
    d = to_dict(a)
    d.pop("state", None)
    spec = effective_spec(a)
    d["effective"] = spec
    t = TEMPLATES.get(a.code) or {}
    d["template_name"], d["group"] = t.get("name", a.code), t.get("group", "CUSTOM")
    trg = spec.get("trigger") or {}
    d["when"] = describe_cron(trg.get("cron", "")) if trg.get("type") == "schedule" else (
        f"mỗi {trg.get('minutes')} phút" if trg.get("type") == "interval" else
        "khi có cảnh báo" if trg.get("type") == "hook" else "khi: " + ", ".join(trg.get("on") or []))
    nr = None
    if trg.get("type") == "schedule" and a.enabled:
        try:
            n = next_run(trg.get("cron", ""), local_now())
            nr = n.isoformat() if n else None
        except ValueError:
            nr = None
    d["next_run"] = nr
    d["last_run_local"] = to_local(a.last_run_at).isoformat() if a.last_run_at else None
    return d


@app.get("/api/automation/catalog")
def automation_catalog(user=Depends(current_user)):
    from .automation.templates import public_catalog
    return public_catalog()


@app.get("/api/automations")
def automations_list(user=Depends(current_user), db: Session = Depends(get_db)):
    return [_auto_dict(a) for a in db.query(models.Automation).order_by(models.Automation.code, models.Automation.id)]


def _auto_body(body: dict, code: str) -> dict:
    from .automation.engine import validate_spec
    spec = body.get("spec")
    if body.get("yaml") is not None:
        import yaml
        try:
            spec = yaml.safe_load(body["yaml"]) or {}
        except yaml.YAMLError as e:
            raise HTTPException(400, f"YAML lỗi: {str(e).splitlines()[0]}") from None
        if isinstance(spec, dict):            # cho phép dán cả khối có id/name/enabled như mẫu trong tài liệu
            body = {**body, **{k: spec.pop(k) for k in ("name", "enabled") if k in spec}}
            spec.pop("id", None)
            spec.pop("kpi", None)
    try:
        spec = validate_spec(code, spec or {})
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"spec": spec, "name": body.get("name"), "enabled": body.get("enabled")}


@app.post("/api/automations")
def automations_create(body: dict, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .automation.templates import TEMPLATES
    code = body.get("code") or "CUSTOM"
    if code not in TEMPLATES:
        raise HTTPException(400, "Template không tồn tại")
    if code != "CUSTOM" and db.query(models.Automation).filter(models.Automation.code == code).first():
        raise HTTPException(400, f"{code} đã được thêm – sửa kịch bản có sẵn")
    v = _auto_body(body, code)
    a = models.Automation(code=code, name=(v["name"] or TEMPLATES[code]["name"])[:128], enabled=bool(v["enabled"]),
                          spec=v["spec"], created_by=user.username)
    db.add(a)
    audit(db, user.username, "create", "automation", None, f"{code} {a.name}")
    db.commit()
    return _auto_dict(a)


@app.put("/api/automations/{aid}")
def automations_update(aid: int, body: dict, user=Depends(admin_user), db: Session = Depends(get_db)):
    a = db.get(models.Automation, aid)
    if not a:
        raise HTTPException(404)
    was_on = a.enabled
    if "spec" in body or "yaml" in body:
        v = _auto_body(body, a.code)
        a.spec = v["spec"]
        if v["name"]:
            a.name = v["name"][:128]
        if v["enabled"] is not None:
            a.enabled = bool(v["enabled"])
    if "name" in body and body["name"]:
        a.name = str(body["name"])[:128]
    if "enabled" in body and "yaml" not in body:
        a.enabled = bool(body["enabled"])
    if was_on and not a.enabled:
        audit(db, user.username, "disable", "automation", aid, f"kịch bản {a.code} {a.name}")
    else:
        audit(db, user.username, "update", "automation", aid, f"{a.code} {a.name} · {'bật' if a.enabled else 'tắt'}")
    db.commit()
    return _auto_dict(a)


@app.delete("/api/automations/{aid}")
def automations_delete(aid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    a = db.get(models.Automation, aid)
    if not a:
        raise HTTPException(404)
    audit(db, user.username, "delete", "automation", aid, f"{a.code} {a.name}")
    db.delete(a)
    db.commit()
    return {"ok": True}


@app.get("/api/automations/{aid}/yaml")
def automations_yaml(aid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    import yaml
    from .automation.engine import effective_spec
    a = db.get(models.Automation, aid)
    if not a:
        raise HTTPException(404)
    doc = {"id": a.code, "name": a.name, "enabled": a.enabled, **effective_spec(a)}
    return {"yaml": yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=None, width=120)}


@app.post("/api/automations/{aid}/run")
async def automations_run(aid: int, dry: bool = True, user=Depends(admin_user)):
    """dry=true: Chạy thử – xem trước tin/báo cáo, không gửi. dry=false: chạy thật ngay."""
    from .automation.engine import run_automation
    try:
        return await run_automation(aid, "test" if dry else "manual", dry_run=dry)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None


@app.post("/api/automations/preview")
async def automations_preview(body: dict, user=Depends(admin_user), db: Session = Depends(get_db)):
    """Xem trước một kịch bản chưa lưu (form/YAML đang sửa)."""
    from .automation.engine import run_automation
    code = body.get("code") or "CUSTOM"
    v = _auto_body(body, code)
    tmp = models.Automation(code=code, name=v["name"] or "Xem trước", enabled=False, spec=v["spec"], created_by=user.username)
    db.add(tmp)
    db.commit()
    try:
        return await run_automation(tmp.id, "test", dry_run=True)
    finally:
        db.delete(db.get(models.Automation, tmp.id))
        db.commit()


@app.post("/api/automation/to-yaml")
def automation_to_yaml(body: dict, user=Depends(current_user)):
    """Form → YAML (kịch bản chưa lưu)."""
    import yaml
    from .automation.engine import validate_spec
    code = body.get("code") or "CUSTOM"
    try:
        spec = validate_spec(code, body.get("spec") or {})
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    doc = {"id": code, "name": body.get("name") or "", "enabled": bool(body.get("enabled")), **spec}
    return {"yaml": yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=None, width=120)}


@app.post("/api/automation/from-yaml")
def automation_from_yaml(body: dict, user=Depends(current_user)):
    """YAML → form: trả spec đã kiểm tra + name/enabled."""
    v = _auto_body({"yaml": body.get("yaml", "")}, body.get("code") or "CUSTOM")
    return v


@app.get("/api/automation/runs")
def automation_runs(automation_id: int | None = None, limit: int = 100, user=Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(models.AutomationRun)
    if automation_id:
        q = q.filter(models.AutomationRun.automation_id == automation_id)
    names = {a.id: (a.code, a.name) for a in db.query(models.Automation)}
    out = []
    for r in q.order_by(models.AutomationRun.id.desc()).limit(min(limit, 500)):
        d = to_dict(r)
        d["code"], d["name"] = names.get(r.automation_id, ("?", "?"))
        out.append(d)
    return out


# ---------------------------------------------------------------- views
def _res_summary(db):
    v = resources_view(db)
    return {"total": v["total"], "problems": v["problems"], "summary": v["summary"], "uncovered": len(v["uncovered"]),
            "top": [{k: r[k] for k in ("name", "asset_id", "check_id", "type", "cpu", "mem", "disk", "disk_name", "level", "levels", "site_name")}
                    for r in v["rows"][:6]]}


@app.get("/api/dashboard")
def dashboard(user=Depends(current_user), db: Session = Depends(get_db)):
    assets = db.query(models.Asset).all()
    checks = db.query(models.Check).filter(models.Check.enabled == True).all()  # noqa: E712
    alerts = db.query(models.Alert).filter(models.Alert.status != "resolved").order_by(models.Alert.id.desc()).all()
    crit = critical_view(db)
    by_type = {}
    for a in assets:
        by_type[a.type] = by_type.get(a.type, 0) + 1
    since = now() - timedelta(hours=24)
    recent = db.query(models.Alert).filter(models.Alert.opened_at >= since).count()
    return {
        "assets_total": len(assets), "by_type": by_type,
        "assets_down": sum(1 for a in assets if a.status == "down"),
        "vms": sum(1 for a in assets if a.type == "vm"), "vms_on": sum(1 for a in assets if a.type == "vm" and a.status == "up"),
        "checks_total": len(checks),
        "checks_status": {s: sum(1 for c in checks if c.status == s) for s in ("ok", "warn", "fail", "unknown")},
        "alerts_open": len(alerts), "alerts_critical": sum(1 for a in alerts if a.severity in ("critical", "down")), "alerts_24h": recent,
        "critical_total": len(crit), "critical_high": sum(1 for c in crit if c["level"] == "High"),
        "critical_no_backup": sum(1 for c in crit if not c["backup_ok"]),
        "critical_unmapped": sum(1 for c in crit if not c["asset_id"] and not c["hosted_externally"]),
        "critical_alerting": sum(1 for c in crit if c["alerts"] > 0),
        "critical_unmonitored": sum(1 for c in crit if not c["checks"]),
        "failing_checks": [serialize("checks", c) for c in checks if c.status in ("fail", "warn")][:20],
        "alerts": [to_dict(a) for a in alerts[:10]],
        "sources": [{"id": c.id, "name": c.name, "type": c.type, "status": c.status, "site_id": c.site_id} for c in checks],
        "sites": [{"id": s.id, "name": s.name, "kind": s.kind} for s in db.query(models.Site).order_by(models.Site.sort, models.Site.id)],
        "resources": _res_summary(db),
        "version": VERSION,
    }


@app.get("/api/topology")
def topology(user=Depends(current_user), db: Session = Depends(get_db)):
    return build_topology(db)


@app.get("/api/risks")
def risks(user=Depends(current_user), db: Session = Depends(get_db)):
    return build_risks(db)


@app.get("/api/search")
def search(q: str = Query(..., min_length=1), user=Depends(current_user), db: Session = Depends(get_db)):
    like = f"%{q}%"
    res = []
    for a in db.query(models.Asset).filter((models.Asset.name.ilike(like)) | (models.Asset.ip.ilike(like)) | (models.Asset.serial.ilike(like))).limit(15):
        res.append({"kind": "asset", "id": a.id, "title": a.name, "sub": f"{a.type} · {a.ip}", "status": a.status})
    for s in db.query(models.Site).filter(models.Site.name.ilike(like)).limit(5):
        res.append({"kind": "site", "id": s.id, "title": s.name, "sub": s.kind})
    for c in db.query(models.CriticalSystem).filter(models.CriticalSystem.name.ilike(like)).limit(5):
        res.append({"kind": "critical", "id": c.id, "title": c.name, "sub": f"Trọng yếu · {c.level}"})
    for c in db.query(models.Check).filter((models.Check.name.ilike(like)) | (models.Check.target.ilike(like))).limit(8):
        res.append({"kind": "check", "id": c.id, "title": c.name, "sub": f"{c.type} · {c.target}", "status": c.status})
    return res


@app.get("/api/audit")
def audit_log(limit: int = 300, user=Depends(current_user), db: Session = Depends(get_db)):
    return [to_dict(a) for a in db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(min(limit, 2000))]


# ---------------------------------------------------------------- settings
@app.get("/api/settings/notify")
def get_notify(user=Depends(admin_user), db: Session = Depends(get_db)):
    s = db.get(models.Setting, "notify")
    raw = (s.value if s else {}) or {}
    return {ch: mask_config(raw.get(ch, {})) for ch in CHANNELS}


@app.put("/api/settings/notify")
def put_notify(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    s = db.get(models.Setting, "notify") or models.Setting(key="notify", value={})
    old = s.value or {}
    s.value = {ch: seal_config(body.get(ch, {}), old.get(ch, {})) for ch in CHANNELS}
    db.merge(s)
    audit(db, user.username, "update", "settings", None, "Cấu hình kênh cảnh báo")
    db.commit()
    return {ch: mask_config(s.value.get(ch, {})) for ch in CHANNELS}


@app.post("/api/settings/notify/test/{channel}")
async def test_notify(channel: str, user=Depends(admin_user)):
    r = await notify("Tin nhắn thử từ IT Ops Workspace", f"Gửi bởi {user.username} lúc {datetime.now():%H:%M %d/%m/%Y}", "info", only=channel)
    return r


@app.get("/api/export")
def export(user=Depends(admin_user), db: Session = Depends(get_db)):
    """Xuất cấu hình (không gồm lịch sử). Mật khẩu trong check được giữ ở dạng mã hoá."""
    data = {"version": VERSION, "exported_at": now().isoformat()}
    for kind, M in [("sites", models.Site), ("assets", models.Asset), ("critical", models.CriticalSystem), ("checks", models.Check)]:
        data[kind] = [to_dict(o) for o in db.query(M).order_by(M.id)]
    return JSONResponse(data, headers={"Content-Disposition": f"attachment; filename=itops-export-{now():%Y%m%d}.json"})


@app.post("/api/import")
def import_data(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    """Nhập lại file export (ghi đè theo id)."""
    count = 0
    for kind, M in [("sites", models.Site), ("assets", models.Asset), ("critical", models.CriticalSystem), ("checks", models.Check)]:
        for row in body.get(kind, []):
            obj = db.get(M, row.get("id")) or M(id=row.get("id"))
            for k, v in row.items():
                if k in ("created_at", "updated_at", "last_checked", "last_seen"):
                    continue
                if hasattr(obj, k):
                    setattr(obj, k, v)
            db.merge(obj)
            count += 1
        db.flush()
    audit(db, user.username, "import", "data", None, f"Nhập {count} bản ghi")
    db.commit()
    return {"imported": count}


@app.post("/api/reset-data")
def reset_data(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    """Xoá toàn bộ site/tài sản/check/cảnh báo (vd. xoá dữ liệu mẫu). Cần gửi confirm='XOA'."""
    if secmon.PRODUCTION:   # C10: khoá khi chạy thật (ITOPS_ENV=production); vẫn ghi audit lần thử
        audit(db, user.username, "reset_blocked", "data", None, "Thử xoá toàn bộ dữ liệu khi ITOPS_ENV=production")
        db.commit()
        raise HTTPException(403, "Chức năng xoá dữ liệu bị khoá khi chạy thật (ITOPS_ENV=production)")
    if body.get("confirm") != "XOA":
        raise HTTPException(400, "Cần xác nhận")
    for M in (models.CheckResult, models.DailyUptime, models.Alert, models.CriticalSystem, models.Check, models.Event):
        db.query(M).delete()
    db.query(models.Asset).update({models.Asset.parent_id: None})
    db.query(models.Asset).delete()
    db.query(models.Site).delete()
    audit(db, user.username, "delete", "data", None, "Xoá toàn bộ dữ liệu hạ tầng")
    db.commit()
    return {"ok": True}


@app.get("/api/health")
def health():
    """Công khai (trang đăng nhập dùng). Chỉ trả status chung, không lộ dữ liệu."""
    from sqlalchemy import text
    db_ok = True
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    disabled = os.environ.get("DISABLE_SCHEDULER", "").lower() in ("1", "true")
    tick = scheduler.LAST_TICK
    sched = "off" if disabled else "ok" if tick and time.time() - tick < 30 else "starting" if tick is None else "stalled"
    L = receivers.STATS.get("listeners") or {}
    rx_ok = None if not L else all(v.get("ok") for v in L.values())
    return {"ok": db_ok and sched in ("ok", "off", "starting"), "db": db_ok, "scheduler": sched, "receivers_ok": rx_ok,
            "production": secmon.PRODUCTION,
            "version": VERSION, "app_name": os.environ.get("APP_NAME", "IT Ops Workspace")}


# ---------------------------------------------------------------- giám sát an ninh (SLA, audit, archive + hash)
@app.get("/api/secmon")
def secmon_get(user=Depends(admin_user), db: Session = Depends(get_db)):
    v = secmon.get_settings(db)
    v["production"] = secmon.PRODUCTION
    v["archive_path"] = str(secmon.archive_dir(v))
    return v


@app.put("/api/secmon")
def secmon_put(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    body = {k: v for k, v in body.items() if k in secmon.DEFAULTS}
    try:
        v = secmon.save_settings(db, body)
    except (ValueError, TypeError) as e:
        raise HTTPException(400, f"Giá trị không hợp lệ: {e}") from None
    audit(db, user.username, "update", "secmon", None, "Cấu hình Giám sát an ninh")
    db.commit()
    return v


@app.get("/api/secmon/archive")
def secmon_archive(user=Depends(admin_user)):
    cfg = secmon.get_settings()
    rows = secmon.verify_chain(cfg)
    return {"path": str(secmon.archive_dir(cfg)), "days": rows[::-1],
            "ok": all(r["chain_ok"] and (r["file_ok"] or not r["exists"]) for r in rows)}


@app.post("/api/secmon/archive/run")
async def secmon_archive_run(day: str = "", user=Depends(admin_user)):
    from datetime import date as _date
    try:
        d = _date.fromisoformat(day) if day else None
    except ValueError:
        raise HTTPException(400, "Ngày dạng YYYY-MM-DD") from None
    made = await secmon.run_archive(d)
    return {"made": made}


@app.get("/api/receivers/sources")
def receiver_sources(user=Depends(current_user), db: Session = Depends(get_db)):
    """D: nguồn nào đang gửi log/trap tới IT Ops (kể cả bị chặn) – kiểm tra log của thiết bị có tới không."""
    by_ip = {a.ip: a.name for a in db.query(models.Asset).filter(models.Asset.ip != "").all() if a.ip}
    out = []
    for ip, r in ev_mod.STATS["sources"].items():
        out.append({"ip": ip, "asset": by_ip.get(ip, ""), "count": r["count"], "kind": r["kind"], "blocked": r["blocked"],
                    "first": int(r["first"]), "last": int(r["last"]), "ago_s": int(time.time() - r["last"])})
    out.sort(key=lambda x: -x["last"])
    return {"sources": out, "allowed": _receiver_cfg()["allowed_sources"], "listeners": ev_mod.STATS.get("listeners", {})}


# ---------------------------------------------------------------- syslog / SNMP trap
SEV_ORDER = list(range(8))


@app.get("/api/events")
def list_events(q: str = "", kind: str = "", max_severity: int = 7, asset_id: int | None = None, site_id: int | None = None,
                source_ip: str = "", unknown: bool = False, hours: int = 24 * 7, before_id: int | None = None, limit: int = 200,
                user=Depends(current_user), db: Session = Depends(get_db)):
    qry = db.query(models.Event).filter(models.Event.ts >= now() - timedelta(hours=min(hours, 24 * 400)))
    if q:
        like = f"%{q}%"
        qry = qry.filter((models.Event.message.ilike(like)) | (models.Event.app.ilike(like)) | (models.Event.host.ilike(like)) | (models.Event.source_ip.ilike(like)))
    if kind:
        qry = qry.filter(models.Event.kind == kind)
    if max_severity < 7:
        qry = qry.filter(models.Event.severity <= max_severity)
    if asset_id:
        qry = qry.filter(models.Event.asset_id == asset_id)
    if site_id:
        qry = qry.filter(models.Event.site_id == site_id)
    if source_ip:
        qry = qry.filter(models.Event.source_ip == source_ip)
    if unknown:
        qry = qry.filter(models.Event.asset_id.is_(None))
    if before_id:
        qry = qry.filter(models.Event.id < before_id)
    rows = qry.order_by(models.Event.id.desc()).limit(min(limit, 1000)).all()
    names = dict(db.query(models.Asset.id, models.Asset.name).all())
    out = []
    for e in rows:
        d = to_dict(e)
        d["asset_name"] = names.get(e.asset_id, "")
        out.append(d)
    return out


@app.get("/api/events/stats")
def events_stats(hours: int = 24, user=Depends(current_user), db: Session = Depends(get_db)):
    hours = max(1, min(hours, 24 * 30))
    since = now() - timedelta(hours=hours)
    bucket_min = 5 if hours <= 6 else 15 if hours <= 24 else 60
    rows = db.query(models.Event.ts, models.Event.severity).filter(models.Event.ts >= since).all()
    buckets = {}
    for ts, sev in rows:
        k = ts.replace(second=0, microsecond=0, minute=(ts.minute // bucket_min) * bucket_min) if bucket_min < 60 else ts.replace(minute=0, second=0, microsecond=0)
        b = buckets.setdefault(k, [0, 0, 0])
        b[0 if sev <= 3 else 1 if sev == 4 else 2] += 1
    series = [{"ts": k.isoformat() + "Z", "error": v[0], "warning": v[1], "info": v[2]} for k, v in sorted(buckets.items())]
    top = db.query(models.Event.asset_id, models.Event.source_ip, func.count()).filter(models.Event.ts >= since) \
        .group_by(models.Event.asset_id, models.Event.source_ip).order_by(func.count().desc()).limit(10).all()
    names = dict(db.query(models.Asset.id, models.Asset.name).all())
    unknown = db.query(models.Event.source_ip, func.count(), func.max(models.Event.ts), func.max(models.Event.host)) \
        .filter(models.Event.ts >= since, models.Event.asset_id.is_(None)).group_by(models.Event.source_ip).order_by(func.count().desc()).limit(50).all()
    from .events import STATS
    return {
        "bucket_min": bucket_min, "series": series, "total": len(rows),
        "errors": sum(1 for _, s in rows if s <= 3), "warnings": sum(1 for _, s in rows if s == 4),
        "top_sources": [{"asset_id": a, "name": names.get(a) or ip, "source_ip": ip, "count": n} for a, ip, n in top],
        "unknown_sources": [{"source_ip": ip, "count": n, "last": t.isoformat() + "Z", "host": h or ""} for ip, n, t, h in unknown],
        "receiver": {"listeners": STATS["listeners"], "received": STATS["received"], "stored": STATS["stored"],
                     "dropped_rate": STATS["dropped_rate"], "dropped_rule": STATS["dropped_rule"], "dropped_queue": STATS["dropped_queue"],
                     "dropped_acl": STATS["dropped_acl"], "blocked": sorted(STATS["blocked"].items(), key=lambda x: -x[1])[:10],
                     "last": {k: int(v) for k, v in STATS["last"].items()}, "rate_limit": ev_mod.RATE_PER_SOURCE, "retention_days": ev_mod.RETENTION_DAYS},
        "server_ip_hint": os.environ.get("PUBLIC_HOST", ""),
    }


@app.post("/api/events/send-test")
async def events_send_test(body: dict = Body(...), user=Depends(admin_user)):
    """Tự gửi 1 syslog/trap mẫu vào chính bộ nhận để kiểm tra đường ống."""
    import socket as _s
    kind = body.get("kind", "syslog")
    if kind == "syslog":
        msg = f"<12>{datetime.now():%b %d %H:%M:%S} itops-selftest test: Tin thử syslog từ {user.username}".encode()
        sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sock.sendto(msg, ("127.0.0.1", receivers.SYSLOG_UDP_PORT))
        sock.close()
    else:
        from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget, ContextData, NotificationType,
                                                 ObjectIdentity, ObjectType, OctetString, send_notification)
        cfg = _receiver_cfg()
        eng = SnmpEngine()
        await send_notification(eng, CommunityData((cfg["communities"] or ["public"])[0], mpModel=1),
                                await UdpTransportTarget.create(("127.0.0.1", receivers.TRAP_PORT)), ContextData(), "trap",
                                NotificationType(ObjectIdentity("1.3.6.1.4.1.8072.9999.1")).add_varbinds(
                                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"), OctetString("itops-selftest"))))
        eng.close_dispatcher()
    await asyncio.sleep(1.2)
    db = SessionLocal()
    try:
        e = db.query(models.Event).filter(models.Event.ts >= now() - timedelta(seconds=10), models.Event.kind == kind).order_by(models.Event.id.desc()).first()
    finally:
        db.close()
    return {"ok": bool(e), "event": to_dict(e) if e else None}


@app.get("/api/event-rules")
def list_rules(user=Depends(current_user), db: Session = Depends(get_db)):
    names = dict(db.query(models.Asset.id, models.Asset.name).all())
    out = []
    for r in db.query(models.EventRule).order_by(models.EventRule.sort, models.EventRule.id):
        d = to_dict(r)
        d["asset_name"] = names.get(r.asset_id, "")
        d["open_alerts"] = db.query(models.Alert).filter(models.Alert.event_rule_id == r.id, models.Alert.status != "resolved").count()
        out.append(d)
    return out


@app.post("/api/event-rules/test")
def test_rule(body: dict = Body(...), user=Depends(current_user), db: Session = Depends(get_db)):
    """Thử rule: với 1 dòng log mẫu và/hoặc với log 24h gần nhất."""
    _validate_rule(body)
    r = models.EventRule(**{k: body.get(k) for k in EDITABLE["event-rules"] if k in body})
    for k, v in {"kind": "any", "max_severity": 7, "threshold": 1, "window_min": 5, "auto_resolve_min": 0, "action": "alert"}.items():
        if getattr(r, k) is None:
            setattr(r, k, v)
    cr = ev_mod.CompiledRule(r)
    res = {}
    if body.get("sample"):
        from .syslog_parser import parse as _parse
        p = _parse(body["sample"])
        e = {"kind": "syslog", "severity": p["severity"], "app": p["app"], "message": p["message"], "asset_id": r.asset_id, "site_id": r.site_id, "data": {}}
        ok, key = cr.match(e)
        rok, rkey = cr.resolves(e)
        res["sample"] = {"parsed": p, "match": ok, "key": key, "resolves": rok}
    rows = db.query(models.Event).filter(models.Event.ts >= now() - timedelta(hours=24)).order_by(models.Event.id.desc()).limit(5000).all()
    hits = []
    for e in rows:
        d = {"kind": e.kind, "severity": e.severity, "app": e.app, "message": e.message, "asset_id": e.asset_id, "site_id": e.site_id, "data": e.data or {}}
        if cr.match(d)[0]:
            hits.append(to_dict(e))
    res["history"] = {"scanned": len(rows), "matches": len(hits), "examples": hits[:5]}
    return res


@app.get("/api/settings/receivers")
def get_receivers(user=Depends(admin_user)):
    v = _receiver_cfg(raw=True)
    return {"communities": [MASK if c else "" for c in v["communities"]], "communities_count": len(v["communities"]),
            "v3_users": [mask_config(u) for u in v["v3_users"]], "allowed_sources": v["allowed_sources"],
            "ports": {"syslog_udp": receivers.SYSLOG_UDP_PORT, "syslog_tcp": receivers.SYSLOG_TCP_PORT, "snmp_trap": receivers.TRAP_PORT}}


@app.put("/api/settings/receivers")
async def put_receivers(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    old = _receiver_cfg(raw=True)
    comms = []
    for i, c in enumerate(body.get("communities", [])):
        if c == MASK and i < len(old["communities"]):
            comms.append(old["communities"][i])
        elif c and c != MASK:
            comms.append(seal_config({"community": c})["community"])
    users = []
    olds = {u.get("username"): u for u in old["v3_users"]}
    for u in body.get("v3_users", []):
        if u.get("username"):
            users.append(seal_config(u, olds.get(u["username"], {})))
    import ipaddress
    allowed_src = []
    for c in body.get("allowed_sources", old["allowed_sources"]) or []:
        c = str(c).strip()
        if not c:
            continue
        try:
            allowed_src.append(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            raise HTTPException(400, f"IP/subnet không hợp lệ: {c}") from None
    st = db.get(models.Setting, "receivers") or models.Setting(key="receivers", value={})
    st.value = {"communities": comms or [seal_config({"community": "public"})["community"]], "v3_users": users, "allowed_sources": allowed_src}
    db.merge(st)
    audit(db, user.username, "update", "settings", None, "Cấu hình nhận SNMP trap")
    db.commit()
    ev_mod.set_allowed(allowed_src)
    # chạy trên event loop chính (async endpoint) – pysnmp cần loop để mở lại socket
    if receivers._state["trap"] is not None or receivers.STATS["listeners"].get("snmp_trap"):
        receivers.restart_trap(_receiver_cfg())
        await asyncio.sleep(0.2)
    if not receivers.STATS["listeners"].get("snmp_trap", {}).get("ok", True):
        raise HTTPException(500, "Lưu được nhưng không khởi động lại bộ nhận trap: " + receivers.STATS["listeners"]["snmp_trap"].get("error", ""))
    return get_receivers(user)


# generic CRUD đăng ký sau cùng để không đè lên các route cụ thể
app.add_api_route("/api/{kind}/{oid}", get_one, methods=["GET"])
app.add_api_route("/api/{kind}", create, methods=["POST"])
app.add_api_route("/api/{kind}/{oid}", update, methods=["PUT"])
app.add_api_route("/api/{kind}/{oid}", delete, methods=["DELETE"])


# ---------------------------------------------------------------- frontend
STATIC = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(__file__), "..", "static"))
if os.path.isdir(STATIC):
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC, "assets")), name="assets")

    STATIC_REAL = os.path.realpath(STATIC)

    @app.get("/{path:path}")
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        f = os.path.realpath(os.path.join(STATIC_REAL, path))
        # chặn path traversal: file phải nằm trong thư mục static
        if path and f.startswith(STATIC_REAL + os.sep) and os.path.isfile(f):
            return FileResponse(f)
        return FileResponse(os.path.join(STATIC_REAL, "index.html"))
