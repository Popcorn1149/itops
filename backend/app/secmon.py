"""Security monitoring (ISO 27001 / SOC 2):
- SLA acknowledgment by alert severity (24/7 for Critical, business hours for Trouble/Attention) – B5
- Detect behavior within IT Ops itself from audit logs; send to dedicated recipients – B6 / UC-14
- Silent log sources above type-specific thresholds – UC-13 / C13
- Archive logs daily (.jsonl.gz) with a SHA-256 hash chain; send the hash externally – B7 / B8
- Disable dangerous functions when ITOPS_ENV=production – C10"""
import asyncio
import copy
import gzip
import hashlib
import json
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import func

from . import models
from .db import SessionLocal
from .models import now

log = logging.getLogger("secmon")

PRODUCTION = os.environ.get("ITOPS_ENV", "").strip().lower() in ("production", "prod")

DEFAULTS = {
    "business": {"days": [0, 1, 2, 3, 4, 5], "start": "07:30", "end": "18:30"},      # T2–T7, hours địa phương (APP_TZ_OFFSET)
    "sla": {
        "critical": {"mode": "24x7", "ack_min": 15, "ack_min_off": 30},
        "trouble": {"mode": "business", "ack_min": 60},
        "attention": {"mode": "business", "ack_min": 540},
        "notify": True,
    },
    "audit_alert": {"enabled": True, "targets": [{"type": "default"}], "login_fail_threshold": 5, "window_min": 5},
    "silence": {"enabled": True, "firewall": 30, "server": 30, "switch": 1440, "other": 1440},
    "archive": {"enabled": True, "dir": os.environ.get("ARCHIVE_DIR", "archive"), "db_days": 90, "keep_days": 365,
                "hash_targets": [], "run_at": "00:30"},
}
SILENCE_GROUP = {"firewall": "firewall", "router": "firewall", "server": "server", "vm": "server", "host": "server",
                 "switch": "switch", "ap": "switch"}
SEV_SLA = {"down": "critical", "critical": "critical", "trouble": "trouble", "warning": "trouble", "attention": "attention"}

_pending: deque = deque(maxlen=500)          # thông báo audit chờ gửi (audit() chạy đồng bộ trong request)
_login_fails: dict[str, deque] = defaultdict(deque)
_state = {"silence_t": 0.0, "archive_day": None}


# ---------------------------------------------------------------- cài đặt
def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def get_settings(db=None) -> dict:
    own = db is None
    db = db or SessionLocal()
    try:
        s = db.get(models.Setting, "secmon")
        return _merge(DEFAULTS, (s.value if s else {}) or {})
    finally:
        if own:
            db.close()


def save_settings(db, value: dict) -> dict:
    v = _merge(DEFAULTS, value or {})
    for k in ("firewall", "server", "switch", "other"):
        v["silence"][k] = max(5, int(v["silence"].get(k) or 0))
    v["archive"]["db_days"] = max(7, int(v["archive"]["db_days"]))
    v["archive"]["keep_days"] = max(v["archive"]["db_days"], int(v["archive"]["keep_days"]))
    st = db.get(models.Setting, "secmon")
    if st:
        st.value = v
    else:
        db.add(models.Setting(key="secmon", value=v))
    apply_runtime(v)
    return v


def apply_runtime(v: dict | None = None):
    from . import events as ev_mod
    v = v or get_settings()
    ev_mod.RETENTION_DAYS = int(v["archive"]["db_days"])


# ---------------------------------------------------------------- business hours + SLA
def _tz():
    from .automation.engine import TZ
    return TZ


def _hm(s: str) -> tuple[int, int]:
    h, m = (s or "0:0").split(":")
    return int(h), int(m)


def in_business(dt_local: datetime, biz: dict) -> bool:
    if dt_local.weekday() not in biz["days"]:
        return False
    s, e = _hm(biz["start"]), _hm(biz["end"])
    return s <= (dt_local.hour, dt_local.minute) < e


def add_business_minutes(start_local: datetime, minutes: int, biz: dict) -> datetime:
    """Cộng minutes chỉ tính trong business hours."""
    t, left = start_local, float(minutes)
    for _ in range(400):
        sh, sm = _hm(biz["start"])
        eh, em = _hm(biz["end"])
        day_s = t.replace(hour=sh, minute=sm, second=0, microsecond=0)
        day_e = t.replace(hour=eh, minute=em, second=0, microsecond=0)
        if t.weekday() in biz["days"] and t < day_e:
            cur = max(t, day_s)
            avail = (day_e - cur).total_seconds() / 60
            if left <= avail:
                return cur + timedelta(minutes=left)
            left -= avail
        t = (t + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return t


def sla_due(alert, cfg: dict) -> datetime | None:
    """Hạn ack (UTC naive) of alerts; None nếu mức này không có SLA."""
    lvl = SEV_SLA.get(alert.severity or "")
    rule = cfg["sla"].get(lvl) if lvl else None
    if not rule or not alert.opened_at:
        return None
    opened = alert.opened_at
    from .automation.engine import to_local, to_utc_naive
    ol = to_local(opened)
    if rule.get("mode") == "24x7":
        mins = rule["ack_min"] if in_business(ol, cfg["business"]) else rule.get("ack_min_off", rule["ack_min"])
        return opened + timedelta(minutes=int(mins))
    return to_utc_naive(add_business_minutes(ol, int(rule["ack_min"]), cfg["business"]))


def sla_info(alert, cfg: dict) -> dict:
    due = sla_due(alert, cfg)
    if not due:
        return {}
    done = alert.acked_at or (alert.resolved_at if alert.status == "resolved" else None)
    ref = done or now()
    return {"sla_due": due.isoformat() + "Z", "sla_overdue": ref > due, "sla_met": bool(done and done <= due)}


def check_sla(db, cfg: dict) -> list:
    notes = []
    for a in db.query(models.Alert).filter(models.Alert.status == "open", models.Alert.sla_breached == False):  # noqa: E712
        due = sla_due(a, cfg)
        if due and now() > due:
            a.sla_breached = True
            if cfg["sla"].get("notify", True):
                notes.append((f"SLA acknowledgement overdue: {a.title}", f"Opened at {a.opened_at:%H:%M %d/%m} UTC · acknowledgement deadline {due:%H:%M} UTC",
                              "critical" if SEV_SLA.get(a.severity) == "critical" else "warning", None))
    return notes


# ---------------------------------------------------------------- UC-14: alerts from audit log
def classify_audit(user: str, action: str, entity: str, detail: str, cfg: dict):
    """Trả (mức, title, khoá gộp) hoặc None nếu without requiring alerts."""
    if action == "login_failed":
        ip = detail.rsplit(" ", 1)[-1] if detail else "?"
        w = _login_fails[ip]
        t = time.time()
        w.append(t)
        while w and t - w[0] > cfg["audit_alert"]["window_min"] * 60:
            w.popleft()
        if len(w) >= cfg["audit_alert"]["login_fail_threshold"]:
            return "trouble", f"IT Ops: repeated failed sign-ins from {ip}", f"login:{ip}"
        return None
    if action in ("reset", "reset_blocked") or (entity == "data" and action == "delete"):
        return "critical", f"IT Ops: {user} deleted all data" if action != "reset_blocked" else f"IT Ops: {user} attempted to delete data in production", f"reset:{user}"
    if entity == "user" and action == "create":
        sev = "critical" if "role=admin" in detail else "trouble"
        return sev, f"IT Ops: {user} created account {detail.split(' ')[0]}", f"user-create:{detail}"
    if entity == "user" and action == "update" and "role=" in detail:
        return "critical" if "role=admin" in detail else "trouble", f"IT Ops: {user} changed role {detail}", f"user-role:{detail}"
    if entity == "user" and action == "delete":
        return "trouble", f"IT Ops: {user} deleted account {detail}", f"user-del:{detail}"
    if entity == "secmon" and action == "update":
        return "critical", f"IT Ops: {user} changed Security Monitoring settings", f"secmon:{user}"
    if entity == "settings" and action == "update":
        return "trouble", f"IT Ops: {user} – {detail}", f"settings:{detail}"
    if action in ("delete", "disable") and entity in ("checks", "event-rules", "automation"):
        verb = "delete" if action == "delete" else "disabled"
        return "trouble", f"IT Ops: {user} {verb} {detail}", f"{entity}:{action}:{detail}"
    if action == "import":
        return "trouble", f"IT Ops: {user} imported data ({detail})", f"import:{user}"
    return None


def on_audit(db, user: str, action: str, entity: str, entity_id, detail: str):
    try:
        cfg = get_settings(db)
        if not cfg["audit_alert"].get("enabled", True):
            return
        r = classify_audit(user, action, entity, detail or "", cfg)
        if not r:
            return
        sev, title, key = r
        dkey = f"audit:{key}"[:255]
        ex = db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved").first()
        if ex:
            ex.count = (ex.count or 1) + 1
            ex.last_seen = now()
            return
        a = models.Alert(source="audit", dedupe_key=dkey, severity=sev, title=title[:255], actor=user[:64],
                         message=f"Performed by: {user} · {action} {entity} {detail}"[:2000], last_seen=now(), count=1)
        db.add(a)
        _pending.append((title, a.message, sev, cfg["audit_alert"].get("targets") or [{"type": "default"}]))
    except Exception:
        log.exception("Audit alert failed")


async def flush_pending():
    from .automation.engine import send_to
    while _pending:
        title, text, sev, targets = _pending.popleft()
        try:
            await send_to(targets, title, text + "\n(Alert about an administrator action – the actor cannot close this alert)", sev)
        except Exception:
            log.exception("Failed to send audit alerts")


# ---------------------------------------------------------------- UC-13: log source im lặng
def check_silence(db, cfg: dict) -> list:
    sc = cfg["silence"]
    if not sc.get("enabled", True):
        return []
    since = now() - timedelta(days=8)
    last = dict(db.query(models.Event.asset_id, func.max(models.Event.ts))
                .filter(models.Event.ts > since, models.Event.asset_id.isnot(None), models.Event.kind != "winlog")
                .group_by(models.Event.asset_id).all())
    notes = []
    open_keys = {a.dedupe_key: a for a in db.query(models.Alert).filter(models.Alert.source == "silence", models.Alert.status != "resolved")}
    for aid, ts in last.items():
        asset = db.get(models.Asset, aid)
        if not asset:
            continue
        grp = SILENCE_GROUP.get(asset.type, "other")
        limit = int(sc.get(grp, sc["other"]))
        key = f"silence:{aid}"
        quiet = (now() - ts).total_seconds() / 60
        if quiet <= limit:
            a = open_keys.get(key)
            if a:
                a.status, a.resolved_at = "resolved", now()
                a.message = f"{a.message} · log reception has resumed"[:2000]
                notes.append((f"{a.title} – log reception has resumed", "", "resolved", {"kind": "resolve", "alert_id": a.id, "asset_id": aid}))
            continue
        checks = db.query(models.Check).filter(models.Check.asset_id == aid, models.Check.enabled == True).all()  # noqa: E712
        if grp == "switch":
            snmp = [c for c in checks if c.type == "snmp"]
            if snmp and not any(c.status in ("ok", "warn") for c in snmp):
                continue          # SNMP cũng không trả lời → devices DOWN, monitoring check already báo
        elif checks and all(c.severity == "down" or c.status == "fail" and c.severity in (None, "down") for c in checks):
            continue              # devices không truy cập được → không phải im lặng log
        if key in open_keys:
            continue
        h = int(quiet // 60)
        txt = f"No logs received for {h} hours and {int(quiet % 60)} minutes (threshold: {limit} minutes for group {grp}) while the device is still active."
        a = models.Alert(source="silence", dedupe_key=key, asset_id=aid, site_id=asset.site_id, severity="trouble",
                         title=f"Silent log source: {asset.name}"[:255], message=txt, last_seen=now(), count=1)
        db.add(a)
        db.flush()
        notes.append((a.title, txt, "trouble", {"kind": "open", "alert_id": a.id, "asset_id": aid, "site_id": asset.site_id}))
    return notes


# ---------------------------------------------------------------- B7/B8: archive + chuỗi hash
def archive_dir(cfg: dict) -> Path:
    """Đường dẫn tương đối tính from thư items dữ liệu (DATA_DIR). Use đường dẫn tuyệt đối / disk mạng (\\\\NAS\\itops) để lưu ra NAS."""
    from .db import DATA_DIR
    p = Path(cfg["archive"]["dir"])
    return p if p.is_absolute() or str(p).startswith("\\\\") else Path(DATA_DIR) / p


def _row(t: str, obj) -> dict:
    d = {c.key: getattr(obj, c.key) for c in obj.__mapper__.column_attrs}
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat() + "Z"
    d["_t"] = t
    return d


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _chain_file(base: Path) -> Path:
    return base / "hash-chain.csv"


def read_chain(base: Path) -> list[dict]:
    f = _chain_file(base)
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines()[1:]:
        p = line.split(",")
        if len(p) >= 5:
            out.append({"day": p[0], "file": p[1], "rows": int(p[2]), "sha256": p[3], "chain": p[4]})
    return out


def archive_day(db, cfg: dict, day) -> dict | None:
    """Xuất log + audit of một days (hours địa phương) ra file nén, nối ando chuỗi hash. Không ghi đè file already có."""
    from .automation.engine import to_utc_naive
    base = archive_dir(cfg)
    base.mkdir(parents=True, exist_ok=True)
    chain = read_chain(base)
    if any(c["day"] == day.isoformat() for c in chain):
        return None
    start = to_utc_naive(datetime(day.year, day.month, day.day, tzinfo=_tz()))
    end = start + timedelta(days=1)
    rel = f"{day:%Y}/{day:%m}/itops-{day.isoformat()}.jsonl.gz"
    fp = base / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    with gzip.open(fp, "wt", encoding="utf-8") as f:
        for M, t in ((models.Event, "event"), (models.AuditLog, "audit"), (models.Alert, "alert")):
            col = M.opened_at if M is models.Alert else M.ts
            q = db.query(M).filter(col >= start, col < end).order_by(M.id).yield_per(2000)
            for o in q:
                f.write(json.dumps(_row(t, o), ensure_ascii=False, default=str) + "\n")
                rows += 1
    digest = sha256_file(fp)
    prev = chain[-1]["chain"] if chain else "0" * 64
    link = hashlib.sha256(f"{prev}|{day.isoformat()}|{digest}".encode()).hexdigest()
    cf = _chain_file(base)
    new = not cf.exists()
    with open(cf, "a", encoding="utf-8") as f:
        if new:
            f.write("day,file,rows,sha256,chain\n")
        f.write(f"{day.isoformat()},{rel},{rows},{digest},{link}\n")
    return {"day": day.isoformat(), "file": rel, "rows": rows, "sha256": digest, "chain": link}


def verify_chain(cfg: dict) -> list[dict]:
    base = archive_dir(cfg)
    prev = "0" * 64
    out = []
    for c in read_chain(base):
        fp = base / c["file"]
        ok_file = fp.exists() and sha256_file(fp) == c["sha256"]
        link = hashlib.sha256(f"{prev}|{c['day']}|{c['sha256']}".encode()).hexdigest()
        out.append({**c, "file_ok": ok_file, "chain_ok": link == c["chain"], "exists": fp.exists(),
                    "size": fp.stat().st_size if fp.exists() else 0})
        prev = c["chain"]
    return out


def prune_archive(cfg: dict):
    base = archive_dir(cfg)
    if not base.exists():
        return
    cut = (datetime.now(_tz()).date() - timedelta(days=int(cfg["archive"]["keep_days"]))).isoformat()
    for p in base.glob("*/*/itops-*.jsonl.gz"):
        d = p.name[6:16]
        if d < cut:
            p.unlink(missing_ok=True)   # dòng trong hash-chain.csv giữ lại làm bằng chứng already fromng tồn tại


async def run_archive(force_day=None) -> list:
    cfg = get_settings()
    if not cfg["archive"].get("enabled", True) and not force_day:
        return []
    today = datetime.now(_tz()).date()
    days = [force_day] if force_day else [today - timedelta(days=i) for i in range(7, 0, -1)]   # bù tối đa 7 days bị lỡ

    def work():
        db = SessionLocal()
        try:
            res = []
            for d in days:
                r = archive_day(db, cfg, d)
                if r:
                    res.append(r)
            prune_archive(cfg)
            return res
        finally:
            db.close()
    made = await asyncio.to_thread(work)
    if made and cfg["archive"].get("hash_targets"):
        from .automation.engine import send_to
        text = "\n".join(f"{m['day']}: {m['rows']} records\nSHA-256 {m['sha256']}\nChain {m['chain']}" for m in made)
        await send_to(cfg["archive"]["hash_targets"], f"IT Ops – log hash for {made[-1]['day']}", text, "info")
    return made


# ---------------------------------------------------------------- vòng chạy
async def loop():
    from .automation.engine import dispatch
    apply_runtime()
    while True:
        try:
            await flush_pending()
            cfg = get_settings()

            def work():
                db = SessionLocal()
                try:
                    notes = check_sla(db, cfg)
                    if time.time() - _state["silence_t"] > 300:
                        _state["silence_t"] = time.time()
                        notes += check_silence(db, cfg)
                    db.commit()
                    return notes
                finally:
                    db.close()
            notes = await asyncio.to_thread(work)
            if notes:
                await dispatch(notes)
            lt = datetime.now(_tz())
            if lt.strftime("%H:%M") >= cfg["archive"]["run_at"] and _state["archive_day"] != lt.date():
                _state["archive_day"] = lt.date()
                await run_archive()
        except Exception:
            log.exception("Security Monitor failed")
        await asyncio.sleep(20)
