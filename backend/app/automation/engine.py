"""Automation engine.

- A workflow is an `Automation` record with a declarative `spec`:
    trigger: {type: schedule, cron: "30 7 * * *"} | {type: interval, minutes: 5} | {type: event, on: [alert_opened, ...]} | {type: hook}
    scope:   {sites: all | [id], asset_types: [...], severities: [...], name_contains: "..."}
    params:  template-specific parameters
    actions: [{type: default} | {type: telegram, chat: "-100..."} | {type: email, to: "a@b.vn"} | {type: webhook, url: "..."}]
    level:   L0 notify · L1 notify with suggestion · L2 approval required · L3 execute (reversible actions only)
- Cron times use Vietnam time (UTC+7, adjusted by APP_TZ_OFFSET).
- No workflow may delete data or disable devices."""
import asyncio
import copy
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .. import models
from ..db import SessionLocal
from ..models import now

log = logging.getLogger("automation")
TZ = timezone(timedelta(hours=float(os.environ.get("APP_TZ_OFFSET", "7"))))
EVENTS = ("alert_opened", "alert_resolved", "alert_escalated")
LAST_TICK: float | None = None


# ---------------------------------------------------------------- thời gian
def local_now() -> datetime:
    return datetime.now(TZ).replace(second=0, microsecond=0)


def to_local(dt: datetime | None) -> datetime | None:
    """DB lưu UTC không múi hours → hours VN."""
    return dt.replace(tzinfo=timezone.utc).astimezone(TZ) if dt else None


def to_utc_naive(dt_local: datetime) -> datetime:
    return dt_local.astimezone(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- five-field cron expressions (minute hour day month weekday)
_CRON_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
_CRON_NAMES = ["minute", "hour", "day", "month", "weekday"]


def _cron_field(expr: str, lo: int, hi: int, name: str) -> set[int]:
    vals: set[int] = set()
    for part in expr.split(","):
        step = 1
        if "/" in part:
            part, st = part.split("/", 1)
            if not st.isdigit() or int(st) < 1:
                raise ValueError(f"cron: step '/{st}' of {name} is invalid")
            step = int(st)
        if part in ("*", ""):
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise ValueError(f"cron: in approximately '{part}' of {name} is invalid")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
        else:
            raise ValueError(f"cron: '{part}' of {name} is invalid")
        if a < lo or b > hi or a > b:
            raise ValueError(f"cron: {name} must be between {lo} and {hi}")
        vals.update(range(a, b + 1, step))
    return vals


def parse_cron(expr: str) -> list[set[int]]:
    parts = str(expr or "").split()
    if len(parts) != 5:
        raise ValueError("cron must contain exactly five fields: minute hour day month weekday (e.g. '30 7 * * *' = 07:30 every day)")
    f = [_cron_field(p, lo, hi, n) for p, (lo, hi), n in zip(parts, _CRON_RANGES, _CRON_NAMES, strict=True)]
    if 7 in f[4]:
        f[4].add(0)               # 0 and 7 đều là Sunday
    f.append({"dom": parts[2] != "*", "dow": parts[4] != "*"})
    return f


def cron_match(expr: str, dt: datetime) -> bool:
    m, h, dom, mon, dow, flags = parse_cron(expr)
    if dt.minute not in m or dt.hour not in h or dt.month not in mon:
        return False
    wd = (dt.weekday() + 1) % 7   # Python: Monday = 0 → cron: Sunday = 0
    d_ok, w_ok = dt.day in dom, wd in dow
    if flags["dom"] and flags["dow"]:
        return d_ok or w_ok        # chuẩn cron: cả hai bị giới hạn → một trong hai
    return d_ok and w_ok


def next_run(expr: str, after: datetime, limit_days: int = 400) -> datetime | None:
    t = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    m, h, *_ = parse_cron(expr)
    end = t + timedelta(days=limit_days)
    while t < end:
        if t.hour not in h:
            t = (t + timedelta(hours=1)).replace(minute=0)
            continue
        if cron_match(expr, t):
            return t
        t += timedelta(minutes=1)
    return None


def describe_cron(expr: str) -> str:
    """Mô tả tiếng Việt cho các mẫu hay dùng."""
    try:
        m, h, dom, mon, dow = expr.split()
    except ValueError:
        return expr
    days = {"0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday", "7": "Sunday"}
    if m.isdigit() and h.isdigit():
        at = f"{int(h):02d}:{int(m):02d}"
        if dom == "*" and mon == "*" and dow == "*":
            return f"{at} daily"
        if dom == "*" and mon == "*" and dow in days:
            return f"{at} {days[dow]} weekly"
        if dom == "*" and mon == "*" and dow == "1-5":
            return f"{at} Monday–Friday"
        if dom.isdigit() and mon == "*" and dow == "*":
            return f"{at} day {dom} monthly"
        if dom.isdigit() and dow == "*" and "," in mon:
            return f"{at} day {dom} in months {mon}"
    return f"cron {expr}"


# ---------------------------------------------------------------- phạm vi
SEV_GROUP = {"High": ("down", "critical"), "Medium": ("trouble", "warning"), "Low": ("attention",)}


def expand_sevs(sevs) -> set[str]:
    out = set()
    for s in sevs or []:
        out.update(SEV_GROUP.get(s, (s,)))
    return out


def in_scope(scope: dict, *, site_id=None, asset=None, severity=None, name: str = "") -> bool:
    scope = scope or {}
    sites = scope.get("sites", "all")
    if sites not in ("all", None, []) and site_id not in sites:
        return False
    types = scope.get("asset_types") or []
    if types and (not asset or asset.type not in types):
        return False
    sevs = expand_sevs(scope.get("severities"))
    if sevs and severity not in sevs:
        return False
    nc = str(scope.get("name_contains") or "").strip().lower()
    if nc and nc not in (name or "").lower():
        return False
    return True


# ---------------------------------------------------------------- gửi tin theo người nhận
def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def send_to(targets: list | None, subject: str, text: str, severity: str = "info") -> dict:
    """targets: [{type: default}] → các kênh đã bật trong Cài đặt; hoặc chỉ định chat Telegram / email / webhook riêng
    (dùng thông tin bot/SMTP ở Cài đặt)."""
    from .. import notify as nt
    targets = targets or [{"type": "default"}]
    res: dict = {}
    cfg = nt.load_notify_settings()
    icon = {"critical": "🔴", "down": "🔴", "warning": "🟠", "trouble": "🟠", "attention": "🟡", "resolved": "🟢", "info": "🔵"}.get(severity, "🔔")
    for i, t in enumerate(targets):
        kind = t.get("type", "default")
        key = f"{kind}:{t.get('chat') or t.get('to') or t.get('url') or ''}" if kind != "default" else "default"
        try:
            if kind == "default":
                r = await nt.notify(subject, text, severity if severity in ("critical", "warning", "resolved", "info") else "info")
                res.update({f"default/{k}": v for k, v in r.items()} or {"default": "no notification channels are enabled in Settings"})
                continue
            if kind == "telegram":
                tg = cfg.get("telegram") or {}
                if not tg.get("bot_token"):
                    raise RuntimeError("Telegram bot is not configured in Settings")
                await nt.send_telegram({**tg, "chat_id": t.get("chat") or tg.get("chat_id")}, f"{icon} <b>{_esc(subject)}</b>\n{_esc(text)}")
            elif kind == "email":
                em = cfg.get("email") or {}
                if not em.get("host"):
                    raise RuntimeError("SMTP is not configured in Settings")
                await nt.send_email({**em, "to": t.get("to") or em.get("to")}, f"{icon} {subject}", text)
            elif kind == "webhook":
                await nt.send_webhook({"url": t.get("url") or (cfg.get("webhook") or {}).get("url")}, f"{icon} {subject}", text)
            else:
                raise RuntimeError(f"recipient type '{kind}' is not supported")
            res[key or str(i)] = "ok"
        except Exception as e:
            res[key or str(i)] = f"error: {type(e).__name__} {e}"[:200]
    return res


# ---------------------------------------------------------------- kết quả chạy
@dataclass
class Msg:
    subject: str
    text: str
    severity: str = "info"
    targets: list | None = None      # None = theo actions of workflow


@dataclass
class RunResult:
    status: str = "ok"               # ok | skipped | error
    summary: str = ""
    messages: list = field(default_factory=list)
    output: str = ""                 # bản xem trước đầy đủ (hiện trên giao diện)


@dataclass
class Ctx:
    db: object
    auto: object
    spec: dict
    params: dict
    scope: dict
    now: datetime                    # hours VN
    trigger: str
    dry_run: bool
    state: dict

    def p(self, key, default=None):
        v = self.params.get(key)
        return default if v in (None, "") else v


def _templates():
    from .templates import TEMPLATES
    return TEMPLATES


def effective_spec(auto) -> dict:
    """Full spec = mặc định of template + phần người dùng sửa."""
    t = _templates().get(auto.code)
    base = copy.deepcopy(t["spec"]) if t else {}
    user = copy.deepcopy(auto.spec or {})
    out = {**base, **{k: v for k, v in user.items() if k != "params"}}
    out["params"] = {**(base.get("params") or {}), **(user.get("params") or {})}
    return out


async def run_automation(auto_id: int, trigger: str = "manual", dry_run: bool = False, event: dict | None = None) -> dict:
    """Run one automation. dry_run = chỉ xem trước, do not send, không ghi bộ nhớ status."""
    db = SessionLocal()
    try:
        auto = db.get(models.Automation, auto_id)
        if not auto:
            raise ValueError("Not found workflow")
        spec = effective_spec(auto)
        state = copy.deepcopy(auto.state or {})
        ctx = Ctx(db=db, auto=auto, spec=spec, params=spec.get("params") or {}, scope=spec.get("scope") or {},
                  now=local_now(), trigger=trigger, dry_run=dry_run, state=state)
        t = _templates().get(auto.code)
        fn = (t.get("preview") if trigger in ("test", "manual") and t.get("preview") else t.get("run")) if t else None
        try:
            if fn is None:
                raise ValueError(f"Template {auto.code} does not exist")
            res: RunResult = fn(ctx, event) if t.get("wants_event") else fn(ctx)
            if trigger in ("test", "manual") and t.get("hook") and res.messages:
                res.messages = [Msg(m.subject, m.text, m.severity) for m in res.messages]
                if trigger == "manual":      # template hook không có tin để gửi – chỉ xem
                    dry_run = True
        except Exception as e:
            log.exception("automation %s error", auto.code)
            res = RunResult("error", f"Error: {type(e).__name__} {e}"[:300])
        sent = {}
        if res.messages and res.status == "ok":
            preview = "\n\n".join(f"■ {m.subject}\n{m.text}" for m in res.messages)
            res.output = res.output or preview
            if not dry_run:
                db.commit()       # lưu thay đổi of template (VD đánh dấu leo thang) trước khi gửi
                for m in res.messages:
                    r = await send_to(m.targets or spec.get("actions"), m.subject, m.text, m.severity)
                    sent.update(r)
        if not dry_run:
            auto.state = state
            auto.last_run_at = now()
            if not (res.status == "skipped" and trigger in ("tick", "interval", "event")):
                auto.last_status, auto.last_summary = res.status, res.summary[:500]
        if res.status == "skipped" and trigger in ("tick", "interval", "event") and not dry_run:
            db.commit()                     # không ghi lịch sử cho lần chạy định kỳ không có gì (tránh rác)
            return {"status": res.status, "summary": res.summary, "output": "", "sent": {}, "messages": []}
        db.add(models.AutomationRun(automation_id=auto.id, trigger=trigger, status=res.status, summary=res.summary[:500],
                                    output=res.output[:20000], sent=sent, dry_run=dry_run))
        _trim_runs(db, auto.id)
        db.commit()
        return {"status": res.status, "summary": res.summary, "output": res.output, "sent": sent,
                "messages": [{"subject": m.subject, "text": m.text, "severity": m.severity} for m in res.messages]}
    finally:
        db.close()


def _trim_runs(db, auto_id: int, keep: int = 300):
    ids = [r[0] for r in db.query(models.AutomationRun.id).filter(models.AutomationRun.automation_id == auto_id)
           .order_by(models.AutomationRun.id.desc()).offset(keep).limit(1000).all()]
    if ids:
        db.query(models.AutomationRun).filter(models.AutomationRun.id.in_(ids)).delete(synchronize_session=False)


# ---------------------------------------------------------------- vòng lặp
def due(auto, spec: dict, t: datetime) -> bool:
    trg = spec.get("trigger") or {}
    kind = trg.get("type")
    last = to_local(auto.last_run_at)
    if kind == "schedule":
        try:
            return cron_match(trg.get("cron", ""), t) and not (last and last.replace(second=0, microsecond=0) >= t)
        except ValueError:
            return False
    if kind == "interval":
        mins = max(1, int(trg.get("minutes") or 5))
        return not last or (t - last) >= timedelta(minutes=mins) - timedelta(seconds=5)
    return False


async def tick(t: datetime | None = None):
    """Gọi every ~30 giây: chạy workflow tới lịch, phần định kỳ of template 'hook', gộp uptime theo days."""
    t = t or local_now()
    db = SessionLocal()
    try:
        autos = [(a.id, a.code, effective_spec(a), a) for a in db.query(models.Automation).filter(models.Automation.enabled == True).all()]  # noqa: E712
        todo = []
        for aid, code, spec, a in autos:
            tpl = _templates().get(code) or {}
            if due(a, spec, t):
                todo.append((aid, (spec.get("trigger") or {}).get("type")))
            elif tpl.get("tick") and not (a.last_run_at and to_local(a.last_run_at) >= t):
                todo.append((aid, "tick"))
    finally:
        db.close()
    for aid, trg in todo:
        await run_automation(aid, trg)
    await asyncio.to_thread(rollup_uptime)


async def loop():
    global LAST_TICK
    import time as _t
    await asyncio.sleep(5)
    while True:
        LAST_TICK = _t.time()
        try:
            await tick()
        except Exception:
            log.exception("automation tick error")
        await asyncio.sleep(30)


# ---------------------------------------------------------------- gộp uptime theo days (hours VN)
_ROLLED: dict = {}


def rollup_uptime(force: bool = False):
    """Gộp check_results thành daily_uptime cho các days đã qua (chạy tối đa 1  changes/hours)."""
    key = local_now().strftime("%Y-%m-%d %H")
    if _ROLLED.get("k") == key and not force:
        return
    _ROLLED["k"] = key
    from sqlalchemy import func
    db = SessionLocal()
    try:
        today = local_now().replace(hour=0, minute=0)
        start = today - timedelta(days=14)
        have = {(r.check_id, r.day) for r in db.query(models.DailyUptime).filter(models.DailyUptime.day >= start.strftime("%Y-%m-%d"))}
        intervals = {c.id: (c.interval or 60) for c in db.query(models.Check).all()}
        d = start
        while d < today:
            day = d.strftime("%Y-%m-%d")
            lo, hi = to_utc_naive(d), to_utc_naive(d + timedelta(days=1))
            CR = models.CheckResult
            rows = db.query(CR.check_id, func.count(), func.sum(_down_expr())).filter(CR.ts >= lo, CR.ts < hi).group_by(CR.check_id).all()
            for cid, total, down in rows:
                if (cid, day) in have and not force:
                    continue
                down = int(down or 0)
                row = db.get(models.DailyUptime, (cid, day)) or models.DailyUptime(check_id=cid, day=day)
                row.total, row.down = int(total), down
                row.down_minutes = round(down * intervals.get(cid, 60) / 60, 1)
                db.merge(row)
            d += timedelta(days=1)
        db.commit()
    finally:
        db.close()


def _down_expr():
    """down = True, hoặc bản ghi cũ (NULL) error mà không có số liệu."""
    from sqlalchemy import and_, case, or_
    CR = models.CheckResult
    return case((or_(CR.down == True, and_(CR.down.is_(None), CR.status == "fail", CR.metrics.is_(None))), 1), else_=0)  # noqa: E712


def uptime_between(db, check_ids: list[int], start_local: datetime, end_local: datetime) -> dict:
    """{check_id: (total, down, down_minutes)} – dùng daily_uptime cho days đã gộp, bản ghi thô cho phần remaining lại."""
    from sqlalchemy import func
    out = {cid: [0, 0, 0.0] for cid in check_ids}
    if not check_ids:
        return {}
    intervals = {c.id: (c.interval or 60) for c in db.query(models.Check).filter(models.Check.id.in_(check_ids))}
    rolled_days = set()
    d = start_local.replace(hour=0, minute=0)
    days = []
    while d < end_local:
        if d >= start_local and d + timedelta(days=1) <= end_local:
            days.append(d.strftime("%Y-%m-%d"))
        d += timedelta(days=1)
    for r in db.query(models.DailyUptime).filter(models.DailyUptime.check_id.in_(check_ids), models.DailyUptime.day.in_(days or ["-"])):
        o = out[r.check_id]
        o[0] += r.total; o[1] += r.down; o[2] += r.down_minutes
        rolled_days.add((r.check_id, r.day))
    CR = models.CheckResult
    # days theo hours địa phương. Use literal (không bind param) để biểu thức trong SELECT and GROUP BY giống hệt nhau – PostgreSQL required
    from sqlalchemy import literal_column
    off_min = int(TZ.utcoffset(None).total_seconds() // 60)
    day_expr = func.to_char(CR.ts + literal_column(f"interval '{off_min} minutes'"), literal_column("'YYYY-MM-DD'"))
    q = db.query(CR.check_id, day_expr, func.count(), func.sum(_down_expr())).filter(
        CR.check_id.in_(check_ids), CR.ts >= to_utc_naive(start_local), CR.ts < to_utc_naive(end_local)).group_by(CR.check_id, day_expr)
    for cid, day, total, down in q:
        if (cid, day) in rolled_days:
            continue
        o = out[cid]
        o[0] += total; o[1] += int(down or 0); o[2] += int(down or 0) * intervals.get(cid, 60) / 60
    return {k: tuple(v) for k, v in out.items()}


# ---------------------------------------------------------------- xử lý thông báo alerts (hook)
HOOK_ORDER = ["LCM-01", "INC-01", "INC-02", "INC-05"]


async def dispatch(items: list):
    """Nhận danh sách thông báo from bộ giám sát / bộ nhận log rồi:
    1) cho các template hook xử lý (bảo trì → gom nguyên nhân gốc → chống flapping → gắn runbook),
    2) chạy kịch bản tự tạo theo sự kiện,
    3) gửi phần remaining lại qua các kênh mặc định."""
    from ..notify import notify
    norm = []
    for it in items:
        subj, text, sev, *rest = it
        norm.append({"subject": subj, "text": text, "severity": sev, "ctx": (rest[0] if rest else {}) or {}})
    if not norm:
        return
    db = SessionLocal()
    try:
        autos = db.query(models.Automation).filter(models.Automation.enabled == True).all()  # noqa: E712
        hooks = {a.code: a for a in autos if a.code in HOOK_ORDER}
        evs = [a.id for a in autos if (effective_spec(a).get("trigger") or {}).get("type") == "event"]
        tpls = _templates()
        out = []
        for it in norm:
            keep = True
            for code in HOOK_ORDER:
                a = hooks.get(code)
                if not a or not keep:
                    continue
                spec = effective_spec(a)
                ctx = Ctx(db=db, auto=a, spec=spec, params=spec.get("params") or {}, scope=spec.get("scope") or {},
                          now=local_now(), trigger="hook", dry_run=False, state=copy.deepcopy(a.state or {}))
                try:
                    verdict = tpls[code]["hook"](ctx, it)
                except Exception:
                    log.exception("hook %s error", code)
                    continue
                a.state = ctx.state
                if verdict and verdict.get("note"):
                    db.add(models.AutomationRun(automation_id=a.id, trigger="hook", status="ok", summary=verdict["note"][:500],
                                                output=f"{it['subject']}\n{it['text']}"[:5000]))
                    a.last_run_at, a.last_status, a.last_summary = now(), "ok", verdict["note"][:500]
                if verdict and verdict.get("suppress"):
                    keep = False
                    aid = it["ctx"].get("alert_id")
                    al = db.get(models.Alert, aid) if aid else None
                    if al and it["ctx"].get("kind") != "resolve":
                        al.suppressed, al.suppress_reason = True, verdict["note"][:255]
                for extra in (verdict or {}).get("extra", []):
                    out.append(extra)
            if keep:
                out.append(it)
        db.commit()
    finally:
        db.close()
    for it in out:
        try:
            await notify(it["subject"], it["text"], it["severity"])
        except Exception:
            log.exception("Notification failed")
    for aid in evs:
        for it in norm:
            try:
                await run_automation(aid, "event", event=it)
            except Exception:
                log.exception("event automation error")


# ---------------------------------------------------------------- kiểm tra spec (form + YAML)
def validate_spec(code: str, spec: dict) -> dict:
    """Trả về spec đã chuẩn hoá; error → ValueError với câu tiếng Việt."""
    if not isinstance(spec, dict):
        raise ValueError("Automation must be a key-value object: expected (trigger, scope, params, actions...)")
    t = _templates().get(code)
    if not t:
        raise ValueError(f"Template {code} does not exist")
    full = {**copy.deepcopy(t["spec"]), **spec}
    trg = full.get("trigger") or {}
    kind = trg.get("type")
    allowed = t.get("triggers") or ["schedule", "interval", "event"]
    if kind not in allowed:
        raise ValueError(f"trigger.type must be one of: {', '.join(allowed)}")
    if kind == "schedule":
        parse_cron(trg.get("cron", ""))
    if kind == "interval":
        m = trg.get("minutes")
        if not isinstance(m, int) or not 1 <= m <= 10080:
            raise ValueError("trigger.minutes must be a number of minutes 1–10080")
    if kind == "event":
        on = trg.get("on") or []
        bad = [x for x in on if x not in EVENTS]
        if not on or bad:
            raise ValueError(f"trigger.on must be a list containing values from: {', '.join(EVENTS)}")
    acts = full.get("actions") or [{"type": "default"}]
    full["actions"] = acts
    if not isinstance(acts, list):
        raise ValueError("actions must be a recipient list")
    for a in acts:
        if isinstance(a, dict) and isinstance(a.get("to"), list):      # mẫu trong tài liệu: to: [a@b.vn, c@d.vn]
            a["to"] = ", ".join(str(x) for x in a["to"])
        if isinstance(a, dict) and a.get("chat") is not None:
            a["chat"] = str(a["chat"])
        if not isinstance(a, dict) or a.get("type") not in ("default", "telegram", "email", "webhook"):
            raise ValueError("Each recipient requires a type: default / telegram / email / webhook")
        if a["type"] == "email" and a.get("to") and not re.fullmatch(r"[^@\s,]+@[^@\s,]+(\s*,\s*[^@\s,]+@[^@\s,]+)*", str(a["to"])):
            raise ValueError(f"Email '{a['to']}' is invalid")
        if a["type"] == "webhook" and a.get("url") and not str(a["url"]).startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")
    lvl = full.get("level", "L0")
    if lvl not in ("L0", "L1", "L2", "L3"):
        raise ValueError("level must be L0 / L1 / L2 / L3")
    if lvl in ("L2", "L3") and not t.get("reversible"):
        raise ValueError("This template only sends notifications – L2/L3 levels are only for reversible actions")
    if t.get("validate"):
        t["validate"](full)
    return {k: full[k] for k in ("trigger", "scope", "params", "actions", "level") if k in full} | (
        {"content": full["content"]} if "content" in full else {}) | ({"send_when": full["send_when"]} if "send_when" in full else {})
