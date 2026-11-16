"""Template library – sourced from "IT Ops Workspace – Automation Templates".

Only includes templates that work with the system data currently available (all are covered by tests/test_automation.py).
Templates requiring integrations not yet available (Veeam/Synology, Redfish, configuration vault, Telegram callback, Mbps history, etc.)
are listed in UNSUPPORTED so the UI can show the reason clearly.

Each template: metadata (name, group, description, KPI) + default spec + one of these functions:
  run(ctx) -> RunResult            run on a schedule / interval / manual trigger
  hook(ctx, item) -> dict | None   process alert notifications before sending (suppress / extra / note)
  tick=True                        run function is called every interval (periodic part of a hook template)"""
import statistics
from datetime import timedelta

from sqlalchemy import func

from .. import models
from ..models import now
from . import blocks as B
from .engine import Msg, RunResult, cron_match, expand_sevs, in_scope, to_local, to_utc_naive

DEFAULT_TARGETS = [{"type": "default"}]


def _spec(trigger, params=None, scope=None, level="L0", actions=None, **extra):
    return {"trigger": trigger, "scope": scope or {"sites": "all"}, "params": params or {}, "actions": actions or DEFAULT_TARGETS,
            "level": level, **extra}


def _skip(summary):
    return RunResult("skipped", summary)


def _dow_vi(t):
    return ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][t.weekday()]


# ================================================================ RPT – Báo cáo
def rpt01(ctx):
    db, sc = ctx.db, ctx.scope
    t = ctx.now
    _, ov, _ = B.overview(db, sc)
    _, wan, _ = B.wan_lines(db, sc)
    _, al, n_al = B.open_alerts(db, sc, limit=int(ctx.p("max_alerts", 8)))
    _, inc, _ = B.incidents(db, sc, hours=24)
    _, ssl, n_ssl = B.ssl_expiring(db, sc, days=int(ctx.p("ssl_days", 14)))
    _, res, n_res = B.resources_top(db, sc, n=5)
    text = "\n".join([*ov, "WAN: " + " | ".join(wan), "Open alerts:" if n_al else "Open alerts: none", *(al if n_al else []),
                      *inc, *(["Expiring soon:", *ssl] if n_ssl else []), *(["Resources:", *res] if n_res else [])])
    subj = f"IT digest {t.strftime('%H:%M')} – {_dow_vi(t)} {t.strftime('%d/%m')}"
    return RunResult("ok", f"{n_al} open alerts · {n_ssl} SSL expiring soon", [Msg(subj, text, "info")])


def _period_report(ctx, days, title, include):
    db, sc = ctx.db, ctx.scope
    end = ctx.now.replace(hour=0, minute=0)
    if ctx.p("include_today"):
        end = ctx.now
    sections, decisions = [], []
    _, up, _ = B.uptime_by_site(db, sc, days=days, end=end)
    _, inc, n_inc = B.mtta_mttr(db, sc, days=days)
    _, noisy, _ = B.top_noisy(db, sc, days=days, n=int(ctx.p("top_n", 5)))
    _, logs, _ = B.log_top(db, sc, hours=days * 24, n=5)
    _, al, n_al = B.open_alerts(db, sc, limit=5)
    _, ssl, n_ssl = B.ssl_expiring(db, sc, days=30)
    _, res, n_res = B.resources_top(db, sc, n=5)
    target = float(ctx.p("uptime_target", 99.5))
    below = [line for line in up if "%" in line and float(line.split(": ")[1].split("%")[0]) < target]
    summary = [f"Uptime: {'met' if not below else 'NOT MET'} target {target:g}%" + (f" ({len(below)} sites below target)" if below else ""),
               inc[0], f"Open: {n_al} alerts"]
    sections.append("Summary:\n" + "\n".join(summary))
    sections.append("Key metrics:\n" + "\n".join(up + inc[1:]))
    if "noisy" in include:
        sections.append("Notable incidents:\n" + "\n".join(noisy + ["Key logs:"] + logs))
    if n_al:
        decisions.append(f"{n_al} alerts remain open – review the list and assign an owner")
    if n_res:
        decisions += [f"Consider upgrading/cleanup: {line[2:]}" for line in res[:3]]
    if n_ssl:
        decisions += [f"Renew {line[2:]}" for line in ssl[:3]]
    if below:
        decisions.append("Uptime below target at: " + ", ".join(b[2:].split(":")[0] for b in below))
    sections.append("Decisions required:\n" + ("\n".join(f"- {d}" for d in decisions[:6]) if decisions else "- None"))
    start = (end - timedelta(days=days)).strftime("%d/%m")
    subj = f"{title} {start}–{(end - timedelta(minutes=1)).strftime('%d/%m/%Y')}"
    return RunResult("ok", f"{n_inc} incidents · {len(decisions)} decisions required", [Msg(subj, "\n\n".join(sections), "info")])


def rpt02(ctx):
    return _period_report(ctx, 7, "Weekly Operations Report", include={"noisy"})


def rpt03(ctx):
    """Last month SLA compared with target and the month before last."""
    from .engine import uptime_between
    db, sc = ctx.db, ctx.scope
    first = ctx.now.replace(day=1, hour=0, minute=0)
    prev_end = first
    prev_start = (first - timedelta(days=1)).replace(day=1)
    pp_start = (prev_start - timedelta(days=1)).replace(day=1)
    target = float(ctx.p("uptime_target", 99.5))
    assets = {a.id: a for a in db.query(models.Asset)}
    sites = {s.id: s.name for s in db.query(models.Site)}
    checks = [c for c in db.query(models.Check) if in_scope(sc, site_id=c.site_id or (assets[c.asset_id].site_id if c.asset_id in assets else None),
                                                           asset=assets.get(c.asset_id))]
    ids = [c.id for c in checks]
    cur, old = uptime_between(db, ids, prev_start, prev_end), uptime_between(db, ids, pp_start, prev_start)

    def agg(data, group):
        out = {}
        for c in checks:
            t = data.get(c.id)
            if not t or not t[0]:
                continue
            k = group(c)
            if k is None:
                continue
            o = out.setdefault(k, [0, 0, 0.0])
            o[0] += t[0]; o[1] += t[1]; o[2] += t[2]
        return out
    by_site = lambda c: c.site_id or (assets[c.asset_id].site_id if c.asset_id in assets else None)  # noqa: E731
    crit = {cid: cs for cs in db.query(models.CriticalSystem) for cid in (cs.check_ids or [])}
    s_cur, s_old = agg(cur, by_site), agg(old, by_site)
    c_cur = agg(cur, lambda c: crit[c.id].name if c.id in crit else None)
    lines, worst = [], []
    for sid, (tot, dn, mins) in sorted(s_cur.items(), key=lambda x: x[0] or 0):
        pct = (tot - dn) / tot * 100
        o = s_old.get(sid)
        cmp = f" (previous month {(o[0] - o[1]) / o[0] * 100:.2f}%)" if o and o[0] else ""
        mark = "✓" if pct >= target else "✗"
        lines.append(f"{mark} {sites.get(sid, 'No site assigned')}: {pct:.3f}% · DOWN {B.fmt_dur(mins)}{cmp}")
        if pct < target:
            worst.append((pct, sites.get(sid, "?")))
    crit_lines = []
    for name, (tot, dn, mins) in sorted(c_cur.items()):
        pct = (tot - dn) / tot * 100
        crit_lines.append(f"{'✓' if pct >= target else '✗'} {name}: {pct:.3f}% · DOWN {B.fmt_dur(mins)}")
        if pct < target:
            worst.append((pct, name))
    days_cov = len({r.day for r in db.query(models.DailyUptime.day).filter(models.DailyUptime.day >= prev_start.strftime("%Y-%m-%d"),
                                                                         models.DailyUptime.day < prev_end.strftime("%Y-%m-%d"))})
    month_days = (prev_end - prev_start).days
    recs = [f"Find the root cause and fallback plan for {n} ({p:.2f}%)" for p, n in sorted(worst)[:3]]
    if not recs:
        recs = ["Maintain: all sites and critical systems meet their targets"]
    if days_cov < month_days:
        recs.append(f"Note: data is available for only {days_cov}/{month_days} days (the system did not run continuously); results are not representative of the full month")
    text = "\n\n".join([f"Uptime target: {target:g}%", "By site:\n" + ("\n".join(lines) or "No data available"),
                        *(["Critical systems:\n" + "\n".join(crit_lines)] if crit_lines else []),
                        "Recommendations:\n" + "\n".join(f"- {r}" for r in recs[:4])])
    subj = f"Monthly SLA report {prev_start.strftime('%m/%Y')}"
    return RunResult("ok", f"{len(worst)} items below target · {days_cov}/{month_days} days with data", [Msg(subj, text, "info")])


def rpt04(ctx):
    _, lines, n = B.backup_risks(ctx.db, ctx.scope)
    if not n and ctx.p("skip_if_empty", True):
        return _skip("No risks or systems missing backups")
    return RunResult("ok", f"{n} risk items", [Msg(f"Backup and risks – {ctx.now.strftime('%d/%m/%Y')}", "\n".join(lines), "info")])


def rpt06(ctx):
    _, lines, n = B.asset_changes(ctx.db, ctx.scope, days=int(ctx.p("days", 30)), silent_days=int(ctx.p("silent_days", 7)))
    return RunResult("ok", f"{n} items to review", [Msg(f"Asset changes – {ctx.now.strftime('%m/%Y')}", "\n".join(lines), "info")])


# ================================================================ INC – Warning / sự cố (hook)
def _alert_of(ctx, item):
    aid = (item.get("ctx") or {}).get("alert_id")
    return ctx.db.get(models.Alert, aid) if aid else None


def _ancestors(db, asset_id, limit=10):
    out, seen = [], set()
    a = db.get(models.Asset, asset_id) if asset_id else None
    while a and a.parent_id and a.parent_id not in seen and len(out) < limit:
        seen.add(a.parent_id)
        a = db.get(models.Asset, a.parent_id)
        if a:
            out.append(a)
    return out


def _descendants(db, asset_id):
    kids = {}
    for a in db.query(models.Asset.id, models.Asset.parent_id):
        kids.setdefault(a.parent_id, []).append(a.id)
    out, stack = [], list(kids.get(asset_id, []))
    while stack:
        x = stack.pop()
        if x in out or x == asset_id:
            continue
        out.append(x)
        stack += kids.get(x, [])
    return out


def inc01_hook(ctx, item):
    """Group by root cause: when a parent asset is DOWN, suppress child alerts; include the number of affected devices in the parent notification."""
    c = item.get("ctx") or {}
    if c.get("kind") not in ("open", "escalate"):
        return None
    al = _alert_of(ctx, item)
    if not al or not al.asset_id:
        return None
    db = ctx.db
    for anc in _ancestors(db, al.asset_id):
        parent_down = db.query(models.Alert).filter(models.Alert.asset_id == anc.id, models.Alert.status != "resolved",
                                                    models.Alert.severity == "down").first()
        if parent_down:
            return {"suppress": True, "note": f"Suppress: {al.title} – do {anc.name} (cha) is DOWN"}
    if al.severity == "down":
        kids = _descendants(db, al.asset_id)
        if kids:
            names = [a.name for a in db.query(models.Asset).filter(models.Asset.id.in_(kids)).limit(8)]
            item["text"] += f"\n\n⚠ {len(kids)} downstream devices affected: {', '.join(names)}{'…' if len(kids) > 8 else ''}" \
                            "\nIndividual alerts from these devices will be grouped into this incident."
            return {"note": f"{al.title}: gom {len(kids)} downstream devices"}
    return None


def inc02_hook(ctx, item):
    """Flapping protection: >= N status changes within M minutes are grouped into one flapping notification; individual notifications are suppressed."""
    c = item.get("ctx") or {}
    cid = c.get("check_id")
    if not cid or c.get("kind") not in ("open", "resolve"):
        return None
    mins, need = int(ctx.p("window_min", 10)), int(ctx.p("changes", 3))
    since = now() - timedelta(minutes=mins)
    rows = ctx.db.query(models.CheckResult.down, models.CheckResult.status).filter(
        models.CheckResult.check_id == cid, models.CheckResult.ts >= since).order_by(models.CheckResult.id).all()
    seq = [bool(d) if d is not None else st == "fail" for d, st in rows]          # chỉ tính lên/xuống (DOWN ↔ không DOWN)
    changes = sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
    if changes < need:
        return None
    flap = ctx.state.setdefault("flapping", {})
    last = flap.get(str(cid))
    chk = ctx.db.get(models.Check, cid)
    name = chk.name if chk else f"check {cid}"
    if last and (now() - _parse(last)) < timedelta(minutes=int(ctx.p("quiet_min", 60))):
        return {"suppress": True, "note": f"Suppress individual notifications: {name} is flapping ({changes} times/{mins} minutes)"}
    flap[str(cid)] = now().isoformat()
    extra = {"subject": f"{name} flapping", "severity": "warning", "ctx": {"kind": "flap", "check_id": cid},
             "text": f"Status changed {changes} times within {mins} minutes. Suppress individual notifications for {ctx.p('quiet_min', 60)} minutes.\n"
                     f"Most recent: {item['subject']}"}
    return {"suppress": True, "extra": [extra], "note": f"{name}: flapping ({changes} times/{mins} minutes) – grouped into one notification"}


def _parse(s):
    from datetime import datetime
    return datetime.fromisoformat(s)


RUNBOOKS = {
    "wan": ["Check the ISP modem/ONT indicators", "Ping the ISP gateway from the firewall (Diagnostics › Ping)",
            "Check Gateway Monitor in pfSense", "Call the ISP and provide the contract/customer ID"],
    "ping": ["Ping from another device on the same network to rule out a routing issue", "Check the switch port connected to the device (link LEDs and port status)",
             "Check the device power supply / UPS", "If it is a VM, check its status in ESXi"],
    "snmp": ["Check whether the device still responds to ping", "Check the SNMP service and community/ACL on the device",
             "Check whether the firewall blocks UDP 161"],
    "http": ["Open the URL in a browser", "Check the web service/application pool on the server", "Check DNS and the SSL certificate"],
    "ssh": ["Check whether the server still responds to ping", "Sign in to the console/iLO if SSH is unavailable", "Check disk space and RAM"],
    "cpu": ["Identify processes with high CPU usage (top / Task Manager)", "Compare with scheduled backups/antivirus scans", "Consider adding vCPUs if the issue persists"],
    "mem": ["Identify processes using large amounts of RAM", "Check for memory leaks (long-running services)", "Consider adding RAM"],
    "disk": ["Identify directories consuming the most space", "Clean up old logs/backups", "Expand the disk or move data"],
    "internet": ["Check whether other WAN links are still operational", "Check Gateway Monitor on the firewall", "Contact the ISP if all links are down"],
}


def inc05_hook(ctx, item):
    """Attached runbook: add 3–5 troubleshooting steps to the alert based on check type, metric, or critical system."""
    c = item.get("ctx") or {}
    if c.get("kind") not in ("open", "escalate"):
        return None
    al = _alert_of(ctx, item)
    if not al:
        return None
    db = ctx.db
    chk = db.get(models.Check, al.check_id) if al.check_id else None
    custom = ctx.p("rules") or []
    steps, src = None, ""
    for r in custom:      # rule riêng: {contains: "VNPT", steps: [...]}
        if r.get("contains") and r["contains"].lower() in (al.title + " " + (chk.name if chk else "")).lower() and r.get("steps"):
            steps, src = r["steps"], f"rule '{r['contains']}'"
            break
    if not steps and chk:
        crit = next((cs for cs in db.query(models.CriticalSystem) if chk.id in (cs.check_ids or []) and (cs.runbook or "").strip()), None)
        if crit:
            steps, src = [s.strip("-• ").strip() for s in crit.runbook.splitlines() if s.strip()], f"system {crit.name}"
    if not steps:
        from ..topology import wan_role
        key = al.metric or ("wan" if chk and (wan_role(chk) or chk.type == "internet") else chk.type if chk else None)
        if key == "internet":
            key = "wan"
        steps, src = RUNBOOKS.get(key or ""), key or ""
    if not steps:
        return None
    item["text"] += "\n\nTroubleshooting steps:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps[:5], 1))
    return {"note": f"Attach runbook ({src}) to: {al.title}"}


def inc03(ctx):
    """Escalation: if an alert is not acknowledged within X minutes, notify the next escalation level."""
    db = ctx.db
    steps = ctx.p("steps") or []
    done = ctx.state.setdefault("done", {})
    msgs, notes = [], []
    open_ids = set()
    for al in db.query(models.Alert).filter(models.Alert.status == "open", models.Alert.suppressed == False):  # noqa: E712
        open_ids.add(str(al.id))
        age = (now() - al.opened_at).total_seconds() / 60
        for i, st in enumerate(steps):
            if i in done.get(str(al.id), []):
                continue
            if al.severity not in expand_sevs(st.get("severities") or ["High"]) or age < float(st.get("after_min", 15)):
                continue
            label = st.get("label") or f"step {i + 1}"
            msgs.append(Msg(f"[Leo thang – {label}] {al.title}",
                            f"Not acknowledged after {int(age)} minutes (opened at {B.fmt_local(al.opened_at)}).\n{al.message}\n\n"
                            "Click Acknowledge on the Alerts page to stop escalation.", "critical" if al.severity in B.HIGH else "warning",
                            st.get("targets") or None))
            done.setdefault(str(al.id), []).append(i)
            al.escalation_level = max(al.escalation_level or 0, i + 1)
            notes.append(f"{al.title} → {label}")
    for k in list(done):             # dọn bộ nhớ of alerts received/đóng
        if k not in open_ids:
            done.pop(k)
    if not msgs:
        return _skip("No alerts require escalation")
    return RunResult("ok", "; ".join(notes)[:300], msgs)


def inc08(ctx):
    """User notification: if a critical system is DOWN for more than X minutes, send an outage notice; when it recovers, send a restoration notice."""
    db = ctx.db
    mins = float(ctx.p("down_minutes", 10))
    levels = ctx.p("levels") or ["High"]
    sent = ctx.state.setdefault("down", {})
    msgs = []
    for cs in db.query(models.CriticalSystem):
        if cs.level not in levels:
            continue
        ids = list(cs.check_ids or [])
        if cs.asset_id:
            ids += [c.id for c in db.query(models.Check.id).filter(models.Check.asset_id == cs.asset_id)]
        if not ids:
            continue
        al = db.query(models.Alert).filter(models.Alert.check_id.in_(ids), models.Alert.status != "resolved",
                                           models.Alert.severity == "down", models.Alert.metric.is_(None)).order_by(models.Alert.opened_at).first()
        key = str(cs.id)
        if al and (now() - al.opened_at).total_seconds() / 60 >= mins and key not in sent:
            sent[key] = al.opened_at.isoformat()
            msgs.append(Msg(f"{cs.name} is experiencing an outage", ctx.p("msg_down", "{system} is experiencing an outage. IT has been notified and is investigating. "
                                                            "We will provide an update when the service is restored.").format(system=cs.name), "warning"))
        elif not al and key in sent:
            dur = (now() - _parse(sent.pop(key))).total_seconds() / 60
            msgs.append(Msg(f"{cs.name} has been restored", ctx.p("msg_up", "{system} has returned to normal "
                                                                 "(outage duration: approximately {minutes} minutes). Thank you for your patience.")
                            .format(system=cs.name, minutes=int(dur)), "resolved"))
    if not msgs:
        return _skip("No critical system status changes")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


# ================================================================ PRE – Phòng ngừa / dự báo
def _linreg(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sxx
    return slope, my - slope * mx


def pre01(ctx):
    """Disk capacity forecast: use linear regression on daily disk usage and alert if the threshold is expected to be reached within N days."""
    db = ctx.db
    target, horizon = float(ctx.p("target_pct", 90)), float(ctx.p("horizon_days", 14))
    window, min_h = int(ctx.p("window_days", 14)), float(ctx.p("min_hours", 24))
    since = now() - timedelta(days=window)
    assets = {a.id: a for a in db.query(models.Asset)}
    found = []
    for c in db.query(models.Check).filter(models.Check.enabled == True):  # noqa: E712
        rs = (c.last_data or {}).get("res") or {}
        if rs.get("disk") is None:
            continue
        a = assets.get(c.asset_id)
        if not in_scope(ctx.scope, site_id=c.site_id or (a.site_id if a else None), asset=a, name=c.name):
            continue
        pts = [(r.ts, r.metrics.get("disk")) for r in db.query(models.CheckResult.ts, models.CheckResult.metrics)
               .filter(models.CheckResult.check_id == c.id, models.CheckResult.ts >= since, models.CheckResult.metrics.isnot(None))
               if r.metrics and r.metrics.get("disk") is not None]
        if len(pts) < 6 or (pts[-1][0] - pts[0][0]).total_seconds() / 3600 < min_h:
            continue
        t0 = pts[0][0]
        xs = [(t - t0).total_seconds() / 86400 for t, _ in pts]
        ys = [v for _, v in pts]
        slope, _ = _linreg(xs, ys)
        cur = ys[-1]
        if cur >= target:
            found.append((0, f"- {a.name if a else c.name} ({rs.get('disk_name') or 'Disk'}): current usage {cur:g}% ≥ {target:g}%"))
        elif slope > 0.01:
            days = (target - cur) / slope
            if days <= horizon:
                eta = (ctx.now + timedelta(days=days)).strftime("%d/%m")
                found.append((days, f"- {a.name if a else c.name} ({rs.get('disk_name') or 'Disk'}): {cur:g}% → reaching {target:g}% in approximately {eta} "
                                    f"(remaining ~{days:.0f} days, increasing by {slope:.2f}%/days)"))
    if not found:
        return _skip("No disks are expected to fill within the forecast window")
    found.sort()
    return RunResult("ok", f"{len(found)} disks approaching capacity", [Msg(f"Disk capacity forecast: {len(found)} disks within the next {horizon:g} days",
                                                         "\n".join(x for _, x in found) + "\n\nForecast based on trends; at least 7 days of data are required for accuracy.",
                                                         "warning")])


def pre02(ctx):
    """SSL expiry: send reminders at 30 / 14 / 7 days; the final reminder is Critical."""
    db = ctx.db
    marks = sorted({int(x) for x in (ctx.p("days") or [30, 14, 7])}, reverse=True)
    sent = ctx.state.setdefault("sent", {})
    msgs = []
    for c in db.query(models.Check).filter(models.Check.type == "http", models.Check.enabled == True):  # noqa: E712
        d = (c.last_data or {}).get("cert_days")
        if d is None:
            continue
        key = str(c.id)
        if d > marks[0]:
            sent.pop(key, None)            # đã gia hạn → reset
            continue
        hit = min(m for m in marks if d <= m)
        if sent.get(key) is not None and sent[key] <= hit:
            continue
        sent[key] = hit
        host = c.target.split("://")[-1].split("/")[0]
        last = hit == marks[-1]
        msgs.append(Msg(f"SSL {host} {'has expired' if d < 0 else f'remaining {d} days'}",
                        f"Certificate for {host} ({c.name}) {'has expired' if d < 0 else f'expires in {d} days'}. Reminder threshold: {hit} days."
                        + ("\nThis is the final reminder – renew immediately." if last else ""), "critical" if last else "warning"))
    if not msgs:
        return _skip("No certificates have reached a new reminder threshold")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


def pre04(ctx):
    """Latency trend: the latest 15-minute average exceeds the 7-day baseline by k standard deviations."""
    db = ctx.db
    k, recent_min = float(ctx.p("sigma", 3)), int(ctx.p("recent_min", 15))
    min_delta, base_h = float(ctx.p("min_delta_ms", 5)), float(ctx.p("min_baseline_hours", 24))
    cool = ctx.state.setdefault("cool", {})
    cut = now() - timedelta(minutes=recent_min)
    since = now() - timedelta(days=7)
    found = []
    for c in db.query(models.Check).filter(models.Check.enabled == True, models.Check.type.in_(("ping", "internet", "tcp", "http"))):  # noqa: E712
        if not in_scope(ctx.scope, site_id=c.site_id, name=c.name):
            continue
        rows = db.query(models.CheckResult.ts, models.CheckResult.latency).filter(
            models.CheckResult.check_id == c.id, models.CheckResult.ts >= since, models.CheckResult.latency.isnot(None),
            models.CheckResult.status != "fail").order_by(models.CheckResult.ts).all()
        base = [v for t, v in rows if t < cut]
        rec = [v for t, v in rows if t >= cut]
        if len(base) < 30 or len(rec) < 3 or (cut - rows[0][0]).total_seconds() / 3600 < base_h:
            continue
        mu, sd = statistics.fmean(base), statistics.pstdev(base)
        r = statistics.fmean(rec)
        if r > mu + k * sd and r - mu >= min_delta:
            key = str(c.id)
            if key in cool and now() - _parse(cool[key]) < timedelta(hours=float(ctx.p("cooldown_hours", 6))):
                continue
            cool[key] = now().isoformat()
            found.append(f"- {c.name}: {r:.1f} ms over {recent_min} minutes (baseline {mu:.1f} ± {sd:.1f} ms)")
    if not found:
        return _skip("Latency is within the normal range")
    return RunResult("ok", f"{len(found)} latency checks showing an unusual increase",
                     [Msg("Early warning: abnormal latency increase", "\n".join(found) + "\n\nThe service is not down yet, but the network path should be checked.", "info")])


def pre08(ctx):
    """Abnormal logs: error/warning log volume in the last hour is X times the average for the same hour over the previous 7 days."""
    db = ctx.db
    mult, min_count = float(ctx.p("multiplier", 3)), int(ctx.p("min_count", 30))
    t1 = now()
    t0 = t1 - timedelta(hours=1)
    cur = dict(db.query(models.Event.source_ip, func.count()).filter(models.Event.ts >= t0, models.Event.severity <= 4,
                                                                    models.Event.source_ip != "127.0.0.1").group_by(models.Event.source_ip).all())
    cool = ctx.state.setdefault("cool", {})
    found = []
    for ip, n in cur.items():
        if n < min_count:
            continue
        hist = []
        for d in range(1, 8):
            hist.append(db.query(func.count(models.Event.id)).filter(models.Event.source_ip == ip, models.Event.severity <= 4,
                                                                      models.Event.ts >= t0 - timedelta(days=d), models.Event.ts < t1 - timedelta(days=d)).scalar())
        base = sum(hist) / 7
        if n >= mult * max(base, 1):
            if ip in cool and now() - _parse(cool[ip]) < timedelta(hours=float(ctx.p("cooldown_hours", 3))):
                continue
            cool[ip] = now().isoformat()
            sample = db.query(models.Event).filter(models.Event.source_ip == ip, models.Event.ts >= t0, models.Event.severity <= 4) \
                .order_by(models.Event.id.desc()).limit(10).all()
            host = sample[0].host if sample else ""
            found.append(f"■ {host or ip} ({ip}): {n} error logs/alerts in 1 hour (normally ~{base:.0f})\n"
                         + "\n".join(f"  {e.message[:140]}" for e in sample))
    if not found:
        return _skip("Log volume is within the normal range")
    return RunResult("ok", f"{len(found)} log sources with unusual activity", [Msg("Log Anomaly", "\n\n".join(found), "info")])


# ================================================================ LCM – Maintenance / vòng đời
def _in_window(w, t):
    """Is the current time within a maintenance window? (cron = start time, duration_min = duration)."""
    dur = int(w.get("duration_min", 60))
    for m in range(0, dur):
        if cron_match(w["cron"], t - timedelta(minutes=m)):
            return True
    return False


def _window_targets(db, w):
    assets = {a.id: a for a in db.query(models.Asset)}
    ids = set(w.get("assets") or [])
    sites = set(w.get("sites") or [])
    for a in assets.values():
        if a.site_id in sites:
            ids.add(a.id)
    for aid in list(ids):            # gồm cả downstream devices
        ids.update(_descendants(db, aid))
    return ids


def lcm01_hook(ctx, item):
    """Maintenance window: suppress alerts for devices in scope during the configured window."""
    c = item.get("ctx") or {}
    al = _alert_of(ctx, item)
    asset_id = c.get("asset_id") or (al.asset_id if al else None)
    if not asset_id:
        return None
    for w in ctx.p("windows") or []:
        if _in_window(w, ctx.now) and asset_id in _window_targets(ctx.db, w):
            return {"suppress": True, "note": f"Maintenance '{w.get('name', '')}': do not send {item['subject']}"}
    return None


def lcm01(ctx):
    """Recurring task: send a reminder one day before; when maintenance ends, rerun all checks in scope and send the results."""
    db = ctx.db
    msgs = []
    for w in ctx.p("windows") or []:
        name = w.get("name") or "Maintenance"
        tg = _window_targets(db, w)
        if cron_match(w["cron"], ctx.now + timedelta(hours=float(ctx.p("remind_hours", 24)))):
            start = ctx.now + timedelta(hours=float(ctx.p("remind_hours", 24)))
            msgs.append(Msg(f"Maintenance reminder: {name}", f"Starts {start.strftime('%H:%M %d/%m')}, lasts {w.get('duration_min', 60)} minutes, "
                                                         f"{len(tg)} devices. Alerts for these devices will be suppressed during the maintenance window.", "info"))
        if cron_match(w["cron"], ctx.now - timedelta(minutes=int(w.get("duration_min", 60)))):
            checks = db.query(models.Check).filter(models.Check.enabled == True, models.Check.asset_id.in_(tg or [-1])).all()  # noqa: E712
            ctx.state.setdefault("post_check", {})[name] = [c.id for c in checks]
            ok = sum(1 for c in checks if c.status == "ok")
            bad = [c.name for c in checks if c.status != "ok"]
            msgs.append(Msg(f"After maintenance '{name}': {ok}/{len(checks)} healthy",
                            ("Remaining failures: " + ", ".join(bad[:10])) if bad else "All checks are healthy. Alerting has been re-enabled.",
                            "warning" if bad else "resolved"))
            if not ctx.dry_run:
                _rerun_checks([c.id for c in checks])
    if not msgs:
        return _skip("No maintenance window is scheduled")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


def _rerun_checks(ids):
    import asyncio
    from .. import scheduler
    for cid in ids:
        try:
            asyncio.get_running_loop().create_task(scheduler.run_check(cid))
        except RuntimeError:
            pass


SUGGEST = {"switch": "Ping + SNMP", "router": "Ping + SNMP", "firewall": "Ping + SNMP (or pfSense API)", "ap": "Ping + SNMP",
           "server": "Ping + SSH", "vm": "Ping + SSH", "host": "Ping + ESXi", "nas": "Ping + SNMP", "ups": "SNMP",
           "website": "HTTP + SSL", "printer": "Ping", "camera": "Ping"}


def lcm02(ctx):
    """Onboarding: assets without checks and unknown log sources are detected; suggest checks and a checklist."""
    db = ctx.db
    has = {c.asset_id for c in db.query(models.Check.asset_id).filter(models.Check.asset_id.isnot(None))}
    since = now() - timedelta(days=int(ctx.p("days", 7)))
    lines = []
    for a in db.query(models.Asset).filter(models.Asset.created_at >= since):
        if a.id in has or a.type in ("container",) or not in_scope(ctx.scope, site_id=a.site_id, asset=a):
            continue
        miss = [x for x, ok in (("site", a.site_id), ("owner", (a.owner or "").strip()), ("IP", (a.ip or "").strip())) if not ok]
        lines.append(f"- {a.name} ({a.type}): should add {SUGGEST.get(a.type, 'Ping')}" + (f" · missing {', '.join(miss)}" if miss else ""))
    unk = B.unknown_sources(db, int(ctx.p("days", 7)))
    for ip, n in unk[:10]:
        lines.append(f"- Unknown source {ip}: {n} logs – create assets, then add checks")
    if not lines:
        return _skip("No new assets require onboarding")
    return RunResult("ok", f"{len(lines)} items to onboard", [Msg("Asset Onboarding", "\n".join(lines) +
                                                               "\n\nChecklist: site · owner · criticality · backup", "info")])


def lcm03(ctx):
    """Offboarding: if an asset is not responding for more than N days, recommend archiving it (do not delete or disable automatically)."""
    db = ctx.db
    days = int(ctx.p("days", 30))
    cut = now() - timedelta(days=days)
    has = {c.asset_id for c in db.query(models.Check.asset_id).filter(models.Check.enabled == True, models.Check.asset_id.isnot(None))}  # noqa: E712
    lines = []
    for a in db.query(models.Asset):
        if a.id not in has or not in_scope(ctx.scope, site_id=a.site_id, asset=a):
            continue
        silent_since = a.last_seen or a.created_at
        if a.status in ("down", "unknown") and silent_since and silent_since < cut:
            lines.append(f"- {a.name} ({a.ip or a.type}): not responding since {B.fmt_local(silent_since)}")
    if not lines:
        return _skip(f"No assets have been silent for more than {days} days")
    return RunResult("ok", f"{len(lines)} assets to review", [Msg(f"Recommend archiving {len(lines)} assets", "\n".join(lines) +
                                                                  "\n\nConfirm on the Assets page: disable the check / change status to 'Disabled'. "
                                                                  "The system does not delete assets automatically.", "info")])


def lcm06(ctx):
    """Periodic data review (start of each quarter)."""
    db = ctx.db
    lines = []
    assets = [a for a in db.query(models.Asset) if in_scope(ctx.scope, site_id=a.site_id, asset=a) and a.type not in ("vm", "container")]
    no_owner = [a.name for a in assets if not (a.owner or "").strip()]
    no_site = [a.name for a in assets if not a.site_id]
    old_off = [c.name for c in db.query(models.Check).filter(models.Check.enabled == False)  # noqa: E712
               if not c.last_checked or c.last_checked < now() - timedelta(days=14)]
    rules = [r.name for r in db.query(models.EventRule).filter(models.EventRule.enabled == True)  # noqa: E712
             if (not r.last_hit or r.last_hit < now() - timedelta(days=90)) and (r.created_at or now() - timedelta(days=91)) < now() - timedelta(days=90)]
    users = [u.username for u in db.query(models.User) if (u.last_login or u.created_at) < now() - timedelta(days=90)]
    crit_no = [c.name for c in db.query(models.CriticalSystem) if not (c.owner or "").strip()]
    for label, xs in (("Assets missing an owner", no_owner), ("Assets without an assigned site", no_site), ("Checks disabled for > 14 days", old_off),
                      ("Log rules with no matches in the last 90 days", rules), ("Accounts inactive for more than 90 days", users),
                      ("Critical systems missing an owner", crit_no)):
        lines.append(f"{label}: {len(xs)}" + (" – " + ", ".join(xs[:10]) + ("…" if len(xs) > 10 else "") if xs else ""))
    total = len(no_owner) + len(no_site) + len(old_off) + len(rules) + len(users) + len(crit_no)
    return RunResult("ok", f"{total} items to clean up", [Msg(f"Quarterly Data Review – {ctx.now.strftime('%m/%Y')}", "\n".join(lines), "info")])


# ================================================================ xem trước cho template hook (nút Chạy thử)
def inc01_preview(ctx):
    db = ctx.db
    lines = []
    for al in db.query(models.Alert).filter(models.Alert.status != "resolved", models.Alert.severity == "down", models.Alert.asset_id.isnot(None)):
        kids = _descendants(db, al.asset_id)
        if kids:
            child = db.query(models.Alert).filter(models.Alert.asset_id.in_(kids), models.Alert.status != "resolved").count()
            lines.append(f"- {al.title}: {len(kids)} downstream devices · {child} child alerts will be grouped")
    tree = sum(1 for a in db.query(models.Asset.parent_id) if a.parent_id)
    head = f"The parent-child tree currently has {tree} links. When a parent device is DOWN, child-device alerts are not sent separately."
    return RunResult("ok", f"{len(lines)} open root-cause incidents", [Msg("Preview: group by root cause",
                                                                 head + "\n\n" + ("\n".join(lines) or "No parent devices are currently DOWN."))])


def inc02_preview(ctx):
    db = ctx.db
    mins, need = int(ctx.p("window_min", 10)), int(ctx.p("changes", 3))
    since = now() - timedelta(minutes=mins)
    lines = []
    for c in db.query(models.Check).filter(models.Check.enabled == True):  # noqa: E712
        rows = db.query(models.CheckResult.down, models.CheckResult.status).filter(
            models.CheckResult.check_id == c.id, models.CheckResult.ts >= since).order_by(models.CheckResult.id).all()
        seq = [bool(d) if d is not None else st == "fail" for d, st in rows]
        n = sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
        if n >= need:
            lines.append(f"- {c.name}: {n} status changes within {mins} minutes")
    return RunResult("ok", f"{len(lines)} check is flapping", [Msg("Preview: Flapping Protection",
                                                                    f"Rule: ≥ {need} status changes within {mins} minutes → group into one notification and suppress individual alerts "
                                                                    f"{ctx.p('quiet_min', 60)} minutes.\n\n" + ("\n".join(lines) or "No checks are currently flapping."))])


def inc05_preview(ctx):
    db = ctx.db
    shown = []
    for al in db.query(models.Alert).filter(models.Alert.status != "resolved").order_by(models.Alert.opened_at.desc()).limit(3):
        item = {"subject": al.title, "text": "", "ctx": {"kind": "open", "alert_id": al.id}}
        v = inc05_hook(ctx, item)
        if v:
            shown.append(f"■ {al.title}{item['text']}")
    if not shown:
        shown = ["Example when WAN is down:\nTroubleshooting steps:\n" + "\n".join(f"{i}. {x}" for i, x in enumerate(RUNBOOKS["wan"], 1))]
    return RunResult("ok", f"{len(shown)} examples", [Msg("Preview: Attached Runbook", "\n\n".join(shown))])


def lcm01_preview(ctx):
    from .engine import next_run
    db = ctx.db
    ws = ctx.p("windows") or []
    if not ws:
        return RunResult("ok", "None maintenance window", [Msg("Preview: Maintenance Schedule", "No maintenance windows are configured. Add a window: name, start time (cron), "
                                                                                    "duration, devices, or site.")])
    lines = []
    for w in ws:
        n = next_run(w["cron"], ctx.now)
        tg = _window_targets(db, w)
        lines.append(f"- {w.get('name', 'Maintenance')}: {'IN PROGRESS' if _in_window(w, ctx.now) else 'next at ' + (n.strftime('%H:%M %d/%m') if n else '?')}"
                     f" · {w.get('duration_min', 60)} minutes · {len(tg)} devices")
    return RunResult("ok", f"{len(ws)} maintenance window", [Msg("Preview: Maintenance Schedule", "\n".join(lines))])


# ================================================================ Workflow tự tạo
PLACEHOLDERS = ("title", "message", "severity", "asset", "site", "check", "time")


def custom(ctx, event=None):
    db = ctx.db
    content = ctx.spec.get("content") or {}
    if event is not None:                      # theo sự kiện alerts
        c = event.get("ctx") or {}
        kind = {"open": "alert_opened", "resolve": "alert_resolved", "escalate": "alert_escalated"}.get(c.get("kind"))
        if kind not in ((ctx.spec.get("trigger") or {}).get("on") or []):
            return _skip("Event does not match trigger")
        al = db.get(models.Alert, c["alert_id"]) if c.get("alert_id") else None
        asset = db.get(models.Asset, al.asset_id) if al and al.asset_id else None
        site_id = (al.site_id if al else None) or (asset.site_id if asset else None)
        sev = al.severity if al else ""
        if not in_scope(ctx.scope, site_id=site_id, asset=asset, severity=sev if kind != "alert_resolved" else None,
                        name=(al.title if al else event["subject"])):
            return _skip("Out of scope")
        site = db.get(models.Site, site_id) if site_id else None
        chk = db.get(models.Check, al.check_id) if al and al.check_id else None
        vals = {"title": event["subject"], "message": event["text"], "severity": B.SEV_LABEL.get(sev, sev or "Processed"),
                "asset": asset.name if asset else "", "site": site.name if site else "", "check": chk.name if chk else "",
                "time": ctx.now.strftime("%H:%M %d/%m")}
        subj = _fmt(content.get("title") or "{title}", vals)
        text = _fmt(content.get("message") or "{message}", vals)
        return RunResult("ok", subj, [Msg(subj, text, "resolved" if kind == "alert_resolved" else "warning")])
    names = content.get("blocks") or ["overview", "open_alerts"]
    text, items = B.render(db, ctx.scope, names, content.get("block_params") or {})
    if ctx.spec.get("send_when", "always") == "has_items" and not items:
        return _skip("Nothing to report (send_when: has_items)")
    subj = _fmt(content.get("title") or ctx.auto.name, {"time": ctx.now.strftime("%H:%M %d/%m")})
    intro = content.get("message")
    return RunResult("ok", f"{items} items", [Msg(subj, (intro + "\n\n" if intro else "") + text, "info")])


def _fmt(tpl, vals):
    out = str(tpl)
    for k, v in vals.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _validate_custom(spec):
    content = spec.get("content") or {}
    bad = [b for b in content.get("blocks") or [] if b not in B.BLOCKS]
    if bad:
        raise ValueError(f"Block does not exist: {', '.join(bad)}. Use: {', '.join(B.BLOCKS)}")
    if spec.get("send_when", "always") not in ("always", "has_items"):
        raise ValueError("send_when must be either always or has_items")
    if (spec.get("trigger") or {}).get("type") in ("schedule", "interval") and not content.get("blocks"):
        raise ValueError("Scheduled automation requires content.blocks (VD [overview, open_alerts])")


def _validate_windows(spec):
    for w in (spec.get("params") or {}).get("windows") or []:
        from .engine import parse_cron
        if not isinstance(w, dict) or not w.get("cron"):
            raise ValueError("Each maintenance window requires a cron expression (start time) and duration_min")
        parse_cron(w["cron"])
        if not (w.get("assets") or w.get("sites")):
            raise ValueError(f"Window '{w.get('name', '')}' requires assets or sites")


def _validate_steps(spec):
    for s in (spec.get("params") or {}).get("steps") or []:
        if not isinstance(s, dict) or not isinstance(s.get("after_min"), (int, float)):
            raise ValueError("Each escalation step requires after_min (minutes)")


# ================================================================ danh items
def T(code, group, name, desc, spec, *, run=None, hook=None, tick=False, kpi="", data="Available", triggers=None, reversible=False,
      fields=None, validate=None, wants_event=False, preview=None):
    return {"code": code, "group": group, "name": name, "desc": desc, "spec": spec, "run": run, "hook": hook, "tick": tick, "kpi": kpi,
            "preview": preview,
            "data": data, "triggers": triggers or (["schedule", "interval", "event"] if code == "CUSTOM" else ["schedule", "interval"]),
            "reversible": reversible, "fields": fields or [], "validate": validate, "wants_event": wants_event}


F = lambda key, label, kind="number", **kw: {"key": key, "label": label, "type": kind, **kw}  # noqa: E731

TEMPLATES = {t["code"]: t for t in [
    T("RPT-01", "RPT", "Morning Digest", "Devices in critical state, open alerts, incidents in the last 24 hours, WAN/Internet line status, expiring SSL certificates, and resources above thresholds.",
      _spec({"type": "schedule", "cron": "30 7 * * *"}, {"ssl_days": 14, "max_alerts": 8}), run=rpt01,
      kpi="Delivered on time 100%; IT no longer needs to compile the morning digest manually",
      fields=[F("ssl_days", "SSL expiration reminder (days)"), F("max_alerts", "Maximum number of alerts to include")]),
    T("RPT-02", "RPT", "Weekly Operations Report", "Uptime by site, incident count, MTTA/MTTR, top devices by incident count, key logs, and decisions required.",
      _spec({"type": "schedule", "cron": "0 8 * * 1"}, {"uptime_target": 99.5, "top_n": 5}), run=rpt02,
      kpi="Management can review within 24 hours without requesting additional data", data="Available · MTTA requires users to acknowledge incidents",
      fields=[F("uptime_target", "Uptime target (%)", step=0.1), F("top_n", "Top N devices")]),
    T("RPT-03", "RPT", "Monthly SLA report", "Last month uptime percentage by site and critical system versus target, downtime minutes, comparison with the previous month, and recommendations.",
      _spec({"type": "schedule", "cron": "0 8 1 * *"}, {"uptime_target": 99.5}), run=rpt03,
      kpi="Management receives SLA figures on time every month", data="Available (daily uptime aggregation) · accurate when the system runs continuously",
      fields=[F("uptime_target", "Uptime target (%)", step=0.1)]),
    T("RPT-04", "RPT", "Backup & Risks", "Critical systems without backups, single points of failure (SPOFs), and failing dependencies on the topology map.",
      _spec({"type": "schedule", "cron": "0 16 * * 5"}, {"skip_if_empty": True}), run=rpt04, data="Available (backup flag)",
      kpi="Zero High-criticality systems without backups", fields=[F("skip_if_empty", "Do not send when no risks are found", "bool")]),
    T("RPT-06", "RPT", "Asset Changes", "New assets, unresolved unknown sources, silent assets, and assets without an owner.",
      _spec({"type": "schedule", "cron": "0 9 1 * *"}, {"days": 30, "silent_days": 7}), run=rpt06,
      kpi="100% of assets have an assigned owner", fields=[F("days", "Reporting period (days)"), F("silent_days", "Silent for more than (days)")]),

    T("INC-01", "INC", "Group by Root Cause", "Parent device (firewall, switch, host) DOWN → suppress downstream device alerts and send one notification with the number of affected devices.",
      _spec({"type": "hook"}, level="L3"), hook=inc01_hook, preview=inc01_preview, triggers=["hook"], reversible=True, data="Available (parent-child tree on topology map)",
      kpi="No more than 2 notifications per incident"),
    T("INC-02", "INC", "Flapping Protection", "≥ N status changes within M minutes → group into one flapping notification and suppress individual notifications.",
      _spec({"type": "hook"}, {"changes": 3, "window_min": 10, "quiet_min": 60}, level="L3"), hook=inc02_hook, preview=inc02_preview, triggers=["hook"], reversible=True,
      kpi="No more repeated up/down notification sequences",
      fields=[F("changes", "Number of status changes"), F("window_min", "Within (minutes)"), F("quiet_min", "Suppress individual notifications (minutes)")]),
    T("INC-03", "INC", "Severity-based Escalation", "If an alert is not acknowledged within X minutes, notify the next escalation level (team lead, manager).",
      _spec({"type": "interval", "minutes": 1}, {"steps": [
          {"label": "Team lead", "after_min": 15, "severities": ["High"], "targets": []},
          {"label": "Manager", "after_min": 60, "severities": ["High"], "targets": []},
          {"label": "IT team (Medium)", "after_min": 30, "severities": ["Medium"], "targets": []}]}, level="L3"),
      run=inc03, triggers=["interval"], reversible=True, data="Available · recipients must be configured for each step",
      kpi="High-severity MTTA < 15 minutes", validate=_validate_steps, fields=[F("steps", "Escalation steps", "steps")]),
    T("INC-05", "INC", "Attach Runbook", "Attach 3–5 troubleshooting steps to alert notifications by check type (WAN, ping, SNMP, HTTP, SSH, CPU/RAM/Disk) or the critical-system runbook.",
      _spec({"type": "hook"}, {"rules": []}, level="L1"), hook=inc05_hook, preview=inc05_preview, triggers=["hook"], data="Available (default runbook + critical-system runbooks)",
      kpi="On-call staff can act immediately without asking for clarification", fields=[F("rules", "Runbook selected by keyword", "rules")]),
    T("INC-08", "INC", "User Notifications", "Critical system is DOWN for more than X minutes → notify the general group that it is experiencing an outage; when it recovers → send a recovery notification.",
      _spec({"type": "interval", "minutes": 1}, {"down_minutes": 10, "levels": ["High"],
                                                 "msg_down": "{system} is experiencing an outage. IT has been notified and is investigating. We will provide another update when the service is restored.",
                                                 "msg_up": "{system} has returned to normal (outage duration: approximately {minutes} minutes). Thank you for your patience."},
            level="L2"),
      run=inc08, triggers=["interval"], reversible=True, data="Available (critical systems + attached checks)",
      kpi="Users are informed of incidents before contacting IT",
      fields=[F("down_minutes", "Send after DOWN for (minutes)"), F("levels", "Criticality", "multi", options=["High", "Medium", "Low"]),
              F("msg_down", "Outage message template", "textarea"), F("msg_up", "Recovery message template", "textarea")]),

    T("PRE-01", "PRE", "Disk / Datastore Capacity Forecast", "Linear regression of disk usage (Linux, Windows, datastore, NAS volume); alert if the threshold is expected to be reached within N days.",
      _spec({"type": "schedule", "cron": "0 8 * * *"}, {"target_pct": 90, "horizon_days": 14, "window_days": 14, "min_hours": 24}), run=pre01,
      data="Available (CPU/RAM/Disk history) · accurate after ≥ 7 days", kpi="≥ 50% of disk-capacity incidents are predicted in advance",
      fields=[F("target_pct", "Full threshold (%)"), F("horizon_days", "Alert if full within (days)"), F("window_days", "Based on data from (days)"),
              F("min_hours", "Minimum data required (hours)")]),
    T("PRE-02", "PRE", "SSL Expiration", "Send reminders at 30 / 14 / 7 days; the final reminder is Critical. Automatically reset after renewal.",
      _spec({"type": "schedule", "cron": "0 9 * * *"}, {"days": [30, 14, 7]}), run=pre02, data="Available (HTTP check with SSL)",
      kpi="Zero incidents caused by expired SSL certificates", fields=[F("days", "Reminder thresholds (days)", "list")]),
    T("PRE-04", "PRE", "Unusual Latency Increase", "The latest 15-minute average exceeds the 7-day baseline by 3 standard deviations → raise an early alert before an outage.",
      _spec({"type": "interval", "minutes": 5}, {"sigma": 3, "recent_min": 15, "min_delta_ms": 5, "min_baseline_hours": 24, "cooldown_hours": 6}),
      run=pre04, data="Available (latency history) · accurate after ≥ 7 days", kpi="Detect network degradation before an outage",
      fields=[F("sigma", "Number of standard deviations", step=0.5), F("recent_min", "Recent window (minutes)"), F("min_delta_ms", "Minimum increase (ms)"),
              F("min_baseline_hours", "Minimum baseline duration (hours)"), F("cooldown_hours", "Do not repeat within (hours)")]),
    T("PRE-08", "PRE", "Log Anomaly", "The number of error logs/alerts in the past hour is X times the average for the same hour over the previous 7 days → include 10 representative lines.",
      _spec({"type": "interval", "minutes": 15}, {"multiplier": 3, "min_count": 30, "cooldown_hours": 3}), run=pre08, data="Available (device logs)",
      kpi="Detect abnormal device behavior through logs", fields=[F("multiplier", "Multiplier"), F("min_count", "Minimum (logs/hour)"),
                                                          F("cooldown_hours", "Do not repeat within (hours)")]),

    T("LCM-01", "LCM", "Maintenance Schedule", "During the maintenance window, suppress alerts from in-scope devices. Send a reminder 1 day beforehand; rerun all checks when the window ends and send the results.",
      _spec({"type": "hook"}, {"windows": [], "remind_hours": 24}, level="L3"), hook=lcm01_hook, run=lcm01, preview=lcm01_preview, tick=True, triggers=["hook"],
      reversible=True, validate=_validate_windows, kpi="Zero false alerts during maintenance windows",
      fields=[F("windows", "Maintenance windows", "windows"), F("remind_hours", "Remind in advance (hours)")]),
    T("LCM-02", "LCM", "Asset Onboarding", "New asset with no checks / unknown log source → suggest checks by asset type and a required checklist.",
      _spec({"type": "schedule", "cron": "0 9 * * *"}, {"days": 7}, level="L1"), run=lcm02, kpi="New assets have a check within 24 hours",
      fields=[F("days", "Assets created within (days)")]),
    T("LCM-03", "LCM", "Offboarding / Decommissioning", "Assets that have not responded for more than N days are flagged for archival. No automatic deletion or shutdown.",
      _spec({"type": "schedule", "cron": "0 9 * * 1"}, {"days": 30}, level="L1"), run=lcm03, kpi="Asset inventory stays aligned with reality",
      fields=[F("days", "No response for more than (days)")]),
    T("LCM-06", "LCM", "Periodic Data Review", "At the start of each quarter: review assets missing an owner/site, long-disabled checks, unmatched log rules, and accounts that have not signed in.",
      _spec({"type": "schedule", "cron": "0 9 1 1,4,7,10 *"}), run=lcm06, kpi="Clean asset data every quarter"),

    T("CUSTOM", "CUSTOM", "Custom Workflow", "Choose the trigger (schedule / interval / alert event), scope, content, and recipients.",
      _spec({"type": "schedule", "cron": "0 8 * * 1-5"}, content={"title": "Infrastructure status {time}", "blocks": ["overview", "open_alerts"]},
            send_when="always"),
      run=custom, wants_event=True, validate=_validate_custom),
]}

UNSUPPORTED = [
    ("RPT-05", "WAN and bandwidth", "WAN Mbps history is required (currently only the latest reading is stored)"),
    ("INC-04", "Handle directly in Telegram", "Requires a Telegram bot callback endpoint (the IT Ops host must have a public address)"),
    ("INC-06", "Controlled remediation", "Requires an allowlist of SSH commands and an approval step"),
    ("INC-07", "Incident record + postmortem", "Requires an incident record table"),
    ("PRE-03", "WAN nearing saturation", "Requires Mbps history and the contracted bandwidth for each link"),
    ("PRE-05", "Hardware health", "Requires Redfish (iLO/iDRAC) or normalized RAID/SMART traps"),
    ("PRE-06", "Backup verification", "Requires Veeam / Synology Active Backup integration and RPO data"),
    ("PRE-07", "Configuration changed", "Requires an SSH-based configuration archive"),
    ("LCM-04", "Warranty, licenses, and contracts", "Requires expiry date, vendor, and cost fields"),
    ("LCM-05", "Firmware / patches", "Requires a minimum-version table"),
    ("LCM-07", "Lifecycle-based replacement", "Requires a purchase date field"),
    ("LCM-08", "Recovery exercise", "Requires test results and RTO fields"),
]


def public_catalog():
    from .engine import describe_cron
    out = []
    for t in TEMPLATES.values():
        trg = t["spec"]["trigger"]
        when = describe_cron(trg["cron"]) if trg.get("type") == "schedule" else (
            f"every {trg['minutes']} minutes" if trg.get("type") == "interval" else "when an alert occurs" if trg.get("type") in ("hook", "event") else "")
        out.append({k: t[k] for k in ("code", "group", "name", "desc", "kpi", "data", "fields")} | {"spec": t["spec"], "when": when,
                                                                                                   "triggers": t["triggers"],
                                                                                                   "reversible": t["reversible"]})
    return {"templates": out, "unsupported": [{"code": c, "name": n, "reason": r} for c, n, r in UNSUPPORTED],
            "blocks": [{"key": k, "label": v[0]} for k, v in B.BLOCKS.items()], "placeholders": list(PLACEHOLDERS)}


__all__ = ["TEMPLATES", "public_catalog", "to_local", "to_utc_naive"]
