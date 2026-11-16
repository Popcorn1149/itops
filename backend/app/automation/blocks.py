"""Shared content blocks for reports (RPT-* templates and custom workflows).

Each block returns (title, [lines], item count). A count of 0 means "nothing to report"."""
from datetime import timedelta

from sqlalchemy import func

from .. import models
from ..models import now
from .engine import expand_sevs, in_scope, to_local, to_utc_naive, uptime_between

SEV_LABEL = {"down": "DOWN", "critical": "Critical", "trouble": "Trouble", "warning": "Trouble", "attention": "Attention"}
HIGH = ("down", "critical")


def _assets(db):
    return {a.id: a for a in db.query(models.Asset).all()}


def _sites(db):
    return {s.id: s.name for s in db.query(models.Site).all()}


def _site_of(obj, assets):
    sid = getattr(obj, "site_id", None)
    if sid:
        return sid
    a = assets.get(getattr(obj, "asset_id", None))
    return a.site_id if a else None


def fmt_dur(minutes: float) -> str:
    m = int(round(minutes))
    if m < 60:
        return f"{m} minutes"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} hours {m} minutes" if m else f"{h} hours"
    d, h = divmod(h, 24)
    return f"{d} days {h} hours"


def fmt_local(dt) -> str:
    t = to_local(dt)
    return t.strftime("%H:%M %d/%m") if t else "?"


# ---------------------------------------------------------------- khối
def overview(db, scope, **_):
    assets = _assets(db)
    sel = [a for a in assets.values() if in_scope(scope, site_id=a.site_id, asset=a)]
    ok = sum(1 for a in sel if a.status in ("up",))
    bad = [a for a in sel if a.status in ("down", "warning")]
    alerts = [al for al in open_alerts_q(db, scope, assets)]
    high = sum(1 for a in alerts if a.severity in HIGH)
    lines = [f"Assets: {ok}/{len(sel)} OK" + (f" · {len(bad)} in error/warning state" if bad else ""),
             f"Open alerts: {len(alerts)}" + (f" ({high} DOWN/Critical)" if high else "")]
    return "Overview", lines, len(bad) + len(alerts)


def open_alerts_q(db, scope, assets=None):
    assets = assets or _assets(db)
    out = []
    for al in db.query(models.Alert).filter(models.Alert.status != "resolved").order_by(models.Alert.opened_at):
        if in_scope(scope, site_id=_site_of(al, assets), asset=assets.get(al.asset_id), severity=al.severity, name=al.title):
            out.append(al)
    return out


def open_alerts(db, scope, limit=10, **_):
    assets = _assets(db)
    al = open_alerts_q(db, scope, assets)
    order = {"down": 0, "critical": 1, "trouble": 2, "warning": 2, "attention": 3}
    al.sort(key=lambda a: (order.get(a.severity, 4), a.opened_at))
    lines = [f"- [{SEV_LABEL.get(a.severity, a.severity)}] {a.title} (from {fmt_local(a.opened_at)})" + (" · acknowledged" if a.status == "acknowledged" else "")
             for a in al[:limit]]
    if len(al) > limit:
        lines.append(f"… and {len(al) - limit} more alerts")
    return "Open alerts", lines or ["None"], len(al)


def incidents(db, scope, hours=24, **_):
    assets = _assets(db)
    since = now() - timedelta(hours=hours)
    al = [a for a in db.query(models.Alert).filter(models.Alert.opened_at >= since)
          if in_scope(scope, site_id=_site_of(a, assets), asset=assets.get(a.asset_id), severity=a.severity, name=a.title)]
    closed = sum(1 for a in al if a.status == "resolved")
    lines = [f"{len(al)} incidents in the last {hours} hours, {closed} closed"] if al else [f"No incidents in the last {hours} hours"]
    return f"Last {hours} hours", lines, len(al)


def wan_lines(db, scope, **_):
    from ..topology import internet_lines
    sites = _sites(db)
    lines, n_down, total = [], 0, 0
    for sid, ls in internet_lines(db).items():
        if not in_scope(scope, site_id=sid):
            continue
        down = sum(1 for x in ls if x["down"])
        n_down += down
        total += len(ls)
        lines.append(f"{sites.get(sid, 'No site assigned')}: {len(ls) - down}/{len(ls)} line" + (f" · {down} down" if down else "")
                     + "".join(f" · {x['name']} {x['latency_ms']:g} ms" for x in ls if x.get("latency_ms") is not None and not x["down"])[:200])
    # thêm WAN đọc from firewall (SNMP/API) nếu có
    assets = _assets(db)
    for c in db.query(models.Check).filter(models.Check.enabled == True):  # noqa: E712
        a = assets.get(c.asset_id)
        d = c.last_data or {}
        if a and a.type == "firewall" and d.get("wan_total") and in_scope(scope, site_id=a.site_id, asset=a):
            mb = f" · ↓{d['wan_in_mbps']:g} ↑{d['wan_out_mbps']:g} Mbps" if d.get("wan_in_mbps") is not None else ""
            lines.append(f"{a.name}: WAN {d.get('wan_up', 0)}/{d['wan_total']} up{mb}")
    return "Internet / WAN", lines or ["No Internet links assigned"], n_down


def ssl_expiring(db, scope, days=14, **_):
    assets = _assets(db)
    rows = []
    for c in db.query(models.Check).filter(models.Check.type == "http", models.Check.enabled == True):  # noqa: E712
        d = (c.last_data or {}).get("cert_days")
        if d is not None and d <= days and in_scope(scope, site_id=_site_of(c, assets), asset=assets.get(c.asset_id), name=c.name):
            rows.append((d, c))
    rows.sort(key=lambda x: x[0])
    lines = [f"- SSL {c.target.split('://')[-1].split('/')[0]}: {'EXPIRED' if d < 0 else f'remaining {d} days'}" for d, c in rows]
    return f"SSL expires in {days} days", lines or ["None"], len(rows)


def resources_top(db, scope, n=5, **_):
    from ..main import resources_view
    v = resources_view(db)
    rows = [r for r in v["rows"] if r["level"] != "ok" and in_scope(scope, site_id=r.get("site_id"), name=r["name"])]
    lines = []
    for r in rows[:n]:
        parts = [f"{k} {r[key]:g}%" for k, key in (("CPU", "cpu"), ("RAM", "mem"), ("Disk", "disk")) if r.get(key) is not None
                 and (r["levels"].get(key) or "ok") != "ok"]
        lines.append(f"- {r['name']}: {', '.join(parts)} ({SEV_LABEL.get(r['level'], r['level'])})")
    return "Resources above threshold", lines or ["None"], len(rows)


def log_top(db, scope, hours=24, n=5, **_):
    since = now() - timedelta(hours=hours)
    q = db.query(models.Event.source_ip, func.max(models.Event.host), func.count()).filter(
        models.Event.ts >= since, models.Event.severity <= 4, models.Event.source_ip != "127.0.0.1").group_by(models.Event.source_ip) \
        .order_by(func.count().desc()).limit(n)
    lines = [f"- {h or ip} ({ip}): {cnt} error logs/alerts" for ip, h, cnt in q]
    return f"Most error logs/alerts ({hours} hours)", lines or ["None"], len(lines)


def uptime_by_site(db, scope, days=7, end=None, **_):
    """Uptime = tỉ lệ lần chạy không DOWN. end = hours VN kết thúc kỳ (mặc định bây hours)."""
    from .engine import local_now
    end = end or local_now()
    start = end - timedelta(days=days)
    assets = _assets(db)
    sites = _sites(db)
    checks = [c for c in db.query(models.Check) if in_scope(scope, site_id=_site_of(c, assets), asset=assets.get(c.asset_id))]
    up = uptime_between(db, [c.id for c in checks], start, end)
    by = {}
    for c in checks:
        t = up.get(c.id)
        if not t or not t[0]:
            continue
        b = by.setdefault(_site_of(c, assets), [0, 0, 0.0])
        b[0] += t[0]; b[1] += t[1]; b[2] += t[2]
    lines, worst = [], 100.0
    for sid, (tot, dn, mins) in sorted(by.items(), key=lambda x: (x[1][0] - x[1][1]) / x[1][0]):
        pct = (tot - dn) / tot * 100
        worst = min(worst, pct)
        lines.append(f"- {sites.get(sid, 'No site assigned')}: {pct:.2f}%" + (f" · DOWN {fmt_dur(mins)}" if dn else ""))
    return f"Uptime by site (last {days} days)", lines or ["No data available"], len(lines)


def mtta_mttr(db, scope, days=7, **_):
    assets = _assets(db)
    since = now() - timedelta(days=days)
    al = [a for a in db.query(models.Alert).filter(models.Alert.opened_at >= since, models.Alert.source != "event")
          if in_scope(scope, site_id=_site_of(a, assets), asset=assets.get(a.asset_id), severity=a.severity)]
    acks = [(a.acked_at - a.opened_at).total_seconds() / 60 for a in al if a.acked_at]
    fixes = [(a.resolved_at - a.opened_at).total_seconds() / 60 for a in al if a.resolved_at]
    lines = [f"Incidents: {len(al)} ({sum(1 for a in al if a.severity in HIGH)} DOWN/Critical)",
             f"MTTA (time until acknowledgment): {fmt_dur(sum(acks) / len(acks)) if acks else 'no one acknowledged'}",
             f"MTTR (time to resolution): {fmt_dur(sum(fixes) / len(fixes)) if fixes else 'no incidents resolved'}"]
    return "Incidents", lines, len(al)


def top_noisy(db, scope, days=7, n=5, **_):
    assets = _assets(db)
    since = now() - timedelta(days=days)
    cnt: dict = {}
    for a in db.query(models.Alert).filter(models.Alert.opened_at >= since):
        key = assets[a.asset_id].name if a.asset_id in assets else a.title.split(" ")[0]
        if in_scope(scope, site_id=_site_of(a, assets), asset=assets.get(a.asset_id)):
            cnt[key] = cnt.get(key, 0) + 1
    top = sorted(cnt.items(), key=lambda x: -x[1])[:n]
    return f"Top {n} devices by incident count", [f"- {k}: {v} occurrences" for k, v in top] or ["None"], len(top)


def backup_risks(db, scope, **_):
    """Rủi ro trên bản đồ: critical systems chưa backup, điểm đơn lẻ (SPOF), depends on đang error..."""
    from ..topology import build_risks
    risks = build_risks(db)
    risks.sort(key=lambda r: {"high": 0, "medium": 1}.get(r.get("severity"), 2))
    lines = [f"- [{'Cao' if r.get('severity') == 'high' else 'TB' if r.get('severity') == 'medium' else 'Low'}] {r['title']}"
             + (f": {r['detail']}" if r.get("detail") else "") for r in risks[:12]]
    if len(risks) > 12:
        lines.append(f"… and {len(risks) - 12} other items")
    return "Backup & Risks", lines or ["No critical systems are missing backups or risk indicators"], len(risks)


def asset_changes(db, scope, days=30, silent_days=7, **_):
    assets = [a for a in _assets(db).values() if in_scope(scope, site_id=a.site_id, asset=a)]
    since = now() - timedelta(days=days)
    new = [a for a in assets if a.created_at and a.created_at >= since]
    silent = [a for a in assets if a.last_seen and a.last_seen < now() - timedelta(days=silent_days)]
    no_owner = [a for a in assets if not (a.owner or "").strip() and a.type not in ("vm", "container")]
    unknown = unknown_sources(db, days)
    lines = [f"New assets ({days} days): {len(new)}" + (" – " + ", ".join(a.name for a in new[:8]) if new else ""),
             f"Unrecognized log sources: {len(unknown)}" + (" – " + ", ".join(ip for ip, _ in unknown[:8]) if unknown else ""),
             f"Silent for > {silent_days} days: {len(silent)}" + (" – " + ", ".join(a.name for a in silent[:8]) if silent else ""),
             f"Missing owner: {len(no_owner)}" + (" – " + ", ".join(a.name for a in no_owner[:8]) if no_owner else "")]
    return "Asset Changes", lines, len(new) + len(unknown) + len(silent) + len(no_owner)


def unknown_sources(db, days=30):
    since = now() - timedelta(days=days)
    q = db.query(models.Event.source_ip, func.count()).filter(models.Event.ts >= since, models.Event.asset_id.is_(None),
                                                             models.Event.source_ip != "127.0.0.1").group_by(models.Event.source_ip)
    return [(ip, n) for ip, n in q]


BLOCKS = {
    "overview": ("Overview assets + alerts", overview),
    "open_alerts": ("Open alerts", open_alerts),
    "incidents": ("Incidents in the last N hours", incidents),
    "wan_lines": ("Internet / WAN", wan_lines),
    "ssl_expiring": ("SSL certificates expiring soon", ssl_expiring),
    "resources_top": ("Resources above threshold", resources_top),
    "log_top": ("Top error logs", log_top),
    "uptime_by_site": ("Uptime theo site", uptime_by_site),
    "mtta_mttr": ("Incident count, MTTA, MTTR", mtta_mttr),
    "top_noisy": ("Devices with the most incidents", top_noisy),
    "backup_risks": ("Backup & Risks", backup_risks),
    "asset_changes": ("Asset Changes", asset_changes),
}


def render(db, scope, names, params=None, header=True) -> tuple[str, int]:
    params = params or {}
    parts, items = [], 0
    for n in names:
        if n not in BLOCKS:
            continue
        title, lines, cnt = BLOCKS[n][1](db, scope, **params)
        items += cnt
        parts.append((f"{title}:\n" if header else "") + "\n".join(lines))
    return "\n\n".join(parts), items


__all__ = ["BLOCKS", "render", "expand_sevs", "to_utc_naive"]
