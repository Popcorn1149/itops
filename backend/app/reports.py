"""Monitoring reports (uptime over 1 / 7 / 14 / 30 days).

Raw check results live RETENTION_DAYS (default 14). So that 30-day (and later) reports still work, the scheduler
rolls them up every hour into two small tables kept REPORT_KEEP_DAYS (default 400):
  * check_daily   – per check per UTC day: runs, DOWN runs, latency min / sum / max
  * check_outages – one row per DOWN period (first DOWN result → first result back up)

Uptime has the same meaning as on the Monitoring page: share of runs that were NOT down. Threshold warnings
(CPU / RAM / disk, service errors) do not count against uptime.
"""
import logging
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from . import models
from .db import get_db
from .models import now
from .security import current_user

log = logging.getLogger("itops.reports")
router = APIRouter()

REPORT_KEEP_DAYS = int(os.environ.get("REPORT_KEEP_DAYS", "400"))
PERIODS = (1, 7, 14, 30)
CR = models.CheckResult
DOWN = or_(CR.down.is_(True), and_(CR.down.is_(None), CR.status == "fail", CR.metrics.is_(None)))   # same rule as /api/checks


def _midnight(t: datetime) -> datetime:
    return t.replace(hour=0, minute=0, second=0, microsecond=0)


def _gap(interval: int | None) -> timedelta:
    """Two DOWN results further apart than this are separate outages."""
    return timedelta(seconds=max(180, 2 * (interval or 60) + 30))


def _raw_stats(db: Session, start: datetime, end: datetime, check_ids=None):
    """{check_id: [total, down, lat_n, lat_sum, lat_min, lat_max]} from raw results in [start, end)."""
    up_lat = case((DOWN, None), else_=CR.latency)
    q = db.query(CR.check_id, func.count(), func.sum(case((DOWN, 1), else_=0)), func.count(up_lat), func.sum(up_lat),
                 func.min(up_lat), func.max(up_lat)).filter(CR.ts >= start, CR.ts < end)
    if check_ids is not None:
        q = q.filter(CR.check_id.in_(check_ids))
    return {cid: [n, int(d or 0), int(ln or 0), float(ls or 0), mn, mx] for cid, n, d, ln, ls, mn, mx in q.group_by(CR.check_id)}


def _rollup_days(db: Session, days: int) -> None:
    today = _midnight(now())
    for i in range(days - 1, -1, -1):
        d0 = today - timedelta(days=i)
        stats = _raw_stats(db, d0, d0 + timedelta(days=1))
        if not stats:
            continue
        db.query(models.CheckDaily).filter(models.CheckDaily.day == d0, models.CheckDaily.check_id.in_(list(stats))).delete(
            synchronize_session=False)
        for cid, (n, dn, ln, ls, mn, mx) in stats.items():
            db.add(models.CheckDaily(check_id=cid, day=d0, total=n, down=dn, lat_n=ln, lat_sum=ls, lat_min=mn, lat_max=mx))


def _rollup_outages(db: Session, days: int) -> None:
    since = now() - timedelta(days=days)
    intervals = dict(db.query(models.Check.id, models.Check.interval))
    rows = db.query(CR.check_id, CR.ts, CR.message).filter(CR.ts >= since, DOWN).order_by(CR.check_id, CR.ts).all()
    clusters = []                                         # [check_id, first_down, last_down, message]
    for cid, ts, msg in rows:
        c = clusters[-1] if clusters else None
        if c and c[0] == cid and ts - c[2] <= _gap(intervals.get(cid)):
            c[2] = ts
        else:
            clusters.append([cid, ts, ts, msg or ""])
    for cid, first, last, msg in clusters:
        back = db.query(func.min(CR.ts)).filter(CR.check_id == cid, CR.ts > last, ~DOWN).scalar()      # first result back up
        gap = _gap(intervals.get(cid))
        prev = (db.query(models.CheckOutage).filter(models.CheckOutage.check_id == cid, models.CheckOutage.start <= first,
                                                    or_(models.CheckOutage.end.is_(None), models.CheckOutage.end >= first - gap))
                .order_by(models.CheckOutage.start.desc()).first())
        if prev:                                          # same outage seen before (or it continues an earlier one)
            prev.end = back
        else:
            db.add(models.CheckOutage(check_id=cid, start=first, end=back, message=msg[:500]))


def rollup(db: Session, days: int = 2) -> None:
    """Refresh the summaries for the last `days` days from raw results and drop summaries older than REPORT_KEEP_DAYS."""
    _rollup_days(db, days)
    _rollup_outages(db, days)
    old = now() - timedelta(days=REPORT_KEEP_DAYS)
    db.query(models.CheckDaily).filter(models.CheckDaily.day < old).delete(synchronize_session=False)
    db.query(models.CheckOutage).filter(models.CheckOutage.start < old).delete(synchronize_session=False)
    db.commit()


def build_report(db: Session, days: int, site_id: int | None = None, check_ids: list[int] | None = None) -> dict:
    t_end = now()
    t_start = t_end - timedelta(days=days)
    rollup(db, 2)                                          # today / yesterday up to date
    checks = db.query(models.Check).order_by(models.Check.name)
    if site_id:
        checks = checks.filter(models.Check.site_id == site_id)
    if check_ids:
        checks = checks.filter(models.Check.id.in_(check_ids))
    checks = checks.all()
    ids = [c.id for c in checks]
    agg = {cid: [0, 0, 0, 0.0, None, None] for cid in ids}

    def add(cid, n, dn, ln, ls, mn, mx):
        a = agg[cid]
        a[0] += n; a[1] += dn; a[2] += ln; a[3] += ls   # noqa: E702
        a[4] = mn if a[4] is None else (a[4] if mn is None else min(a[4], mn))
        a[5] = mx if a[5] is None else (a[5] if mx is None else max(a[5], mx))

    first_full = _midnight(t_start) + timedelta(days=1)
    for cid, st in _raw_stats(db, t_start, min(first_full, t_end), ids).items():          # partial first day (raw, if still kept)
        add(cid, *st)
    if ids:
        for r in db.query(models.CheckDaily).filter(models.CheckDaily.day >= first_full, models.CheckDaily.check_id.in_(ids)):
            add(r.check_id, r.total, r.down, r.lat_n, r.lat_sum, r.lat_min, r.lat_max)

    outages = []
    if ids:
        q = (db.query(models.CheckOutage).filter(models.CheckOutage.check_id.in_(ids), models.CheckOutage.start < t_end,
                                                  or_(models.CheckOutage.end.is_(None), models.CheckOutage.end > t_start))
             .order_by(models.CheckOutage.start))
        outages = q.all()
    down_s, n_out = {}, {}
    names = {c.id: c.name for c in checks}
    out_rows = []
    for o in outages:
        s, e = max(o.start, t_start), min(o.end or t_end, t_end)
        sec = max(0, int((e - s).total_seconds()))
        down_s[o.check_id] = down_s.get(o.check_id, 0) + sec
        n_out[o.check_id] = n_out.get(o.check_id, 0) + 1
        out_rows.append({"check_id": o.check_id, "check": names.get(o.check_id, "?"), "start": o.start.isoformat() + "Z",
                         "end": o.end.isoformat() + "Z" if o.end else None, "seconds": sec, "message": o.message})

    sites = dict(db.query(models.Site.id, models.Site.name))
    rows = []
    for c in checks:
        n, dn, ln, ls, mn, mx = agg[c.id]
        rows.append({"id": c.id, "name": c.name, "type": c.type, "target": c.target, "site": sites.get(c.site_id, ""), "enabled": c.enabled,
                     "runs": n, "down_runs": dn, "uptime": round((n - dn) / n * 100, 3) if n else None,
                     "outages": n_out.get(c.id, 0), "downtime_s": down_s.get(c.id, 0),
                     "lat_min": round(mn, 1) if mn is not None else None, "lat_avg": round(ls / ln, 1) if ln else None,
                     "lat_max": round(mx, 1) if mx is not None else None})
    measured = [r for r in rows if r["runs"]]
    tot_n = sum(r["runs"] for r in measured)
    tot_d = sum(r["down_runs"] for r in measured)
    oldest = db.query(func.min(models.CheckDaily.day)).scalar()
    return {"days": days, "from": t_start.isoformat() + "Z", "to": t_end.isoformat() + "Z", "generated": t_end.isoformat() + "Z",
            "site": sites.get(site_id, "") if site_id else "", "check": ", ".join(c.name for c in checks) if check_ids and len(checks) <= 3 else
            (f"{len(checks)} selected checks" if check_ids else ""),
            "summary": {"checks": len(rows), "measured": len(measured), "uptime": round((tot_n - tot_d) / tot_n * 100, 3) if tot_n else None,
                        "outages": len(out_rows), "downtime_s": sum(down_s.values()),
                        "at_100": sum(1 for r in measured if r["down_runs"] == 0)},
            # data before this moment does not exist (ITOps was not collecting yet) → the report covers less than asked
            "data_since": oldest.isoformat() + "Z" if oldest else None,
            "checks": rows, "outage_list": out_rows}


@router.get("/api/reports/monitoring")
def monitoring_report(days: int = 7, site_id: int | None = None, check_id: int | None = None, check_ids: str = "",
                      user=Depends(current_user), db: Session = Depends(get_db)):
    """check_ids = "3,7,12" → only those checks (any mix of Internet lines, servers, …). check_id = one check."""
    days = days if days in PERIODS else 7
    ids = [int(x) for x in check_ids.replace(";", ",").split(",") if x.strip().isdigit()]
    if check_id:
        ids.append(check_id)
    return build_report(db, days, site_id, ids or None)
