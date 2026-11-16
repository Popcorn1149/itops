"""CVE module – part 4 (priority + SLA) and part 5 (overview, by machine, by CVE, alerts, morning digest, CSV report).

Priority 0–100 is computed by IT Ops only – from the CVE catalogue (CVSS, CISA KEV, EPSS) and how important the
machine is (Critical systems page). A source's own score is never used, so changing tools never changes priority.

    priority = CVSS × 6            (0–60; not scored yet → 5.0)
             + 25 if exploited in the wild (KEV)   + 5 if used by ransomware
             + EPSS percentile × 10 (0–10)
             + importance: critical system High +10 · Medium +5 · Low −5
    P1 ≥ 80 · P2 ≥ 60 · P3 ≥ 40 · P4 < 40

SLA (patch deadline) = confirmation time + days for its category (KEV, else CVSS severity); editable in the policy.
The clock starts when a finding is confirmed: high confidence, seen by 2 sources, or marked verified by a person.
False positives and accepted risk (until their review date) have no deadline.
"""
import asyncio
import csv
import io
import logging
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .vuln_groups import ATTACK_TYPES, attack_types
from . import models
from .db import SessionLocal, get_db
from .security import admin_user, current_user

log = logging.getLogger("itops.vuln")
router = APIRouter()

DEFAULT_POLICY = {
    "sla_days": {"kev": 1, "critical": 7, "high": 30, "medium": 90, "low": 180, "unscored": 30},
    "due_soon_days": 3,
    "alerts": {"enabled": True, "min_priority": 80, "kev": True},
    "digest": {"enabled": True, "hour": 8},
}
BANDS = ((80, "P1"), (60, "P2"), (40, "P3"), (0, "P4"))
IMPORTANCE = {"High": 10, "Medium": 5, "Low": -5}


def utcnow():
    from .vuln import utcnow as u
    return u()


def band(p: int) -> str:
    return next(b for lim, b in BANDS if (p or 0) >= lim)


def get_policy(db: Session) -> dict:
    row = db.get(models.Setting, "vuln_policy")
    v = (row.value if row else None) or {}
    out = {k: (dict(d) if isinstance(d, dict) else d) for k, d in DEFAULT_POLICY.items()}
    for k, d in v.items():
        if k in out and isinstance(out[k], dict) and isinstance(d, dict):
            out[k].update(d)
        elif k in out:
            out[k] = d
    return out


def importance_map(db: Session) -> dict:
    """target → importance level from Critical systems (highest level wins)."""
    rank = {"High": 3, "Medium": 2, "Low": 1}
    by_asset = {}
    for aid, level in db.query(models.CriticalSystem.asset_id, models.CriticalSystem.level).filter(models.CriticalSystem.asset_id.isnot(None)):
        if rank.get(level, 0) > rank.get(by_asset.get(aid), 0):
            by_asset[aid] = level
    out = {f"asset:{a}": lv for a, lv in by_asset.items()}
    for ag_id, asset_id in db.query(models.Agent.id, models.Agent.asset_id).filter(models.Agent.asset_id.isnot(None)):
        if asset_id in by_asset:
            out[f"agent:{ag_id}"] = by_asset[asset_id]
    return out


def score(cvss, kev: bool, ransomware: bool, epss_pct, importance: str | None) -> int:
    p = (cvss if cvss is not None else 5.0) * 6 + (25 if kev else 0) + (5 if ransomware else 0) + (epss_pct or 0) * 10
    p += IMPORTANCE.get(importance or "", 0)
    return int(round(max(0, min(100, p))))


def category(kev: bool, severity: str) -> str:
    if kev:
        return "kev"
    return severity if severity in ("critical", "high", "medium", "low") else "unscored"


def confirmed(f: models.VulnFinding) -> bool:
    return f.confidence == "high" or (f.sources_active or 0) >= 2 or bool(f.verified)


def refresh(db: Session, ids=None) -> int:
    """Recompute priority, SLA category, clock start and deadline for open findings (all, or the given ids)."""
    pol = get_policy(db)
    days = pol["sla_days"]
    imp = importance_map(db)
    now = utcnow()
    q = (db.query(models.VulnFinding, models.Cve).outerjoin(models.Cve, models.Cve.cve_id == models.VulnFinding.cve_id))
    if ids is not None:
        ids = list(set(ids))
        if not ids:
            return 0
    n = 0
    for part in ([ids[i:i + 1000] for i in range(0, len(ids), 1000)] if ids is not None else [None]):
        qq = q.filter(models.VulnFinding.id.in_(part)) if part is not None else q.filter(models.VulnFinding.status == "open")
        for f, c in qq:
            cvss = c.cvss_score if c and c.cvss_score is not None else f.provider_score
            sev = (c.cvss_severity if c and c.cvss_severity else f.provider_severity) or ""
            kev = bool(c and c.kev)
            f.priority = score(cvss, kev, bool(c and c.kev_ransomware), c.epss_percentile if c else None, imp.get(f.target))
            f.sla_category = category(kev, sev)
            if f.status == "open":
                if f.sla_start is None and confirmed(f):
                    f.sla_start = f.first_seen if (f.confidence == "high" and not f.reopened) else now
                f.due_at = f.sla_start + timedelta(days=float(days.get(f.sla_category, 30))) if f.sla_start else None
            n += 1
    db.flush()
    return n


def sla_state(f: models.VulnFinding, triage: str, now, soon_days: int) -> str:
    if f.status != "open" or triage:
        return "none"
    if not f.due_at:
        return "awaiting_verification"
    if f.due_at < now:
        return "overdue"
    if f.due_at < now + timedelta(days=soon_days):
        return "due_soon"
    return "on_track"


# ------------------------------------------------------------------ alerts + morning digest
def _label(db, targets) -> dict:
    from .vuln import _names
    return {t: v["name"] for t, v in _names(db, targets).items()}


async def send_alerts() -> dict:
    """One message per run for new confirmed findings that are exploited (KEV) or reach the alert priority."""
    from .notify import notify
    from .vuln import _untriaged
    with SessionLocal() as db:
        pol = get_policy(db)["alerts"]
        if not pol.get("enabled"):
            return {"sent": 0}
        now = utcnow()
        cond = models.VulnFinding.priority >= int(pol.get("min_priority") or 80)
        if pol.get("kev", True):
            cond = cond | (models.VulnFinding.sla_category == "kev")
        rows = (db.query(models.VulnFinding).filter(models.VulnFinding.status == "open", models.VulnFinding.alerted_at.is_(None),
                                                    models.VulnFinding.sla_start.isnot(None), _untriaged(now), cond)
                .order_by(models.VulnFinding.priority.desc()).all())
        if not rows:
            return {"sent": 0}
        names = _label(db, {f.target for f in rows})
        lines = [f"{band(f.priority)} {f.priority} · {f.cve_id}{' · KEV' if f.sla_category == 'kev' else ''} · {names.get(f.target, f.target)}"
                 f" · due {f.due_at:%d/%m}" for f in rows[:15]]
        if len(rows) > 15:
            lines.append(f"… and {len(rows) - 15} more – see IT Ops › Vulnerabilities")
        for f in rows:
            f.alerted_at = now
        db.commit()
    kev_n = sum(1 for f in rows if f.sla_category == "kev")
    await notify(f"{len(rows)} new urgent vulnerabilit{'y' if len(rows) == 1 else 'ies'}" + (f" ({kev_n} exploited in the wild)" if kev_n else ""),
                 "\n".join(lines), "critical")
    return {"sent": len(rows)}


def digest_text(db: Session) -> tuple[str, str] | None:
    from .vuln import _untriaged
    now = utcnow()
    pol = get_policy(db)
    base = db.query(models.VulnFinding).filter(models.VulnFinding.status == "open", _untriaged(now))
    overdue = base.filter(models.VulnFinding.due_at < now).order_by(models.VulnFinding.priority.desc()).all()
    soon = base.filter(models.VulnFinding.due_at >= now, models.VulnFinding.due_at < now + timedelta(days=pol["due_soon_days"])).count()
    new24 = db.query(func.count(models.VulnFinding.id)).filter(models.VulnFinding.first_seen >= now - timedelta(hours=24)).scalar() or 0
    fixed24 = db.query(func.count(models.VulnFinding.id)).filter(models.VulnFinding.fixed_at >= now - timedelta(hours=24)).scalar() or 0
    kev = base.filter(models.VulnFinding.sla_category == "kev").count()
    verify = base.filter(models.VulnFinding.sla_start.is_(None)).count()
    if not (overdue or soon or new24 or kev):
        return None
    names = _label(db, {f.target for f in overdue[:10]})
    lines = [f"Overdue: {len(overdue)} · due in {pol['due_soon_days']} days: {soon} · exploited (KEV) open: {kev}",
             f"Last 24 h: {new24} new · {fixed24} fixed · awaiting verification: {verify}"]
    if overdue:
        lines.append("")
        lines += [f"{band(f.priority)} {f.cve_id} · {names.get(f.target, f.target)} · {(now - f.due_at).days + 1} d overdue" for f in overdue[:10]]
        if len(overdue) > 10:
            lines.append(f"… and {len(overdue) - 10} more")
    return f"Vulnerabilities – morning digest ({len(overdue)} overdue)", "\n".join(lines)


async def send_digest(force=False) -> dict:
    from .notify import notify
    with SessionLocal() as db:
        t = digest_text(db)
        if not t:
            return {"sent": False, "reason": "nothing to report"}
        row = db.get(models.Setting, "vuln_digest_last")
        today = datetime.now().date().isoformat()
        if row and row.value == today and not force:
            return {"sent": False, "reason": "already sent today"}
        if row:
            row.value = today
        else:
            db.add(models.Setting(key="vuln_digest_last", value=today))
        db.commit()
    res = await notify(t[0], t[1], "warning")
    return {"sent": True, "channels": res}


async def loop():
    """Hourly: refresh priorities / deadlines (the clock moves, KEV/EPSS change); morning digest at the policy hour (local time)."""
    if os.environ.get("VULN_SYNC", "1").lower() in ("0", "false", "no"):
        return
    await asyncio.sleep(180)
    while True:
        try:
            with SessionLocal() as db:
                refresh(db)
                db.commit()
                dg = get_policy(db)["digest"]
            await send_alerts()
            if dg.get("enabled") and datetime.now().hour >= int(dg.get("hour", 8)):
                await send_digest()
        except Exception as e:
            log.warning("vulnerability policy loop: %s", e)
        await asyncio.sleep(3600)


# ------------------------------------------------------------------ API: policy
@router.get("/api/vuln/policy")
def read_policy(user=Depends(current_user), db: Session = Depends(get_db)):
    return {**get_policy(db), "defaults": DEFAULT_POLICY}


@router.put("/api/vuln/policy")
def write_policy(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    old = get_policy(db)
    new = get_policy(db)
    try:
        for k, v in (body.get("sla_days") or {}).items():
            if k in new["sla_days"]:
                d = float(v)
                if not 0 < d <= 3650:
                    raise ValueError
                new["sla_days"][k] = d if d % 1 else int(d)
        if "due_soon_days" in body:
            new["due_soon_days"] = max(1, min(30, int(body["due_soon_days"])))
        a = body.get("alerts") or {}
        new["alerts"].update({k: a[k] for k in ("enabled", "kev") if k in a})
        if "min_priority" in a:
            new["alerts"]["min_priority"] = max(0, min(100, int(a["min_priority"])))
        g = body.get("digest") or {}
        if "enabled" in g:
            new["digest"]["enabled"] = bool(g["enabled"])
        if "hour" in g:
            new["digest"]["hour"] = max(0, min(23, int(g["hour"])))
    except (TypeError, ValueError):
        raise HTTPException(400, "Days must be numbers between 1 and 3650; priority 0–100; hour 0–23")
    row = db.get(models.Setting, "vuln_policy")
    if row:
        row.value = new
    else:
        db.add(models.Setting(key="vuln_policy", value=new))
    db.flush()
    refresh(db)
    changes = [f"{k}: {old[k]} → {new[k]}" for k in new if old[k] != new[k]]
    audit(db, user.username, "update", "vuln_policy", None, detail="Vulnerability policy: " + ("; ".join(changes) or "no change"))
    db.commit()
    return get_policy(db)


@router.post("/api/vuln/digest/test")
async def test_digest(user=Depends(admin_user), db: Session = Depends(get_db)):
    t = digest_text(db)
    if not t:
        return {"sent": False, "reason": "Nothing to report right now (no overdue, due-soon, new or KEV findings)"}
    return await send_digest(force=True)


# ------------------------------------------------------------------ API: overview, by machine, by CVE, CSV
def _open_untriaged(db):
    from .vuln import _untriaged
    return db.query(models.VulnFinding).filter(models.VulnFinding.status == "open", _untriaged(utcnow()))


@router.get("/api/vuln/overview")
def overview(user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    pol = get_policy(db)
    rows = _open_untriaged(db).with_entities(models.VulnFinding.id, models.VulnFinding.target, models.VulnFinding.cve_id,
                                             models.VulnFinding.priority, models.VulnFinding.due_at, models.VulnFinding.sla_category).all()
    by_band = {b: 0 for _, b in BANDS}
    overdue_band = {b: 0 for _, b in BANDS}
    soon = verify = kev = 0
    machines, cves = {}, {}
    for _id, t, cid, p, due, cat in rows:
        b = band(p)
        by_band[b] += 1
        kev += cat == "kev"
        if due is None:
            verify += 1
        elif due < now:
            overdue_band[b] += 1
        elif due < now + timedelta(days=pol["due_soon_days"]):
            soon += 1
        m = machines.setdefault(t, {"target": t, "open": 0, "max_priority": 0, "overdue": 0, "kev": 0})
        m["open"] += 1
        m["max_priority"] = max(m["max_priority"], p)
        m["overdue"] += bool(due and due < now)
        m["kev"] += cat == "kev"
        c = cves.setdefault(cid, {"cve_id": cid, "machines": 0, "max_priority": 0, "overdue": 0, "kev": cat == "kev"})
        c["machines"] += 1
        c["max_priority"] = max(c["max_priority"], p)
        c["overdue"] += bool(due and due < now)
    names = _label(db, set(machines))
    top_m = sorted(machines.values(), key=lambda m: (-m["overdue"], -m["max_priority"], -m["open"]))[:8]
    for m in top_m:
        m["name"] = names.get(m["target"], m["target"])
        m["band"] = band(m["max_priority"])
    top_c = sorted(cves.values(), key=lambda c: (-c["max_priority"], -c["machines"]))[:8]
    for c in top_c:
        c["band"] = band(c["max_priority"])
    # 30-day trend: new vs fixed per day
    start = (now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    new_d = dict(db.query(func.date(models.VulnFinding.first_seen), func.count()).filter(models.VulnFinding.first_seen >= start)
                 .group_by(func.date(models.VulnFinding.first_seen)).all())
    fix_d = dict(db.query(func.date(models.VulnFinding.fixed_at), func.count()).filter(models.VulnFinding.fixed_at >= start)
                 .group_by(func.date(models.VulnFinding.fixed_at)).all())
    trend = []
    for i in range(30):
        d = (start + timedelta(days=i)).date()
        trend.append({"day": d.isoformat(), "new": new_d.get(d, 0), "fixed": fix_d.get(d, 0)})
    fixed30 = db.query(models.VulnFinding.fixed_at, models.VulnFinding.due_at).filter(models.VulnFinding.fixed_at >= now - timedelta(days=30)).all()
    with_due = [(fx, du) for fx, du in fixed30 if du]
    on_time = round(sum(1 for fx, du in with_due if fx <= du) / len(with_due) * 100) if with_due else None
    srcs = db.query(models.VulnSource).all()
    from .vuln import is_stale
    return {"open": len(rows), "by_band": by_band, "overdue": sum(overdue_band.values()), "overdue_by_band": overdue_band,
            "due_soon": soon, "due_soon_days": pol["due_soon_days"], "awaiting_verification": verify, "kev": kev,
            "machines": len(machines), "fixed_30d": len(fixed30), "on_time_pct": on_time, "trend": trend,
            "top_machines": top_m, "top_cves": top_c,
            "sources": [{"id": s.id, "name": s.name, "enabled": s.enabled, "ok": (s.state or {}).get("ok"),
                         "stale": s.enabled and bool((s.state or {}).get("at")) and is_stale(s, now), "at": (s.state or {}).get("at")} for s in srcs]}


@router.get("/api/vuln/by-machine")
def by_machine(q: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    agg = {}
    for t, p, due, cat in _open_untriaged(db).with_entities(models.VulnFinding.target, models.VulnFinding.priority,
                                                             models.VulnFinding.due_at, models.VulnFinding.sla_category):
        m = agg.setdefault(t, {"target": t, "open": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0, "max_priority": 0, "overdue": 0, "kev": 0,
                               "next_due": None})
        m["open"] += 1
        m[band(p)] += 1
        m["max_priority"] = max(m["max_priority"], p)
        m["overdue"] += bool(due and due < now)
        m["kev"] += cat == "kev"
        if due and (m["next_due"] is None or due < m["next_due"]):
            m["next_due"] = due
    from .vuln import _iso, _names
    names = _names(db, set(agg))
    imp = importance_map(db)
    out = []
    for m in agg.values():
        n = names.get(m["target"], {"name": m["target"], "ip": "", "kind": ""})
        if q and q.lower() not in f"{n['name']} {n['ip']}".lower():
            continue
        out.append({**m, "name": n["name"], "ip": n["ip"], "kind": n["kind"], "band": band(m["max_priority"]),
                    "importance": imp.get(m["target"], ""), "next_due": _iso(m["next_due"])})
    return sorted(out, key=lambda m: (-m["overdue"], -m["max_priority"], -m["open"]))


@router.get("/api/vuln/by-cve")
def by_cve(q: str = "", attack: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    agg = {}
    for cid, p, due, cat in _open_untriaged(db).with_entities(models.VulnFinding.cve_id, models.VulnFinding.priority,
                                                               models.VulnFinding.due_at, models.VulnFinding.sla_category):
        if q and q.upper() not in cid:
            continue
        c = agg.setdefault(cid, {"cve_id": cid, "machines": 0, "max_priority": 0, "overdue": 0, "kev": cat == "kev", "next_due": None})
        c["machines"] += 1
        c["max_priority"] = max(c["max_priority"], p)
        c["overdue"] += bool(due and due < now)
        if due and (c["next_due"] is None or due < c["next_due"]):
            c["next_due"] = due
    from .vuln import _iso
    ids, cat_rows = list(agg), {}
    for i in range(0, len(ids), 5000):                     # chunks: big IN lists are slow, but every CVE must get its details
        cat_rows.update({c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_(ids[i:i + 5000]))})
    out = []
    for c in agg.values():
        x = cat_rows.get(c["cve_id"])
        kinds = attack_types(x.cwe if x else [])
        if attack and (attack not in kinds if attack != "none" else bool(kinds)):
            continue
        out.append({**c, "band": band(c["max_priority"]), "next_due": _iso(c["next_due"]), "cvss_score": x.cvss_score if x else None,
                    "cvss_severity": x.cvss_severity if x else "", "epss": x.epss if x else None, "kev_ransomware": bool(x and x.kev_ransomware),
                    "description": ((x.description if x else "") or "")[:200], "products": (x.products if x else [])[:3],
                    "attack": [ATTACK_TYPES[k][0] for k in attack_types(x.cwe if x else [])]})
    return sorted(out, key=lambda c: (-c["max_priority"], -c["machines"]))


@router.get("/api/vuln/export.csv")
def export_csv(q: str = "", status: str = "open", severity: str = "", kev: bool = False, source_id: int = 0, confidence: str = "",
               needs_verification: bool = False, triage: str = "none", target: str = "", band: str = "", sla: str = "", cve: str = "",
               attack: str = "", sort: str = "priority", dir: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    """Exactly what the Findings list shows with the same filters and order (all pages)."""
    from .vuln import findings_query, _finding_rows, order_findings
    now = utcnow()
    rows = findings_query(db, q=q, status=status, severity=severity, kev=kev, source_id=source_id, confidence=confidence,
                          needs_verification=needs_verification, triage=triage, target=target, band=band, sla=sla, cve=cve, attack=attack) \
        .order_by(*order_findings(sort, dir)).limit(100000).all()
    items = _finding_rows(db, rows, now)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Priority", "Score", "Machine", "IP", "CVE", "CVSS", "Severity", "KEV", "EPSS", "Packages", "Confidence", "Status",
                "Triage", "First seen", "SLA", "Due", "Days overdue", "Sources"])
    for f in items:
        w.writerow([f["band"], f["priority"], f["target_name"], f["target_ip"], f["cve_id"], f["cvss_score"] if f["cvss_score"] is not None else "",
                    f["cvss_severity"], "yes" if f["kev"] else "", f["epss"] if f["epss"] is not None else "", "; ".join(f["packages"]),
                    f["confidence"], f["status"], f["triage"], (f["first_seen"] or "")[:10], f["sla_state"], (f["due_at"] or "")[:10],
                    f["overdue_days"] or "", "; ".join(f["sources"])])
    data = "﻿" + buf.getvalue()                                  # BOM so Excel opens UTF-8 correctly
    name = f"vulnerabilities-{datetime.now():%Y%m%d-%H%M}.csv"
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})
