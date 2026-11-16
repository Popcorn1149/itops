"""CVE module – part 3: vulnerability findings (which CVE is on which machine).

Design (decision recorded in README → Roadmap):
  * IT Ops is the core: machines, findings, history, triage and (part 4) priority / SLA live here.
  * Sources are replaceable adapters in app/vulnsrc/ (Wazuh read-only, file import, IT Ops CPE matching).
  * Findings are keyed by (machine, CVE), never by source → switching tools keeps first_seen, triage and SLA.
  * Priority never uses a source's score; that score is kept for reference only.
  * Confidence is a gate, not a weight: low / medium results are flagged "needs verification".
  * Disabling a source never marks its findings fixed: they become "source_off".
  * Each source has a freshness check: results older than its stale limit are labelled stale.
"""
import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.orm import Session

from .vuln_groups import ATTACK_TYPES, attack_types
from . import cve as cve_mod
from . import models
from .db import SessionLocal, get_db
from .inventory import valid_serial
from .security import MASK, SECRET_FIELDS, admin_user, current_user, open_config, seal_config
from . import vuln_policy
from .vulnsrc import CONFIDENCE, PROVIDERS, Snapshot, SourceError

log = logging.getLogger("itops.vuln")
router = APIRouter()
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RANK = {"low": 1, "medium": 2, "high": 3}
_locks: dict[int, asyncio.Lock] = {}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(d):
    return d.isoformat() + "Z" if d else None


def _short(h: str) -> str:
    return (h or "").strip().lower().split(".")[0]


# ------------------------------------------------------------------ host → machine matching
def resolve_hosts(db: Session, source: models.VulnSource, hosts) -> tuple[dict, list]:
    """Map source hosts to IT Ops machines. Order: manual mapping → serial → host name → IP.
    Never guesses: an ambiguous host stays unmatched so the admin can map it by hand."""
    mapping = dict((source.config or {}).get("mapping") or {})
    agents = db.query(models.Agent).filter(models.Agent.revoked_at.is_(None)).all()
    assets = db.query(models.Asset).all()
    idx = {"serial": {}, "name": {}, "ip": {}}

    def add(kind, key, target):
        if key:
            idx[kind].setdefault(key, set()).add(target)
    for a in agents:
        t = f"agent:{a.id}"
        if valid_serial(a.serial):
            add("serial", a.serial.strip().upper(), t)
        add("name", _short(a.hostname), t)
        for ip in {a.ip, *(a.ips or [])}:
            add("ip", (ip or "").strip(), t)
    linked = {a.asset_id for a in agents if a.asset_id}
    for s in assets:
        if s.id in linked:
            continue                                         # the agent represents this asset
        t = f"asset:{s.id}"
        if valid_serial(s.serial):
            add("serial", s.serial.strip().upper(), t)
        add("name", _short(s.name), t)
        add("ip", (s.ip or "").split(",")[0].strip(), t)
    valid = {f"agent:{a.id}" for a in agents} | {f"asset:{s.id}" for s in assets}
    out, unmatched = {}, []
    for h in hosts:
        if h.target:
            out[h.ref] = h.target
            continue
        m = mapping.get(h.ref)
        if m == "ignore":
            continue
        if m in valid:
            out[h.ref] = m
            continue
        reason = "no machine with this serial, name or IP"
        for kind, key in (("serial", (h.serial or "").strip().upper() if valid_serial(h.serial or "") else ""),
                          ("name", _short(h.name)), ("ip", (h.ip or "").strip())):
            hits = idx[kind].get(key) if key else None
            if hits and len(hits) == 1:
                out[h.ref] = next(iter(hits))
                break
            if hits:
                reason = f"several machines share this {kind}"
                break
        else:
            unmatched.append({"ref": h.ref, "name": h.name, "ip": h.ip, "os": h.os, "reason": reason})
            continue
        if h.ref not in out:
            unmatched.append({"ref": h.ref, "name": h.name, "ip": h.ip, "os": h.os, "reason": reason})
    return out, unmatched


# ------------------------------------------------------------------ reconcile
def _chunks(seq, n=1000):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def recompute(db: Session, finding_ids) -> None:
    """Derive status / confidence of findings from their detections (only enabled sources count)."""
    sources = {s.id: s for s in db.query(models.VulnSource)}
    now = utcnow()
    for ids in _chunks(set(finding_ids)):
        dets: dict[int, list] = {}
        for d in db.query(models.VulnDetection).filter(models.VulnDetection.finding_id.in_(ids)):
            dets.setdefault(d.finding_id, []).append(d)
        for f in db.query(models.VulnFinding).filter(models.VulnFinding.id.in_(ids)):
            ds = dets.get(f.id, [])
            live = [d for d in ds if sources.get(d.source_id) and sources[d.source_id].enabled]
            active = [d for d in live if d.active]
            if active:
                if f.status == "fixed":
                    f.reopened = (f.reopened or 0) + 1
                    f.sla_start, f.due_at, f.alerted_at = None, None, None     # came back: new deadline, new alert
                f.status, f.fixed_at = "open", None
                f.confidence = max((sources[d.source_id].confidence for d in active), key=lambda c: RANK.get(c, 0))
                f.sources_active = len({d.source_id for d in active})
                top = max(active, key=lambda d: d.score if d.score is not None else -1)
                f.provider_score, f.provider_severity = top.score, top.severity or ""
                f.packages = sorted({f"{d.package} {d.version}".strip() for d in active if d.package})[:20]
                f.last_seen = max(d.last_seen for d in active)
            else:
                f.sources_active = 0
                if live:                                      # an enabled source looked again and no longer sees it
                    if f.status != "fixed":
                        f.status, f.fixed_at = "fixed", now
                else:                                         # only disabled sources ever saw it → unknown, not fixed
                    f.status = "source_off"


def reconcile(db: Session, source: models.VulnSource, snap: Snapshot) -> dict:
    now = utcnow()
    targets, unmatched = resolve_hosts(db, source, snap.hosts)
    scanned = {targets[h.ref] for h in snap.hosts if h.scanned and h.ref in targets}
    grouped: dict[tuple, list] = {}
    skipped_unmatched = skipped_bad = 0
    for r in snap.records:
        t = targets.get(r.ref)
        cid = str(r.cve_id or "").strip().upper()
        if not t:
            skipped_unmatched += 1
            continue
        if not CVE_RE.match(cid):
            skipped_bad += 1
            continue
        grouped.setdefault((t, cid), []).append(r)
    findings: dict[tuple, models.VulnFinding] = {}
    keys = list(grouped)
    for part in _chunks({t for t, _ in keys}, 500):
        for f in db.query(models.VulnFinding).filter(models.VulnFinding.target.in_(part)):
            findings[(f.target, f.cve_id)] = f
    new = 0
    for t, cid in keys:
        if (t, cid) not in findings:
            kind, _, num = t.partition(":")
            f = models.VulnFinding(target=t, cve_id=cid, status="open", first_seen=now, last_seen=now, packages=[],
                                   agent_id=int(num) if kind == "agent" else None, asset_id=int(num) if kind == "asset" else None,
                                   confidence=source.confidence, triage="", triage_note="", triage_by="", provider_severity="")
            db.add(f)
            findings[(t, cid)] = f
            new += 1
    db.flush()
    by_fid = {findings[k].id: k for k in keys}
    existing = {}
    for part in _chunks(by_fid):
        for d in db.query(models.VulnDetection).filter(models.VulnDetection.source_id == source.id,
                                                       models.VulnDetection.finding_id.in_(part)):
            existing[(d.finding_id, d.package)] = d
    touched, recompute_ids = set(), set(by_fid)
    for k, recs in grouped.items():
        f = findings[k]
        for r in recs:
            pkg = (r.package or "")[:255]
            d = existing.get((f.id, pkg))
            if d is None:
                d = models.VulnDetection(finding_id=f.id, source_id=source.id, package=pkg, first_seen=now)
                db.add(d)
                existing[(f.id, pkg)] = d
            d.version, d.fixed_version = (r.version or "")[:128], (r.fixed_version or "")[:128]
            d.severity, d.score, d.detected_at = r.severity or "", r.score, r.detected_at
            d.active, d.last_seen = True, now
            touched.add((f.id, pkg))
    db.flush()
    gone = 0
    for part in _chunks(scanned, 500):                      # scanned hosts: what the source no longer lists is fixed
        q = (db.query(models.VulnDetection).join(models.VulnFinding, models.VulnFinding.id == models.VulnDetection.finding_id)
             .filter(models.VulnDetection.source_id == source.id, models.VulnDetection.active.is_(True),
                     models.VulnFinding.target.in_(part)))
        for d in q:
            if (d.finding_id, d.package) not in touched:
                d.active = False
                recompute_ids.add(d.finding_id)
                gone += 1
    db.flush()
    recompute(db, recompute_ids)
    queued = cve_mod.want(db, {c for _, c in keys})
    return {"records": len(snap.records), "hosts": len(snap.hosts), "matched_hosts": len({targets[h.ref] for h in snap.hosts if h.ref in targets}),
            "findings": len(keys), "new_findings": new, "no_longer_seen": gone, "skipped_unmatched": skipped_unmatched,
            "skipped_invalid": skipped_bad, "cves_queued_for_nvd": queued, "unmatched": unmatched[:300],
            "unmatched_count": len(unmatched)}


def set_enabled(db: Session, source: models.VulnSource, enabled: bool) -> None:
    source.enabled = enabled
    source.disabled_at = None if enabled else utcnow()
    db.flush()
    ids = [i for (i,) in db.query(models.VulnDetection.finding_id).filter(models.VulnDetection.source_id == source.id).distinct()]
    recompute(db, ids)
    vuln_policy.refresh(db, ids)


def ensure_builtin(db: Session) -> None:
    """Built-in source: IT Ops' own CPE matching for devices without an agent. Created once; can be disabled, not deleted."""
    for kind, prov in PROVIDERS.items():
        if prov.auto_create and not db.query(models.VulnSource).filter(models.VulnSource.kind == kind).first():
            db.add(models.VulnSource(name="IT Ops – CPE matching (devices without agent)", kind=kind, enabled=True,
                                     confidence=prov.default_confidence, config=prov.defaults(), state={}))
    db.commit()


def seed_demo() -> None:
    """DEMO DATA only: a simulated Wazuh with 5 agents, findings of every priority, some overdue, some already fixed."""
    from .vulnsrc import wazuh_demo as wd
    with SessionLocal() as db:
        if db.query(models.VulnSource).filter(models.VulnSource.kind == "wazuh_demo").first():
            return
        for cid, (score, sev, kev, pct, desc) in wd.CATALOGUE.items():
            if not db.query(models.Cve).filter(models.Cve.cve_id == cid).first():
                db.add(models.Cve(cve_id=cid, description=f"{desc} (demo entry – replaced by the next NVD sync)", cvss_score=score,
                                  cvss_severity=sev, cvss_version="3.1", cvss_vector="", status="Analyzed", cwe=[], products=[], references=[],
                                  cpe_match=[], kev=kev, kev_ransomware=False, kev_name="", kev_action="", epss=pct, epss_percentile=pct,
                                  published=utcnow() - timedelta(days=90), last_modified=utcnow() - timedelta(days=10)))
        src = models.VulnSource(name="Wazuh (simulated – demo data)", kind="wazuh_demo", enabled=True, confidence="high",
                                config={"interval_hours": 6, "mapping": {}}, state={})
        db.add(src)
        db.flush()
        reconcile(db, src, wd.snapshot(include_fixed=True))                 # what Wazuh saw weeks ago …
        res = reconcile(db, src, wd.snapshot(include_fixed=False))          # … and today (some were patched since)
        now = utcnow()
        for agent_ref, cid, _p, _v, days, fixed in wd.RECORDS:
            name = next(n for i, n, *_ in wd.AGENTS if i == agent_ref)
            ag = db.query(models.Agent).filter(func.lower(models.Agent.hostname) == name.lower()).first()
            if not ag:
                continue
            f = db.query(models.VulnFinding).filter(models.VulnFinding.target == f"agent:{ag.id}", models.VulnFinding.cve_id == cid).first()
            if f:
                f.first_seen = now - timedelta(days=days)
                f.sla_start = f.first_seen
                if fixed is not None:
                    f.fixed_at = now - timedelta(days=fixed)
                    f.due_at = f.sla_start + timedelta(days=30)
        db.flush()
        vuln_policy.refresh(db)
        db.query(models.VulnFinding).update({models.VulnFinding.alerted_at: now})     # demo: no alert storm on first start
        src.state = {**res, "ok": True, "error": "", "info": wd.snapshot(False).info, "at": _iso(now), "last_ok": _iso(now), "running": False}
        db.commit()
    log.warning("Created a simulated Wazuh source with %d agents for demo data", len(wd.AGENTS))


# ------------------------------------------------------------------ running a source
def _stale_hours(s: models.VulnSource) -> float:
    cfg = s.config or {}
    if s.kind == "file":
        return float(cfg.get("stale_days") or 30) * 24
    return max(float(cfg.get("interval_hours") or 6) * 3, 24)


def is_stale(s: models.VulnSource, now=None) -> bool:
    last = (s.state or {}).get("last_ok")
    if not last:
        return True
    try:
        t = datetime.fromisoformat(last.rstrip("Z"))
    except ValueError:
        return True
    return (now or utcnow()) - t > timedelta(hours=_stale_hours(s))


async def run_source(source_id: int, payload=None) -> dict:
    lock = _locks.setdefault(source_id, asyncio.Lock())
    if lock.locked():
        return {"ok": False, "error": "A sync of this source is already running"}
    async with lock:
        with SessionLocal() as db:
            s = db.get(models.VulnSource, source_id)
            if not s:
                return {"ok": False, "error": "source not found"}
            prov = PROVIDERS.get(s.kind)
            cfg = open_config(s.config or {})
            s.state = {**(s.state or {}), "running": True}
            db.commit()
        t0 = utcnow()
        try:
            if not prov:
                raise SourceError(f"No adapter for source type '{s.kind}'")
            with SessionLocal() as db:
                snap = await prov.collect(cfg, db, payload)
            with SessionLocal() as db:
                s = db.get(models.VulnSource, source_id)
                res = reconcile(db, s, snap)
                vuln_policy.refresh(db)
                res.update(ok=True, error="", info=snap.info, at=_iso(utcnow()), seconds=round((utcnow() - t0).total_seconds(), 1))
                s.state = {**(s.state or {}), **res, "running": False, "last_ok": res["at"]}
                db.commit()
            try:
                await vuln_policy.send_alerts()
            except Exception as e:                       # alerting must never break a sync
                log.warning("vulnerability alerts: %s", e)
            return res
        except Exception as e:
            msg = str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"
            if not isinstance(e, SourceError):
                log.exception("vulnerability source %s failed", source_id)
            with SessionLocal() as db:
                s = db.get(models.VulnSource, source_id)
                s.state = {**(s.state or {}), "running": False, "ok": False, "error": msg[:500], "at": _iso(utcnow())}
                db.commit()
            return {"ok": False, "error": msg[:500]}


async def loop():
    """Background: run each enabled, scheduled source every interval_hours (default 6; CPE matching 24)."""
    if os.environ.get("VULN_SYNC", "1").lower() in ("0", "false", "no"):
        return
    await asyncio.sleep(120)
    while True:
        try:
            with SessionLocal() as db:
                due = []
                for s in db.query(models.VulnSource).filter(models.VulnSource.enabled.is_(True)):
                    prov = PROVIDERS.get(s.kind)
                    if not prov or not prov.scheduled:
                        continue
                    last = (s.state or {}).get("at")
                    hours = float((s.config or {}).get("interval_hours") or (24 if s.kind == "cpe" else 6))
                    if not last or utcnow() - datetime.fromisoformat(last.rstrip("Z")) >= timedelta(hours=hours):
                        due.append(s.id)
            for sid in due:
                await run_source(sid)
        except Exception as e:                               # never kill the app because of a source
            log.warning("vulnerability loop: %s", e)
        await asyncio.sleep(900)


# ------------------------------------------------------------------ API helpers
def _names(db: Session, targets) -> dict:
    a_ids = [int(t[6:]) for t in targets if t.startswith("agent:")]
    s_ids = [int(t[6:]) for t in targets if t.startswith("asset:")]
    out = {}
    if a_ids:
        for a in db.query(models.Agent.id, models.Agent.hostname, models.Agent.ip).filter(models.Agent.id.in_(a_ids)):
            out[f"agent:{a.id}"] = {"name": a.hostname, "ip": a.ip, "kind": "endpoint"}
    if s_ids:
        for a in db.query(models.Asset.id, models.Asset.name, models.Asset.ip, models.Asset.type).filter(models.Asset.id.in_(s_ids)):
            out[f"asset:{a.id}"] = {"name": a.name, "ip": a.ip, "kind": a.type}
    return out


def _triage_active(f: models.VulnFinding, now) -> str:
    if f.triage and (f.triage_until is None or f.triage_until > now):
        return f.triage
    return ""


def _source_view(s: models.VulnSource, now=None) -> dict:
    prov = PROVIDERS.get(s.kind)
    cfg = {k: (MASK if k in SECRET_FIELDS and v else v) for k, v in (s.config or {}).items() if k != "mapping"}
    return {"id": s.id, "name": s.name, "kind": s.kind, "kind_label": prov.label if prov else s.kind, "enabled": s.enabled,
            "confidence": s.confidence, "config": cfg, "mapping": (s.config or {}).get("mapping") or {},
            "state": s.state or {}, "stale": s.enabled and bool((s.state or {}).get("at")) and is_stale(s, now), "stale_hours": _stale_hours(s),
            "scheduled": bool(prov and prov.scheduled), "builtin": bool(prov and prov.singleton),
            "disabled_at": _iso(s.disabled_at), "created_at": _iso(s.created_at)}


def _finding_rows(db: Session, rows, now) -> list[dict]:
    fids = [f.id for f, _ in rows]
    srcs = {s.id: s for s in db.query(models.VulnSource)}
    stale = {i for i, s in srcs.items() if s.enabled and is_stale(s, now)}
    act: dict[int, set] = {}
    if fids:
        for fid, sid in (db.query(models.VulnDetection.finding_id, models.VulnDetection.source_id)
                         .filter(models.VulnDetection.finding_id.in_(fids), models.VulnDetection.active.is_(True)).distinct()):
            act.setdefault(fid, set()).add(sid)
    names = _names(db, {f.target for f, _ in rows})
    soon = vuln_policy.get_policy(db)["due_soon_days"]
    out = []
    for f, c in rows:
        sids = act.get(f.id, set())
        live = {i for i in sids if srcs.get(i) and srcs[i].enabled}
        nvd_score = c.cvss_score if c else None
        t = names.get(f.target, {"name": f.target, "ip": "", "kind": ""})
        out.append({
            "id": f.id, "target": f.target, "target_name": t["name"], "target_ip": t["ip"], "target_kind": t["kind"],
            "cve_id": f.cve_id, "status": f.status, "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen),
            "fixed_at": _iso(f.fixed_at), "reopened": f.reopened, "confidence": f.confidence, "verified": f.verified,
            "sources_active": f.sources_active,
            "needs_verification": f.status == "open" and f.confidence != "high" and not f.verified and f.sources_active < 2,
            "triage": _triage_active(f, now), "triage_until": _iso(f.triage_until), "packages": f.packages or [],
            "cvss_score": nvd_score if nvd_score is not None else f.provider_score,
            "cvss_severity": (c.cvss_severity if c and c.cvss_severity else f.provider_severity) or "",
            "score_source": "nvd" if nvd_score is not None else ("source" if f.provider_score is not None or f.provider_severity else ""),
            "kev": bool(c and c.kev), "kev_ransomware": bool(c and c.kev_ransomware), "epss": c.epss if c else None,
            "epss_percentile": c.epss_percentile if c else None, "description": ((c.description if c else "") or "")[:220],
            "attack": [ATTACK_TYPES[k][0] for k in attack_types(c.cwe if c else [])],
            "in_catalogue": c is not None, "sources": sorted(srcs[i].name for i in live),
            "stale": f.status == "open" and bool(live) and live <= stale,
            "priority": f.priority or 0, "band": vuln_policy.band(f.priority or 0), "sla_category": f.sla_category,
            "sla_start": _iso(f.sla_start), "due_at": _iso(f.due_at),
            "sla_state": vuln_policy.sla_state(f, _triage_active(f, now), now, soon),
            "overdue_days": (now - f.due_at).days + 1 if f.status == "open" and f.due_at and f.due_at < now else 0,
        })
    return out


SEV_EXPR = func.coalesce(func.nullif(models.Cve.cvss_severity, ""), func.nullif(models.VulnFinding.provider_severity, ""), "unscored")
SCORE_EXPR = func.coalesce(models.Cve.cvss_score, models.VulnFinding.provider_score)
_F = models.VulnFinding
_NAME = func.coalesce(select(models.Agent.hostname).where(models.Agent.id == _F.agent_id).scalar_subquery(),
                      select(models.Asset.name).where(models.Asset.id == _F.asset_id).scalar_subquery(), _F.target)
_IP = func.coalesce(select(models.Agent.ip).where(models.Agent.id == _F.agent_id).scalar_subquery(),
                    select(models.Asset.ip).where(models.Asset.id == _F.asset_id).scalar_subquery(), "")
# Sort keys → (expressions, default direction). Text that holds numbers is padded so 10.0.0.9 < 10.0.0.10 and CVE-2024-9999 < CVE-2024-10000.
SORT_COLS = {
    "priority": ([_F.priority], "desc"),
    "due": ([_F.due_at], "asc"),
    "cvss": ([SCORE_EXPR], "desc"),
    "epss": ([models.Cve.epss], "desc"),
    "first_seen": ([_F.first_seen], "desc"),
    "machine": ([func.lower(_NAME)], "asc"),
    "ip": ([func.concat(*[func.lpad(func.split_part(_IP, ".", n), 3, "0") for n in (1, 2, 3, 4)])], "asc"),
    "cve": ([func.split_part(_F.cve_id, "-", 2), func.lpad(func.split_part(_F.cve_id, "-", 3), 9, "0")], "asc"),
    "kev": ([func.coalesce(models.Cve.kev, False)], "desc"),
    "package": ([func.lower(cast(_F.packages, String))], "asc"),
    "confidence": ([case((_F.confidence == "high", 3), (_F.confidence == "medium", 2), (_F.confidence == "low", 1), else_=0)], "desc"),
    "status": ([_F.status], "asc"),
}


def order_findings(sort: str, direction: str = ""):
    exprs, default = SORT_COLS.get(sort, SORT_COLS["priority"])
    d = direction if direction in ("asc", "desc") else default
    return [(e.asc() if d == "asc" else e.desc()).nullslast() for e in exprs] + [_F.id.desc()]


def _untriaged(now):
    return or_(models.VulnFinding.triage == "", and_(models.VulnFinding.triage_until.isnot(None), models.VulnFinding.triage_until <= now))


# ------------------------------------------------------------------ API: findings
def findings_query(db: Session, q: str = "", status: str = "open", severity: str = "", kev: bool = False, source_id: int = 0,
                   confidence: str = "", needs_verification: bool = False, triage: str = "none", target: str = "",
                   band: str = "", sla: str = "", cve: str = "", attack: str = ""):
    now = utcnow()
    qry = db.query(models.VulnFinding, models.Cve).outerjoin(models.Cve, models.Cve.cve_id == models.VulnFinding.cve_id)
    if status != "all":
        qry = qry.filter(models.VulnFinding.status.in_(status.split(",")))
    if triage == "none":
        qry = qry.filter(_untriaged(now))
    elif triage in ("false_positive", "accepted"):
        qry = qry.filter(models.VulnFinding.triage == triage, ~_untriaged(now))
    sev = [s for s in severity.lower().split(",") if s]
    if sev:
        qry = qry.filter(SEV_EXPR.in_(sev))
    if kev:
        qry = qry.filter(models.Cve.kev.is_(True))
    if confidence:
        qry = qry.filter(models.VulnFinding.confidence.in_(confidence.split(",")))
    if needs_verification:
        qry = qry.filter(models.VulnFinding.confidence != "high", models.VulnFinding.verified.is_(False),
                         models.VulnFinding.sources_active < 2)
    if target:
        qry = qry.filter(models.VulnFinding.target == target)
    if cve:
        qry = qry.filter(models.VulnFinding.cve_id == cve.strip().upper())
    bands = [b for b in band.upper().split(",") if b in ("P1", "P2", "P3", "P4")]
    if bands:
        lim = {"P1": (80, 101), "P2": (60, 80), "P3": (40, 60), "P4": (0, 40)}
        qry = qry.filter(or_(*[and_(models.VulnFinding.priority >= lim[b][0], models.VulnFinding.priority < lim[b][1]) for b in bands]))
    if sla:
        soon = now + timedelta(days=vuln_policy.get_policy(db)["due_soon_days"])
        qry = qry.filter(models.VulnFinding.status == "open")
        qry = qry.filter({"overdue": models.VulnFinding.due_at < now,
                          "due_soon": and_(models.VulnFinding.due_at >= now, models.VulnFinding.due_at < soon),
                          "awaiting_verification": models.VulnFinding.due_at.is_(None)}.get(sla, models.VulnFinding.id > 0))
    if source_id:
        qry = qry.filter(models.VulnFinding.id.in_(db.query(models.VulnDetection.finding_id).filter(
            models.VulnDetection.source_id == source_id, models.VulnDetection.active.is_(True))))
    if q.strip():
        t = f"%{q.strip()}%"
        hit_agents = db.query(func.concat("agent:", models.Agent.id)).filter(or_(models.Agent.hostname.ilike(t), models.Agent.ip.ilike(t)))
        hit_assets = db.query(func.concat("asset:", models.Asset.id)).filter(or_(models.Asset.name.ilike(t), models.Asset.ip.ilike(t)))
        qry = qry.filter(or_(models.VulnFinding.cve_id.ilike(t), cast(models.VulnFinding.packages, String).ilike(t),
                             models.Cve.description.ilike(t), models.VulnFinding.target.in_(hit_agents),
                             models.VulnFinding.target.in_(hit_assets)))
    if attack:                                              # attack type from the CVE's CWE ids (vuln_groups.ATTACK_TYPES)
        from .vuln_groups import cwe_filter
        qry = qry.filter(cwe_filter(attack))
    return qry


@router.get("/api/vuln/findings")
def list_findings(q: str = "", status: str = "open", severity: str = "", kev: bool = False, source_id: int = 0,
                  confidence: str = "", needs_verification: bool = False, triage: str = "none", target: str = "",
                  band: str = "", sla: str = "", cve: str = "", attack: str = "",
                  sort: str = "priority", dir: str = "", limit: int = 100, offset: int = 0, user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    qry = findings_query(db, q=q, status=status, severity=severity, kev=kev, source_id=source_id, confidence=confidence,
                         needs_verification=needs_verification, triage=triage, target=target, band=band, sla=sla, cve=cve, attack=attack)
    total = qry.count()
    rows = (qry.order_by(*order_findings(sort, dir))
            .offset(max(0, offset)).limit(min(max(1, limit), 500)).all())
    return {"total": total, "items": _finding_rows(db, rows, now)}


@router.get("/api/vuln/summary")
def vuln_summary(user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    base = (db.query(models.VulnFinding).outerjoin(models.Cve, models.Cve.cve_id == models.VulnFinding.cve_id)
            .filter(models.VulnFinding.status == "open", _untriaged(now)))
    by_sev = dict(base.with_entities(SEV_EXPR, func.count(models.VulnFinding.id)).group_by(SEV_EXPR).all())
    sources = [_source_view(s, now) for s in db.query(models.VulnSource).order_by(models.VulnSource.id)]
    return {
        "open": sum(by_sev.values()), "by_severity": by_sev,
        "kev_open": base.filter(models.Cve.kev.is_(True)).count(),
        "needs_verification": base.filter(models.VulnFinding.confidence != "high", models.VulnFinding.verified.is_(False),
                                          models.VulnFinding.sources_active < 2).count(),
        "machines": base.with_entities(func.count(func.distinct(models.VulnFinding.target))).scalar() or 0,
        "fixed_30d": db.query(func.count(models.VulnFinding.id)).filter(models.VulnFinding.status == "fixed",
                                                                         models.VulnFinding.fixed_at >= now - timedelta(days=30)).scalar() or 0,
        "source_off": db.query(func.count(models.VulnFinding.id)).filter(models.VulnFinding.status == "source_off").scalar() or 0,
        "triaged": db.query(func.count(models.VulnFinding.id)).filter(models.VulnFinding.status == "open", ~_untriaged(now)).scalar() or 0,
        "sources": sources, "kinds": [{"kind": k, "label": p.label, "confidence": p.default_confidence, "defaults": p.defaults()}
                                      for k, p in PROVIDERS.items() if not p.singleton],
    }


@router.get("/api/vuln/findings/{fid}")
def finding_detail(fid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    f = db.get(models.VulnFinding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    c = db.query(models.Cve).filter(models.Cve.cve_id == f.cve_id).first()
    row = _finding_rows(db, [(f, c)], utcnow())[0]
    srcs = {s.id: s for s in db.query(models.VulnSource)}
    row["detections"] = [{"source": srcs[d.source_id].name if d.source_id in srcs else "?", "source_enabled": bool(srcs.get(d.source_id) and srcs[d.source_id].enabled),
                          "confidence": srcs[d.source_id].confidence if d.source_id in srcs else "", "package": d.package,
                          "version": d.version, "fixed_version": d.fixed_version, "severity": d.severity, "score": d.score,
                          "active": d.active, "first_seen": _iso(d.first_seen), "last_seen": _iso(d.last_seen), "detected_at": _iso(d.detected_at)}
                         for d in db.query(models.VulnDetection).filter(models.VulnDetection.finding_id == f.id).order_by(models.VulnDetection.id)]
    row.update(triage_note=f.triage_note, triage_by=f.triage_by, triage_at=_iso(f.triage_at), raw_triage=f.triage,
               cve=cve_mod._row(c, full=True) if c else None)
    return row


class TriageIn(BaseModel):
    action: str                     # verify | unverify | false_positive | accepted | clear
    until: str | None = None        # YYYY-MM-DD for accepted risk
    note: str = ""


@router.post("/api/vuln/findings/{fid}/triage")
def triage_finding(fid: int, body: TriageIn, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    f = db.get(models.VulnFinding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    now = utcnow()
    if body.action in ("verify", "unverify"):
        f.verified = body.action == "verify"
    elif body.action in ("false_positive", "accepted"):
        if body.action == "accepted" and not body.until:
            raise HTTPException(400, "Accepted risk needs an end date (review date)")
        until = None
        if body.until:
            try:
                until = datetime.fromisoformat(body.until[:10])
            except ValueError:
                raise HTTPException(400, "Date must be YYYY-MM-DD")
        if not body.note.strip():
            raise HTTPException(400, "Write a short reason")
        f.triage, f.triage_until, f.triage_note, f.triage_by, f.triage_at = body.action, until, body.note.strip()[:2000], user.username, now
    elif body.action == "clear":
        f.triage, f.triage_until, f.triage_note, f.triage_by, f.triage_at = "", None, "", user.username, now
    else:
        raise HTTPException(400, "Unknown action")
    db.flush()
    vuln_policy.refresh(db, [f.id])
    target = _names(db, [f.target]).get(f.target, {}).get("name", f.target)
    audit(db, user.username, f"vuln_{body.action}", "vuln_finding", f.id,
          detail=f"{f.cve_id} on {target}: {body.action}{' until ' + body.until if body.until else ''}{' – ' + body.note.strip() if body.note.strip() else ''}")
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ API: sources
class SourceIn(BaseModel):
    name: str | None = None
    kind: str | None = None
    confidence: str | None = None
    enabled: bool | None = None
    config: dict | None = None


def _get_source(db, sid) -> models.VulnSource:
    s = db.get(models.VulnSource, sid)
    if not s:
        raise HTTPException(404, "Source not found")
    return s


@router.get("/api/vuln/sources")
def list_sources(user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    return [_source_view(s, now) for s in db.query(models.VulnSource).order_by(models.VulnSource.id)]


@router.post("/api/vuln/sources")
def create_source(body: SourceIn, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    prov = PROVIDERS.get(body.kind or "")
    if not prov or prov.singleton:
        raise HTTPException(400, "Unknown source type")
    if not (body.name or "").strip():
        raise HTTPException(400, "Name is required")
    conf = body.confidence or prov.default_confidence
    if conf not in CONFIDENCE:
        raise HTTPException(400, "Confidence must be high, medium or low")
    cfg = {**prov.defaults(), **(body.config or {})}
    cfg.pop("mapping", None)
    s = models.VulnSource(name=body.name.strip()[:128], kind=prov.kind, enabled=True if body.enabled is None else body.enabled,
                          confidence=conf, config={**seal_config(cfg), "mapping": {}}, state={})
    db.add(s)
    db.flush()
    audit(db, user.username, "create", "vuln_source", s.id, detail=f"Vulnerability source '{s.name}' ({prov.label})")
    db.commit()
    return _source_view(s)


@router.put("/api/vuln/sources/{sid}")
def update_source(sid: int, body: SourceIn, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    s = _get_source(db, sid)
    changes = []
    if body.name is not None and body.name.strip() and body.name.strip() != s.name:
        changes.append(f"name '{s.name}' → '{body.name.strip()}'")
        s.name = body.name.strip()[:128]
    if body.confidence is not None and body.confidence != s.confidence:
        if body.confidence not in CONFIDENCE:
            raise HTTPException(400, "Confidence must be high, medium or low")
        changes.append(f"confidence {s.confidence} → {body.confidence}")
        s.confidence = body.confidence
        ids = [i for (i,) in db.query(models.VulnDetection.finding_id).filter(models.VulnDetection.source_id == s.id).distinct()]
        db.flush()
        recompute(db, ids)
        vuln_policy.refresh(db, ids)
    if body.config is not None:
        old = dict(s.config or {})
        new = {k: v for k, v in body.config.items() if k != "mapping"}
        s.config = {**old, **seal_config(new, old), "mapping": old.get("mapping") or {}}
        changes.append("settings")
    if body.enabled is not None and body.enabled != s.enabled:
        set_enabled(db, s, body.enabled)
        changes.append("enabled" if body.enabled else "DISABLED (its findings become 'source off', never 'fixed')")
    audit(db, user.username, "update", "vuln_source", s.id, detail=f"Vulnerability source '{s.name}': {', '.join(changes) or 'no change'}")
    db.commit()
    return _source_view(s)


@router.post("/api/vuln/sources/{sid}/test")
async def test_source(sid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    s = _get_source(db, sid)
    prov = PROVIDERS.get(s.kind)
    try:
        return {"ok": True, **(await prov.test(open_config(s.config or {}), db))}
    except SourceError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}


@router.post("/api/vuln/sources/{sid}/sync")
async def sync_source(sid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    s = _get_source(db, sid)
    if s.kind == "file":
        raise HTTPException(400, "File sources are updated by importing a file")
    if not s.enabled:
        raise HTTPException(400, "Enable the source first")
    audit(db, user.username, "sync", "vuln_source", s.id, detail=f"Manual sync of vulnerability source '{s.name}'")
    db.commit()
    asyncio.create_task(run_source(s.id))
    return {"started": True}


class ImportIn(BaseModel):
    filename: str = ""
    content: str


@router.post("/api/vuln/sources/{sid}/import")
async def import_file(sid: int, body: ImportIn, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    s = _get_source(db, sid)
    if s.kind != "file":
        raise HTTPException(400, "Only file sources accept imports")
    if not s.enabled:
        raise HTTPException(400, "Enable the source first")
    audit(db, user.username, "import", "vuln_source", s.id, detail=f"Imported '{body.filename[:120]}' into '{s.name}'")
    db.commit()
    res = await run_source(s.id, {"filename": body.filename, "content": body.content})
    if not res.get("ok"):
        raise HTTPException(400, res.get("error") or "Import failed")
    return res


class MapIn(BaseModel):
    ref: str
    target: str                     # agent:<id> | asset:<id> | ignore | "" (remove)


@router.put("/api/vuln/sources/{sid}/mapping")
def set_mapping(sid: int, body: MapIn, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    s = _get_source(db, sid)
    if body.target and body.target != "ignore":
        kind, _, num = body.target.partition(":")
        ok = num.isdigit() and ((kind == "agent" and db.get(models.Agent, int(num))) or (kind == "asset" and db.get(models.Asset, int(num))))
        if not ok:
            raise HTTPException(400, "Machine not found")
    cfg = dict(s.config or {})
    mapping = dict(cfg.get("mapping") or {})
    if body.target:
        mapping[body.ref] = body.target
    else:
        mapping.pop(body.ref, None)
    cfg["mapping"] = mapping
    s.config = cfg
    audit(db, user.username, "map", "vuln_source", s.id, detail=f"'{s.name}': host {body.ref} → {body.target or '(automatic)'}")
    db.commit()
    return {"ok": True, "mapping": mapping}


@router.get("/api/vuln/targets")
def list_targets(q: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    t = f"%{q.strip()}%"
    out = [{"target": f"agent:{a.id}", "name": a.hostname, "ip": a.ip, "kind": "endpoint"}
           for a in db.query(models.Agent).filter(models.Agent.revoked_at.is_(None), or_(models.Agent.hostname.ilike(t), models.Agent.ip.ilike(t)))
           .order_by(models.Agent.hostname).limit(30)]
    out += [{"target": f"asset:{a.id}", "name": a.name, "ip": a.ip, "kind": a.type}
            for a in db.query(models.Asset).filter(or_(models.Asset.name.ilike(t), models.Asset.ip.ilike(t))).order_by(models.Asset.name).limit(30)]
    return out


@router.get("/api/vuln/compare")
def compare_sources(a: int, b: int, user=Depends(current_user), db: Session = Depends(get_db)):
    """Parallel run report: on machines both sources cover, which CVEs both see and which only one sees."""
    sa, sb = _get_source(db, a), _get_source(db, b)

    def pairs(sid):
        return set(db.query(models.VulnFinding.target, models.VulnFinding.cve_id)
                   .join(models.VulnDetection, models.VulnDetection.finding_id == models.VulnFinding.id)
                   .filter(models.VulnDetection.source_id == sid, models.VulnDetection.active.is_(True)).distinct())

    def covered(sid):
        return {t for (t,) in db.query(models.VulnFinding.target).join(models.VulnDetection, models.VulnDetection.finding_id == models.VulnFinding.id)
                .filter(models.VulnDetection.source_id == sid).distinct()}
    common = covered(a) & covered(b)
    pa = {p for p in pairs(a) if p[0] in common}
    pb = {p for p in pairs(b) if p[0] in common}
    names = _names(db, common)

    def sample(ps):
        return [{"target": t, "target_name": names.get(t, {}).get("name", t), "cve_id": c} for t, c in sorted(ps)[:200]]
    both, only_a, only_b = pa & pb, pa - pb, pb - pa
    total = len(pa | pb)
    return {"a": {"id": sa.id, "name": sa.name}, "b": {"id": sb.id, "name": sb.name}, "machines_in_common": len(common),
            "both": len(both), "only_a": len(only_a), "only_b": len(only_b),
            "agreement": round(len(both) / total * 100, 1) if total else None,
            "only_a_items": sample(only_a), "only_b_items": sample(only_b)}
