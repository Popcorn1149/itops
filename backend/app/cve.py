"""CVE module – part 2: CVE catalogue and threat-intelligence feeds.

Sources (each is a FeedSource; add a new feed by writing a subclass and listing it in FEEDS):
  * NVD CVE API 2.0       – CVE details, CVSS, CWE, affected products (CPE). Incremental by lastModified.
  * CISA KEV              – CVEs known to be exploited in the wild (+ due date, ransomware use).
  * FIRST EPSS            – probability that a CVE is exploited in the next 30 days.

Scope kept small on purpose: CVEs modified in the last CVE_BACKFILL_DAYS (default 120) plus every KEV entry.
Matching CVEs to machines is part 3 (app/vuln.py); priority / SLA is part 4.

Environment:
  CVE_SYNC=0                 disable the daily sync loop
  CVE_SYNC_HOURS=24          interval between syncs
  CVE_BACKFILL_DAYS=120      first sync: how far back to load (NVD allows 120 days per request window)
  NVD_API_KEY                optional – raises the NVD rate limit from 5 to 50 requests / 30 s
  NVD_URL, KEV_URL, EPSS_URL override feed addresses (e.g. internal mirror)
"""
import asyncio
import csv
import gzip
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from . import models
from .db import SessionLocal, get_db
from .security import admin_user, current_user

log = logging.getLogger("itops.cve")
router = APIRouter()

NVD_URL = os.environ.get("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
# CISA's site sometimes refuses scripted downloads (403 from its CDN); CISA publishes the same file on GitHub.
KEV_URLS = [u for u in [os.environ.get("KEV_URL"), "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"] if u]
EPSS_URLS = [u for u in [os.environ.get("EPSS_URL"), "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                         "https://epss.cyentia.com/epss_scores-current.csv.gz"] if u]
NVD_WINDOW_DAYS = 120          # NVD maximum range for lastModStartDate / lastModEndDate
NVD_PAGE = 2000                # NVD maximum resultsPerPage
STATE_KEY = "cve_sync"
SEVERITIES = ("critical", "high", "medium", "low", "none")
_lock = asyncio.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _dt(s) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).replace(tzinfo=None) if d.tzinfo else d
    except ValueError:
        return None


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


# ------------------------------------------------------------------ parsing (pure functions, unit-tested)
def parse_nvd_item(item: dict) -> dict:
    """One element of NVD 'vulnerabilities' → column values for models.Cve."""
    c = item.get("cve", item)
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score = severity = version = vector = None
    metrics = c.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):   # CVSS 3.x preferred, as most tools do
        ms = metrics.get(key) or []
        if not ms:
            continue
        m = next((x for x in ms if x.get("type") == "Primary"), ms[0])
        data = m.get("cvssData", {})
        score = data.get("baseScore")
        severity = (data.get("baseSeverity") or m.get("baseSeverity") or "").lower()
        version, vector = str(data.get("version", "")), data.get("vectorString", "")
        break
    cwe = sorted({d.get("value") for w in c.get("weaknesses", []) for d in w.get("description", [])
                  if str(d.get("value", "")).startswith("CWE-")})
    products: list[str] = []
    cpe_match: list[dict] = []
    for conf in c.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = str(m.get("criteria", "")).split(":")
                if m.get("vulnerable") and len(parts) > 4:
                    vp = f"{parts[3]}:{parts[4]}"
                    if vp not in products:
                        products.append(vp)
                    if len(cpe_match) < 200:                       # part 3: version ranges for IT Ops CPE matching
                        r = {"c": m["criteria"]}
                        for src, dst in (("versionStartIncluding", "si"), ("versionStartExcluding", "se"),
                                         ("versionEndIncluding", "ei"), ("versionEndExcluding", "ee")):
                            if m.get(src):
                                r[dst] = str(m[src])
                        cpe_match.append(r)
    refs = [{"url": r.get("url", ""), "tags": r.get("tags", [])[:4]} for r in (c.get("references") or [])[:15] if r.get("url")]
    out = {"cve_id": c.get("id", ""), "published": _dt(c.get("published")), "last_modified": _dt(c.get("lastModified")),
           "status": str(c.get("vulnStatus", ""))[:32], "description": desc, "cvss_score": score,
           "cvss_severity": severity if severity in SEVERITIES else "", "cvss_version": (version or "")[:8],
           "cvss_vector": (vector or "")[:200], "cwe": cwe[:10], "products": products[:30], "references": refs,
           "cpe_match": cpe_match}
    if c.get("cisaExploitAdd"):                                    # NVD repeats the KEV fields
        out.update(kev=True, kev_added=_dt(c.get("cisaExploitAdd")), kev_due=_dt(c.get("cisaActionDue")),
                   kev_name=str(c.get("cisaVulnerabilityName", ""))[:255], kev_action=c.get("cisaRequiredAction", "") or "")
    return out


def parse_kev(doc: dict) -> list[dict]:
    out = []
    for v in doc.get("vulnerabilities", []) or []:
        if not v.get("cveID"):
            continue
        out.append({"cve_id": v["cveID"], "kev": True, "kev_added": _dt(v.get("dateAdded")), "kev_due": _dt(v.get("dueDate")),
                    "kev_ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    "kev_name": str(v.get("vulnerabilityName", ""))[:255], "kev_action": v.get("requiredAction", "") or "",
                    "_vendor_product": f"{v.get('vendorProject', '')}:{v.get('product', '')}".lower().replace(" ", "_"),
                    "_description": v.get("shortDescription", "") or ""})
    return out


def parse_epss_csv(raw: bytes) -> tuple[str, dict[str, tuple[float, float]]]:
    """EPSS daily CSV (optionally gzipped): '#model_version:…,score_date:…' then 'cve,epss,percentile'."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", "replace")
    score_date, rows = "", {}
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            if part.startswith("score_date:"):
                score_date = part.split(":", 1)[1][:10]
        lines = lines[1:]
    for r in csv.DictReader(lines):
        try:
            rows[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
        except (KeyError, ValueError, TypeError):
            continue
    return score_date, rows


# ------------------------------------------------------------------ state
def _state(db: Session) -> dict:
    s = db.get(models.Setting, STATE_KEY)
    return dict(s.value) if s and isinstance(s.value, dict) else {}


def _save_state(db: Session, **changes) -> dict:
    s = db.get(models.Setting, STATE_KEY) or models.Setting(key=STATE_KEY, value={})
    v = dict(s.value or {})
    for k, val in changes.items():
        if isinstance(val, dict) and isinstance(v.get(k), dict):
            v[k] = {**v[k], **val}
        else:
            v[k] = val
    s.value = v
    db.merge(s)
    db.commit()
    return v


def upsert(db: Session, rows: list[dict], only_existing_fields: bool = False) -> tuple[int, int]:
    """Insert or update CVE rows by cve_id. Returns (inserted, updated)."""
    if not rows:
        return 0, 0
    ids = [r["cve_id"] for r in rows]
    have = {c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_(ids))}
    ins = upd = 0
    now = utcnow()
    for r in rows:
        clean = {k: v for k, v in r.items() if not k.startswith("_")}
        c = have.get(r["cve_id"])
        if c is None:
            if only_existing_fields:
                continue
            c = models.Cve(cve_id=r["cve_id"], status="", description="", cvss_severity="", cvss_version="", cvss_vector="",
                           cwe=[], products=[], references=[], cpe_match=[], kev=False, kev_ransomware=False, kev_name="", kev_action="")
            db.add(c)
            have[r["cve_id"]] = c
            ins += 1
        else:
            upd += 1
        for k, v in clean.items():
            setattr(c, k, v)
        c.updated_at = now
    db.commit()
    return ins, upd


# ------------------------------------------------------------------ feeds
class FeedSource:
    name = "feed"

    async def sync(self, client: httpx.AsyncClient, db: Session) -> dict:
        raise NotImplementedError


class NvdSource(FeedSource):
    name = "nvd"

    def __init__(self):
        self.key = os.environ.get("NVD_API_KEY", "")
        self.pause = 0.7 if self.key else 6.5          # NVD rate limit: 50 / 5 requests per 30 s

    async def _pages(self, client, params: dict):
        start = 0
        while True:
            q = {**params, "resultsPerPage": NVD_PAGE, "startIndex": start}
            # NVD flags such as hasKev take no value: send "?hasKev", not "?hasKev="
            url = NVD_URL + "?" + "&".join(k if v == "" else f"{k}={quote(str(v), safe='')}" for k, v in q.items())
            r = await client.get(url, headers={"apiKey": self.key} if self.key else None)
            if r.status_code in (403, 429, 503):             # throttled – wait and retry once
                await asyncio.sleep(30)
                r = await client.get(url, headers={"apiKey": self.key} if self.key else None)
            r.raise_for_status()
            doc = r.json()
            yield [parse_nvd_item(v) for v in doc.get("vulnerabilities", [])]
            start += doc.get("resultsPerPage", 0) or NVD_PAGE
            if start >= doc.get("totalResults", 0):
                return
            await asyncio.sleep(self.pause)

    async def sync(self, client, db) -> dict:
        st = _state(db).get("nvd", {})
        end = utcnow()
        since = _dt(st.get("last_modified_until")) or end - timedelta(days=int(os.environ.get("CVE_BACKFILL_DAYS", "120")))
        total_ins = total_upd = 0
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        win_start = since
        while win_start < end:
            win_end = min(win_start + timedelta(days=NVD_WINDOW_DAYS), end)
            async for rows in self._pages(client, {"lastModStartDate": win_start.strftime(fmt), "lastModEndDate": win_end.strftime(fmt)}):
                i, u = upsert(db, [r for r in rows if r["cve_id"]])
                total_ins, total_upd = total_ins + i, total_upd + u
            _save_state(db, nvd={"last_modified_until": _iso(win_end)})
            win_start = win_end
            await asyncio.sleep(self.pause)
        wanted = list(_state(db).get("wanted") or [])[:int(os.environ.get("NVD_WANTED_PER_SYNC", "300"))]   # CVEs a source reported, not in the catalogue yet
        if wanted:
            have = {c for (c,) in db.query(models.Cve.cve_id).filter(models.Cve.cve_id.in_(wanted))}
            for cid in [w for w in wanted if w not in have]:
                await asyncio.sleep(self.pause)
                try:
                    async for rows in self._pages(client, {"cveId": cid}):
                        i, u = upsert(db, [r for r in rows if r["cve_id"]])
                        total_ins, total_upd = total_ins + i, total_upd + u
                except httpx.HTTPError as e:
                    log.info("NVD lookup %s failed: %s", cid, e)
            rest = [w for w in (_state(db).get("wanted") or []) if w not in set(wanted)]
            _save_state(db, wanted=rest)
        if not st.get("kev_loaded"):                          # once: full details for every KEV CVE, whatever its age
            async for rows in self._pages(client, {"hasKev": ""}):
                i, u = upsert(db, [r for r in rows if r["cve_id"]])
                total_ins, total_upd = total_ins + i, total_upd + u
            _save_state(db, nvd={"kev_loaded": True})
        return {"inserted": total_ins, "updated": total_upd}


class KevSource(FeedSource):
    name = "kev"

    async def sync(self, client, db) -> dict:
        errors, doc, used = [], None, ""
        for url in KEV_URLS:                                    # try the official site, then CISA's GitHub copy
            try:
                r = await client.get(url)
                r.raise_for_status()
                doc = r.json()
                if not isinstance(doc, dict) or "vulnerabilities" not in doc:
                    raise ValueError("not a KEV catalogue")
                used = url
                break
            except Exception as e:
                errors.append(f"{httpx.URL(url).host}: {type(e).__name__}: {str(e)[:120]}")
        if doc is None:
            raise RuntimeError(" | ".join(errors))
        rows = parse_kev(doc)
        listed = {x["cve_id"] for x in rows}
        have = {c.cve_id for c in db.query(models.Cve.cve_id).filter(models.Cve.cve_id.in_(listed))}
        for x in rows:                                          # KEV entry NVD has not returned yet → keep the basics
            if x["cve_id"] not in have:
                x["description"] = x["_description"]
                x["products"] = [x["_vendor_product"]] if x["_vendor_product"] != ":" else []
        ins, upd = upsert(db, rows)
        removed = (db.query(models.Cve).filter(models.Cve.kev.is_(True), ~models.Cve.cve_id.in_(listed))
                   .update({models.Cve.kev: False}, synchronize_session=False))
        db.commit()
        return {"catalog": doc.get("catalogVersion", ""), "source": httpx.URL(used).host, "entries": len(rows), "inserted": ins, "updated": upd, "removed": removed}


class EpssSource(FeedSource):
    name = "epss"

    async def sync(self, client, db) -> dict:
        last_err = None
        for url in EPSS_URLS:
            try:
                r = await client.get(url)
                r.raise_for_status()
                score_date, scores = parse_epss_csv(r.content)
                break
            except Exception as e:                              # try the next mirror
                last_err = e
        else:
            raise last_err or RuntimeError("no EPSS source")
        updated = 0
        ids = [c for (c,) in db.query(models.Cve.cve_id)]
        for i in range(0, len(ids), 2000):
            chunk = [{"cve_id": c, "epss": scores[c][0], "epss_percentile": scores[c][1]} for c in ids[i:i + 2000] if c in scores]
            updated += upsert(db, chunk, only_existing_fields=True)[1]
        return {"score_date": score_date, "scores": len(scores), "updated": updated}


FEEDS: list[FeedSource] = [NvdSource(), KevSource(), EpssSource()]   # order matters: EPSS scores the CVEs loaded before it


async def sync_all(feeds: list[FeedSource] | None = None, client: httpx.AsyncClient | None = None) -> dict:
    """Run every feed; a failing feed does not stop the others. Safe to call concurrently (second call returns busy)."""
    if _lock.locked():
        return {"busy": True}
    async with _lock:
        own = client is None
        client = client or httpx.AsyncClient(timeout=120, follow_redirects=True, headers={"User-Agent": "itops-cve-sync"})
        result = {}
        try:
            with SessionLocal() as db:
                _save_state(db, running=True, started=_iso(utcnow()))
            for f in feeds or FEEDS:
                t0 = utcnow()
                with SessionLocal() as db:
                    try:
                        res = await f.sync(client, db)
                        res.update(ok=True, error="", at=_iso(utcnow()), seconds=round((utcnow() - t0).total_seconds(), 1))
                    except Exception as e:
                        db.rollback()
                        log.warning("CVE feed %s failed: %s", f.name, e)
                        res = {"ok": False, "error": f"{type(e).__name__}: {e}"[:300], "at": _iso(utcnow())}
                    _save_state(db, **{f.name: res})
                    result[f.name] = res
        finally:
            with SessionLocal() as db:
                _save_state(db, running=False, last_run=_iso(utcnow()))
            try:                                              # catalogue changed (KEV, EPSS, CVSS) → priorities / deadlines
                from . import vuln_policy
                with SessionLocal() as db:
                    vuln_policy.refresh(db)
                    db.commit()
                await vuln_policy.send_alerts()
            except Exception as e:
                log.warning("refreshing vulnerability priorities after CVE sync: %s", e)
            if own:
                await client.aclose()
        return result


async def loop():
    """Background: sync once shortly after start, then every CVE_SYNC_HOURS (default 24)."""
    if os.environ.get("CVE_SYNC", "1").lower() in ("0", "false", "no"):
        return
    hours = float(os.environ.get("CVE_SYNC_HOURS", "24"))
    await asyncio.sleep(90)
    while True:
        try:
            with SessionLocal() as db:
                last = _dt(_state(db).get("last_run"))
            if not last or utcnow() - last >= timedelta(hours=hours):
                await sync_all()
        except Exception as e:                                  # never kill the app because of a feed
            log.warning("CVE sync loop: %s", e)
        await asyncio.sleep(3600)


# ------------------------------------------------------------------ API
def _row(c: models.Cve, full: bool = False) -> dict:
    d = {"cve_id": c.cve_id, "published": _iso(c.published), "last_modified": _iso(c.last_modified), "status": c.status,
         "description": c.description if full else (c.description or "")[:300], "cvss_score": c.cvss_score,
         "cvss_severity": c.cvss_severity, "cvss_version": c.cvss_version, "products": c.products or [],
         "kev": c.kev, "kev_added": _iso(c.kev_added), "kev_due": _iso(c.kev_due), "kev_ransomware": c.kev_ransomware,
         "epss": c.epss, "epss_percentile": c.epss_percentile}
    from .vuln_groups import ATTACK_TYPES, attack_types
    d["attack"] = [ATTACK_TYPES[k][0] for k in attack_types(c.cwe)]
    if full:
        d.update(cvss_vector=c.cvss_vector, cwe=c.cwe or [], references=c.references or [], kev_name=c.kev_name,
                 kev_action=c.kev_action, nvd_url=f"https://nvd.nist.gov/vuln/detail/{c.cve_id}")
    return d


SORTS = {"published": models.Cve.published.desc().nullslast(), "cvss": models.Cve.cvss_score.desc().nullslast(),
         "epss": models.Cve.epss.desc().nullslast(), "kev": models.Cve.kev_added.desc().nullslast()}
# Column sorts (server-side over ALL matches): key → (expressions, default direction). CVE ids sort by year then number.
SORT_COLS = {"published": ([models.Cve.published], "desc"), "cvss": ([models.Cve.cvss_score], "desc"), "epss": ([models.Cve.epss], "desc"),
             "kev": ([models.Cve.kev_added], "desc"),
             "cve": ([func.split_part(models.Cve.cve_id, "-", 2), func.lpad(func.split_part(models.Cve.cve_id, "-", 3), 9, "0")], "asc"),
             "product": ([func.lower(cast(models.Cve.products, String))], "asc")}


def order_cves(sort: str, direction: str = ""):
    exprs, default = SORT_COLS.get(sort, SORT_COLS["published"])
    d = direction if direction in ("asc", "desc") else default
    return [(e.asc() if d == "asc" else e.desc()).nullslast() for e in exprs] + [models.Cve.cve_id.desc()]


@router.get("/api/cves")
def list_cves(q: str = "", severity: str = "", kev: bool = False, days: int = 30, min_epss: float = 0.0,
              sort: str = "published", dir: str = "", attack: str = "", limit: int = 100, offset: int = 0,
              user=Depends(current_user), db: Session = Depends(get_db)):
    qry = db.query(models.Cve)
    if days > 0:
        since = utcnow() - timedelta(days=days)
        qry = qry.filter(or_(models.Cve.published >= since, models.Cve.kev_added >= since) if kev else models.Cve.published >= since)
    if kev:
        qry = qry.filter(models.Cve.kev.is_(True))
    sev = [s for s in severity.lower().split(",") if s in SEVERITIES]
    if sev:
        qry = qry.filter(models.Cve.cvss_severity.in_(sev))
    if min_epss > 0:
        qry = qry.filter(models.Cve.epss >= min_epss)
    if q.strip():
        t = f"%{q.strip()}%"
        qry = qry.filter(or_(models.Cve.cve_id.ilike(t), models.Cve.description.ilike(t), models.Cve.kev_name.ilike(t),
                             cast(models.Cve.products, String).ilike(t)))
    if attack:
        from .vuln_groups import cwe_filter
        qry = qry.filter(cwe_filter(attack))
    total = qry.count()
    rows = qry.order_by(*order_cves(sort, dir)).offset(max(0, offset)).limit(min(max(1, limit), 500)).all()
    return {"total": total, "items": [_row(c) for c in rows]}


@router.get("/api/cves/summary")
def cve_summary(user=Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    week = now - timedelta(days=7)
    base = db.query(func.count(models.Cve.id))
    return {
        "total": base.scalar() or 0,
        "new_7d": base.filter(models.Cve.published >= week).scalar() or 0,
        "critical_7d": base.filter(models.Cve.published >= week, models.Cve.cvss_severity == "critical").scalar() or 0,
        "kev_total": db.query(func.count(models.Cve.id)).filter(models.Cve.kev.is_(True)).scalar() or 0,
        "kev_30d": db.query(func.count(models.Cve.id)).filter(models.Cve.kev_added >= now - timedelta(days=30)).scalar() or 0,
        "sync": _state(db),
    }


@router.get("/api/cves/{cve_id}")
def cve_detail(cve_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    c = db.query(models.Cve).filter(func.upper(models.Cve.cve_id) == cve_id.strip().upper()).first()
    if not c:
        raise HTTPException(404, "CVE not found in the local catalogue")
    return _row(c, full=True)


@router.post("/api/cves/sync")
async def cve_sync_now(user=Depends(admin_user), db: Session = Depends(get_db)):
    if _lock.locked():
        return {"started": False, "message": "A sync is already running"}
    from .main import audit
    audit(db, user.username, "sync", "cve", detail="Manual CVE feed sync (NVD, CISA KEV, EPSS)")
    db.commit()
    asyncio.create_task(sync_all())
    return {"started": True, "message": "Sync started – this can take several minutes on the first run"}


def want(db: Session, cve_ids) -> int:
    """Queue CVE ids that a vulnerability source reported but the catalogue does not have (fetched on the next NVD sync)."""
    ids = {str(c).upper() for c in cve_ids if str(c).upper().startswith("CVE-")}
    if not ids:
        return 0
    have = {c for (c,) in db.query(models.Cve.cve_id).filter(models.Cve.cve_id.in_(ids))}
    missing = ids - have
    if missing:
        cur = list(_state(db).get("wanted") or [])
        _save_state(db, wanted=(cur + sorted(missing - set(cur)))[:5000])
    return len(missing)
