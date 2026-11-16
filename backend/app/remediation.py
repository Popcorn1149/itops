"""Remediation Mapping – turn (device, CVE) into a remediation playbook for IT.

    [device + CVE] → advisory context enrichment → remediation mapping → playbook (checklist + references)

Principles (see docs/BACKLOG.md and the README "Remediation Mapping" section):
  * Facts come from STRUCTURED, OFFICIAL data only – never from scraped web pages:
      - vendor advisory APIs (Microsoft MSRC CVRF: KB number, fixed build, restart, workarounds),
      - the vulnerability source that found the issue (e.g. Wazuh `fixed_version`, from distro advisories),
      - the CVE catalogue (NVD / CNA CPE version ranges, CISA KEV required action).
  * Every step carries its source. Steps that do not come from a vendor are a small FIXED set of
    "IT Ops standard steps" (backup, change request, verify, evidence) – no rule matrix (deferred: nobody reviews rules yet).
  * Other web pages are shown only as reference LINKS (never copied into the checklist). Exploit / PoC links are hidden.
  * IT Ops never runs anything on a machine: the playbook is advice for a person.
  * Vendor data is a cache (table `advisories`): if MSRC is unreachable the playbook still works with what is known.

Environment:
  MSRC_URL                 default https://api.msrc.microsoft.com/cvrf/v3.0 (override for an internal mirror / tests)
  MSRC_REFRESH_DAYS=14     re-read a cached MSRC record after N days
  CVE_RECORD_URL           default https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves (official CVE records)
  CVE_RECORD_REFRESH_DAYS=7
  REMEDIATION_MSRC=0       turn the Microsoft lookup off
"""
import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models
from .db import SessionLocal, get_db
from .security import admin_user, current_user
from .vulnsrc.cpe_match import vkey

log = logging.getLogger("itops.remediation")
router = APIRouter()

MSRC_URL = os.environ.get("MSRC_URL", "https://api.msrc.microsoft.com/cvrf/v3.0").rstrip("/")
MSRC_REFRESH_DAYS = int(os.environ.get("MSRC_REFRESH_DAYS", "14"))
MISS_RETRY_HOURS = 24                     # vendor had no record / error → try again after a day
# Official CVE record written by the CNA (the organisation that issued the CVE) – CVE Program "cvelistV5" on GitHub.
# Gives affected / fixed versions and advisory links even when NVD has not analysed the CVE (most CVEs since April 2026).
CVE_RECORD_URL = os.environ.get("CVE_RECORD_URL", "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves").rstrip("/")
CVE_RECORD_REFRESH_DAYS = int(os.environ.get("CVE_RECORD_REFRESH_DAYS", "7"))
_fetch_lock = asyncio.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(d):
    return d.isoformat() + "Z" if d else None


def msrc_enabled() -> bool:
    return os.environ.get("REMEDIATION_MSRC", "1").lower() not in ("0", "false", "no")


# ================================================================== Microsoft MSRC (CVRF API v3)
# CVRF remediation types (MSRC): 0 Workaround · 1 Mitigation · 2 Vendor Fix · 3 None Available · 4 Will Not Fix · 5 Known Issue
REM_TYPES = {0: "workaround", 1: "mitigation", 2: "vendor_fix", 3: "none_available", 4: "will_not_fix", 5: "known_issue"}


def is_microsoft(c: models.Cve | None) -> bool:
    if not c:
        return False
    if any(str(p).startswith("microsoft:") for p in c.products or []):
        return True
    return any("msrc.microsoft.com" in str(r.get("url", "")) for r in c.references or [])


def _val(x) -> str:
    if isinstance(x, dict):
        return str(x.get("Value") or "")
    return str(x or "")


def parse_cvrf(doc: dict, wanted: set[str] | None = None) -> dict[str, dict]:
    """MSRC CVRF JSON document → {CVE: source-neutral advisory data}. Only CVEs in `wanted` (all if None)."""
    names = {}
    tree = doc.get("ProductTree") or {}
    for p in tree.get("FullProductName") or []:
        names[str(p.get("ProductID"))] = _val(p.get("Value")) or str(p.get("Value") or "")
    for br in tree.get("Branch") or []:                      # some documents nest names under Branch → Items
        for it in br.get("Items") or []:
            for p in it.get("Items") or []:
                names.setdefault(str(p.get("ProductID")), str(p.get("Value") or ""))
    out = {}
    for v in doc.get("Vulnerability") or []:
        cve = str(v.get("CVE") or "").upper()
        if not cve or (wanted is not None and cve not in wanted):
            continue
        exploited = disclosed = None
        assessment = ""
        for t in v.get("Threats") or []:
            if t.get("Type") == 1:                            # "Exploit Status"
                txt = _val(t.get("Description"))
                for part in txt.split(";"):
                    k, _, val = part.partition(":")
                    k, val = k.strip().lower(), val.strip()
                    if k == "exploited":
                        exploited = val.lower() == "yes"
                    elif k == "publicly disclosed":
                        disclosed = val.lower() == "yes"
                    elif k.startswith("latest software release"):
                        assessment = val
                break
        rems = []
        for r in v.get("Remediations") or []:
            kind = REM_TYPES.get(r.get("Type"), str(r.get("Type")))
            pids = [str(i) for i in r.get("ProductID") or []]
            desc = _val(r.get("Description")).strip()
            rems.append({
                "type": kind, "subtype": str(r.get("SubType") or ""),
                "kb": desc if kind == "vendor_fix" and desc.isdigit() else "",
                "text": "" if kind == "vendor_fix" and desc.isdigit() else re.sub(r"<[^>]+>", " ", desc)[:1500].strip(),
                "url": str(r.get("URL") or ""), "fixed_build": str(r.get("FixedBuild") or ""),
                "restart": _val(r.get("RestartRequired")), "supersedes": str(r.get("Supercedence") or ""),
                "products": sorted({names.get(i, f"product {i}") for i in pids}),
            })
        out[cve] = {"title": _val(v.get("Title")), "exploited": exploited, "publicly_disclosed": disclosed,
                    "exploitability": assessment, "remediations": rems,
                    "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"}
    return out


async def _msrc_doc_id(client: httpx.AsyncClient, cve: str) -> str | None:
    r = await client.get(f"{MSRC_URL}/updates('{cve}')", headers={"Accept": "application/json"})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    vals = (r.json() or {}).get("value") or []
    return str(vals[0].get("ID")) if vals else None


_DOCS: dict[str, tuple[datetime, dict]] = {}     # doc_id → (time, every CVE parsed) – monthly documents are several MB
DOC_TTL = timedelta(hours=6)


async def _msrc_parsed(client: httpx.AsyncClient, doc_id: str) -> dict[str, dict]:
    hit = _DOCS.get(doc_id)
    if hit and utcnow() - hit[0] < DOC_TTL:
        return hit[1]
    r = await client.get(f"{MSRC_URL}/cvrf/{doc_id}", headers={"Accept": "application/json"})
    r.raise_for_status()
    parsed = parse_cvrf(r.json())
    _DOCS[doc_id] = (utcnow(), parsed)
    for k in sorted(_DOCS, key=lambda k: _DOCS[k][0])[:-2]:      # keep only the 2 most recent documents in memory
        _DOCS.pop(k, None)
    return parsed


def _store(db: Session, cve: str, *, doc_id="", data=None, found=True, error="", source="msrc"):
    row = db.query(models.Advisory).filter_by(source=source, cve_id=cve).first()
    if not row:
        row = models.Advisory(source=source, cve_id=cve)
        db.add(row)
    if error and row.found and row.data:              # vendor briefly unreachable → keep the good copy, note the error
        row.error = error[:300]
        row.fetched_at = utcnow()
        return
    row.doc_id, row.data, row.found, row.error, row.fetched_at = doc_id, data or {}, found, error[:300], utcnow()


def _due(row: models.Advisory | None, now: datetime) -> bool:
    if not row:
        return True
    if row.found and not row.error:
        days = CVE_RECORD_REFRESH_DAYS if row.source == "cve" else MSRC_REFRESH_DAYS
        return now - row.fetched_at > timedelta(days=days)
    return now - row.fetched_at > timedelta(hours=MISS_RETRY_HOURS)


async def fetch_msrc(cves: list[str], client: httpx.AsyncClient | None = None, force: bool = False,
                     max_docs: int = 12) -> dict:
    """Look up Microsoft advisories for these CVEs and cache them. One release document serves every CVE in it."""
    if not msrc_enabled() or not cves:
        return {"looked_up": 0}
    now = utcnow()
    with SessionLocal() as db:
        have = {a.cve_id: a for a in db.query(models.Advisory).filter(models.Advisory.source == "msrc",
                                                                      models.Advisory.cve_id.in_(cves))}
    todo = [c for c in dict.fromkeys(x.upper() for x in cves) if force or _due(have.get(c), now)]
    if not todo:
        return {"looked_up": 0}
    own = client is None
    client = client or httpx.AsyncClient(timeout=60, follow_redirects=True, headers={"User-Agent": "itops-remediation"})
    stats = {"looked_up": len(todo), "found": 0, "missing": 0, "errors": 0, "documents": 0}
    try:
        async with _fetch_lock:
            by_doc: dict[str, list[str]] = {}
            for cve in todo:
                try:
                    did = await _msrc_doc_id(client, cve)
                except Exception as e:
                    stats["errors"] += 1
                    with SessionLocal() as db:
                        _store(db, cve, found=False, error=f"{type(e).__name__}: {e}")
                        db.commit()
                    continue
                if not did:
                    stats["missing"] += 1
                    with SessionLocal() as db:
                        _store(db, cve, found=False)
                        db.commit()
                    continue
                by_doc.setdefault(did, []).append(cve)
            for did, group in list(by_doc.items())[:max_docs]:
                try:
                    parsed = await _msrc_parsed(client, did)
                    stats["documents"] += 1
                except Exception as e:
                    stats["errors"] += len(group)
                    parsed, err = {}, f"{type(e).__name__}: {e}"
                else:
                    err = ""
                with SessionLocal() as db:
                    for cve in group:
                        if cve in parsed:
                            stats["found"] += 1
                            _store(db, cve, doc_id=did, data=parsed[cve])
                        else:
                            _store(db, cve, doc_id=did, found=False, error=err)
                    # the same monthly document usually has other CVEs open on our machines → save them now (no 2nd download)
                    if parsed:
                        extra = (set(open_microsoft_cves(db)) & set(parsed)) - set(group)
                        rows = {a.cve_id: a for a in db.query(models.Advisory).filter(models.Advisory.source == "msrc",
                                                                                     models.Advisory.cve_id.in_(extra))}
                        for cve in extra:
                            if _due(rows.get(cve), now):
                                _store(db, cve, doc_id=did, data=parsed[cve])
                                stats["found"] += 1
                    db.commit()
    finally:
        if own:
            await client.aclose()
    return stats


def open_microsoft_cves(db: Session, limit: int = 300) -> list[str]:
    """CVEs of open findings that look like Microsoft products (candidates for the daily MSRC refresh)."""
    open_ids = db.query(models.VulnFinding.cve_id).filter(models.VulnFinding.status == "open").distinct()
    rows = db.query(models.Cve).filter(models.Cve.cve_id.in_(open_ids.subquery().select())).limit(5000)   # no DISTINCT on JSON columns
    return [c.cve_id for c in rows if is_microsoft(c)][:limit]


# ================================================================== official CVE record (CNA, cvelistV5)
TAG_MAP = {"x_refsource_confirm": "Vendor Advisory", "vendor-advisory": "Vendor Advisory", "patch": "Patch",
           "mitigation": "Mitigation", "release-notes": "Release Notes", "exploit": "Exploit", "x_refsource_misc": "",
           "third-party-advisory": "Third Party Advisory", "technical-description": "Technical Description"}


def cve_record_url(cve: str) -> str:
    _, year, num = cve.split("-")
    return f"{CVE_RECORD_URL}/{year}/{int(num) // 1000}xxx/{cve}.json"


def _cna_cvss(metrics: list) -> dict:
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
        for m in metrics or []:
            d = m.get(key)
            if d and d.get("baseScore") is not None:
                sev = str(d.get("baseSeverity") or "").lower()
                return {"score": float(d["baseScore"]), "severity": sev, "version": str(d.get("version") or key[5:].replace("_", ".")),
                        "vector": str(d.get("vectorString") or "")[:200]}
    return {}


def parse_cve_record(doc: dict) -> dict:
    """CVE JSON 5 record → what Remediation Mapping needs (source-neutral)."""
    meta = doc.get("cveMetadata") or {}
    cna = (doc.get("containers") or {}).get("cna") or {}
    adps = (doc.get("containers") or {}).get("adp") or []
    refs: dict[str, set] = {}
    for r in cna.get("references") or []:
        if r.get("url"):
            refs.setdefault(r["url"], set()).update(TAG_MAP.get(str(t).lower(), "") for t in r.get("tags") or [])
    exploitation = ""
    metrics = list(cna.get("metrics") or [])
    for a in adps:
        for r in a.get("references") or []:
            if r.get("url") and r["url"] not in refs:              # ADP links only add new URLs (CNA tags win)
                refs[r["url"]] = {TAG_MAP.get(str(t).lower(), "") for t in r.get("tags") or []}
        for m in a.get("metrics") or []:
            o = (m.get("other") or {}).get("content") or {}
            for opt in o.get("options") or []:
                if "Exploitation" in opt:
                    exploitation = str(opt["Exploitation"]).lower()
        metrics += a.get("metrics") or []
    affected = []
    for a in cna.get("affected") or []:
        affected.append({"vendor": re.sub(r"\s+", " ", str(a.get("vendor") or "")).strip(),
                         "product": re.sub(r"\s+", " ", str(a.get("product") or "")).strip(),
                         "default": str(a.get("defaultStatus") or ""),
                         "versions": [{k: v for k, v in x.items() if k in ("version", "status", "lessThan", "lessThanOrEqual", "changes", "versionType")}
                                      for x in (a.get("versions") or [])][:60]})
    desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), "")
    cwe = sorted({d.get("cweId") for p in cna.get("problemTypes") or [] for d in p.get("descriptions") or [] if d.get("cweId")})
    return {"state": meta.get("state", ""), "assigner": meta.get("assignerShortName", ""), "title": str(cna.get("title") or "")[:300],
            "description": desc, "cvss": _cna_cvss(cna.get("metrics") or []) or _cna_cvss(metrics), "cwe": cwe[:10],
            "affected": affected[:30], "exploitation": exploitation,
            "references": [{"url": u, "tags": sorted(t for t in tags if t)} for u, tags in list(refs.items())[:20]]}


def catalogue_row(cve: str, rec: dict) -> dict:
    """A CVE catalogue row from the CNA record – used only while NVD has not delivered the CVE yet (NVD overwrites it later)."""
    cv = rec.get("cvss") or {}
    prods = []
    for a in rec.get("affected", []):
        v, p = (re.sub(r"[^a-z0-9]+", "_", a["vendor"].lower()).strip("_"), re.sub(r"[^a-z0-9]+", "_", a["product"].lower()).strip("_"))
        if v and p and f"{v}:{p}" not in prods:
            prods.append(f"{v}:{p}")
    return {"cve_id": cve, "status": "CNA record", "description": rec.get("description", ""), "cvss_score": cv.get("score"),
            "cvss_severity": cv.get("severity", "") if cv.get("severity") in ("critical", "high", "medium", "low", "none") else "",
            "cvss_version": cv.get("version", "")[:8], "cvss_vector": cv.get("vector", ""), "cwe": rec.get("cwe", []),
            "products": prods[:30], "references": rec.get("references", [])[:15], "cpe_match": []}


def _tok(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", str(s).lower()))


def _is_ver(s) -> bool:
    return bool(re.match(r"^v?\d", str(s or "").strip()))


def _cna_matches(a: dict, name: str) -> bool:
    """Does a CNA 'affected' entry (vendor + product) describe this installed package name?"""
    nt = _tok(name)
    pt = _tok(a["product"]) - {"the", "for", "and", "of"}
    vt = _tok(a["vendor"])
    if pt and pt <= nt:
        return True                                               # "7-Zip" ⊂ "7-Zip 26.00 (x64)"
    big = {w for w in pt & nt if len(w) >= 4}
    return bool(vt and vt <= nt and big)                          # Veeam + "Backup" (CNA wrote "Backup and Recovery")


def _cna_target(v: dict, ver: str) -> tuple[str, str] | None:
    """One CNA 'versions' item + installed version → (op, version) of the first safe version, or None if not affected / unknown."""
    if str(v.get("status", "affected")).lower() != "affected":
        return None
    have = vkey(ver) if ver else None
    text = str(v.get("version") or "").strip()
    m = re.match(r"^(<=|<|≤)\s*(\S+)", text)                      # GitHub-style "<= 26.00"
    if m:
        bound, incl = m.group(2), m.group(1) in ("<=", "≤")
        if have is None or (have <= vkey(bound) if incl else have < vkey(bound)):
            return (">", bound) if incl else (">=", bound)
        return None
    lo = text if _is_ver(text) and text not in ("0",) else ""
    if lo and lo in (str(v.get("lessThan") or ""), str(v.get("lessThanOrEqual") or "")):
        lo = ""                                                   # common CNA slip: {version: X, lessThanOrEqual: X} means "up to X"
    if have is not None and lo and have < vkey(lo):
        return None                                               # installed version is below this range
    if v.get("changes"):                                          # log4j-style: status changes at given versions
        pts = sorted([(vkey(c["at"]), c["at"], str(c.get("status", "")).lower()) for c in v["changes"] if _is_ver(c.get("at"))])
        if have is None:
            return None
        state, nxt = "affected", None
        for k, at, st in pts:
            if have >= k:
                state = st
            elif nxt is None and st == "unaffected" and state == "affected":
                nxt = at
        if state != "affected":
            return None
        upper = v.get("lessThan") if _is_ver(v.get("lessThan")) else None
        if nxt:
            return (">=", nxt)
        if upper and have < vkey(upper):
            return (">=", upper)
        return None
    for key, op in (("lessThan", ">="), ("lessThanOrEqual", ">")):
        b = v.get(key)
        if _is_ver(b) and b != "*":
            if have is None or (have < vkey(b) if key == "lessThan" else have <= vkey(b)):
                return (op, b)
            return None
    return None                                                   # a single affected version: no fixed version in the record


def cna_state(rec: dict, name: str, ver: str) -> str:
    """'in' = the CVE record says this installed version is affected · 'out' = it lists versions for this product and
    this one is not among them · '' = cannot tell (product not listed, no version, no usable ranges)."""
    if not ver:
        return ""
    have, usable = vkey(ver), False
    for a in rec.get("affected", []):
        if not _cna_matches(a, name):
            continue
        for v in a["versions"]:
            if str(v.get("status", "")).lower() != "affected":
                continue
            text = str(v.get("version") or "").strip()
            if _cna_target(v, ver):
                return "in"
            if re.match(r"^(<=|<|≤)", text) or v.get("lessThan") or v.get("lessThanOrEqual") or v.get("changes"):
                usable = True                                       # a real range that does not contain this version
            elif _is_ver(text):
                usable = True
                if vkey(re.sub(r"\s*\(.*\)$", "", text)) == have:
                    return "in"                                     # exact affected version, e.g. "24.08 (x64)"
    return "out" if usable else ""


def _range_state(c: models.Cve | None, product: str, version: str) -> str:
    """Same as cna_state, for NVD CPE ranges."""
    if not c or not version or not product:
        return ""
    v, seen = vkey(version), False
    for e in c.cpe_match or []:
        if e.get("c", "").split(":")[3:5] != product.split(":"):
            continue
        parts = e["c"].split(":")
        if len(parts) > 5 and parts[5] not in ("*", "-", ""):        # exact version in the CPE itself
            seen = True
            if vkey(parts[5]) == v:
                return "in"
            continue
        if not any(k in e for k in ("si", "se", "ei", "ee")):
            continue
        seen = True
        if ("si" in e and v < vkey(e["si"])) or ("se" in e and v <= vkey(e["se"])):
            continue
        if ("ee" in e and v >= vkey(e["ee"])) or ("ei" in e and v > vkey(e["ei"])):
            continue
        return "in"
    return "out" if seen else ""


def cna_fix(rec: dict, name: str, ver: str) -> tuple[str, list[str]]:
    """→ ("26.01 or later" | "a version newer than 26.00" | "", [affected versions listed by the CNA for this product])."""
    best, listed = None, []
    for a in rec.get("affected", []):
        if not _cna_matches(a, name):
            continue
        for v in a["versions"]:
            if str(v.get("status", "")).lower() == "affected" and v.get("version"):
                listed.append(str(v["version"]))
            t = _cna_target(v, ver)
            if t and (best is None or vkey(t[1]) > vkey(best[1]) or (vkey(t[1]) == vkey(best[1]) and t[0] == ">=")):
                best = t
    if not best:
        return "", listed[:5]
    return (f"{best[1]} or later" if best[0] == ">=" else f"a version newer than {best[1]}"), listed[:5]


async def fetch_cve_records(cves: list[str], client: httpx.AsyncClient | None = None, force: bool = False,
                            limit: int = 800) -> dict:
    """Official CVE records → cache (advisories.source='cve'); CVEs missing from the catalogue are added from the record."""
    cves = [c for c in dict.fromkeys(x.upper() for x in cves) if re.fullmatch(r"CVE-\d{4}-\d{4,7}", c)]
    if not cves:
        return {"looked_up": 0}
    now = utcnow()
    with SessionLocal() as db:
        have = {a.cve_id: a for a in db.query(models.Advisory).filter(models.Advisory.source == "cve", models.Advisory.cve_id.in_(cves))}
    todo = [c for c in cves if force or _due(have.get(c), now)][:limit]
    stats = {"looked_up": len(todo), "found": 0, "missing": 0, "errors": 0, "added_to_catalogue": 0}
    if not todo:
        return stats
    own = client is None
    client = client or httpx.AsyncClient(timeout=30, follow_redirects=True, headers={"User-Agent": "itops-remediation"})
    sem = asyncio.Semaphore(8)

    async def one(cve):
        async with sem:
            try:
                r = await client.get(cve_record_url(cve))
                if r.status_code == 404:
                    return cve, None, ""
                r.raise_for_status()
                return cve, parse_cve_record(r.json()), ""
            except Exception as e:
                return cve, None, f"{type(e).__name__}: {e}"
    try:
        results = await asyncio.gather(*(one(c) for c in todo))
        with SessionLocal() as db:
            cat = {c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_([c for c, rec, _ in results if rec]))}
            new_rows = []
            for cve, rec, err in results:
                if err:
                    stats["errors"] += 1
                    _store(db, cve, source="cve", found=False, error=err)
                elif rec is None or rec.get("state") == "REJECTED":
                    stats["missing"] += 1
                    _store(db, cve, source="cve", found=False)
                else:
                    stats["found"] += 1
                    _store(db, cve, source="cve", data=rec)
                    c = cat.get(cve)
                    if c is None:
                        new_rows.append(catalogue_row(cve, rec))
                    else:                                           # fill gaps NVD left (never overwrite NVD values)
                        cv = rec.get("cvss") or {}
                        if c.cvss_score is None and cv.get("score") is not None:
                            c.cvss_score, c.cvss_severity = cv["score"], cv.get("severity", "")
                            c.cvss_version, c.cvss_vector = cv.get("version", "")[:8], cv.get("vector", "")
                        if not c.description and rec.get("description"):
                            c.description = rec["description"]
            db.commit()
            if new_rows:
                ins, _ = cve_mod.upsert(db, new_rows)
                stats["added_to_catalogue"] = ins
            if new_rows or stats["found"]:
                from . import vuln_policy                           # scores changed → priorities / deadlines
                vuln_policy.refresh(db)
                db.commit()
    finally:
        if own:
            await client.aclose()
    return stats


def records_wanted(db: Session, limit: int = 800) -> list[str]:
    """Open findings whose CVE is missing from the catalogue or has no NVD version data → need the official CVE record."""
    open_ids = [c for (c,) in db.query(models.VulnFinding.cve_id).filter(models.VulnFinding.status == "open").distinct()]
    have = {c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_(open_ids))} if open_ids else {}
    return [c for c in open_ids if c not in have or not (have[c].cpe_match or [])][:limit]


# ================================================================== device context
ARCH = {"amd64": "x64-based", "x86_64": "x64-based", "arm64": "ARM64-based", "386": "32-bit", "x86": "32-bit"}


def windows_product_match(a: models.Agent | None, product: str) -> bool:
    """Is this MSRC product name the Windows edition this agent runs? (e.g. 'Windows 10 Version 22H2 for x64-based Systems')"""
    if not a or a.os_family != "windows" or not product:
        return False
    os_name, p = (a.os_name or ""), product.lower()
    m = re.search(r"windows (server )?(\d{2,4})", os_name.lower())
    if not m:
        return False
    if m.group(1):                                                    # Windows Server 2016/2019/2022/2025
        fam = f"windows server {m.group(2)}"
        if not p.startswith(fam) or "server core" in p:
            return False
        if "edition" in p:                                            # "Windows Server 2022, 23H2 Edition"
            return bool(a.os_release) and a.os_release.lower() in p
        return True
    fam = f"windows {m.group(2)}"                                     # Windows 10 / 11
    if not p.startswith(fam):
        return False
    if a.os_release and f"version {a.os_release.lower()}" not in p:
        return False
    arch = ARCH.get((a.arch or "").lower())
    return not arch or arch.lower() in p


def _build_tuple(s: str) -> tuple[int, int] | None:
    """'10.0.19045.4780' → (19045, 4780)."""
    m = re.match(r"\d+\.\d+\.(\d+)\.(\d+)", s or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def _device(db: Session, f: models.VulnFinding) -> dict:
    d = {"target": f.target, "name": f.target, "kind": "", "os": "", "agent": None, "asset": None}
    if f.agent_id and (a := db.get(models.Agent, f.agent_id)):
        d.update(name=a.hostname, kind=a.os_kind or "client", os=" ".join(x for x in [a.os_name, a.os_release] if x),
                 build=f"{a.os_build}.{a.os_ubr}" if a.os_build and a.os_ubr is not None else (a.os_build or ""), agent=a)
    elif f.asset_id and (s := db.get(models.Asset, f.asset_id)):
        d.update(name=s.name, kind=s.type or "", os=" ".join(x for x in [s.vendor, s.model, s.os] if x), asset=s)
    return d


def _installed(db: Session, agent: models.Agent | None, product: str) -> tuple[str, str]:
    """(software name, version) currently reported by the agent for a CPE product like 'veeam:backup_\\&_replication'."""
    if not agent or not product:
        return "", ""
    words = _tok(product.split(":")[-1].replace("\\", "")) - {"the", "for", "and", "of"}
    if not words:
        return "", ""
    q = db.query(models.AgentSoftware).filter(models.AgentSoftware.agent_id == agent.id,
                                              func.lower(models.AgentSoftware.name).contains(max(words, key=len)))
    hits = sorted([sw for sw in q.limit(50) if words <= _tok(sw.name)], key=lambda sw: len(sw.name))   # whole words only
    return (hits[0].name, hits[0].norm_version or hits[0].version) if hits else ("", "")


def _fix_from_ranges(c: models.Cve | None, product: str, version: str) -> str:
    """NVD / CNA CPE ranges → the first NOT affected version for the branch the installed version is on.
    Returns "12.2.0.334" (upgrade to ≥), "> 5.4.1" (anything newer), "" (unknown / not covered by the ranges)."""
    if not c or not product:
        return ""
    v = vkey(version) if version else None
    targets = []
    for e in c.cpe_match or []:
        if e.get("c", "").split(":")[3:5] != product.split(":") or not ("ee" in e or "ei" in e):
            continue
        cand = e["ee"] if "ee" in e else f"> {e['ei']}"
        if v is None:
            targets.append(cand)
            continue
        if ("si" in e and v < vkey(e["si"])) or ("se" in e and v <= vkey(e["se"])):
            continue                                        # installed version is on another branch
        if ("ee" in e and v < vkey(e["ee"])) or ("ei" in e and v <= vkey(e["ei"])):
            return cand                                     # this range contains the installed version
    targets = list(dict.fromkeys(targets))
    if len(targets) == 1:
        return targets[0]
    return " or ".join(targets[:4]) + " (depending on the installed branch)" if targets else ""


# ================================================================== references
OFFICIAL_TAGS = {"Vendor Advisory", "Patch", "Mitigation", "Release Notes", "US Government Resource"}
HIDDEN_TAGS = {"Exploit"}


# Microsoft apps updated through the Microsoft Store (no KB in MSRC). Names as MSRC / Windows list them.
STORE_APPS = ("photos", "paint", "paint 3d", "3d viewer", "hevc", "vp9", "av1", "raw image", "webp", "heif", "mpeg-2", "video extensions",
              "image extension", "snipping tool", "snip & sketch", "notepad", "calculator", "camera", "windows terminal", "store",
              "media player", "clipchamp", "outlook for windows", "whiteboard", "to do", "sticky notes", "xbox", "phone link")


def _is_store_app(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in STORE_APPS)


def _ms_app_name(r: dict) -> str:
    """'Microsoft Photos App' / 'More Information for Microsoft Photos' → 'Microsoft Photos'."""
    p = (r.get("products") or [""])[0] or ""
    if not p:
        m = re.search(r"for (.+)$", r.get("text") or "")
        p = m.group(1) if m else "the application"
    return re.sub(r"\s+app$", "", p.strip(), flags=re.I)


def _ms_installed(dets, app: str) -> str:
    """Installed version of that app as a source reported it ('Photos 2019.19071.12548.0' → '2019.19071.12548.0')."""
    want = _tok(app) - {"microsoft", "app", "windows"}
    for d, _ in dets:
        if d.package and d.version and want and want <= _tok(d.package):
            return d.version
    return ""


def _words(product: str) -> list[str]:
    """'veeam:backup_\\&_replication' → ['backup', 'replication'];  '7-zip:7-zip' → ['7', 'zip']."""
    return [w for w in re.split(r"[^a-z0-9]+", product.split(":")[-1].replace("\\", "").lower()) if w and w not in ("the", "for", "and", "of")]


def _references(c: models.Cve | None, cve_id: str, ms: dict | None, rec: dict | None = None) -> dict:
    official, catalog, other, hidden = [], [], [], 0
    if ms:
        official.append({"title": "Microsoft Security Update Guide", "url": ms["url"], "source": "Microsoft"})
    if c and c.kev:
        official.append({"title": "CISA Known Exploited Vulnerabilities", "source": "CISA",
                         "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"})
    seen = {x["url"] for x in official}
    rtags = {r["url"]: set(r.get("tags") or []) for r in (rec or {}).get("references", [])}
    merged = [{"url": r.get("url", ""), "tags": set(r.get("tags") or []) | rtags.get(r.get("url", ""), set())} for r in (c.references if c else []) or []]
    merged += [{"url": u, "tags": t} for u, t in rtags.items() if u not in {m["url"] for m in merged}]
    for r in merged:
        url, tags = str(r.get("url", "")), set(r.get("tags") or [])
        if not url.startswith(("https://", "http://")) or url in seen:
            continue
        seen.add(url)
        host = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
        item = {"title": host, "url": url, "source": ", ".join(sorted(tags)) or "reference"}
        if tags & HIDDEN_TAGS and not tags & OFFICIAL_TAGS:
            hidden += 1                                       # exploit / PoC code: not offered to IT staff
        elif tags & OFFICIAL_TAGS:
            official.append(item)
        else:
            other.append(item)
    catalog += [{"title": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "source": "NIST"},
                {"title": "CVE.org record", "url": f"https://www.cve.org/CVERecord?id={cve_id}", "source": "CVE Program"},
                {"title": "Wazuh CTI", "url": f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}", "source": "Wazuh"}]
    return {"official": official[:12], "catalog": catalog, "other": other[:10], "hidden_exploit_links": hidden}


# ================================================================== playbook
def _step(phase, text, source, kind, url="", detail=""):
    return {"phase": phase, "text": text, "source": source, "kind": kind, "url": url, "detail": detail}


def build_playbook(db: Session, f: models.VulnFinding | None, cve_id: str) -> dict:
    """Advisory context + remediation mapping → playbook. `f` may be None (CVE without a device)."""
    c = db.query(models.Cve).filter(models.Cve.cve_id == cve_id).first()
    dev = _device(db, f) if f else {"name": "", "kind": "", "os": "", "agent": None, "asset": None, "target": ""}
    agent = dev.get("agent")
    adv = db.query(models.Advisory).filter_by(source="msrc", cve_id=cve_id).first()
    ms = adv.data if adv and adv.found and adv.data else None
    radv = db.query(models.Advisory).filter_by(source="cve", cve_id=cve_id).first()
    rec = radv.data if radv and radv.found and radv.data else None
    dets = (db.query(models.VulnDetection, models.VulnSource.name)
            .join(models.VulnSource, models.VulnSource.id == models.VulnDetection.source_id)
            .filter(models.VulnDetection.finding_id == f.id, models.VulnDetection.active.is_(True)).all()) if f else []

    facts, steps, fixes, mitig, evidence, affected_listed = [], [], [], [], [], []
    host = dev["name"] or "the device"
    exploited = bool(c and c.kev) or bool(ms and ms.get("exploited")) or bool(rec and rec.get("exploitation") == "active")

    # ---------------------------------------------------------- facts (each with its source)
    if c and c.kev:
        facts.append({"label": "Exploited", "value": "Yes – CISA KEV" + (", used by ransomware" if c.kev_ransomware else "")
                      + (f", CISA due {c.kev_due:%Y-%m-%d}" if c.kev_due else ""), "source": "CISA KEV"})
    elif rec and rec.get("exploitation") == "active":
        facts.append({"label": "Exploited", "value": "Yes – exploitation seen (CISA assessment)", "source": "CVE record"})
    elif rec and rec.get("exploitation") == "poc" and not (ms and ms.get("exploited")):
        facts.append({"label": "Exploited", "value": "Not seen yet – public proof-of-concept exists (CISA assessment)", "source": "CVE record"})
    elif ms and ms.get("exploited") is not None:
        facts.append({"label": "Exploited", "source": "Microsoft MSRC",
                      "value": ("Yes" if ms["exploited"] else "No") + (f" – {ms['exploitability']}" if ms.get("exploitability") else "")})
    if dev["os"]:
        facts.append({"label": "OS", "value": dev["os"] + (f" · build {dev['build']}" if dev.get("build") else ""),
                      "source": "IT Ops agent" if agent else "IT Ops asset"})

    # ---------------------------------------------------------- 1) source that found it (e.g. Wazuh fixed_version from distro feeds)
    seen_fix, affected = set(), {}
    for d, sname in dets:
        if d.fixed_version:
            key = (d.package, d.version, d.fixed_version)
            if key not in seen_fix:
                seen_fix.add(key)
                fixes.append(_step("fix", f"Update {d.package or 'the affected package'} from {d.version or '?'} to {d.fixed_version} or later",
                                   sname, "source"))
        elif d.package and d.version and not re.match(r"(microsoft )?windows", d.package.lower()):   # the OS itself: see "OS"
            affected.setdefault((d.version, sname), []).append(d.package)
    for (ver, sname), pkgs in affected.items():            # one line per version, not one per package
        pkgs = sorted(set(pkgs), key=len)
        more = [x[len(pkgs[0]):].strip() if x.startswith(pkgs[0]) else x for x in pkgs[1:4]]   # "… Server" → "Server"
        name = pkgs[0] if ver in pkgs[0] else f"{pkgs[0]} {ver}"     # "7-Zip 26.00 (x64)": version already in the name
        facts.append({"label": "Installed", "source": sname, "value": name + (f" (+ {', '.join(more)})" if more else "")})

    # ---------------------------------------------------------- 2) Microsoft MSRC: KB per product, fixed build, workarounds
    ms_match = []
    if ms:
        vendor_fixes = [r for r in ms.get("remediations", []) if r["type"] == "vendor_fix"]
        ms_match = [r for r in vendor_fixes if any(windows_product_match(agent, p) for p in r["products"])]
        windows_cve = is_windows_cve(ms)
        shown = ms_match or (vendor_fixes[:6] if not agent or not windows_cve else [])
        for r in shown:
            prods = [p for p in r["products"] if windows_product_match(agent, p)] or r["products"][:3]
            extra = []
            if r["kb"]:
                what = f"Install KB{r['kb']}"
                if r["fixed_build"]:
                    extra.append(f"fixed build {r['fixed_build']}")
                target = "" if ms_match else f" for {'; '.join(prods)}"     # matched this machine → the OS row already says which
            elif r["fixed_build"] and (not r["text"] or r["text"].lower().startswith("more information")):
                # No KB: an app updated on its own (Microsoft Store app, Edge, Teams…). MSRC still publishes the fixed build,
                # so say it as an action: "Update Microsoft Photos from 2019.x to 2022.30050.31008.0 or later".
                app = _ms_app_name(r)
                inst = _ms_installed(dets, app)
                what = f"Update {app}" + (f" from {inst}" if inst else "") + f" to {r['fixed_build']} or later"
                if _is_store_app(app):
                    what += " – Microsoft Store › Library › Get updates (or: winget upgrade)"
                target = ""
            else:
                what, target = (r["text"] or "Apply the vendor update"), "" if ms_match else f" for {'; '.join(prods)}"
                if r["fixed_build"]:
                    extra.append(f"fixed build {r['fixed_build']}")
            if r["restart"].lower() == "yes":
                extra.append("restart needed")
            fixes.append(_step("fix", f"{what}{target}" + (f" ({', '.join(extra)})" if extra else ""),
                               "Microsoft MSRC", "vendor", r["url"]))
        if agent and agent.os_family == "windows" and vendor_fixes and not ms_match and windows_cve:
            facts.append({"label": "Windows edition", "source": "IT Ops",
                          "value": f"No MSRC update listed for {dev['os']} – check the edition is still supported (end of servicing?)"})
        for r in ms.get("remediations", []):
            if r["type"] in ("workaround", "mitigation") and r["text"]:
                mitig.append(_step("mitigate", r["text"][:600], "Microsoft MSRC", "vendor", r["url"]))
            elif r["type"] in ("none_available", "will_not_fix") and r["text"]:
                facts.append({"label": "Vendor note", "value": r["text"][:300], "source": "Microsoft MSRC"})

    # ---------------------------------------------------------- 3) CVE catalogue: CPE version ranges (NVD / CNA)
    if not fixes and c:
        products = [p for p in (c.products or []) if not p.startswith("microsoft:windows")]
        for p in products[:5]:
            name, ver = _installed(db, agent, p)
            origin = "agent inventory" if ver else ""
            words = _words(p)
            hits = sorted([(d, sn) for d, sn in dets if d.version and d.package and words and set(words) <= _tok(d.package)],
                          key=lambda x: len(x[0].package))
            for d, sn in hits[:1]:                            # what the scanner saw (e.g. Wazuh "Veeam Backup & Replication 12.1.0.2131")
                st2 = _range_state(c, p, d.version)
                if st2:
                    evidence.append((st2, d.package, d.version, "NVD", sn))
                if not ver:
                    name, ver, origin = d.package, d.version, sn
            st = _range_state(c, p, ver)
            if st and origin == "agent inventory":
                evidence.append((st, name, ver, "NVD", origin))
            target = _fix_from_ranges(c, p, ver) if st != "out" else ""
            if target:
                label = name or " ".join(_words(p)).title() or p
                to = f"a version {target}" if target.startswith(">") else (f"{target}" if " or " in target else f"{target} or later")
                txt = f"Update {label}" + (f" from {ver}" if ver and ver not in label else "") + f" to {to}"
                fixes.append(_step("fix", txt, "NVD / CNA version ranges", "catalog"))
                if ver and not any(x["label"] == "Installed" for x in facts):
                    facts.append({"label": "Installed", "value": f"{label} {ver}", "source": "IT Ops agent inventory"})
                break

    # ---------------------------------------------------------- 4) official CVE record (CNA): versions when NVD has none
    if rec and rec.get("affected") and (not fixes or not evidence):
        cands = [(d.package, d.version, sn) for d, sn in dets if d.package]
        if agent:
            for a in rec["affected"]:
                words = _tok(a["product"]) - {"the", "for", "and", "of"}
                if words:
                    for sw in (db.query(models.AgentSoftware).filter(models.AgentSoftware.agent_id == agent.id,
                               func.lower(models.AgentSoftware.name).contains(max(words, key=len))).limit(50)):
                        cands.append((sw.name, sw.norm_version or sw.version, "agent inventory"))
        listed_all = []
        # affected copies first, so the Fix names the copy that needs it
        for name, ver, origin in sorted(set(cands), key=lambda x: (cna_state(rec, x[0], x[1]) != "in", len(x[0]))):
            st = cna_state(rec, name, ver)
            if st:
                evidence.append((st, name, ver, "CVE record", origin))
            target, listed = cna_fix(rec, name, ver)
            listed_all += listed
            if target and not fixes:                          # keep looping: other copies still count as evidence
                fixes.append(_step("fix", f"Update {name}" + (f" from {ver}" if ver and ver not in name else "") + f" to {target}",
                                   f"CVE record ({rec.get('assigner') or 'CNA'})", "catalog"))
        affected_listed = list(dict.fromkeys(listed_all))

    # ---------------------------------------------------------- 5) CISA required action (KEV)
    if c and c.kev and c.kev_action:
        mitig.insert(0, _step("mitigate", c.kev_action.strip(), "CISA KEV", "catalog"))

    # ---------------------------------------------------------- Known / Not known / Exposure (facts only, nothing guessed)
    ins = [e for e in evidence if e[0] == "in"]
    outs = [e for e in evidence if e[0] == "out"]
    out_of_range = bool(outs) and not ins and not ms_match
    if ins:
        _, nm, ver, src, _o = ins[0]
        facts.append({"label": "Affected", "value": f"Yes – {nm}" + (f" {ver}" if ver not in nm else "") + f" is within the affected versions ({src})",
                      "source": src})
    elif out_of_range:
        _, nm, ver, src, _o = outs[0]
        facts.append({"label": "Affected", "value": f"Unclear – {nm}" + (f" {ver}" if ver not in nm else "")
                      + f" is outside the affected versions in the {src}; the scanner may be wrong", "source": src})
    seen_v = {}
    for _st, nm, ver, _src, origin in evidence:
        if ver:
            seen_v.setdefault(ver, origin)
    if len(seen_v) > 1:                                     # e.g. Wazuh 26.01 vs agent inventory 24.08 → two copies?
        facts.append({"label": "Versions differ", "source": "IT Ops",
                      "value": ", ".join(f"{v} ({o})" for v, o in seen_v.items()) + " – more than one copy may be installed; check and update all of them"})
    if affected_listed and not fixes:
        facts.append({"label": "Affected versions", "value": ", ".join(affected_listed[:5]), "source": "CVE record"})
    checked = [n for n in dict.fromkeys(sname for _, sname in dets)]
    if c and c.status != "CNA record":
        checked.append("NVD")
    if radv:
        checked.append("the CVE record")
    if adv:
        checked.append("Microsoft")
    still_loading = cve_id in _LOADING or c is None
    if not fixes and not out_of_range:
        facts.append({"label": "Not known", "source": "IT Ops",
                      "value": "Fixed version – not published in " + (", ".join(checked) if checked else "the sources checked so far")
                               + (" (still checking)" if still_loading else "")})
    if f:
        others = (db.query(func.count(models.VulnFinding.id))
                  .filter(models.VulnFinding.cve_id == cve_id, models.VulnFinding.status == "open", models.VulnFinding.id != f.id).scalar() or 0)
        kind = {"server": "Server", "client": "Endpoint"}.get(dev.get("kind") or "", (dev.get("kind") or "Device").capitalize())
        facts.append({"label": "Exposure", "source": "IT Ops",
                      "value": f"{kind} · " + (f"also open on {others} other machine{'s' if others != 1 else ''}" if others else "only this machine")})

    # ---------------------------------------------------------- status
    if fixes:
        status, headline = "fix_available", "A fix is available"
    elif out_of_range:
        status, headline = "check_version", "Installed version looks unaffected – verify"
    elif mitig:
        status, headline = "mitigation_only", "No fixed version published yet – mitigations only"
    else:
        status, headline = "no_fix_yet", "No fixed version published yet"
    pending = bool(is_microsoft(c) and msrc_enabled() and (not adv or (adv.error and not adv.found)))

    # ---------------------------------------------------------- IT Ops reminders (short fixed set, not a rule matrix)
    std = "IT Ops"
    server = dev.get("kind") == "server" or dev.get("asset") is not None
    remind = [_step("remind", f"Snapshot / back up {host} first and patch in a maintenance window"
                              + (" – tell the service owner" if server else ""), std, "itops"),
              _step("remind", "Record it in a change request with evidence (installed version / KB)", std, "itops")]
    if exploited:
        mitig.append(_step("mitigate", "Check for signs of compromise (new admin accounts, unknown services, antivirus alerts)", std, "itops"))
    refs = _references(c, cve_id, ms, rec)
    nxt, watch = [], []
    ver_now = next((e[2] for e in ins if e[2]), "") or next((d.version for d, _ in dets if d.version), "")
    if out_of_range:
        nxt.append(_step("next", f"Check the version actually installed on {host}. If it is outside the affected versions, "
                                 "set the finding to false positive with a short note", std, "itops"))
    elif not fixes:
        link = refs["official"][0]["url"] if refs["official"] else ""
        nxt.append(_step("next", "Check the vendor's release notes for a version " + (f"newer than {ver_now} " if ver_now else "")
                                 + f"that mentions {cve_id}; update only to a version that lists the fix", std, "itops", link))
        nxt.append(_step("next", "IT Ops checks " + (", ".join(c for c in checked if c not in {sname for _, sname in dets}) or "the sources")
                                 + " again every day – the fixed version appears here when it is published", std, "itops"))
    if agent and agent.os_family == "windows":
        watch.append(_step("watch", f"Microsoft Defender detections on {host} raise an IT Ops alert automatically", std, "itops"))
    if fixes or out_of_range:
        watch.append(_step("watch", "After the change, the agent / scanner reports the new version and the finding closes by itself", std, "itops"))
    verify = []
    fixed_builds = [_build_tuple(r["fixed_build"]) for r in ms_match if _build_tuple(r["fixed_build"])]
    if agent and fixed_builds and agent.os_build and agent.os_ubr is not None:
        need = max(fixed_builds)
        have = (int(agent.os_build), int(agent.os_ubr)) if str(agent.os_build).isdigit() else None
        if have and have[0] == need[0]:
            ok = have[1] >= need[1]
            verify.append(_step("fix", f"This machine is on build {have[0]}.{have[1]} – "
                                          + ("already patched, the finding should close at the next scan" if ok else f"not patched yet (needs {need[0]}.{need[1]})"),
                                "IT Ops agent + Microsoft MSRC", "check", detail="ok" if ok else "pending"))
    if out_of_range:
        remind = []                                         # nothing to patch until the version is confirmed
    steps = fixes + verify + nxt + mitig + watch + remind
    out = {
        "cve_id": cve_id, "target": dev.get("target", ""), "device": {k: dev[k] for k in ("name", "kind", "os") if k in dev}
        | ({"build": dev["build"]} if dev.get("build") else {}),
        "status": status, "headline": headline, "exploited": exploited,
        "priority": f.priority if f else None, "due_at": _iso(f.due_at) if f else None,
        "title": (ms or {}).get("title") or (c.kev_name if c and c.kev_name else "") or (rec or {}).get("title")
                 or ((c.description or "")[:140] if c else ""),
        "facts": facts, "steps": steps, "references": refs,
        "advisory": {"microsoft": is_microsoft(c), "pending": pending,
                     "fetched_at": _iso(adv.fetched_at) if adv else None, "error": adv.error if adv else "",
                     "found": bool(adv and adv.found)},
        "sources_used": sorted({s["source"] for s in steps if s["kind"] != "itops"} | {x["source"] for x in facts}),
        "generated_at": _iso(utcnow()),
    }
    out["text"] = as_text(out)
    return out


def is_windows_cve(ms: dict) -> bool:
    return any(p.lower().startswith("windows") for r in ms.get("remediations", []) for p in r["products"])


PHASES = [("fix", "Fix"), ("next", "Next"), ("mitigate", "Reduce risk now"), ("watch", "Watch"), ("remind", "Reminders")]


def as_text(p: dict) -> str:
    """Plain-text checklist for a ticket / change request."""
    lines = [f"{p['cve_id']}" + (f" · {p['device']['name']}" if p["device"].get("name") else "") + f" · {p['headline']}"]
    if p.get("title"):
        lines.append(p["title"])
    if p.get("due_at"):
        lines.append(f"Due: {p['due_at'][:10]}" + (f" · priority {p['priority']}" if p.get("priority") is not None else ""))
    for fct in p["facts"]:
        lines.append(f"- {fct['label']}: {fct['value']}")
    for key, label in PHASES:
        items = [s for s in p["steps"] if s["phase"] == key]
        if items:
            lines.append(f"\n{label}:")
            lines += [f"- {s['text']}" + (f"\n  {s['url']}" if s["url"] else "") for s in items]
    refs = p["references"]["official"] + p["references"]["catalog"]
    if refs:
        lines.append("\nReferences:")
        lines += [f"- {r['title']}: {r['url']}" for r in refs]
    return "\n".join(lines)


# ================================================================== API
_LOADING: set[str] = set()          # CVEs being looked up in the background right now


def _needs(db: Session, cve_id: str) -> tuple[bool, bool]:
    """(Microsoft advisory due, official CVE record due) for this CVE."""
    c = db.query(models.Cve).filter(models.Cve.cve_id == cve_id).first()
    now = utcnow()
    ms = is_microsoft(c) and msrc_enabled() and _due(db.query(models.Advisory).filter_by(source="msrc", cve_id=cve_id).first(), now)
    rec = (c is None or not (c.cpe_match or [])) and _due(db.query(models.Advisory).filter_by(source="cve", cve_id=cve_id).first(), now)
    return bool(ms), bool(rec)


async def _lookup(cve_id: str, ms: bool, rec: bool, force: bool = False):
    try:
        if rec:
            await fetch_cve_records([cve_id], force=force)
        if ms:
            await fetch_msrc([cve_id], force=force)
    except Exception as e:                                  # vendor slow / unreachable → next request tries again later
        log.info("advisory lookup for %s: %s", cve_id, e)
    finally:
        _LOADING.discard(cve_id)


async def _ensure_advisories(db: Session, cve_id: str, force: bool = False):
    """Cached → nothing to do. Missing / old → look it up in the background (the page asks again in a moment).
    force (admin "Refresh") → wait for the answer."""
    c = db.query(models.Cve).filter(models.Cve.cve_id == cve_id).first()
    if force:
        _LOADING.add(cve_id)
        try:
            await asyncio.wait_for(_lookup(cve_id, is_microsoft(c) and msrc_enabled(), True, force=True), timeout=60)
        except Exception as e:
            log.info("advisory refresh for %s: %s", cve_id, e)
        _LOADING.discard(cve_id)
        db.expire_all()
        return
    ms, rec = _needs(db, cve_id)
    if (ms or rec) and cve_id not in _LOADING:
        _LOADING.add(cve_id)
        asyncio.get_running_loop().create_task(_lookup(cve_id, ms, rec))


def _with_loading(p: dict) -> dict:
    p["advisory"]["loading"] = p["cve_id"] in _LOADING
    return p


@router.get("/api/vuln/findings/{fid}/remediation")
async def finding_remediation(fid: int, refresh: bool = False, user=Depends(current_user), db: Session = Depends(get_db)):
    f = db.get(models.VulnFinding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    if refresh and user.role != "admin":
        raise HTTPException(403, "Only administrators can refresh vendor data")
    await _ensure_advisories(db, f.cve_id, force=refresh)
    return _with_loading(build_playbook(db, f, f.cve_id))


@router.get("/api/remediation/{cve_id}")
async def cve_remediation(cve_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    cve_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        raise HTTPException(400, "Invalid CVE id")
    await _ensure_advisories(db, cve_id)
    return _with_loading(build_playbook(db, None, cve_id))


@router.post("/api/remediation/refresh")
async def refresh_all(user=Depends(admin_user)):
    """Refresh Microsoft advisories for every open Microsoft finding now (also runs after each daily CVE sync)."""
    with SessionLocal() as db:
        cves = open_microsoft_cves(db)
    return await fetch_msrc(cves, force=True, max_docs=24)


# ================================================================== daily refresh (runs with the CVE catalogue sync)
from . import cve as cve_mod  # noqa: E402


class MsrcFeed(cve_mod.FeedSource):
    """Microsoft MSRC advisories for open Microsoft findings – a cache for Remediation Mapping."""
    name = "msrc"

    async def sync(self, client, db) -> dict:
        if not msrc_enabled():
            return {"skipped": "REMEDIATION_MSRC=0"}
        res = await fetch_msrc(open_microsoft_cves(db), client=client)
        # keep the cache small: drop saved advisories of CVEs that no longer have any finding
        live = {c for (c,) in db.query(models.VulnFinding.cve_id).distinct()}
        old = [a for a in db.query(models.Advisory) if a.cve_id not in live]             # msrc + cve records
        for a in old:
            db.delete(a)
        db.commit()
        res["removed"] = len(old)
        if res.get("looked_up") and res.get("errors") == res.get("looked_up"):
            raise RuntimeError(f"MSRC unreachable for all {res['looked_up']} CVEs")
        return res


class CveRecordFeed(cve_mod.FeedSource):
    """Official CVE records (CNA) for open findings that NVD has not covered (missing from the catalogue / no version data)."""
    name = "cverecord"

    async def sync(self, client, db) -> dict:
        res = await fetch_cve_records(records_wanted(db), client=client)
        if res.get("looked_up") and res.get("errors") == res.get("looked_up"):
            raise RuntimeError(f"CVE records unreachable for all {res['looked_up']} CVEs")
        return res


for _feed in (CveRecordFeed(), MsrcFeed()):    # after NVD / KEV / EPSS
    if not any(f.name == _feed.name for f in cve_mod.FEEDS):
        cve_mod.FEEDS.append(_feed)
