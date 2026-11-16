"""Vulnerabilities grouped the way IT works on them.

1. By software – open findings grouped by the installed product ("Google Chrome", "7-Zip", "Windows Server 2022 …").
   One row = one job: update that software on N machines. The version to update to comes only from published data,
   never guessed, in this order for each CVE:
     a. the scanner's fixed version (e.g. Wazuh, from the vendor / distro feed)
     b. the official CVE record from the vendor (CNA) – "affected < 26.01" → 26.01
     c. NVD affected-version ranges (CPE) for that product
     d. Microsoft MSRC – the KB update for the Windows edition / Office product
   Only data already cached by the remediation feeds is used (no internet call while the page loads).
   When some CVEs still have no published fix, the row says so.
2. Attack type – plain labels from the CWE ids in the CVE catalogue (code execution, memory corruption, privilege
   escalation…). A CVE can have several labels; a CVE without a mapped CWE has none ("not classified").
"""
import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from . import models
from .db import get_db
from .security import current_user
from .vulnsrc.cpe_match import vkey

router = APIRouter()

# ------------------------------------------------------------------ attack types (CWE → label)
ATTACK_TYPES = {
    "rce": ("Code execution", [77, 78, 94, 95, 96, 502, 434, 917, 1336, 74]),
    "memory": ("Memory corruption", [119, 120, 121, 122, 124, 416, 415, 787, 788, 843, 190, 191, 680, 822, 823, 824, 457, 908, 704]),
    "privesc": ("Privilege escalation", [269, 250, 266, 268, 274, 648, 732, 276, 281, 427, 428, 426, 59, 1188]),
    "auth": ("Authentication bypass", [287, 288, 290, 294, 306, 307, 862, 863, 639, 285, 284, 521, 798, 1390, 1391, 620, 640, 613]),
    "info": ("Information disclosure", [200, 201, 203, 209, 212, 532, 538, 359, 312, 319, 125, 126, 127, 226, 922, 1230]),
    "traversal": ("Path traversal", [22, 23, 24, 35, 36, 73]),
    "injection": ("Injection / XSS", [79, 80, 89, 90, 91, 93, 113, 116, 352, 611, 918, 1021, 601]),
    "dos": ("Denial of service", [400, 770, 674, 835, 404, 401, 772, 476, 369, 617, 1333, 834, 789, 1325]),
}
_CWE_TO = {}
for _k, (_lbl, _ids) in ATTACK_TYPES.items():
    for _i in _ids:
        _CWE_TO.setdefault(f"CWE-{_i}", []).append(_k)


def attack_types(cwes) -> list[str]:
    """['rce', 'memory'] for a CVE's CWE list, in ATTACK_TYPES order."""
    got = {k for c in (cwes or []) for k in _CWE_TO.get(str(c).upper(), [])}
    return [k for k in ATTACK_TYPES if k in got]


def cwe_filter(kind: str):
    """SQL condition on models.Cve.cwe for one attack type ("none" = CVEs without any mapped CWE)."""
    col = cast(models.Cve.cwe, String)
    if kind == "none":
        all_ids = [c for c in _CWE_TO]
        return ~or_(*[col.like(f'%"{c}"%') for c in all_ids])
    if kind not in ATTACK_TYPES:
        raise HTTPException(400, "unknown attack type")
    return or_(*[col.like(f'%"CWE-{i}"%') for i in ATTACK_TYPES[kind][1]])


@router.get("/api/vuln/attack-types")
def list_attack_types(user=Depends(current_user)):
    return [{"key": k, "label": lbl} for k, (lbl, _) in ATTACK_TYPES.items()]


# ------------------------------------------------------------------ software name → product key
# 131.0.6778.85 · 24.08 · 3.0.2-0ubuntu1.10 · 1:2.3.4-1 (but NOT year ranges like 2015-2022, which name the product)
_VER = re.compile(r"(?<![\w.])v?(?:\d+:)?\d+(?:\.\d+)+(?:[-+~][0-9a-z.+~]*)?(?![\w.])", re.I)
_ARCH = re.compile(r"\b(x64|x86|x86_64|amd64|arm64|aarch64|i386|i686|64[- ]?bit|32[- ]?bit|win64|win32)\b", re.I)
_LOCALE = re.compile(r"\b[a-z]{2}-[a-z]{2}\b", re.I)                         # en-US, vi-VN


def product_key(name: str) -> tuple[str, str]:
    """('google chrome', 'Google Chrome') – versions, architecture and locale removed so copies on different machines group."""
    s = re.sub(r"\([^)]*\)", " ", name or "")                                # "(x64 en-US)", "(64-bit)"
    s = re.sub(r"\s+-\s+.*$", " ", s)                                        # "… Redistributable - 14.38.33130"
    s = _VER.sub(" ", s)
    s = _ARCH.sub(" ", s)
    s = _LOCALE.sub(" ", s)
    s = re.sub(r"[\s_]+", " ", s).strip(" -_.,")
    return s.lower(), s or (name or "").strip()


def _fix_ok(v: str) -> bool:
    v = (v or "").strip()
    return bool(v) and v not in ("0", "*", "-", "n/a", "N/A", "None", "none")


def _groups(db: Session):
    """{key: group} from active detections of open, untriaged findings."""
    from .vuln_policy import _open_untriaged, band
    rows = (_open_untriaged(db).join(models.VulnDetection, models.VulnDetection.finding_id == models.VulnFinding.id)
            .filter(models.VulnDetection.active.is_(True))
            .with_entities(models.VulnFinding.id, models.VulnFinding.target, models.VulnFinding.cve_id, models.VulnFinding.priority,
                           models.VulnFinding.due_at, models.VulnFinding.sla_category, models.VulnDetection.package,
                           models.VulnDetection.version, models.VulnDetection.fixed_version).all())
    groups, names = {}, {}
    for fid, target, cve, prio, due, cat, pkg, ver, fix in rows:
        if not pkg:
            continue
        key, disp = product_key(pkg)
        if not key:
            continue
        g = groups.setdefault(key, {"key": key, "findings": {}, "cves": {}, "machines": {}, "names": {}})
        g["names"][disp] = g["names"].get(disp, 0) + 1
        g["findings"][fid] = (prio, due, cat)
        c = g["cves"].setdefault(cve, {"fix": set(), "kev": False, "prio": 0, "machines": set(), "versions": set(), "via": ""})
        c["kev"] |= cat == "kev"
        c["prio"] = max(c["prio"], prio or 0)
        c["machines"].add(target)
        if ver:
            c["versions"].add(ver)
        if _fix_ok(fix):
            c["fix"].add(fix.strip())
            c["via"] = "scanner"
        m = g["machines"].setdefault(target, {"versions": set(), "cves": set(), "prio": 0})
        if ver:
            m["versions"].add(ver)
        m["cves"].add(cve)
        m["prio"] = max(m["prio"], prio or 0)
    return groups, band


_VNUM = re.compile(r"\d+(?:\.\d+)*[a-z0-9.-]*", re.I)
_MS_GENERIC = {"microsoft", "for", "and", "the", "x64", "x86", "32", "64", "bit", "based", "systems", "editions", "edition", "version"}


def _vendor_fixes(db: Session, g: dict) -> None:
    """Fill CVEs of a group that have no scanner fix from the vendor data the remediation feeds cached (b, c, d above)."""
    from .remediation import cna_fix, _fix_from_ranges, _range_state, _tok, _words, windows_product_match
    need = [cid for cid, c in g["cves"].items() if not c["fix"]]
    if not need:
        return
    adv = {}
    for a in db.query(models.Advisory).filter(models.Advisory.cve_id.in_(need), models.Advisory.found.is_(True)):
        adv.setdefault(a.cve_id, {})[a.source] = a.data or {}
    cat = {c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_(need))}
    name = max(g["names"], key=g["names"].get)
    gtok = _tok(name)
    agents = {}
    ids = [int(t[6:]) for t in g["machines"] if t.startswith("agent:")]
    if ids:
        agents = {f"agent:{a.id}": a for a in db.query(models.Agent).filter(models.Agent.id.in_(ids))}
    for cid in need:
        c = g["cves"][cid]
        vers = sorted(c["versions"], key=vkey) or [""]
        rec, ms = adv.get(cid, {}).get("cve"), adv.get(cid, {}).get("msrc")
        # b) official CVE record (CNA)
        if rec and rec.get("affected"):
            for v in vers:
                txt, _ = cna_fix(rec, name, v)
                m = _VNUM.search(txt or "")
                if m and txt.endswith("or later"):
                    c["fix"].add(m.group(0)); c["via"] = c["via"] or "CVE record"          # noqa: E702
                elif m:
                    c["newer_than"] = m.group(0); c["via"] = c["via"] or "CVE record"      # noqa: E702
        # c) NVD affected-version ranges for the matching CPE product
        x = cat.get(cid)
        if not c["fix"] and x:
            for prod in (x.products or [])[:8]:
                w = _words(prod)
                if not w or not set(w) <= gtok:
                    continue
                for v in vers:
                    if v and _range_state(x, prod, v) == "out":
                        continue
                    t = _fix_from_ranges(x, prod, v)
                    if t and not t.startswith(">") and " or " not in t:
                        c["fix"].add(t); c["via"] = c["via"] or "NVD"                       # noqa: E702
                    elif t.startswith(">"):
                        c["newer_than"] = t[1:].strip(); c["via"] = c["via"] or "NVD"       # noqa: E702
                if c["fix"] or c.get("newer_than"):
                    break
        # d) Microsoft MSRC: KB for this Windows edition (per machine) or this Microsoft product
        if ms and not c["fix"]:
            kbs = set()
            for r in ms.get("remediations", []):
                if r.get("type") != "vendor_fix":
                    continue
                if not r.get("kb") and r.get("fixed_build"):          # Store app / Edge…: MSRC gives the fixed build, no KB
                    if any((gtok - _MS_GENERIC - {"app"}) and (gtok - _MS_GENERIC - {"app"}) <= (_tok(p) - _MS_GENERIC - {"app"})
                           for p in r.get("products", [])):
                        c["fix"].add(r["fixed_build"])
                        c["via"] = c["via"] or "Microsoft MSRC"
                    continue
                if not r.get("kb"):
                    continue
                for prod in r.get("products", []):
                    pt = _tok(prod) - _MS_GENERIC
                    on_machine = any(windows_product_match(agents.get(t), prod) for t in c["machines"])
                    by_name = "windows" not in pt and bool(gtok - _MS_GENERIC) and (gtok - _MS_GENERIC) <= pt
                    if on_machine or by_name:
                        kbs.add(f"KB{r['kb']}")
            if kbs:
                c["kbs"] = sorted(kbs)
                c["via"] = c["via"] or "Microsoft MSRC"


def _top_fix(cves: dict) -> dict:
    """What to do for the whole group: highest fixed version, or 'newer than X', plus Microsoft KBs; and how many CVEs are covered."""
    fixes = [f for c in cves.values() for f in c["fix"]]
    best = max(fixes, key=lambda v: (vkey(v), v)) if fixes else ""
    newer = [c["newer_than"] for c in cves.values() if c.get("newer_than") and not c["fix"]]
    nt = max(newer, key=vkey) if newer and (not best or vkey(max(newer, key=vkey)) >= vkey(best)) else ""
    kbs = sorted({k for c in cves.values() for k in c.get("kbs", [])})
    via = sorted({c["via"] for c in cves.values() if c.get("via")})
    covered = sum(1 for c in cves.values() if c["fix"] or c.get("newer_than") or c.get("kbs"))
    return {"fix_version": best, "newer_than": nt, "kbs": kbs[:6], "kbs_more": max(0, len(kbs) - 6), "fix_from": via, "cves_with_fix": covered}


@router.get("/api/vuln/by-software")
def by_software(q: str = "", attack: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    from .vuln import utcnow, _iso
    now = utcnow()
    groups, band = _groups(db)
    all_cves = {c for g in groups.values() for c in g["cves"]}
    cat = {}
    ids = list(all_cves)
    for i in range(0, len(ids), 5000):
        cat.update({c.cve_id: c for c in db.query(models.Cve.cve_id, models.Cve.cwe, models.Cve.cvss_score)
                    .filter(models.Cve.cve_id.in_(ids[i:i + 5000]))})
    out = []
    for g in groups.values():
        name = max(g["names"], key=g["names"].get)
        if q and q.lower() not in name.lower():
            continue
        kinds = {}
        for cid in g["cves"]:
            for k in attack_types(cat[cid].cwe if cid in cat else []):
                kinds[k] = kinds.get(k, 0) + 1
        if attack and (attack not in kinds if attack != "none" else bool(kinds)):
            continue
        _vendor_fixes(db, g)
        fx = _top_fix(g["cves"])
        dues = [d for _, d, _ in g["findings"].values() if d]
        mx = max(p or 0 for p, _, _ in g["findings"].values())
        out.append({"key": g["key"], "name": name, "cves": len(g["cves"]), "machines": len(g["machines"]), "findings": len(g["findings"]),
                    "max_priority": mx, "band": band(mx), "kev": sum(1 for c in g["cves"].values() if c["kev"]),
                    "overdue": sum(1 for _, d, _ in g["findings"].values() if d and d < now),
                    "next_due": _iso(min(dues)) if dues else None,
                    "max_cvss": max((cat[c].cvss_score or 0 for c in g["cves"] if c in cat), default=None) or None,
                    **fx,
                    "attack": [{"key": k, "label": ATTACK_TYPES[k][0], "cves": n} for k, n in sorted(kinds.items(), key=lambda x: -x[1])]})
    return sorted(out, key=lambda r: (-r["max_priority"], -r["kev"], -r["machines"], r["name"].lower()))


@router.get("/api/vuln/by-software/detail")
def by_software_detail(key: str, user=Depends(current_user), db: Session = Depends(get_db)):
    from .vuln import _names
    groups, band = _groups(db)
    g = groups.get(key)
    if not g:
        raise HTTPException(404, "No open findings for this software")
    cat = {c.cve_id: c for c in db.query(models.Cve).filter(models.Cve.cve_id.in_(list(g["cves"])))}
    names = _names(db, set(g["machines"]))
    _vendor_fixes(db, g)
    fx = _top_fix(g["cves"])
    machines = []
    for t, m in g["machines"].items():
        n = names.get(t, {"name": t, "ip": ""})
        machines.append({"target": t, "name": n["name"], "ip": n.get("ip", ""), "versions": sorted(m["versions"], key=vkey),
                         "cves": len(m["cves"]), "max_priority": m["prio"], "band": band(m["prio"])})
    cves = []
    for cid, c in g["cves"].items():
        x = cat.get(cid)
        cves.append({"cve_id": cid, "max_priority": c["prio"], "band": band(c["prio"]), "kev": c["kev"], "machines": len(c["machines"]),
                     "cvss_score": x.cvss_score if x else None, "cvss_severity": x.cvss_severity if x else "",
                     "fixed_versions": sorted(c["fix"], key=vkey), "newer_than": c.get("newer_than", ""), "kbs": c.get("kbs", []),
                     "fix_from": c.get("via", ""),
                     "attack": [ATTACK_TYPES[k][0] for k in attack_types(x.cwe if x else [])],
                     "description": ((x.description if x else "") or "")[:220]})
    return {"key": key, "name": max(g["names"], key=g["names"].get), **fx,
            "machines": sorted(machines, key=lambda m: (-m["max_priority"], m["name"].lower())),
            "cves": sorted(cves, key=lambda c: (-c["max_priority"], c["cve_id"]))}
