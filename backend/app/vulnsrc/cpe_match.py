"""IT Ops' own matching for devices WITHOUT an agent (ESXi, firewalls, NAS, APs…) using NVD CPE data.

Medium confidence by design: it relies on the product/version text the device reports, so results are shown as
'needs verification' until a person (or a second source) confirms them.
Identify a device precisely by setting Asset → meta → "cpe": "vendor:product:version" (several separated by ';').
"""
import re

from sqlalchemy import String, cast

from .. import models
from . import HostRef, Provider, Record, Snapshot, register

# (regex on "vendor model os" text, [vendor:product, …]); group 1 = version
RULES = [
    (r"\besxi\s+v?(\d+(?:\.\d+){1,3})", ["vmware:esxi"]),
    (r"vcenter server\s+(\d+(?:\.\d+){1,3})", ["vmware:vcenter_server"]),
    (r"forti(?:os|gate)\D{0,20}v?(\d+\.\d+\.\d+)", ["fortinet:fortios"]),
    (r"pfsense\D{0,20}(\d+\.\d+(?:\.\d+)?)", ["pfsense:pfsense", "netgate:pfsense_plus"]),
    (r"opnsense\D{0,20}(\d+\.\d+(?:\.\d+)?)", ["opnsense:opnsense"]),
    (r"pve-manager/(\d+\.\d+(?:\.\d+)?)", ["proxmox:virtual_environment"]),
    (r"arubaos\D{0,20}(\d+\.\d+\.\d+\.\d+)", ["arubanetworks:arubaos", "hpe:arubaos", "arubanetworks:instant"]),
    (r"routeros\D{0,20}(\d+\.\d+(?:\.\d+)?)", ["mikrotik:routeros"]),
    (r"\bdsm\s*(\d+\.\d+(?:\.\d+)?)", ["synology:diskstation_manager"]),
]
SKIP_TYPES = ("service", "website", "internet", "vm", "container")


def vkey(v: str) -> tuple:
    parts = re.findall(r"\d+|[a-z]+", str(v).lower())
    out = [(1, int(p)) if p.isdigit() else (0, p) for p in parts]
    while out and out[-1] == (1, 0):                       # 8.0.0 == 8.0
        out.pop()
    return tuple(out)


def identify(a: models.Asset) -> list[tuple[str, str]]:
    """Asset → [(vendor:product, version)]."""
    manual = str((a.meta or {}).get("cpe") or "").strip()
    if manual:
        out = []
        for part in manual.split(";"):
            bits = [b.strip().lower() for b in part.split(":")]
            if len(bits) >= 3 and bits[0] and bits[1] and bits[2]:
                out.append((f"{bits[0]}:{bits[1]}", bits[2]))
        return out
    text = " ".join([a.vendor or "", a.model or "", a.os or ""]).lower()
    for rx, products in RULES:
        m = re.search(rx, text)
        if m:
            return [(p, m.group(1)) for p in products]
    return []


def matches(entry: dict, version: str) -> bool:
    """One NVD cpeMatch entry (criteria + optional ranges) against an installed version."""
    parts = entry.get("c", "").split(":")
    if len(parts) < 7:
        return False
    cver, cupd = parts[5], parts[6]
    v = vkey(version)
    if any(k in entry for k in ("si", "se", "ei", "ee")):
        if "si" in entry and not v >= vkey(entry["si"]):
            return False
        if "se" in entry and not v > vkey(entry["se"]):
            return False
        if "ei" in entry and not v <= vkey(entry["ei"]):
            return False
        if "ee" in entry and not v < vkey(entry["ee"]):
            return False
        return True
    if cver == "*":
        return True                                        # NVD: every version is affected
    if cver in ("-", ""):
        return False
    full = cver
    m = re.match(r"(?:update|u|p)_?(\d+)", cupd or "")
    if m:
        full = f"{cver}.{m.group(1)}"                       # ESXi 8.0 update 2 → 8.0.2
    return vkey(full) == v


@register
class CpeProvider(Provider):
    kind = "cpe"
    label = "IT Ops CPE matching (devices without agent)"
    default_confidence = "medium"
    singleton = True
    auto_create = True

    def defaults(self) -> dict:
        return {"interval_hours": 24}

    async def collect(self, cfg, db, payload=None) -> Snapshot:
        with_agent = {i for (i,) in db.query(models.Agent.asset_id).filter(models.Agent.asset_id.isnot(None))}
        hosts, records, cache = [], [], {}
        for a in db.query(models.Asset).filter(~models.Asset.type.in_(SKIP_TYPES)):
            if a.id in with_agent:
                continue                                    # machines with an agent are covered by Wazuh / other sources
            ids = identify(a)
            if not ids:
                continue
            ref = f"asset:{a.id}"
            hosts.append(HostRef(ref=ref, name=a.name, ip=a.ip, target=ref, scanned=True))
            for vp, ver in ids:
                if vp not in cache:
                    cache[vp] = (db.query(models.Cve.cve_id, models.Cve.cpe_match, models.Cve.cvss_severity, models.Cve.cvss_score)
                                 .filter(cast(models.Cve.products, String).ilike(f'%"{vp}"%')).all())
                for cid, entries, sev, score in cache[vp]:
                    if any(e.get("c", "").split(":")[3:5] == vp.split(":") and matches(e, ver) for e in entries or []):
                        records.append(Record(ref=ref, cve_id=cid, package=vp.split(":")[1], version=ver, severity=sev or "", score=score))
        return Snapshot(hosts=hosts, records=records, info={"devices_identified": len(hosts), "products": len(cache)})
