"""File import – CSV or JSON from any scanner (or a Wazuh 'Discover' CSV export).

Proves the core does not depend on any one tool (acceptance test 3), and is the fallback while a tool is down.
Columns are matched by name (case-insensitive); the first match wins:
  host      host, hostname, computer, asset, agent.name, agent_name, name
  ip        ip, ip_address, agent.ip, host.ip
  cve       cve, cve_id, cveid, vulnerability.id, vulnerability, id
  package   package, package.name, software, product
  version   version, package.version, installed_version
  fixed     fixed_version, fixed, fix_version, solution_version
  severity  severity, vulnerability.severity
  score     score, cvss, cvss_score, vulnerability.score.base
Every host in the file counts as fully scanned: CVEs of that host that are not in the new file become 'fixed'.
"""
import csv
import io
import json

from . import HostRef, Provider, Record, Snapshot, SourceError, norm_severity, register, to_float

COLS = {
    "host": ("host", "hostname", "computer", "asset", "agent.name", "agent_name", "name"),
    "ip": ("ip", "ip_address", "agent.ip", "host.ip"),
    "cve": ("cve", "cve_id", "cveid", "vulnerability.id", "vulnerability", "id"),
    "package": ("package", "package.name", "software", "product"),
    "version": ("version", "package.version", "installed_version"),
    "fixed": ("fixed_version", "fixed", "fix_version", "solution_version"),
    "severity": ("severity", "vulnerability.severity"),
    "score": ("score", "cvss", "cvss_score", "vulnerability.score.base"),
}
MAX_BYTES = 30 * 1024 * 1024


def _flatten(d: dict, prefix="") -> dict:
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}".lower()
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def parse(content: str) -> list[dict]:
    if len(content.encode("utf-8", "ignore")) > MAX_BYTES:
        raise SourceError("File is larger than 30 MB – split it or filter it first")
    text = content.lstrip("﻿").strip()
    if not text:
        raise SourceError("The file is empty")
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise SourceError(f"Not valid JSON: {e}")
        if isinstance(data, dict):                             # {"items": [...]} or an OpenSearch response
            data = data.get("items") or [h.get("_source", h) for h in data.get("hits", {}).get("hits", [])] or [data]
        rows = [_flatten(x) for x in data if isinstance(x, dict)]
    else:
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        rows = [{(k or "").strip().lower(): v for k, v in r.items()} for r in csv.DictReader(io.StringIO(text), dialect=dialect)]
    out = []
    for r in rows:
        x = {}
        for key, names in COLS.items():
            x[key] = next((str(r[n]).strip() for n in names if r.get(n) not in (None, "")), "")
        out.append(x)
    if out and not any(x["cve"] for x in out):
        raise SourceError("No CVE column found – expected a column named cve, cve_id or vulnerability.id")
    if out and not any(x["host"] or x["ip"] for x in out):
        raise SourceError("No host column found – expected host, hostname, agent.name or ip")
    return out


@register
class FileImportProvider(Provider):
    kind = "file"
    label = "File import (CSV / JSON)"
    default_confidence = "medium"
    scheduled = False

    def defaults(self) -> dict:
        return {"stale_days": 30, "mapping": {}}

    async def collect(self, cfg, db, payload=None) -> Snapshot:
        if not payload:
            raise SourceError("Upload a CSV or JSON file to import")
        rows = parse(payload.get("content", ""))
        hosts, records = {}, []
        for x in rows:
            ref = (x["host"] or x["ip"]).lower()
            if not ref or not x["cve"].upper().startswith("CVE-"):
                continue
            hosts.setdefault(ref, HostRef(ref=ref, name=x["host"], ip=x["ip"], scanned=True))
            records.append(Record(ref=ref, cve_id=x["cve"], package=x["package"], version=x["version"], fixed_version=x["fixed"],
                                  severity=norm_severity(x["severity"]), score=to_float(x["score"])))
        return Snapshot(hosts=list(hosts.values()), records=records,
                        info={"file": str(payload.get("filename", ""))[:200], "rows": len(rows), "hosts": len(hosts)})
