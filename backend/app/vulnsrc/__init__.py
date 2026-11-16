"""Replaceable vulnerability sources (CVE module part 3).

A provider only answers: "which CVEs does the tool see on which host?". It returns a Snapshot; app/vuln.py
maps hosts to IT Ops machines, stores findings keyed by (machine, CVE) and computes everything else.
Priority / weights NEVER come from a provider (its score is stored for reference only).

To add a tool: write one file here with a Provider subclass decorated with @register, then import it at the
bottom of this file. Nothing else in IT Ops has to change.
"""
from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("critical", "high", "medium", "low", "none")
CONFIDENCE = ("high", "medium", "low")


@dataclass
class HostRef:
    ref: str                  # id inside the source (Wazuh agent id, host name in a file, asset:<id>)
    name: str = ""
    ip: str = ""
    serial: str = ""
    os: str = ""
    scanned: bool = True      # True = the source has a current, complete view → CVEs no longer listed are fixed
    target: str = ""          # already resolved to an IT Ops machine (agent:<id> | asset:<id>)


@dataclass
class Record:
    ref: str
    cve_id: str
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    severity: str = ""
    score: float | None = None
    detected_at: datetime | None = None


@dataclass
class Snapshot:
    hosts: list[HostRef] = field(default_factory=list)
    records: list[Record] = field(default_factory=list)
    info: dict = field(default_factory=dict)      # shown on the source card (version, document count, warnings)


class SourceError(Exception):
    """Error with a message a system / network admin can act on (no stack traces in the UI)."""


class Provider:
    kind = ""
    label = ""
    default_confidence = "high"
    scheduled = True          # synced by the background loop (file imports are manual)
    singleton = False         # only one source of this kind, not creatable from the UI
    auto_create = False       # created automatically at startup (built-in)

    def defaults(self) -> dict:
        return {}

    async def test(self, cfg: dict, db) -> dict:
        return {"ok": True}

    async def collect(self, cfg: dict, db, payload=None) -> Snapshot:
        raise NotImplementedError


PROVIDERS: dict[str, Provider] = {}


def register(cls):
    PROVIDERS[cls.kind] = cls()
    return cls


def norm_severity(s) -> str:
    s = str(s or "").strip().lower()
    return {"moderate": "medium", "important": "high", "info": "none", "informational": "none"}.get(s, s if s in SEVERITIES else "")


def to_float(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


from . import wazuh, file_import, cpe_match, wazuh_demo  # noqa: E402,F401  (registers the providers)
