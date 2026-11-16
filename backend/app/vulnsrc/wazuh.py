"""Wazuh adapter – READ ONLY. Tested with Wazuh 4.14.x (vulnerability states in the indexer since 4.8).

  Wazuh server API (55000): agent list (id, name, IP, OS, status) + hardware serial → used to match IT Ops machines.
  Wazuh indexer   (9200):   index wazuh-states-vulnerabilities-* → one document per (agent, package, CVE).

Everything Wazuh-specific lives in this file. If Wazuh changes its format after an upgrade, only this file changes;
the check in _records() stops the sync with a clear message instead of silently importing nothing.
"""
import asyncio
import ssl
from datetime import datetime, timezone

import httpx

from . import HostRef, Provider, Record, Snapshot, SourceError, norm_severity, register, to_float

TESTED = ("4.14",)
FIELDS = ["agent.id", "agent.name", "package.name", "package.version", "vulnerability.id", "vulnerability.severity",
          "vulnerability.score.base", "vulnerability.detected_at"]
MAX_DOCS = 500_000


def _get(d: dict, path: str):
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def _dt(s):
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).replace(tzinfo=None) if d.tzinfo else d
    except (TypeError, ValueError):
        return None


def _explain(where: str, e: Exception) -> SourceError:
    if isinstance(e, SourceError):
        return e
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        hint = {401: "wrong user name or password", 403: "the user has no permission for this",
                404: "address or index not found – check the URL / index pattern"}.get(code, e.response.text[:200])
        return SourceError(f"{where}: HTTP {code} – {hint}")
    msg = str(e) or type(e).__name__
    if "CERTIFICATE" in msg.upper() or isinstance(e, ssl.SSLError):
        return SourceError(f"{where}: TLS certificate not trusted – paste Wazuh's root CA (root-ca.pem) in the source settings, "
                           "and use the same host name / IP that the certificate was issued for")
    if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout)):
        return SourceError(f"{where}: cannot connect ({msg[:120]}) – check the address, the port and the firewall")
    if isinstance(e, httpx.TimeoutException):
        return SourceError(f"{where}: timed out – Wazuh is slow or the network drops packets")
    return SourceError(f"{where}: {type(e).__name__}: {msg[:200]}")


def _verify(cfg: dict):
    if cfg.get("verify_tls") is False:
        return False
    ca = (cfg.get("ca_cert") or "").strip()
    if ca:
        try:
            return ssl.create_default_context(cadata=ca)
        except ssl.SSLError as e:
            raise SourceError(f"The CA certificate pasted in the settings is not valid PEM: {e}")
    return True


@register
class WazuhProvider(Provider):
    kind = "wazuh"
    label = "Wazuh (read-only)"
    default_confidence = "high"

    def defaults(self) -> dict:
        return {"api_url": "https://WAZUH-IP:55000", "username": "", "password": "",
                "indexer_url": "https://WAZUH-IP:9200", "indexer_username": "", "indexer_password": "",
                "index": "wazuh-states-vulnerabilities-*", "ca_cert": "", "verify_tls": True, "interval_hours": 6,
                "mapping": {}}

    # -------------------------------------------------------------- API (55000)
    async def _token(self, c: httpx.AsyncClient, cfg) -> str:
        url = cfg["api_url"].rstrip("/") + "/security/user/authenticate"
        try:
            r = await c.post(url, auth=(cfg.get("username", ""), cfg.get("password", "")))
            if r.status_code == 405:                                   # very old API: GET
                r = await c.get(url, auth=(cfg.get("username", ""), cfg.get("password", "")))
            r.raise_for_status()
            return r.json()["data"]["token"]
        except Exception as e:
            raise _explain("Wazuh API", e)

    async def _api(self, c, cfg, tok, path, **params):
        r = await c.get(cfg["api_url"].rstrip("/") + path, params=params, headers={"Authorization": f"Bearer {tok}"})
        r.raise_for_status()
        return r.json().get("data", {})

    async def _agents(self, c, cfg, tok) -> list[dict]:
        out, offset = [], 0
        try:
            while True:
                d = await self._api(c, cfg, tok, "/agents", limit=500, offset=offset, select="id,name,ip,os.name,os.version,status")
                items = d.get("affected_items", [])
                out += items
                offset += len(items)
                if not items or offset >= d.get("total_affected_items", 0):
                    return out
        except Exception as e:
            raise _explain("Wazuh API (agent list)", e)

    async def _serials(self, c, cfg, tok, ids: list[str]) -> dict:
        sem, out = asyncio.Semaphore(8), {}

        async def one(i):
            async with sem:
                try:
                    d = await self._api(c, cfg, tok, f"/syscollector/{i}/hardware")
                    s = (d.get("affected_items") or [{}])[0].get("board_serial", "")
                    if s:
                        out[i] = str(s)
                except Exception:
                    pass                                                  # serial is only a matching aid
        await asyncio.gather(*(one(i) for i in ids[:1000]))
        return out

    # -------------------------------------------------------------- indexer (9200)
    async def _records(self, c, cfg) -> list[dict]:
        base, auth = cfg["indexer_url"].rstrip("/"), (cfg.get("indexer_username", ""), cfg.get("indexer_password", ""))
        index = cfg.get("index") or "wazuh-states-vulnerabilities-*"
        docs, sid = [], None
        try:
            r = await c.post(f"{base}/{index}/_search", params={"scroll": "2m"}, auth=auth,
                             json={"size": 1000, "_source": FIELDS, "query": {"match_all": {}}})
            r.raise_for_status()
            while True:
                body = r.json()
                sid = body.get("_scroll_id")
                hits = body.get("hits", {}).get("hits", [])
                if not hits:
                    break
                docs += [h.get("_source", {}) for h in hits]
                if len(docs) >= MAX_DOCS:
                    break
                r = await c.post(f"{base}/_search/scroll", auth=auth, json={"scroll": "2m", "scroll_id": sid})
                r.raise_for_status()
        except Exception as e:
            raise _explain("Wazuh indexer", e)
        finally:
            if sid:
                try:
                    await c.request("DELETE", f"{base}/_search/scroll", auth=auth, json={"scroll_id": [sid]})
                except Exception:
                    pass
        if docs and not any(_get(d, "vulnerability.id") and _get(d, "agent.id") for d in docs[:200]):
            raise SourceError("Wazuh indexer: documents have an unexpected format (no vulnerability.id / agent.id). "
                              "Wazuh may have changed its data model after an upgrade – the sync was stopped and the last "
                              "results were kept. See README → Wazuh upgrade checklist.")
        return docs

    def _client(self, cfg):
        return httpx.AsyncClient(timeout=60, verify=_verify(cfg), follow_redirects=False)

    async def test(self, cfg, db) -> dict:
        out = {}
        async with self._client(cfg) as c:
            tok = await self._token(c, cfg)
            try:
                info = await self._api(c, cfg, tok, "/")
            except Exception as e:
                raise _explain("Wazuh API", e)
            out["version"] = str(info.get("api_version", "")).lstrip("v")
            out["tested"] = out["version"].startswith(TESTED)
            out["agents"] = len(await self._agents(c, cfg, tok))
            try:
                r = await c.post(cfg["indexer_url"].rstrip("/") + f"/{cfg.get('index') or 'wazuh-states-vulnerabilities-*'}/_count",
                                 auth=(cfg.get("indexer_username", ""), cfg.get("indexer_password", "")), json={"query": {"match_all": {}}})
                r.raise_for_status()
                out["vulnerability_documents"] = r.json().get("count", 0)
            except Exception as e:
                raise _explain("Wazuh indexer", e)
        return out

    async def collect(self, cfg, db, payload=None) -> Snapshot:
        async with self._client(cfg) as c:
            tok = await self._token(c, cfg)
            try:
                version = str((await self._api(c, cfg, tok, "/")).get("api_version", "")).lstrip("v")
            except Exception as e:
                raise _explain("Wazuh API", e)
            agents = await self._agents(c, cfg, tok)
            serials = await self._serials(c, cfg, tok, [a["id"] for a in agents if a.get("status") == "active"])
            docs = await self._records(c, cfg)
        hosts = {a["id"]: HostRef(ref=a["id"], name=a.get("name", ""), ip=a.get("ip", "") if a.get("ip") not in ("any", "127.0.0.1") else "",
                                  serial=serials.get(a["id"], ""), os=" ".join(filter(None, [_get(a, "os.name"), _get(a, "os.version")])),
                                  scanned=a.get("status") == "active") for a in agents}
        records = []
        for d in docs:
            aid, cid = str(_get(d, "agent.id") or ""), str(_get(d, "vulnerability.id") or "")
            if not aid or not cid:
                continue
            if aid not in hosts:                                          # agent removed from Wazuh but state left behind
                hosts[aid] = HostRef(ref=aid, name=str(_get(d, "agent.name") or ""), scanned=False)
            records.append(Record(ref=aid, cve_id=cid, package=str(_get(d, "package.name") or ""),
                                  version=str(_get(d, "package.version") or ""),
                                  severity=norm_severity(_get(d, "vulnerability.severity")),
                                  score=to_float(_get(d, "vulnerability.score.base")),
                                  detected_at=_dt(_get(d, "vulnerability.detected_at"))))
        return Snapshot(hosts=list(hosts.values()), records=records,
                        info={"version": version, "tested": version.startswith(TESTED), "agents": len(agents),
                              "documents": len(docs), "truncated": len(docs) >= MAX_DOCS})
