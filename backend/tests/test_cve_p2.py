"""CVE module – part 2: feed parsing, sync (mocked network) and the /api/cves endpoints."""
import asyncio
import gzip
from datetime import datetime, timedelta, timezone

import httpx

from app import cve, models
from app.db import SessionLocal

NOW = datetime.now(timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_item(cid, days_ago=1, score=9.8, sev="CRITICAL", product="cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*", kev=False, desc=None):
    c = {"id": cid, "published": _iso(days_ago), "lastModified": _iso(days_ago), "vulnStatus": "Analyzed",
         "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": desc or f"{cid} remote code execution"}],
         "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": sev,
                                                                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
                     "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
         "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
         "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": product},
                                                     {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
         "references": [{"url": f"https://example.org/{cid}", "tags": ["Vendor Advisory"]}]}
    if kev:
        c.update(cisaExploitAdd="2026-11-01", cisaActionDue="2026-11-22", cisaVulnerabilityName="Fortinet FortiOS RCE",
                 cisaRequiredAction="Apply mitigations per vendor instructions.")
    return {"cve": c}


def test_parse_nvd_item_prefers_cvss31_and_extracts_products():
    r = cve.parse_nvd_item(nvd_item("CVE-2026-0001", kev=True))
    assert (r["cve_id"], r["cvss_score"], r["cvss_severity"], r["cvss_version"]) == ("CVE-2026-0001", 9.8, "critical", "3.1")
    assert r["description"].startswith("CVE-2026-0001") and r["cwe"] == ["CWE-787"]
    assert r["products"] == ["fortinet:fortios"]                       # non-vulnerable CPE ignored
    assert r["kev"] is True and r["kev_due"].date().isoformat() == "2026-11-22"
    v40 = {"cve": {"id": "CVE-2026-0002", "metrics": {"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 6.9, "baseSeverity": "MEDIUM"}}]}}}
    assert cve.parse_nvd_item(v40)["cvss_severity"] == "medium"
    assert cve.parse_nvd_item({"cve": {"id": "CVE-2026-0003"}})["cvss_score"] is None   # awaiting analysis: no metrics


def test_parse_kev_and_epss():
    kev = cve.parse_kev({"catalogVersion": "2026.11.10", "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch"}]})
    assert kev[0]["kev_ransomware"] is True and kev[0]["_vendor_product"] == "apache:log4j2"
    csv_text = "#model_version:v2025.03.14,score_date:2026-11-10T00:00:00+0000\ncve,epss,percentile\nCVE-2021-44228,0.97,0.9999\nCVE-X,bad,1\n"
    date, rows = cve.parse_epss_csv(gzip.compress(csv_text.encode()))
    assert date == "2026-11-10" and rows == {"CVE-2021-44228": (0.97, 0.9999)}


def _transport():
    items = [nvd_item("CVE-2026-1001", 1, 9.8, "CRITICAL", kev=True), nvd_item("CVE-2026-1002", 2, 7.5, "HIGH",
             product="cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*", desc="Exchange Server spoofing"),
             nvd_item("CVE-2026-1003", 40, 4.3, "MEDIUM", product="cpe:2.3:a:vmware:esxi:*:*:*:*:*:*:*:*")]
    kev_items = [nvd_item("CVE-2021-44228", 1800, 10.0, "CRITICAL", product="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", kev=True)]

    def handler(req: httpx.Request):
        if "nvd" in req.url.host:
            data = kev_items if "hasKev" in req.url.params else items
            return httpx.Response(200, json={"resultsPerPage": len(data), "startIndex": 0, "totalResults": len(data), "vulnerabilities": data})
        if "cisa" in req.url.host:
            return httpx.Response(200, json={"catalogVersion": "2026.11.10", "vulnerabilities": [
                {"cveID": "CVE-2026-1001", "vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": _iso(1)[:10],
                 "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "FortiOS RCE"},
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "dateAdded": "2021-12-10", "dueDate": "2021-12-24"},
                {"cveID": "CVE-2019-9999", "vendorProject": "Acme", "product": "Old Box", "dateAdded": "2022-01-01",
                 "shortDescription": "Only in KEV, not returned by NVD yet"}]})
        if "epss" in req.url.host:
            body = "#model_version:v1,score_date:2026-11-10T00:00:00+0000\ncve,epss,percentile\n" \
                   "CVE-2026-1001,0.91,0.99\nCVE-2026-1002,0.02,0.71\nCVE-2021-44228,0.97,0.9999\n"
            return httpx.Response(200, content=gzip.compress(body.encode()))
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_sync_and_api(client, admin, viewer, monkeypatch):
    with SessionLocal() as db:
        db.query(models.Cve).delete()
        db.query(models.Setting).filter_by(key=cve.STATE_KEY).delete()
        db.commit()
    for f in cve.FEEDS:
        if isinstance(f, cve.NvdSource):
            monkeypatch.setattr(f, "pause", 0)
    monkeypatch.setenv("CVE_BACKFILL_DAYS", "60")

    async def run():
        async with httpx.AsyncClient(transport=_transport()) as c:
            return await cve.sync_all(client=c)
    res = asyncio.run(run())
    assert res["nvd"]["ok"] and res["kev"]["ok"] and res["epss"]["ok"], res
    assert res["epss"]["updated"] == 3 and res["kev"]["entries"] == 3

    s = client.get("/api/cves/summary", headers=viewer).json()
    assert s["total"] == 5 and s["kev_total"] == 3 and s["new_7d"] == 2 and s["critical_7d"] == 1
    assert s["sync"]["nvd"]["ok"] and s["sync"]["running"] is False

    lst = client.get("/api/cves?days=30", headers=viewer).json()
    assert [x["cve_id"] for x in lst["items"]] == ["CVE-2026-1001", "CVE-2026-1002"]          # newest first, 40-day-old excluded
    assert lst["items"][0]["kev"] and lst["items"][0]["epss"] == 0.91 and lst["items"][0]["kev_ransomware"] is True
    assert client.get("/api/cves?days=0&q=exchange", headers=viewer).json()["total"] == 1     # search description / product
    assert client.get("/api/cves?days=0&q=vmware:esxi", headers=viewer).json()["total"] == 1
    assert client.get("/api/cves?days=0&severity=critical", headers=viewer).json()["total"] == 2
    kev_only = client.get("/api/cves?days=0&kev=true&sort=epss", headers=viewer).json()
    assert [x["cve_id"] for x in kev_only["items"]][:2] == ["CVE-2021-44228", "CVE-2026-1001"]
    assert client.get("/api/cves?days=0&min_epss=0.5", headers=viewer).json()["total"] == 2

    d = client.get("/api/cves/cve-2019-9999", headers=viewer).json()                           # KEV-only entry kept with basics
    assert d["kev"] and d["description"].startswith("Only in KEV") and d["products"] == ["acme:old_box"]
    d = client.get("/api/cves/CVE-2026-1001", headers=viewer).json()
    assert d["nvd_url"].endswith("CVE-2026-1001") and d["references"] and d["cvss_vector"].startswith("CVSS:3.1")
    assert client.get("/api/cves/CVE-0000-0000", headers=viewer).status_code == 404

    assert client.post("/api/cves/sync", headers=viewer).status_code == 403                    # admins only

    # a failing feed does not stop the others; KEV removals clear the flag
    def broken(req):
        return httpx.Response(500) if "nvd" in req.url.host else _transport().handle_request(req)

    async def run2():
        async with httpx.AsyncClient(transport=httpx.MockTransport(broken)) as c:
            return await cve.sync_all(client=c)
    res2 = asyncio.run(run2())
    assert res2["nvd"]["ok"] is False and "500" in res2["nvd"]["error"] and res2["kev"]["ok"] and res2["epss"]["ok"]


def test_kev_falls_back_to_cisa_github_copy_when_site_refuses(client):
    doc = {"catalogVersion": "2026.11.09", "vulnerabilities": [{"cveID": "CVE-2026-77001", "vendorProject": "Acme", "product": "Gw",
                                                                  "vulnerabilityName": "Acme GW RCE", "dateAdded": "2026-11-09", "dueDate": "2026-11-30",
                                                                  "requiredAction": "Patch", "knownRansomwareCampaignUse": "Unknown",
                                                                  "shortDescription": "Fallback test"}]}

    def handler(req):
        if req.url.host == "www.cisa.gov":
            return httpx.Response(403, text="Access Denied")
        if req.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, json=doc)
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            with SessionLocal() as db:
                return await cve.KevSource().sync(c, db)
    res = asyncio.run(go())
    assert res["source"] == "raw.githubusercontent.com" and res["entries"] == 1
    with SessionLocal() as db:
        assert db.query(models.Cve).filter(models.Cve.cve_id == "CVE-2026-77001", models.Cve.kev.is_(True)).count() == 1

    def down(req):
        return httpx.Response(403, text="Access Denied")

    async def fail():
        async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as c:
            with SessionLocal() as db:
                return await cve.KevSource().sync(c, db)
    try:
        asyncio.run(fail())
        raise AssertionError("should fail")
    except RuntimeError as e:
        assert "www.cisa.gov" in str(e) and "raw.githubusercontent.com" in str(e)
