"""Remediation Mapping: vendor advisory (Microsoft MSRC) + CVE catalogue + source data → playbook for IT.
MSRC is mocked with a document in the real CVRF JSON shape (tests/fixtures/msrc_2026-Oct.json)."""
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app import models, remediation as rem
from app.db import SessionLocal

TAG = uuid.uuid4().hex[:6].upper()
DOC = json.loads((Path(__file__).parent / "fixtures" / "msrc_2026-Oct.json").read_text(encoding="utf-8"))
WIN, OFFICE, VEEAM, LINUX, NOTMS = "CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90011", "CVE-2026-90012", "CVE-2026-90013"


class FakeMsrc:
    def __init__(self):
        self.calls, self.down = [], False

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req.url.path)
        if self.down:
            raise httpx.ConnectError("unreachable", request=req)
        p = req.url.path
        if "/updates(" in p:
            cve = p.split("'")[1]
            if cve in (WIN, OFFICE):
                return httpx.Response(200, json={"value": [{"ID": "2026-Oct", "CvrfUrl": "x"}]})
            return httpx.Response(404, json={"error": "not found"})
        if p.endswith("/cvrf/2026-Oct"):
            assert req.headers.get("accept") == "application/json"
            return httpx.Response(200, json=DOC)
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch):
    monkeypatch.setattr(rem, "CVE_RECORD_URL", "http://127.0.0.1:9")      # background lookups must not reach GitHub in tests


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def mk_client(fake):
    return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))


@pytest.fixture(scope="module")
def world():
    """Windows 10 22H2 machine (build 19045.4529), a Veeam server, a Linux server; findings from a file-import source."""
    with SessionLocal() as db:
        def agent(name, **kw):
            a = models.Agent(uid=f"rem-{name}-{TAG}".lower(), key_hash="x", hostname=f"{name}-{TAG}", ips=[], macs=[], summary={}, **kw)
            db.add(a)
            db.flush()
            return a
        pc = agent("PC", os_family="windows", os_name="Windows 10 Pro", os_release="22H2", os_build="19045", os_ubr=4529, arch="amd64", os_kind="client")
        srv = agent("VEEAM", os_family="windows", os_name="Windows Server 2022 Standard", os_release="21H2", os_build="20348", os_ubr=2762,
                    arch="amd64", os_kind="server")
        lin = agent("LNX", os_family="linux", os_name="Ubuntu 22.04.4 LTS", os_kind="server")
        db.add(models.AgentSoftware(agent_id=srv.id, name="Veeam Backup & Replication", version="12.1.2.172", norm_version="12.1.2.172"))
        for cid, products, kw in [
            (WIN, ["microsoft:windows_10_22h2", "microsoft:windows_server_2022"], dict(kev=True, kev_action="Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", kev_due=datetime(2026, 11, 20))),
            (OFFICE, ["microsoft:office_long_term_servicing_channel"], {}),
            (VEEAM, ["veeam:backup_\\&_replication"], dict(kev=True, kev_ransomware=True, kev_action="Apply mitigations per vendor instructions.")),
            (LINUX, ["openssl:openssl"], {}),
            (NOTMS, ["acme:widget"], {}),
        ]:
            db.query(models.Cve).filter_by(cve_id=cid).delete()
            db.add(models.Cve(cve_id=cid, description=f"test {cid}", cvss_score=8.8, cvss_severity="high", products=products, **kw,
                              cpe_match=[{"c": "cpe:2.3:a:veeam:backup_\\&_replication:*:*:*:*:*:*:*:*", "si": "12.0.0.1420", "ee": "12.2.0.334"},
                                         {"c": "cpe:2.3:a:veeam:backup_\\&_replication:*:*:*:*:*:*:*:*", "ee": "11.0.1.1261"}] if cid == VEEAM else [],
                              references=[{"url": "https://www.veeam.com/kb4649", "tags": ["Vendor Advisory"]},
                                          {"url": "https://github.com/someone/poc-exploit", "tags": ["Exploit", "Third Party Advisory"]},
                                          {"url": "https://blog.example.org/analysis", "tags": ["Third Party Advisory"]}] if cid == VEEAM else []))
        src = models.VulnSource(name=f"Import {TAG}", kind="file", enabled=True, confidence="high", config={}, state={})
        db.add(src)
        db.flush()
        out = {}
        for key, a, cid, det in [("pc_win", pc, WIN, None), ("pc_office", pc, OFFICE, None), ("srv_win", srv, WIN, None),
                                 ("veeam", srv, VEEAM, None), ("linux", lin, LINUX, ("openssl", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.18")),
                                 ("notms", lin, NOTMS, None)]:
            f = models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", sources_active=1, priority=70,
                                   due_at=datetime(2026, 11, 20))
            db.add(f)
            db.flush()
            if det:
                db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package=det[0], version=det[1], fixed_version=det[2]))
            out[key] = f.id
        db.query(models.Advisory).filter(models.Advisory.cve_id.in_([WIN, OFFICE, VEEAM, LINUX, NOTMS])).delete()
        db.commit()
    fake = FakeMsrc()
    res = run(rem.fetch_msrc([WIN, OFFICE, NOTMS], client=mk_client(fake)))
    assert res["found"] == 2 and res["missing"] == 1 and res["documents"] == 1, res
    out["fake"] = fake
    return out


def test_parse_cvrf_shape():
    p = rem.parse_cvrf(DOC, {WIN, OFFICE})
    assert set(p) == {WIN, OFFICE}
    w = p[WIN]
    assert w["exploited"] is True and w["publicly_disclosed"] is False and w["exploitability"] == "Exploitation Detected"
    kb = next(r for r in w["remediations"] if r["kb"] == "5048888")
    assert kb["type"] == "vendor_fix" and kb["fixed_build"] == "10.0.19045.5011" and kb["restart"] == "Yes"
    assert "Windows 10 Version 22H2 for x64-based Systems" in kb["products"]
    wa = next(r for r in w["remediations"] if r["type"] == "workaround")
    assert "<" not in wa["text"] and "netsh int ipv6" in wa["text"]
    assert p[OFFICE]["remediations"][0]["kb"] == "" and p[OFFICE]["remediations"][0]["text"] == "Click to Run"


def test_windows_product_match():
    a = models.Agent(os_family="windows", os_name="Windows 10 Pro", os_release="22H2", arch="amd64")
    m = rem.windows_product_match
    assert m(a, "Windows 10 Version 22H2 for x64-based Systems")
    assert not m(a, "Windows 10 Version 22H2 for 32-bit Systems") and not m(a, "Windows 10 Version 1809 for x64-based Systems")
    assert not m(a, "Windows 11 Version 23H2 for x64-based Systems")
    s = models.Agent(os_family="windows", os_name="Windows Server 2022 Standard", os_release="21H2", arch="amd64")
    assert m(s, "Windows Server 2022") and not m(s, "Windows Server 2022 (Server Core installation)") and not m(s, "Windows Server 2019")
    assert not m(models.Agent(os_family="linux", os_name="Ubuntu"), "Windows Server 2022")


def test_cache_is_reused_and_misses_retry_later(world):
    fake = FakeMsrc()
    assert run(rem.fetch_msrc([WIN, OFFICE, NOTMS], client=mk_client(fake)))["looked_up"] == 0 and fake.calls == []
    with SessionLocal() as db:
        miss = db.query(models.Advisory).filter_by(source="msrc", cve_id=NOTMS).one()
        assert miss.found is False
        miss.fetched_at -= timedelta(hours=25)
        db.commit()
    assert run(rem.fetch_msrc([NOTMS], client=mk_client(fake)))["looked_up"] == 1


def test_windows_playbook_kb_build_and_kev(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['pc_win']}/remediation", headers=viewer).json()
    assert p["status"] == "fix_available" and p["exploited"] is True
    fixes = [s for s in p["steps"] if s["phase"] == "fix" and s["kind"] != "check"]
    assert len(fixes) == 1 and fixes[0]["text"] == "Install KB5048888 (fixed build 10.0.19045.5011, restart needed)"
    assert fixes[0]["source"] == "Microsoft MSRC" and "KB5048888" in fixes[0]["url"] and "restart needed" in fixes[0]["text"]
    assert "KB5048899" not in json.dumps(fixes), "Windows 11 KB must not be offered to a Windows 10 machine"
    ver = next(s for s in p["steps"] if s["kind"] == "check")
    assert ver["text"] == "This machine is on build 19045.4529 – not patched yet (needs 19045.5011)" and ver["detail"] == "pending"
    mit = [s for s in p["steps"] if s["phase"] == "mitigate"]
    assert mit[0]["source"] == "CISA KEV" and any("netsh" in s["text"] and s["source"] == "Microsoft MSRC" for s in mit)
    assert any("signs of compromise" in s["text"] for s in mit)
    refs = p["references"]
    assert refs["official"][0]["url"].endswith(WIN) and any("cisa.gov" in r["url"] for r in refs["official"])
    assert any(r["title"] == "Wazuh CTI" and r["url"].endswith(WIN) for r in refs["catalog"])
    assert "- Install KB5048888" in p["text"] and "Fix:" in p["text"] and "[ ]" not in p["text"]
    assert [s["phase"] for s in p["steps"]][0] == "fix"                                  # Fix comes first
    assert len([s for s in p["steps"] if s["phase"] == "remind"]) == 2                  # short reminders only
    assert any("Defender" in s["text"] for s in p["steps"] if s["phase"] == "watch")
    assert [f["label"] for f in p["facts"]] == ["Exploited", "OS", "Exposure"]                       # one exploited row, no duplicates
    assert "[CISA KEV]" not in p["text"] and "Microsoft MSRC" not in p["text"]          # no source tags in the export


def test_server_already_patched_signal(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['srv_win']}/remediation", headers=viewer).json()
    assert any("KB5048800" in s["text"] for s in p["steps"] if s["phase"] == "fix")
    chk = next(s for s in p["steps"] if s["kind"] == "check")
    assert chk["detail"] == "ok" and "already patched" in chk["text"]
    assert any("service owner" in s["text"] for s in p["steps"] if s["phase"] == "remind")   # server → notify owners


def test_office_fix_shown_for_app_on_windows(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['pc_office']}/remediation", headers=viewer).json()
    fx = [s for s in p["steps"] if s["phase"] == "fix"]
    assert fx and "Click to Run" in fx[0]["text"] and "Office LTSC 2021" in fx[0]["text"]
    assert not any(s["kind"] == "check" for s in p["steps"])


def test_veeam_fix_from_version_ranges_and_hidden_exploits(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['veeam']}/remediation", headers=viewer).json()
    fx = [s for s in p["steps"] if s["phase"] == "fix"]
    assert fx[0]["text"] == "Update Veeam Backup & Replication from 12.1.2.172 to 12.2.0.334 or later"
    assert fx[0]["source"] == "NVD / CNA version ranges"
    assert any(f["label"] == "Exploited" and "ransomware" in f["value"] for f in p["facts"])
    refs = p["references"]
    assert [r["url"] for r in refs["official"] if "veeam" in r["url"]] == ["https://www.veeam.com/kb4649"]
    assert refs["hidden_exploit_links"] == 1 and not any("poc-exploit" in r["url"] for r in refs["other"] + refs["official"])
    assert any("blog.example.org" in r["url"] for r in refs["other"])
    assert p["advisory"]["microsoft"] is False


def test_asset_with_scanner_packages_veeam(client, viewer):
    with SessionLocal() as db:
        a = models.Asset(name=f"Service.US-{TAG}", type="server", os="Microsoft Windows Server 2016 or later (64-bit)")
        db.add(a)
        db.flush()
        src = db.query(models.VulnSource).filter_by(name=f"Import {TAG}").one()
        f = models.VulnFinding(target=f"asset:{a.id}", asset_id=a.id, cve_id=VEEAM, status="open", sources_active=1)
        db.add(f)
        db.flush()
        for pkg in ("Veeam Backup & Replication", "Veeam Backup & Replication Server", "Veeam Backup & Replication Console"):
            db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package=pkg, version="12.1.0.2131"))
        db.commit()
        fid = f.id
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    fx = [s for s in p["steps"] if s["phase"] == "fix"]
    assert fx[0]["text"] == "Update Veeam Backup & Replication from 12.1.0.2131 to 12.2.0.334 or later"
    inst = [x for x in p["facts"] if x["label"] == "Installed"]
    assert len(inst) == 1 and inst[0]["value"] == "Veeam Backup & Replication 12.1.0.2131 (+ Server, Console)"
    assert not any(x["label"] == "Affected package" for x in p["facts"])


def test_linux_fix_from_source_fixed_version(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['linux']}/remediation", headers=viewer).json()
    fx = [s for s in p["steps"] if s["phase"] == "fix"]
    assert fx[0]["text"] == "Update openssl from 3.0.2-0ubuntu1.15 to 3.0.2-0ubuntu1.18 or later" and fx[0]["source"] == f"Import {TAG}"


def test_no_data_falls_back_to_links(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['notms']}/remediation", headers=viewer).json()
    assert p["status"] == "no_fix_yet" and p["headline"] == "No fixed version published yet"
    assert not [s for s in p["steps"] if s["phase"] == "fix"]                         # no "update" claim without a known fix
    assert any("release notes" in s["text"] and NOTMS in s["text"] for s in p["steps"] if s["phase"] == "next")
    assert any(x["label"] == "Not known" for x in p["facts"])
    assert all(s["kind"] == "itops" for s in p["steps"])                             # nothing invented as "vendor"


def test_msrc_unreachable_still_returns_playbook(client, admin, world, monkeypatch):
    monkeypatch.setattr(rem, "MSRC_URL", "http://127.0.0.1:9")                        # nothing listens there
    p = client.get(f"/api/vuln/findings/{world['pc_win']}/remediation?refresh=1", headers=admin).json()
    assert p["cve_id"] == WIN and p["steps"]                                         # still a playbook (KEV + standard steps)
    assert any("KB5048888" in s["text"] for s in p["steps"]), "cached MSRC data must survive a failed refresh"
    assert p["advisory"]["error"] and p["advisory"]["found"]


def test_refresh_admin_only_and_cve_endpoint(client, viewer, world):
    assert client.get(f"/api/vuln/findings/{world['pc_win']}/remediation?refresh=1", headers=viewer).status_code == 403
    assert client.get("/api/remediation/not-a-cve", headers=viewer).status_code == 400
    p = client.get(f"/api/remediation/{VEEAM.lower()}", headers=viewer).json()
    assert p["cve_id"] == VEEAM and "12.2.0.334" in json.dumps(p["steps"]) and p["device"] == {"name": "", "kind": "", "os": ""}


def test_msrc_feed_registered():
    from app import cve
    assert [f.name for f in cve.FEEDS][-1] == "msrc"


def test_first_open_answers_at_once_and_loads_in_background(client, viewer, world, monkeypatch):
    cid = "CVE-2026-90021"
    with SessionLocal() as db:
        db.query(models.Cve).filter_by(cve_id=cid).delete()
        db.query(models.Advisory).filter_by(cve_id=cid).delete()
        db.add(models.Cve(cve_id=cid, products=["microsoft:windows_10_22h2"], description="x"))
        pc = db.query(models.Agent).filter_by(hostname=f"PC-{TAG}").one()
        f = models.VulnFinding(target=f"agent:{pc.id}", agent_id=pc.id, cve_id=cid, status="open")
        db.add(f)
        db.commit()
        fid = f.id
    gate = []

    async def slow_fetch(cves, **kw):                      # Microsoft is slow: the page must not wait for it
        while not gate:
            await asyncio.sleep(0.05)
        with SessionLocal() as db:
            rem._store(db, cid, doc_id="2026-Oct", data=rem.parse_cvrf(DOC, {WIN})[WIN])
            db.commit()
        return {}
    monkeypatch.setattr(rem, "fetch_msrc", slow_fetch)
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    assert p["advisory"]["loading"] is True and p["advisory"]["pending"] is True and p["steps"]
    assert client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()["advisory"]["loading"] is True   # no 2nd lookup
    gate.append(True)
    import time
    for _ in range(50):
        p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
        if not p["advisory"]["loading"]:
            break
        time.sleep(0.1)
    assert not p["advisory"]["loading"] and any("KB5048888" in s["text"] for s in p["steps"])



def test_one_download_serves_other_open_cves_and_cache_is_pruned(world):
    with SessionLocal() as db:                                   # forget the Office record; WIN stays fresh
        db.query(models.Advisory).filter_by(source="msrc", cve_id=OFFICE).delete()
        db.commit()
    rem._DOCS.clear()
    fake = FakeMsrc()
    run(rem.fetch_msrc([WIN], client=mk_client(fake), force=True))
    assert sum(1 for c in fake.calls if c.endswith("/cvrf/2026-Oct")) == 1
    with SessionLocal() as db:                                   # Office (open finding, same document) saved without asking
        assert db.query(models.Advisory).filter_by(source="msrc", cve_id=OFFICE, found=True).count() == 1
        db.add(models.Advisory(source="msrc", cve_id="CVE-2026-99999", data={"remediations": []}))   # no finding anywhere
        db.commit()
    with SessionLocal() as db:
        res = run(rem.MsrcFeed().sync(mk_client(FakeMsrc()), db))
    assert res["removed"] >= 1
    with SessionLocal() as db:
        assert db.query(models.Advisory).filter_by(cve_id="CVE-2026-99999").count() == 0
        assert db.query(models.Advisory).filter_by(source="msrc", cve_id=WIN).count() == 1


# ================================================================== official CVE record (CNA) – real records from cvelistV5
REC_DIR = Path(__file__).parent / "fixtures" / "cvelist"


def rec_of(cid):
    return rem.parse_cve_record(json.loads((REC_DIR / f"{cid}.json").read_text(encoding="utf-8")))


class FakeCveList:
    def __init__(self):
        self.calls = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req.url.path)
        cid = req.url.path.rsplit("/", 1)[-1].removesuffix(".json")
        f = REC_DIR / f"{cid}.json"
        return httpx.Response(200, content=f.read_bytes()) if f.exists() else httpx.Response(404)


@pytest.mark.parametrize("cid,name,ver,expect", [
    ("CVE-2026-48095", "7-Zip 26.00 (x64)", "26.00", "a version newer than 26.00"),      # GitHub CNA text form "<= 26.00"
    ("CVE-2026-48095", "7-Zip 26.01 (x64)", "26.01", ""),                                # already fixed
    ("CVE-2026-48095", "WinZip 27.0", "27.0", ""),                                      # "zip" must not match WinZip
    ("CVE-2024-40711", "Veeam Backup & Replication", "12.1.0.2131", "a version newer than 12.1.2"),   # CNA misnamed product + X..X range
    ("CVE-2024-40711", "Veeam Agent for Windows", "6.1", ""),                           # same vendor, other product
    ("CVE-2025-0411", "7-Zip 24.08 (x64)", "24.08", ""),                                # only one affected version listed
    ("CVE-2021-44228", "Apache Log4j2", "2.14.1", "2.15.0 or later"),                   # "changes": branch-aware
    ("CVE-2021-44228", "Apache Log4j2", "2.12.1", "2.12.2 or later"),
    ("CVE-2021-44228", "Apache Log4j2", "2.3.2", ""),
])
def test_cna_fix_real_records(cid, name, ver, expect):
    assert rem.cna_fix(rec_of(cid), name, ver)[0] == expect


def test_parse_cve_record_real():
    r = rec_of("CVE-2026-48095")
    assert r["assigner"] == "GitHub_M" and r["cvss"]["score"] == 8.8 and r["cvss"]["severity"] == "high"
    assert r["exploitation"] == "poc" and "CWE-787" in r["cwe"]
    tags = {x["url"]: x["tags"] for x in r["references"]}
    assert tags["https://securitylab.github.com/advisories/GHSL-2026-140_7-Zip/"] == ["Vendor Advisory"]   # CNA CONFIRM wins over ADP "exploit"
    assert rem.cve_record_url("CVE-2025-0411").endswith("/2025/0xxx/CVE-2025-0411.json")
    assert rem.cve_record_url("CVE-2026-48095").endswith("/2026/48xxx/CVE-2026-48095.json")


def test_seven_zip_not_in_catalogue_like_computer_0000(client, viewer, world):
    """The reported case: Wazuh says '7-Zip 26.00 (x64)' has CVE-2026-48095; the CVE is not in the catalogue
    (older than the 120-day NVD window) and NVD would not have versions anyway → the CVE record must give the fix."""
    cid = "CVE-2026-48095"
    with SessionLocal() as db:
        db.query(models.Cve).filter_by(cve_id=cid).delete()
        db.query(models.Advisory).filter_by(cve_id=cid).delete()
        pc = db.query(models.Agent).filter_by(hostname=f"PC-{TAG}").one()
        src = db.query(models.VulnSource).filter_by(name=f"Import {TAG}").one()
        f = models.VulnFinding(target=f"agent:{pc.id}", agent_id=pc.id, cve_id=cid, status="open", sources_active=1,
                               provider_score=8.8, provider_severity="high")
        db.add(f)
        db.flush()
        db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package="7-Zip 26.00 (x64)", version="26.00"))
        db.commit()
        fid = f.id
    assert cid in rem.records_wanted(SessionLocal())
    fake = FakeCveList()
    res = run(rem.fetch_cve_records([cid], client=mk_client(fake)))
    assert res["found"] == 1 and res["added_to_catalogue"] == 1
    with SessionLocal() as db:
        c = db.query(models.Cve).filter_by(cve_id=cid).one()
        assert c.cvss_score == 8.8 and c.status == "CNA record" and "Versions 26.00 and prior" in c.description
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    fx = [s for s in p["steps"] if s["phase"] == "fix"]
    assert fx[0]["text"] == "Update 7-Zip 26.00 (x64) to a version newer than 26.00" and fx[0]["source"] == "CVE record (GitHub_M)"
    assert p["status"] == "fix_available" and p["title"].startswith("GHSL-2026-140")
    inst = [x["value"] for x in p["facts"] if x["label"] == "Installed"]
    assert inst == ["7-Zip 26.00 (x64)"]                                                # no "26.00 26.00"
    assert any("proof-of-concept" in x["value"] for x in p["facts"] if x["label"] == "Exploited")
    assert any("securitylab.github.com" in r["url"] for r in p["references"]["official"])
    assert any("sourceforge.net" in r["url"] for r in p["references"]["other"])


def test_seven_zip_from_nvd_ranges_when_catalogue_has_them(client, viewer, world):
    cid = "CVE-2026-48096"
    with SessionLocal() as db:
        db.query(models.Cve).filter_by(cve_id=cid).delete()
        db.add(models.Cve(cve_id=cid, products=["7-zip:7-zip"], description="x",
                          cpe_match=[{"c": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", "ee": "26.01"}]))
        lin = db.query(models.Agent).filter_by(hostname=f"LNX-{TAG}").one()
        src = db.query(models.VulnSource).filter_by(name=f"Import {TAG}").one()
        f = models.VulnFinding(target=f"agent:{lin.id}", agent_id=lin.id, cve_id=cid, status="open")
        db.add(f)
        db.flush()
        db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package="7-Zip 26.00 (x64)", version="26.00"))
        db.commit()
        fid = f.id
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    assert [s["text"] for s in p["steps"] if s["phase"] == "fix"][0] == "Update 7-Zip 26.00 (x64) to 26.01 or later"


def test_no_data_wording_is_honest(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['notms']}/remediation", headers=viewer).json()
    fx = [s["text"] for s in p["steps"] if s["phase"] == "fix"]
    assert p["headline"] == "No fixed version published yet"
    assert not any("latest version" in t for t in fx)
    assert not any("official links below" in t for t in fx) or p["references"]["official"]   # never point to links that are not there



# ================================================================== honest output when the fix is unknown / version outside the range
def _finding_with(cid, host, pkg, ver, rec_file=None):
    with SessionLocal() as db:
        a = db.query(models.Agent).filter_by(hostname=f"{host}-{TAG}").one()
        src = db.query(models.VulnSource).filter_by(name=f"Import {TAG}").one()
        if not db.query(models.Cve).filter_by(cve_id=cid).first():
            db.add(models.Cve(cve_id=cid, status="CNA record", description="x", products=[]))
        if rec_file and not db.query(models.Advisory).filter_by(source="cve", cve_id=cid).first():
            db.add(models.Advisory(source="cve", cve_id=cid, data=rec_of(rec_file), found=True))
        f = models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", sources_active=1)
        db.add(f)
        db.flush()
        db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package=pkg, version=ver))
        db.commit()
        return f.id


def test_no_fix_published_is_stated_not_guessed(client, viewer, world):
    fid = _finding_with("CVE-2025-0411", "PC", "7-Zip 24.08 (x64)", "24.08", "CVE-2025-0411")
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    facts = {x["label"]: x["value"] for x in p["facts"]}
    assert p["status"] == "no_fix_yet"
    assert facts["Affected"].startswith("Yes – 7-Zip 24.08 (x64) is within the affected versions")
    assert facts["Not known"].startswith("Fixed version – not published in") and "the CVE record" in facts["Not known"]
    assert facts["Exposure"] == "Endpoint · only this machine"
    nxt = [s["text"] for s in p["steps"] if s["phase"] == "next"]
    assert "newer than 24.08" in nxt[0] and "CVE-2025-0411" in nxt[0] and "every day" in nxt[1]
    assert not [s for s in p["steps"] if s["phase"] == "fix"]


def test_installed_version_outside_range_is_flagged(client, viewer, world):
    fid = _finding_with("CVE-2026-48095", "LNX", "7-Zip 26.01 (x64)", "26.01", "CVE-2026-48095")
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    facts = {x["label"]: x["value"] for x in p["facts"]}
    assert p["status"] == "check_version" and "verify" in p["headline"]
    assert facts["Affected"].startswith("Unclear – 7-Zip 26.01 (x64) is outside the affected versions")
    assert "Not known" not in facts and not [s for s in p["steps"] if s["phase"] == "fix"]
    assert any("false positive" in s["text"] for s in p["steps"] if s["phase"] == "next")
    assert not [s for s in p["steps"] if s["phase"] == "remind"]


def test_exposure_counts_other_machines(client, viewer, world):
    p = client.get(f"/api/vuln/findings/{world['pc_win']}/remediation", headers=viewer).json()
    assert {x["label"]: x["value"] for x in p["facts"]}["Exposure"].startswith("Endpoint · also open on")


def test_two_copies_scanner_and_agent_disagree(client, viewer, world):
    """Wazuh sees 7-Zip 26.01 (fixed) but the agent inventory also has 7-Zip 24.08 (affected) → affected, and say why."""
    with SessionLocal() as db:
        srv = db.query(models.Agent).filter_by(hostname=f"VEEAM-{TAG}").one()
        db.add(models.AgentSoftware(agent_id=srv.id, name="7-Zip 24.08 (x64)", version="24.08", norm_version="24.08"))
        db.commit()
    fid = _finding_with("CVE-2026-48095", "VEEAM", "7-Zip 26.01 (x64)", "26.01", "CVE-2026-48095")
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    facts = {x["label"]: x["value"] for x in p["facts"]}
    assert p["status"] == "fix_available"
    assert facts["Affected"].startswith("Yes – 7-Zip 24.08 (x64) is within")
    assert "26.01" in facts["Versions differ"] and "24.08 (agent inventory)" in facts["Versions differ"]
    assert [s["text"] for s in p["steps"] if s["phase"] == "fix"][0] == "Update 7-Zip 24.08 (x64) to a version newer than 26.00"


def test_store_app_fix_is_an_action():
    """MSRC gives no KB for Microsoft Store apps, only a fixed build ('More Information for Microsoft Photos').
    The step must say what to do: update the app from the installed version to the fixed build."""
    from types import SimpleNamespace as NS
    r = {"type": "vendor_fix", "kb": "", "text": "More Information for Microsoft Photos", "fixed_build": "2022.30050.31008.0",
         "products": ["Microsoft Photos App"], "url": "https://apps.microsoft.com/x", "restart": ""}
    assert rem._ms_app_name(r) == "Microsoft Photos" and rem._is_store_app("Microsoft Photos")
    dets = [(NS(package="Photos", version="2019.19071.12548.0"), "Wazuh")]
    assert rem._ms_installed(dets, "Microsoft Photos") == "2019.19071.12548.0"
    assert not rem._is_store_app("Microsoft Edge (Chromium-based)")


def test_store_app_playbook_text(client, viewer):
    import uuid
    from app import models
    from app.db import SessionLocal
    cid = "CVE-2099-77001"
    with SessionLocal() as db:
        a = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname="PHOTOS-PC", ip="10.79.0.1", ips=[], os_family="windows",
                         os_name="Windows 10 Pro", os_release="22H2", arch="amd64")
        src = models.VulnSource(name="photos-src", kind="file", enabled=True, confidence="high", config={}, state={})
        db.add_all([a, src])
        db.flush()
        db.add(models.Advisory(source="msrc", cve_id=cid, found=True, data={
            "title": "Microsoft Photos App Remote Code Execution Vulnerability", "exploited": False, "publicly_disclosed": False,
            "exploitability": "Exploitation Less Likely", "url": "", "remediations": [
                {"type": "vendor_fix", "subtype": "", "kb": "", "text": "More Information for Microsoft Photos", "url": "https://apps.microsoft.com/x",
                 "fixed_build": "2022.30050.31008.0", "restart": "", "supersedes": "", "products": ["Microsoft Photos App"]}]}))
        f = models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", priority=55, confidence="high",
                               packages=["Photos 2019.19071.12548.0"], sources_active=1)
        db.add(f)
        db.flush()
        db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package="Photos", version="2019.19071.12548.0", fixed_version="", active=True))
        db.commit()
        fid = f.id
    p = client.get(f"/api/vuln/findings/{fid}/remediation", headers=viewer).json()
    fixes = [s["text"] for s in p["steps"] if s["phase"] == "fix"]
    assert fixes and fixes[0] == ("Update Microsoft Photos from 2019.19071.12548.0 to 2022.30050.31008.0 or later"
                                  " – Microsoft Store › Library › Get updates (or: winget upgrade)"), fixes
    assert "More Information" not in " ".join(fixes)
