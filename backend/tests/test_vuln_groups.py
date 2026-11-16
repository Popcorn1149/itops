"""By software (one row = one update job) and attack-type labels from CWE."""
import uuid

import pytest

from app import models
from app.db import SessionLocal
from app.vuln_groups import product_key

TAG = "grp-" + uuid.uuid4().hex[:6]


@pytest.fixture(scope="module")
def data(client, admin):
    with SessionLocal() as db:
        src = models.VulnSource(name=f"src-{TAG}", kind="file", enabled=True, confidence="high", config={}, state={})
        db.add(src)
        cves = {f"CVE-2099-{TAG[-4:]}{i}": cwe for i, cwe in enumerate([["CWE-416"], ["CWE-79"], ["CWE-787", "CWE-94"], []])}
        for cid, cwe in cves.items():
            db.add(models.Cve(cve_id=cid, description=TAG, cvss_score=8.0, cvss_severity="high", status="Analyzed", cvss_version="3.1",
                              cvss_vector="", cwe=cwe, products=[], references=[], cpe_match=[], kev=False, kev_ransomware=False,
                              kev_name="", kev_action=""))
        db.flush()
        ids = list(cves)
        agents = []
        for i in range(3):
            a = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=f"{TAG}-pc{i}", ip=f"10.77.0.{i + 1}", ips=[], os_family="windows")
            db.add(a)
            db.flush()
            agents.append(a)
        # Chrome: CVE 0,1,2 on 3 machines, two versions installed, fixes 131.0.2 and 131.0.10 → update to 131.0.10
        gc = f"Google Chrome {TAG}"            # unique names: other test files also create Chrome / 7-Zip findings
        plan = [(agents[0], ids[0], gc, "130.0.1", "131.0.2"), (agents[1], ids[0], f"{gc} 130.0.5 (x64)", "130.0.5", "131.0.2"),
                (agents[2], ids[1], gc, "130.0.5", "131.0.10"), (agents[0], ids[2], gc, "130.0.1", ""),
                # 7-Zip: one CVE without any reported fix
                (agents[1], ids[3], f"7-Zip {TAG} 24.08 (x64)", "24.08", "")]
        for a, cid, pkg, ver, fix in plan:
            f = models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", priority=70, confidence="high",
                                   packages=[f"{pkg} {ver}"], sources_active=1)
            db.add(f)
            db.flush()
            db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package=pkg, version=ver, fixed_version=fix, active=True))
        db.commit()
        return ids


def test_product_key_groups_copies():
    assert product_key("Google Chrome 131.0.6778.85")[0] == product_key("Google Chrome (x64 en-US)")[0] == "google chrome"
    assert product_key("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130")[0] != product_key("Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.1")[0]
    assert product_key("openssl 1:3.0.13-0ubuntu3.4")[0] == "openssl"


def test_by_software_one_row_per_job(client, admin, data):
    rows = {r["name"]: r for r in client.get("/api/vuln/by-software", params={"q": TAG}, headers=admin).json()}
    r = rows[f"Google Chrome {TAG}"]
    assert r["cves"] == 3 and r["machines"] == 3 and r["findings"] == 4
    assert r["fix_version"] == "131.0.10" and r["cves_with_fix"] == 2          # highest REPORTED fix; one CVE has none
    kinds = {a["key"] for a in r["attack"]}
    assert {"memory", "injection", "rce"} <= kinds
    seven = rows[f"7-Zip {TAG}"]
    assert seven["fix_version"] == "" and not seven["newer_than"] and not seven["kbs"]   # nothing published → nothing invented

    d = client.get("/api/vuln/by-software/detail", params={"key": r["key"]}, headers=admin).json()
    assert {m["name"] for m in d["machines"]} == {f"{TAG}-pc0", f"{TAG}-pc1", f"{TAG}-pc2"}
    pc0 = next(m for m in d["machines"] if m["name"] == f"{TAG}-pc0")
    assert pc0["versions"] == ["130.0.1"] and pc0["cves"] == 2
    assert client.get("/api/vuln/by-software/detail", params={"key": "nope"}, headers=admin).status_code == 404


def test_attack_filter_everywhere(client, admin, data):
    xss = client.get("/api/vuln/findings", params={"q": TAG, "attack": "injection", "triage": "all"}, headers=admin).json()["items"]
    assert [f["cve_id"] for f in xss] == [data[1]] and xss[0]["attack"] == ["Injection / XSS"]
    mem = {f["cve_id"] for f in client.get("/api/vuln/findings", params={"q": TAG, "attack": "memory"}, headers=admin).json()["items"]}
    assert mem == {data[0], data[2]}
    none = {f["cve_id"] for f in client.get("/api/vuln/findings", params={"q": TAG, "attack": "none"}, headers=admin).json()["items"]}
    assert none == {data[3]}
    bc = {c["cve_id"] for c in client.get("/api/vuln/by-cve", params={"attack": "rce"}, headers=admin).json()}
    assert data[2] in bc and data[0] not in bc
    cat = client.get("/api/cves", params={"q": TAG, "days": 0, "attack": "memory"}, headers=admin).json()["items"]
    assert {c["cve_id"] for c in cat} == {data[0], data[2]}
    assert client.get("/api/vuln/findings", params={"attack": "bogus"}, headers=admin).status_code == 400
    assert len(client.get("/api/vuln/attack-types", headers=admin).json()) == 8


def test_vendor_data_fills_what_to_do(client, admin):
    """No scanner fix → use the cached official data: CVE record (CNA) and Microsoft MSRC KB for the right Windows edition."""
    import json
    from pathlib import Path
    from app import remediation as rem
    fx = Path(__file__).parent / "fixtures"
    tag = "vd-" + uuid.uuid4().hex[:5]
    ms = rem.parse_cvrf(json.loads((fx / "msrc_2026-Oct.json").read_text(encoding="utf-8")))
    with SessionLocal() as db:
        src = models.VulnSource(name=f"src-{tag}", kind="file", enabled=True, confidence="high", config={}, state={})
        win = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=f"{tag}-win", ip="10.78.0.1", ips=[], os_family="windows",
                           os_name="Windows 10 Pro", os_release="22H2", arch="amd64")
        lnx = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=f"{tag}-pc", ip="10.78.0.2", ips=[], os_family="windows")
        db.add_all([src, win, lnx])
        db.flush()
        for cid, data in [("CVE-2026-48095", rem.parse_cve_record(json.loads((fx / "cvelist/CVE-2026-48095.json").read_text()))),
                          ("CVE-2025-0411", rem.parse_cve_record(json.loads((fx / "cvelist/CVE-2025-0411.json").read_text())))]:
            db.query(models.Advisory).filter_by(source="cve", cve_id=cid).delete()
            db.add(models.Advisory(source="cve", cve_id=cid, data=data, found=True))
        db.query(models.Advisory).filter_by(source="msrc", cve_id="CVE-2026-90001").delete()
        db.add(models.Advisory(source="msrc", cve_id="CVE-2026-90001", data=ms["CVE-2026-90001"], found=True))
        for a, cid, pkg, ver in [(win, "CVE-2026-90001", f"Microsoft Windows 10 Pro {tag}", "10.0.19045.4000"),
                                 (lnx, "CVE-2026-48095", f"7-Zip {tag} 26.00 (x64)", "26.00"),
                                 (lnx, "CVE-2025-0411", f"7-Zip {tag} 26.00 (x64)", "26.00")]:
            f = models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", priority=60, confidence="high",
                                   packages=[f"{pkg} {ver}"], sources_active=1)
            db.add(f)
            db.flush()
            db.add(models.VulnDetection(finding_id=f.id, source_id=src.id, package=pkg, version=ver, fixed_version="", active=True))
        db.commit()
    rows = {r["name"]: r for r in client.get("/api/vuln/by-software", params={"q": tag}, headers=admin).json()}
    w = rows[f"Microsoft Windows 10 Pro {tag}"]
    assert w["kbs"] == ["KB5048888"] and w["fix_from"] == ["Microsoft MSRC"]          # Windows 11 KB5048899 not offered
    z = rows[f"7-Zip {tag}"]
    assert z["fix_version"] == "" and z["newer_than"] == "26.00" and z["fix_from"] == ["CVE record"]
    assert z["cves_with_fix"] == 1 and z["cves"] == 2                                  # CVE-2025-0411 record lists no fix → not invented
