"""Findings are sorted by the server over ALL matching rows, so paging never mixes up the order
(sorting only the page on screen made "CVE ascending" start at 2024 on one filter and 2022 on another)."""
import uuid

import pytest

from app import models
from app.db import SessionLocal

TAG = "sorttest-" + uuid.uuid4().hex[:6]
CVES = ["CVE-2024-10000", "CVE-2022-0001", "CVE-2024-9999", "CVE-2023-5000", "CVE-2025-1", "CVE-2022-22965"]
IPS = ["10.0.0.10", "10.0.0.9", "10.0.1.2", "9.255.0.1", "10.0.0.100", "10.0.0.11"]


@pytest.fixture(scope="module")
def data(client, admin):
    with SessionLocal() as db:
        for i, (cid, ip) in enumerate(zip(CVES, IPS)):
            a = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=f"{TAG}-{'fedcba'[i]}", ip=ip, ips=[ip], os_family="windows")
            db.add(a)
            db.flush()
            db.add(models.VulnFinding(target=f"agent:{a.id}", agent_id=a.id, cve_id=cid, status="open", priority=10 * i,
                                      confidence=["high", "medium", "low"][i % 3], packages=[f"pkg{i}"]))
        db.commit()


def ids(client, admin, **p):
    r = client.get("/api/vuln/findings", params={"status": "all", "triage": "all", "q": TAG, **p}, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_cve_sort_is_numeric_and_spans_pages(client, admin, data):
    want = ["CVE-2022-0001", "CVE-2022-22965", "CVE-2023-5000", "CVE-2024-9999", "CVE-2024-10000", "CVE-2025-1"]
    assert [f["cve_id"] for f in ids(client, admin, sort="cve", dir="asc")] == want
    assert [f["cve_id"] for f in ids(client, admin, sort="cve", dir="desc")] == want[::-1]
    paged = ids(client, admin, sort="cve", dir="asc", limit=2) + ids(client, admin, sort="cve", dir="asc", limit=2, offset=2) \
        + ids(client, admin, sort="cve", dir="asc", limit=2, offset=4)
    assert [f["cve_id"] for f in paged] == want


def test_ip_machine_priority_sorts(client, admin, data):
    assert [f["target_ip"] for f in ids(client, admin, sort="ip")] == ["9.255.0.1", "10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.100", "10.0.1.2"]
    assert [f["target_name"][-1] for f in ids(client, admin, sort="machine")] == list("abcdef")
    assert [f["priority"] for f in ids(client, admin)] == sorted([f["priority"] for f in ids(client, admin)], reverse=True)
    assert [f["confidence"] for f in ids(client, admin, sort="confidence")][:2] == ["high", "high"]
    for k in ("due", "cvss", "epss", "first_seen", "kev", "package", "status", "bogus"):
        assert len(ids(client, admin, sort=k, dir="asc")) == 6


def test_export_follows_list_filters_and_order(client, admin, data):
    r = client.get("/api/vuln/export.csv", params={"status": "all", "triage": "all", "q": TAG, "sort": "cve", "dir": "asc",
                                                   "confidence": "high"}, headers=admin)
    assert r.status_code == 200
    lines = [l for l in r.text.splitlines()[1:] if l]
    cves = [l.split(",")[4] for l in lines]
    listed = [f["cve_id"] for f in ids(client, admin, sort="cve", dir="asc", confidence="high")]
    assert cves == listed and len(cves) == 2          # only the filtered rows, same order as the list


def test_cve_catalogue_sorts_on_server(client, admin):
    from datetime import datetime
    ids_ = [f"CVE-1999-{n}" for n in (10000, 9999, 123, 77777)]
    with SessionLocal() as db:
        for c in ids_:
            db.add(models.Cve(cve_id=c, description=TAG, cvss_score=5.0, cvss_severity="medium", status="Analyzed", cvss_version="3.1",
                              cvss_vector="", cwe=[], products=[], references=[], cpe_match=[], kev=False, kev_ransomware=False,
                              kev_name="", kev_action="", published=datetime(2026, 1, 1)))
        db.commit()
    got = lambda **p: [c["cve_id"] for c in client.get("/api/cves", params={"q": TAG, "days": 0, **p}, headers=admin).json()["items"]]
    want = ["CVE-1999-123", "CVE-1999-9999", "CVE-1999-10000", "CVE-1999-77777"]
    assert got(sort="cve", dir="asc") == want
    assert got(sort="cve", dir="desc") == want[::-1]
    assert got(sort="cve", dir="asc", limit=2, offset=2) == want[2:]


def test_audit_search_reaches_old_entries(client, admin):
    with SessionLocal() as db:
        db.add(models.AuditLog(user="old-user", action="update", entity="x", detail=f"needle {TAG}"))
        db.commit()
        for i in range(30):
            db.add(models.AuditLog(user="noise", action="update", entity="x", detail=f"noise {i}"))
        db.commit()
    assert not any(TAG in a["detail"] for a in client.get("/api/audit", params={"limit": 10}, headers=admin).json())
    hit = client.get("/api/audit", params={"limit": 10, "q": TAG}, headers=admin).json()
    assert len(hit) == 1 and hit[0]["user"] == "old-user"
