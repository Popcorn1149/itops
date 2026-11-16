"""CVE module – parts 4 (priority + SLA) and 5 (overview, by machine, by CVE, alerts, morning digest, CSV)."""
import asyncio
import uuid
from datetime import timedelta

import pytest

from app import models, vuln, vuln_policy
from app.db import SessionLocal

TAG = uuid.uuid4().hex[:6].upper()
HA, HB = f"P45-A-{TAG}", f"P45-B-{TAG}"
CK, CH, CU = "CVE-2026-92001", "CVE-2026-92002", "CVE-2026-92003"


def cve_row(cid, score, sev, kev=False, pct=None, ransom=False):
    return models.Cve(cve_id=cid, description=f"test {cid}", cvss_score=score, cvss_severity=sev, status="Analyzed", cvss_version="3.1",
                      cvss_vector="", cwe=[], products=[], references=[], cpe_match=[], kev=kev, kev_ransomware=ransom, kev_name="",
                      kev_action="", epss_percentile=pct, epss=pct)


@pytest.fixture(scope="module")
def world(client, admin):
    with SessionLocal() as db:
        asset = models.Asset(name=f"srv-{TAG}", type="server", meta={})
        db.add(asset)
        db.flush()
        a = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=HA, ip="10.92.0.1", ips=[], os_family="windows", asset_id=asset.id)
        b = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=HB, ip="10.92.0.2", ips=[], os_family="windows")
        db.add_all([a, b, models.CriticalSystem(name=f"ERP {TAG}", level="High", asset_id=asset.id),
                    cve_row(CK, 9.8, "critical", kev=True, pct=0.95), cve_row(CH, 7.5, "high")])
        db.commit()
        ta, tb = f"agent:{a.id}", f"agent:{b.id}"
    src = client.post("/api/vuln/sources", json={"name": f"P45 scanner {TAG}", "kind": "file", "confidence": "high"}, headers=admin).json()
    rows = f"host,cve\n{HA},{CK}\n{HB},{CH}\n{HB},{CU}\n"
    r = client.post(f"/api/vuln/sources/{src['id']}/import", json={"filename": "a.csv", "content": rows}, headers=admin)
    assert r.status_code == 200, r.text
    return {"A": ta, "B": tb, "src": src["id"]}


def get(client, h, **p):
    r = client.get("/api/vuln/findings", params={"q": TAG, "status": "all", "triage": "all", **p}, headers=h)
    assert r.status_code == 200, r.text
    return {(f["target"], f["cve_id"]): f for f in r.json()["items"]}


def test_score_formula():
    assert vuln_policy.score(9.8, True, False, 0.95, "High") == 100
    assert vuln_policy.score(7.5, False, False, None, None) == 45
    assert vuln_policy.score(None, False, False, None, "Low") == 25                 # not scored → CVSS 5
    assert vuln_policy.score(9.8, False, False, 0.1, None) == 60
    assert [vuln_policy.band(p) for p in (100, 80, 79, 60, 59, 40, 39, 0)] == ["P1", "P1", "P2", "P2", "P3", "P3", "P4", "P4"]


def test_priority_and_deadlines(client, admin, world):
    f = get(client, admin)
    k, h, u = f[(world["A"], CK)], f[(world["B"], CH)], f[(world["B"], CU)]
    assert k["priority"] == 100 and k["band"] == "P1" and k["sla_category"] == "kev"      # critical system High + KEV
    assert h["priority"] == 45 and h["band"] == "P3" and h["sla_category"] == "high"
    assert u["sla_category"] == "unscored" and u["score_source"] == ""
    from datetime import datetime
    d = lambda x: datetime.fromisoformat(x["due_at"].rstrip("Z")) - datetime.fromisoformat(x["first_seen"].rstrip("Z"))
    assert d(k) == timedelta(days=1) and d(h) == timedelta(days=30) and d(u) == timedelta(days=30)
    assert k["sla_state"] == "due_soon" and h["sla_state"] == "on_track"
    only_p1 = get(client, admin, band="P1")
    assert set(only_p1) == {(world["A"], CK)}
    assert set(get(client, admin, cve=CH)) == {(world["B"], CH)}


def test_unconfirmed_has_no_deadline_until_verified(client, admin, world):
    src = client.post("/api/vuln/sources", json={"name": f"P45 low {TAG}", "kind": "file", "confidence": "low"}, headers=admin).json()
    client.post(f"/api/vuln/sources/{src['id']}/import", json={"filename": "b.csv", "content": f"host,cve\n{HA},{CH}\n"}, headers=admin)
    x = get(client, admin)[(world["A"], CH)]
    assert x["due_at"] is None and x["sla_state"] == "awaiting_verification" and x["needs_verification"]
    assert x["priority"] == 55                                                           # 45 + critical system High
    client.post(f"/api/vuln/findings/{x['id']}/triage", json={"action": "verify"}, headers=admin)
    y = get(client, admin)[(world["A"], CH)]
    assert y["due_at"] and y["sla_state"] == "on_track"


def test_priority_does_not_depend_on_source(client, admin, world):
    before = get(client, admin)[(world["B"], CH)]
    other = client.post("/api/vuln/sources", json={"name": f"P45 other {TAG}", "kind": "file", "confidence": "high"}, headers=admin).json()
    client.post(f"/api/vuln/sources/{other['id']}/import", json={"filename": "c.csv",
                "content": f"host,cve,score,severity\n{HB},{CH},2.0,low\n"}, headers=admin)
    after = get(client, admin)[(world["B"], CH)]
    assert after["priority"] == before["priority"] and after["due_at"] == before["due_at"] and after["sources_active"] == 2


def test_catalogue_change_tightens_deadline(client, admin, world):
    with SessionLocal() as db:
        c = db.query(models.Cve).filter(models.Cve.cve_id == CH).one()
        c.kev = True
        db.commit()
        vuln_policy.refresh(db)
        db.commit()
    x = get(client, admin)[(world["B"], CH)]
    assert x["sla_category"] == "kev" and x["priority"] == 70 and x["sla_state"] == "due_soon"
    with SessionLocal() as db:
        db.query(models.Cve).filter(models.Cve.cve_id == CH).one().kev = False
        db.commit()
        vuln_policy.refresh(db)
        db.commit()


def test_overdue_overview_by_machine_by_cve(client, admin, viewer, world):
    with SessionLocal() as db:                                                       # pretend B's high CVE was confirmed 40 days ago
        f = db.query(models.VulnFinding).filter(models.VulnFinding.target == world["B"], models.VulnFinding.cve_id == CH).one()
        f.sla_start = f.first_seen = vuln.utcnow() - timedelta(days=40)
        vuln_policy.refresh(db, [f.id])
        db.commit()
    od = get(client, admin, sla="overdue")
    assert (world["B"], CH) in od and od[(world["B"], CH)]["overdue_days"] == 11
    ov = client.get("/api/vuln/overview", headers=viewer).json()
    assert ov["overdue"] >= 1 and ov["by_band"]["P1"] >= 1 and len(ov["trend"]) == 30 and ov["kev"] >= 1
    machines = {m["target"]: m for m in client.get("/api/vuln/by-machine", params={"q": TAG}, headers=viewer).json()}
    assert machines[world["B"]]["overdue"] == 1 and machines[world["A"]]["importance"] == "High" and machines[world["A"]]["band"] == "P1"
    cves = {c["cve_id"]: c for c in client.get("/api/vuln/by-cve", headers=viewer).json()}
    assert cves[CH]["machines"] == 2 and cves[CK]["kev"] and cves[CK]["band"] == "P1"
    # accepted risk → no longer overdue
    fid = od[(world["B"], CH)]["id"]
    client.post(f"/api/vuln/findings/{fid}/triage", json={"action": "accepted", "until": "2099-01-01", "note": "vendor patch pending"}, headers=admin)
    assert (world["B"], CH) not in get(client, admin, sla="overdue", triage="none")
    client.post(f"/api/vuln/findings/{fid}/triage", json={"action": "clear"}, headers=admin)


def test_policy_edit_validates_and_recomputes(client, admin, viewer, world):
    assert client.put("/api/vuln/policy", json={"sla_days": {"high": 60}}, headers=viewer).status_code == 403
    assert client.put("/api/vuln/policy", json={"sla_days": {"high": -1}}, headers=admin).status_code == 400
    r = client.put("/api/vuln/policy", json={"sla_days": {"high": 60}, "digest": {"hour": 7}}, headers=admin)
    assert r.status_code == 200 and r.json()["sla_days"]["high"] == 60 and r.json()["digest"]["hour"] == 7
    assert get(client, admin)[(world["B"], CH)]["sla_state"] == "on_track"           # 40 days < 60 days
    log = client.get("/api/audit", headers=admin).json()
    assert any(x["entity"] == "vuln_policy" for x in log)
    client.put("/api/vuln/policy", json={"sla_days": {"high": 30}, "digest": {"hour": 8}}, headers=admin)


def test_alerts_once_and_digest(client, admin, world, monkeypatch):
    sent = []

    async def fake_notify(subject, text, severity="critical", only=None):
        sent.append((subject, text, severity))
        return {"telegram": "ok"}
    monkeypatch.setattr("app.notify.notify", fake_notify)
    with SessionLocal() as db:                                                       # earlier syncs already alerted; reset ours
        for f in db.query(models.VulnFinding).filter(models.VulnFinding.target.in_([world["A"], world["B"]])):
            f.alerted_at = None
        db.commit()
    res = asyncio.run(vuln_policy.send_alerts())
    assert res["sent"] >= 1 and len(sent) == 1
    assert CK in sent[0][1] and HA in sent[0][1] and "exploited" in sent[0][0]
    assert asyncio.run(vuln_policy.send_alerts())["sent"] == 0 and len(sent) == 1         # never twice
    subject, text = vuln_policy.digest_text(SessionLocal())
    assert "morning digest" in subject and "Overdue:" in text and CH in text and HB in text
    with SessionLocal() as db:
        row = db.get(models.Setting, "vuln_digest_last")
        if row:
            db.delete(row)
            db.commit()
    assert asyncio.run(vuln_policy.send_digest())["sent"] is True
    assert asyncio.run(vuln_policy.send_digest())["reason"] == "already sent today"


def test_csv_report(client, viewer, world):
    r = client.get("/api/vuln/export.csv", headers=viewer)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    text = r.content.decode("utf-8")
    assert text.startswith("﻿Priority,Score,Machine") and CK in text and HA in text
