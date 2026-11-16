"""Demo data: simulated Wazuh (5 agents) for previewing the Vulnerabilities screens – never in a real database."""
import uuid

from app import models, vuln
from app.db import SessionLocal
from app.vulnsrc import wazuh_demo


def test_builtin_never_creates_the_demo_source(client):
    with SessionLocal() as db:
        vuln.ensure_builtin(db)
        assert not db.query(models.VulnSource).filter(models.VulnSource.kind == "wazuh_demo").first()


def test_seed_demo_shows_every_state(client, admin):
    with SessionLocal() as db:
        for _i, name, ip, os_name in wazuh_demo.AGENTS[:4]:
            if not db.query(models.Agent).filter(models.Agent.hostname == name).first():
                db.add(models.Agent(uid=f"demo-test-{uuid.uuid4().hex[:6]}", key_hash="x" * 64, hostname=name, ip=ip, ips=[], os_family="windows"))
        db.commit()
    vuln.seed_demo()
    vuln.seed_demo()                                                      # idempotent
    with SessionLocal() as db:
        srcs = db.query(models.VulnSource).filter(models.VulnSource.kind == "wazuh_demo").all()
        assert len(srcs) == 1
        st = srcs[0].state
        assert st["ok"] and st["unmatched_count"] == 1 and st["unmatched"][0]["name"] == "WAZUH-LAB-07"
        sid = srcs[0].id
    items = client.get("/api/vuln/findings", params={"source_id": sid, "limit": 200}, headers=admin).json()["items"]
    assert {f["band"] for f in items} >= {"P1", "P2"} and any(f["sla_state"] == "overdue" for f in items)
    assert any(f["kev"] for f in items) and all(f["confidence"] == "high" for f in items)
    fixed = client.get("/api/vuln/findings", params={"status": "fixed", "q": "CVE-2023-4863", "triage": "all"}, headers=admin).json()["items"]
    assert fixed and fixed[0]["fixed_at"]
    ov = client.get("/api/vuln/overview", headers=admin).json()
    assert ov["overdue"] >= 1 and sum(d["fixed"] for d in ov["trend"]) >= 2
    s = client.get("/api/vuln/summary", headers=admin).json()
    assert "wazuh_demo" not in {k["kind"] for k in s["kinds"]}                     # cannot be added from the UI
    assert client.post("/api/vuln/sources", json={"name": "x", "kind": "wazuh_demo"}, headers=admin).status_code == 400
