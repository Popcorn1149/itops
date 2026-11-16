"""CVE module – part 3: findings from replaceable sources (Wazuh mocked, file import, IT Ops CPE matching).

Includes the 3 architecture acceptance tests agreed for the design:
  1. Wazuh unreachable → IT Ops keeps machines, findings and history; results are labelled stale, never "fixed".
  2. Wazuh's own CVE data is not needed for priority → scores come from the IT Ops catalogue; unknown CVEs are queued for NVD.
  3. Wazuh replaced by a file import → the core keeps the same findings (same id, first_seen, triage).
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import httpx
import pytest

from app import cve, models, vuln
from app.db import SessionLocal
from app.vulnsrc import file_import, wazuh
from app.vulnsrc.cpe_match import identify, matches, vkey

TAG = uuid.uuid4().hex[:6].upper()
HOST_A, HOST_B, HOST_C = f"VP3-A-{TAG}", f"VP3-B-{TAG}", f"VP3-C-{TAG}"
CVE1, CVE2, CVE3 = "CVE-2026-91001", "CVE-2026-91002", "CVE-2026-91003"


# ------------------------------------------------------------------ fake Wazuh (API + indexer)
class FakeWazuh:
    def __init__(self):
        self.down = False
        self.bad_format = False
        self.version = "v4.14.5"
        self.agents = [{"id": "001", "name": HOST_A, "ip": "10.91.0.1", "status": "active", "os": {"name": "Windows 11", "version": "23H2"}},
                       {"id": "002", "name": f"UNKNOWN-{TAG}", "ip": "10.91.0.99", "status": "active"},
                       {"id": "003", "name": HOST_B, "ip": "10.91.0.2", "status": "disconnected"}]
        self.docs = [self.doc("001", CVE1, "openssl", "3.0.2", "High", 5.0), self.doc("001", CVE2, "curl", "7.81"),
                     self.doc("002", CVE1, "openssl", "3.0.2"), self.doc("003", CVE3, "7zip", "19.00")]

    @staticmethod
    def doc(aid, cid, pkg, ver, sev="Medium", score=6.5):
        return {"agent": {"id": aid, "name": "x"}, "package": {"name": pkg, "version": ver},
                "vulnerability": {"id": cid, "severity": sev, "score": {"base": score}, "detected_at": "2026-11-01T10:00:00Z"}}

    def handler(self, req: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("Connection refused", request=req)
        p = req.url.path
        if p.endswith("/security/user/authenticate"):
            ok = req.headers.get("authorization", "").startswith("Basic ")
            return httpx.Response(200 if ok else 401, json={"data": {"token": "jwt"}})
        if p == "/":
            return httpx.Response(200, json={"data": {"api_version": self.version}})
        if p == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": self.agents, "total_affected_items": len(self.agents)}})
        if p.startswith("/syscollector/"):
            return httpx.Response(200, json={"data": {"affected_items": [{"board_serial": "To be filled by O.E.M."}]}})
        if p.endswith("/_count"):
            return httpx.Response(200, json={"count": len(self.docs)})
        if p.endswith("/_search") and "scroll" not in p:
            docs = [{"something": 1}] if self.bad_format else self.docs
            return httpx.Response(200, json={"_scroll_id": "s1", "hits": {"hits": [{"_source": d} for d in docs]}})
        if p.endswith("/_search/scroll"):
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(200, json={"_scroll_id": "s1", "hits": {"hits": []}})
        return httpx.Response(404, json={})


@pytest.fixture(scope="module")
def fake(monkeypatch_module):
    fw = FakeWazuh()
    monkeypatch_module.setattr(wazuh.WazuhProvider, "_client",
                               lambda self, cfg: httpx.AsyncClient(transport=httpx.MockTransport(fw.handler), base_url="https://wazuh"))
    return fw


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def machines(client, admin):
    with SessionLocal() as db:
        ids = []
        for h, ip in ((HOST_A, "10.91.0.1"), (HOST_B, "10.91.0.2")):
            a = models.Agent(uid=str(uuid.uuid4()), key_hash="x" * 64, hostname=h, ip=ip, ips=[ip], os_family="windows")
            db.add(a)
            db.flush()
            ids.append(a.id)
        db.add(models.Cve(cve_id=CVE1, description="OpenSSL test bug", cvss_score=9.8, cvss_severity="critical", status="Analyzed",
                          cvss_version="3.1", cvss_vector="", cwe=[], products=[], references=[], cpe_match=[], kev=True,
                          kev_ransomware=False, kev_name="", kev_action="", epss=0.42))
        db.commit()
    return {"A": f"agent:{ids[0]}", "B": f"agent:{ids[1]}"}


def run(sid, payload=None):
    return asyncio.run(vuln.run_source(sid, payload))


def findings(client, h, **params):
    r = client.get("/api/vuln/findings", params={"status": "all", "triage": "all", "q": TAG, **params}, headers=h)
    assert r.status_code == 200, r.text
    return {(f["target"], f["cve_id"]): f for f in r.json()["items"]}


# ------------------------------------------------------------------ pure functions
def test_version_compare_and_cpe_ranges():
    assert vkey("8.0.0") == vkey("8.0") and vkey("7.2.10") > vkey("7.2.9") and vkey("10.0") > vkey("9.9.9")
    rng = {"c": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "si": "7.2.0", "ee": "7.2.8"}
    assert matches(rng, "7.2.5") and not matches(rng, "7.2.8") and not matches(rng, "7.0.9")
    assert matches({"c": "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}, "8.0.2")
    assert not matches({"c": "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}, "8.0.3")
    assert matches({"c": "cpe:2.3:o:x:y:*:*:*:*:*:*:*:*"}, "1.0") and not matches({"c": "cpe:2.3:o:x:y:-:*:*:*:*:*:*:*"}, "1.0")
    a = models.Asset(name="esx01", vendor="Dell", model="R650", os="ESXi 8.0.2", meta={})
    assert identify(a) == [("vmware:esxi", "8.0.2")]
    a.meta = {"cpe": "Fortinet:FortiOS:7.2.5; bad"}
    assert identify(a) == [("fortinet:fortios", "7.2.5")]


def test_nvd_parser_keeps_ranges():
    item = {"cve": {"id": "CVE-2026-9", "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.2.0", "versionEndExcluding": "7.2.8"},
        {"vulnerable": False, "criteria": "cpe:2.3:h:fortinet:x:-:*:*:*:*:*:*:*"}]}]}]}}
    assert cve.parse_nvd_item(item)["cpe_match"] == [{"c": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "si": "7.2.0", "ee": "7.2.8"}]


def test_file_parser_accepts_wazuh_export_and_rejects_garbage():
    rows = file_import.parse("agent.name;vulnerability.id;package.name;package.version;vulnerability.severity\nPC1;CVE-2026-1;curl;7.81;High\n")
    assert rows[0]["host"] == "PC1" and rows[0]["cve"] == "CVE-2026-1" and rows[0]["severity"] == "High"
    j = file_import.parse('[{"hostname": "PC2", "cve_id": "CVE-2026-2", "score": "7.5"}]')
    assert j[0]["host"] == "PC2" and j[0]["score"] == "7.5"
    for bad in ("", "a,b\n1,2\n", "{not json"):
        with pytest.raises(Exception):
            file_import.parse(bad)


# ------------------------------------------------------------------ Wazuh source end-to-end
@pytest.fixture(scope="module")
def wz(client, admin, fake, machines):
    r = client.post("/api/vuln/sources", json={"name": f"Wazuh {TAG}", "kind": "wazuh", "config": {
        "api_url": "https://wazuh:55000", "username": "itops-ro", "password": "S3cret!",
        "indexer_url": "https://wazuh:9200", "indexer_username": "itops-ro", "indexer_password": "S3cret2!"}}, headers=admin)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["config"]["password"] == "__SECRET__" and s["config"]["indexer_password"] == "__SECRET__"
    with SessionLocal() as db:
        raw = db.get(models.VulnSource, s["id"]).config
        assert raw["password"].startswith("enc2:") and raw["indexer_password"].startswith("enc2:")
    return s["id"]


def test_wazuh_test_connection(client, admin, wz):
    r = client.post(f"/api/vuln/sources/{wz}/test", headers=admin).json()
    assert r["ok"] and r["version"] == "4.14.5" and r["tested"] is True and r["agents"] == 3


def test_wazuh_sync_matches_machines_and_never_guesses(client, admin, wz, machines):
    res = run(wz)
    assert res["ok"], res
    assert res["unmatched_count"] == 1 and res["unmatched"][0]["ref"] == "002"        # unknown host → listed, not guessed
    f = findings(client, admin)
    a1, a2, b3 = f[(machines["A"], CVE1)], f[(machines["A"], CVE2)], f[(machines["B"], CVE3)]
    assert a1["status"] == a2["status"] == b3["status"] == "open"
    assert a1["confidence"] == "high" and not a1["needs_verification"] and a1["sources"] == [f"Wazuh {TAG}"]
    # priority input comes from the IT Ops catalogue, never from Wazuh (Wazuh said 5.0 / High)
    assert a1["cvss_score"] == 9.8 and a1["cvss_severity"] == "critical" and a1["score_source"] == "nvd" and a1["kev"]
    assert a2["score_source"] == "source" and a2["cvss_score"] == 6.5                  # not in catalogue yet → temporary
    with SessionLocal() as db:
        assert CVE2 in (cve._state(db).get("wanted") or [])                         # acceptance 2: queued for NVD
    d = client.get(f"/api/vuln/findings/{a1['id']}", headers=admin).json()
    assert d["detections"][0]["package"] == "openssl" and d["detections"][0]["score"] == 5.0


def test_manual_mapping_of_unmatched_host(client, admin, wz, machines, fake):
    r = client.put(f"/api/vuln/sources/{wz}/mapping", json={"ref": "002", "target": machines["B"]}, headers=admin)
    assert r.status_code == 200, r.text
    assert run(wz)["unmatched_count"] == 0
    assert (machines["B"], CVE1) in findings(client, admin)
    client.put(f"/api/vuln/sources/{wz}/mapping", json={"ref": "002", "target": "ignore"}, headers=admin)
    assert client.put(f"/api/vuln/sources/{wz}/mapping", json={"ref": "002", "target": "agent:999999"}, headers=admin).status_code == 400


def test_no_longer_listed_is_fixed_only_for_scanned_hosts(client, admin, wz, machines, fake):
    first = findings(client, admin)[(machines["A"], CVE1)]
    fake.docs = [d for d in fake.docs if d["vulnerability"]["id"] != CVE2 and d["agent"]["id"] != "003"]
    assert run(wz)["ok"]
    f = findings(client, admin)
    assert f[(machines["A"], CVE2)]["status"] == "fixed"
    assert f[(machines["B"], CVE3)]["status"] == "open"            # agent 003 is disconnected → not scanned → unknown, kept
    assert f[(machines["A"], CVE1)]["first_seen"] == first["first_seen"]
    fake.docs.append(fake.doc("001", CVE2, "curl", "7.81"))           # comes back → reopened, same finding
    run(wz)
    again = findings(client, admin)[(machines["A"], CVE2)]
    assert again["status"] == "open" and again["reopened"] == 1


def test_acceptance_1_wazuh_down_keeps_core_and_marks_stale(client, admin, wz, machines, fake):
    before = findings(client, admin)
    fake.down = True
    try:
        res = run(wz)
        assert not res["ok"] and "cannot connect" in res["error"]
        r = client.post(f"/api/vuln/sources/{wz}/test", headers=admin).json()
        assert not r["ok"] and "Wazuh API" in r["error"]
    finally:
        fake.down = False
    after = findings(client, admin)
    assert {k: v["status"] for k, v in after.items()} == {k: v["status"] for k, v in before.items()}   # nothing "fixed"
    assert client.get("/api/agents", headers=admin).status_code == 200                                 # machines still there
    with SessionLocal() as db:                                        # pretend the last good sync was 3 days ago
        s = db.get(models.VulnSource, wz)
        s.state = {**s.state, "last_ok": (vuln.utcnow() - timedelta(days=3)).isoformat() + "Z"}
        db.commit()
    assert findings(client, admin)[(machines["A"], CVE1)]["stale"] is True
    src = next(x for x in client.get("/api/vuln/sources", headers=admin).json() if x["id"] == wz)
    assert src["stale"] and src["state"]["ok"] is False
    assert run(wz)["ok"]
    assert findings(client, admin)[(machines["A"], CVE1)]["stale"] is False


def test_wazuh_format_change_stops_and_keeps_data(client, admin, wz, machines, fake):
    fake.bad_format = True
    try:
        res = run(wz)
    finally:
        fake.bad_format = False
    assert not res["ok"] and "unexpected format" in res["error"]
    assert findings(client, admin)[(machines["A"], CVE1)]["status"] == "open"


def test_triage_requires_reason_and_date_and_is_audited(client, admin, viewer, wz, machines):
    fid = findings(client, admin)[(machines["A"], CVE2)]["id"]
    url = f"/api/vuln/findings/{fid}/triage"
    assert client.post(url, json={"action": "false_positive", "note": "x"}, headers=viewer).status_code == 403
    assert client.post(url, json={"action": "accepted", "note": "legacy app"}, headers=admin).status_code == 400   # no date
    assert client.post(url, json={"action": "false_positive"}, headers=admin).status_code == 400                    # no reason
    assert client.post(url, json={"action": "false_positive", "note": "curl not used"}, headers=admin).status_code == 200
    assert (machines["A"], CVE2) not in {k for k, v in findings(client, admin, triage="none").items()}
    log = client.get("/api/audit", headers=admin).json()
    assert any(x["action"] == "vuln_false_positive" and CVE2 in x["detail"] for x in log)


def test_acceptance_3_replace_wazuh_with_file_import(client, admin, wz, machines):
    keep = findings(client, admin)
    r = client.post("/api/vuln/sources", json={"name": f"Scanner export {TAG}", "kind": "file"}, headers=admin)
    fid = r.json()["id"]
    assert r.json()["confidence"] == "medium"
    csv_text = ("agent.name,vulnerability.id,package.name,package.version,vulnerability.severity\n"
                f"{HOST_A},{CVE1},openssl,3.0.2,High\n{HOST_A},{CVE2},curl,7.81,Medium\n")
    res = client.post(f"/api/vuln/sources/{fid}/import", json={"filename": "export.csv", "content": csv_text}, headers=admin)
    assert res.status_code == 200, res.text
    both = findings(client, admin)[(machines["A"], CVE1)]
    assert both["sources_active"] == 2 and both["confidence"] == "high"
    cmp = client.get("/api/vuln/compare", params={"a": wz, "b": fid}, headers=admin).json()
    assert cmp["machines_in_common"] == 1 and cmp["both"] == 2 and cmp["only_a"] == 0
    # turn Wazuh off: same findings continue from the file source – same id, first_seen and triage
    assert client.put(f"/api/vuln/sources/{wz}", json={"enabled": False}, headers=admin).status_code == 200
    f = findings(client, admin)
    a1, a2 = f[(machines["A"], CVE1)], f[(machines["A"], CVE2)]
    assert a1["id"] == keep[(machines["A"], CVE1)]["id"] and a1["first_seen"] == keep[(machines["A"], CVE1)]["first_seen"]
    assert a1["status"] == "open" and a1["confidence"] == "medium" and a1["needs_verification"]   # gate, not weight
    assert a1["cvss_score"] == 9.8                                                                # priority input unchanged
    assert a2["triage"] == "false_positive"                                                       # triage survives the switch
    assert f[(machines["B"], CVE3)]["status"] == "source_off"         # only Wazuh saw it → unknown, NOT "fixed"
    # disabling the last source: findings are "source_off", never "fixed"
    client.put(f"/api/vuln/sources/{fid}", json={"enabled": False}, headers=admin)
    assert findings(client, admin)[(machines["A"], CVE1)]["status"] == "source_off"
    for sid in (wz, fid):
        client.put(f"/api/vuln/sources/{sid}", json={"enabled": True}, headers=admin)
    assert findings(client, admin)[(machines["A"], CVE1)]["status"] == "open"


def test_cpe_matching_for_device_without_agent(client, admin):
    with SessionLocal() as db:
        esx = models.Asset(name=f"esx-{TAG}", type="host", vendor="Dell", os="ESXi 8.0.2", meta={})
        fw = models.Asset(name=f"fw-{TAG}", type="firewall", vendor="Fortinet", os="FortiGate v7.2.9", meta={})
        db.add_all([esx, fw])
        db.add(models.Cve(cve_id="CVE-2026-91010", description="ESXi bug", cvss_score=8.1, cvss_severity="high", status="Analyzed",
                          cvss_version="3.1", cvss_vector="", cwe=[], references=[], kev=False, kev_ransomware=False, kev_name="", kev_action="",
                          products=["vmware:esxi"], cpe_match=[{"c": "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}]))
        db.add(models.Cve(cve_id="CVE-2026-91011", description="FortiOS bug", cvss_score=9.6, cvss_severity="critical", status="Analyzed",
                          cvss_version="3.1", cvss_vector="", cwe=[], references=[], kev=False, kev_ransomware=False, kev_name="", kev_action="",
                          products=["fortinet:fortios"], cpe_match=[{"c": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "si": "7.2.0", "ee": "7.2.8"}]))
        db.commit()
        esx_t, fw_t = f"asset:{esx.id}", f"asset:{fw.id}"
        cpe_id = db.query(models.VulnSource).filter(models.VulnSource.kind == "cpe").first().id
    assert run(cpe_id)["ok"]
    f = findings(client, admin)
    hit = f[(esx_t, "CVE-2026-91010")]
    assert hit["confidence"] == "medium" and hit["needs_verification"] and hit["target_name"] == f"esx-{TAG}"
    assert (fw_t, "CVE-2026-91011") not in f                                     # 7.2.9 is outside 7.2.0–7.2.8
    fid = hit["id"]
    client.post(f"/api/vuln/findings/{fid}/triage", json={"action": "verify"}, headers=admin)
    assert not findings(client, admin)[(esx_t, "CVE-2026-91010")]["needs_verification"]
    with SessionLocal() as db:                                                   # upgrade ESXi → fixed on next run
        db.get(models.Asset, int(esx_t[6:])).os = "ESXi 8.0.3"
        db.commit()
    run(cpe_id)
    assert findings(client, admin)[(esx_t, "CVE-2026-91010")]["status"] == "fixed"


def test_summary_and_permissions(client, admin, viewer, wz):
    s = client.get("/api/vuln/summary", headers=viewer).json()
    assert s["open"] >= 1 and {"wazuh", "file"} <= {k["kind"] for k in s["kinds"]}
    assert any(x["kind"] == "cpe" and x["builtin"] for x in s["sources"])
    assert client.post("/api/vuln/sources", json={"name": "x", "kind": "wazuh"}, headers=viewer).status_code == 403
    assert client.post("/api/vuln/sources", json={"name": "x", "kind": "cpe"}, headers=admin).status_code == 400
    assert client.post(f"/api/vuln/sources/{wz}/sync", headers=viewer).status_code == 403
