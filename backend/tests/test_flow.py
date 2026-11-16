"""Luồng vận hành: check → kết quả → status tài sản → cảnh báo → gửi thông báo → phục hồi; đồng bộ ESXi lên bản đồ."""
import asyncio
import socket
import time

import pytest

from app import scheduler, models
from app.db import SessionLocal
from tests import simulators as S


def mk(client, h, _kind, **body):
    r = client.post(f"/api/{_kind}", json=body, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def get(client, h, path):
    return client.get(path, headers=h).json()


@pytest.fixture
def notify_all(client, admin, sim_port, smtp):
    client.put("/api/settings/notify", headers=admin, json={
        "telegram": {"enabled": True, "bot_token": "999:QA", "chat_id": "-100", "include_warnings": True},
        "webhook": {"enabled": True, "url": f"http://127.0.0.1:{sim_port}/hook", "include_warnings": False},
        "email": {"enabled": True, "host": "127.0.0.1", "port": smtp["port"], "security": "none", "from": "itops@qa.local", "to": "it@qa.local"},
    })
    yield
    client.put("/api/settings/notify", headers=admin, json={"telegram": {}, "email": {}, "webhook": {}})


@pytest.fixture(scope="module")
def smtp():
    from aiosmtpd.controller import Controller
    box = {"messages": []}

    class H:
        async def handle_DATA(self, server, session, envelope):
            box["messages"].append(envelope.content.decode(errors="ignore"))
            return "250 OK"

    port = S.free_port()
    ctl = Controller(H(), hostname="127.0.0.1", port=port)
    ctl.start()
    box["port"] = port
    yield box
    ctl.stop()


class Port:
    """Port TCP bật/tắt được để giả lập service sống/chết."""
    def __init__(self):
        self.port = S.free_port()
        self.sock = None

    def up(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen()

    def down(self):
        if self.sock:
            self.sock.close()
            self.sock = None


def test_alert_lifecycle_with_notifications(client, admin, clean, notify_all, smtp):
    p = Port()
    s = mk(client, admin, "sites", name="HQ")
    a = mk(client, admin, "assets", name="ERP-APP", type="vm", site_id=s["id"])
    c = mk(client, admin, "checks", name="ERP port", type="tcp", target="127.0.0.1", asset_id=a["id"], enabled=False,
           config={"port": p.port, "timeout": 2, "alert_after": 2})
    smtp["messages"].clear()

    async def scenario():
        p.up()
        r = await scheduler.run_check(c["id"])
        assert r["status"] == "ok"
        assert get(client, admin, f"/api/assets/{a['id']}")["status"] == "up"
        p.down()
        await scheduler.run_check(c["id"])  # error lần 1: chưa báo
        assert get(client, admin, "/api/alerts") == []
        assert get(client, admin, f"/api/assets/{a['id']}")["status"] == "down"
        await scheduler.run_check(c["id"])  # error lần 2: mở cảnh báo + gửi
        al = get(client, admin, "/api/alerts")
        assert len(al) == 1 and al[0]["severity"] == "down" and al[0]["asset_name"] == "ERP-APP" and al[0]["site_name"] == "HQ"
        await scheduler.run_check(c["id"])  # error lần 3: do not send trùng
        assert len(get(client, admin, "/api/alerts")) == 1
        assert len(S.STATE["telegram"]) == 1 and len(S.STATE["webhook"]) == 1 and len(smtp["messages"]) == 1
        tg = S.STATE["telegram"][0]
        assert tg["chat_id"] == "-100" and "ERP port DOWN" in tg["text"] and tg["parse_mode"] == "HTML"
        p.up()
        r = await scheduler.run_check(c["id"])  # phục hồi
        assert r["status"] == "ok"
        p.down()

    asyncio.run(scenario())
    assert get(client, admin, "/api/alerts") == []
    res = get(client, admin, "/api/alerts?status=resolved")
    assert res[0]["resolved_at"] is not None
    assert len(S.STATE["telegram"]) == 2 and "has recovered" in S.STATE["telegram"][1]["text"]
    assert len(smtp["messages"]) == 2 and "Subject:" in smtp["messages"][0]
    chk = get(client, admin, f"/api/checks/{c['id']}")
    assert chk["fail_count"] == 0
    hist = get(client, admin, f"/api/checks/{c['id']}/history")
    assert [h["status"] for h in hist] == ["ok", "fail", "fail", "fail", "ok"]
    lst = next(x for x in get(client, admin, "/api/checks") if x["id"] == c["id"])
    assert lst["uptime_24h"] == 40.0


def test_warning_then_escalation(client, admin, clean, notify_all, sim_port):
    c = mk(client, admin, "checks", name="Web chậm", type="http", target=f"http://127.0.0.1:{sim_port}/web/slow", enabled=False,
           config={"warn_ms": 300, "alert_after": 1})

    async def scenario():
        await scheduler.run_check(c["id"])
        al = get(client, admin, "/api/alerts")
        assert al[0]["severity"] == "trouble" and "Trouble" in al[0]["title"]
        assert len(S.STATE["webhook"]) == 0, "webhook đặt include_warnings=False → do not send cảnh báo andng"
        assert len(S.STATE["telegram"]) == 1
        client.put(f"/api/checks/{c['id']}", headers=admin, json={"target": f"http://127.0.0.1:{sim_port}/web/500"})
        await scheduler.run_check(c["id"])
        al = get(client, admin, "/api/alerts")
        assert len(al) == 1 and al[0]["severity"] == "down" and "DOWN" in al[0]["title"]
        assert len(S.STATE["webhook"]) == 1 and len(S.STATE["telegram"]) == 2

    asyncio.run(scenario())


def test_notification_failure_does_not_break_monitoring(client, admin, clean, notify_all):
    S.STATE["telegram_fail"] = True
    try:
        c = mk(client, admin, "checks", name="X", type="tcp", target="127.0.0.1", enabled=False, config={"port": 1, "alert_after": 1, "timeout": 1})
        asyncio.run(scheduler.run_check(c["id"]))
        assert len(get(client, admin, "/api/alerts")) == 1
        r = client.post("/api/settings/notify/test/telegram", headers=admin).json()
        assert r["telegram"] != "ok" and "400" in r["telegram"]
    finally:
        S.STATE["telegram_fail"] = False


def test_ack_and_manual_resolve(client, admin, viewer, clean):
    c = mk(client, admin, "checks", name="Y", type="tcp", target="127.0.0.1", enabled=False, config={"port": 1, "alert_after": 1, "timeout": 1})
    asyncio.run(scheduler.run_check(c["id"]))
    aid = get(client, admin, "/api/alerts")[0]["id"]
    r = client.post(f"/api/alerts/{aid}/ack", headers=viewer)  # helpdesk được nhận xử lý
    assert r.status_code == 200 and r.json()["acked_by"] == "helpdesk"
    assert get(client, admin, "/api/alerts?status=acknowledged")[0]["id"] == aid
    assert client.post(f"/api/alerts/{aid}/xyz", headers=admin).status_code == 400
    client.post(f"/api/alerts/{aid}/resolve", headers=admin)
    assert get(client, admin, "/api/alerts") == []


def test_deleting_or_disabling_check_closes_alert(client, admin, clean):
    c1 = mk(client, admin, "checks", name="del", type="tcp", target="127.0.0.1", enabled=False, config={"port": 1, "alert_after": 1, "timeout": 1})
    c2 = mk(client, admin, "checks", name="off", type="tcp", target="127.0.0.1", enabled=False, config={"port": 1, "alert_after": 1, "timeout": 1})

    async def scenario():
        await scheduler.run_check(c1["id"])
        await scheduler.run_check(c2["id"])
    asyncio.run(scenario())
    assert len(get(client, admin, "/api/alerts")) == 2
    client.delete(f"/api/checks/{c1['id']}", headers=admin)
    client.put(f"/api/checks/{c2['id']}", json={"enabled": False}, headers=admin)
    assert get(client, admin, "/api/alerts") == [], "Warning of check đã xoá/tắt không được treo mãi"


def test_change_check_type_keeps_history(client, admin, clean):
    c = mk(client, admin, "checks", name="chg", type="tcp", target="127.0.0.1", enabled=False, config={"port": 1, "alert_after": 1, "timeout": 1})
    asyncio.run(scheduler.run_check(c["id"]))
    assert len(get(client, admin, "/api/alerts")) == 1
    hist_before = get(client, admin, f"/api/checks/{c['id']}/history")
    r = client.put(f"/api/checks/{c['id']}", json={"type": "ping", "config": {"alert_after": 1}}, headers=admin)
    assert r.status_code == 200 and r.json()["type"] == "ping" and r.json()["status"] == "unknown"
    assert get(client, admin, "/api/alerts") == [], "Warning of loại cũ phải đóng"
    assert len(get(client, admin, f"/api/checks/{c['id']}/history")) >= 1 and hist_before, "Lịch sử phải giữ"
    log = get(client, admin, "/api/audit")
    assert any("type tcp → ping" in (a.get("detail") or "") for a in log)
    bad = client.put(f"/api/checks/{c['id']}", json={"type": "xyz"}, headers=admin)
    assert bad.status_code == 400


def test_esxi_discovery_into_map(client, admin, clean, monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.esxi_default()
    s = mk(client, admin, "sites", name="HQ")
    sw = mk(client, admin, "assets", name="SW-CORE", type="switch", site_id=s["id"])
    c = mk(client, admin, "checks", name="vCenter", type="esxi", target="vc.lab", site_id=s["id"], enabled=False,
           config={"username": "ro", "password": S.ESXI["password"]})
    client.put(f"/api/checks/{c['id']}", json={"asset_id": sw["id"]}, headers=admin)  # vCenter gắn ando switch
    asyncio.run(scheduler.run_check(c["id"]))
    assets = get(client, admin, "/api/assets")
    by = {a["name"]: a for a in assets}
    assert {"esx01.lab", "esx02.lab", "DC01", "ERP-DB", "OLD-CENTOS", "FILE-SRV"} <= set(by)
    assert "TEMPLATE-W22" not in by
    assert by["esx01.lab"]["parent_id"] == sw["id"] and by["esx01.lab"]["site_id"] == s["id"]
    assert by["DC01"]["parent_id"] == by["esx01.lab"]["id"] and by["FILE-SRV"]["parent_id"] == by["esx02.lab"]["id"]
    assert by["OLD-CENTOS"]["status"] == "off" and by["DC01"]["ip"] == "10.0.20.10"
    assert by["esx01.lab"]["source"] == f"check:{c['id']}"

    # chạy lại: không nhân bản; VM bị xoá → đánh dấu missing; VM chuyển host → đổi cha
    S.ESXI["hosts"][0].vm = [v for v in S.ESXI["hosts"][0].vm if v._moId != "vm-3"]
    moved = [v for v in S.ESXI["hosts"][0].vm if v._moId == "vm-1"][0]
    S.ESXI["hosts"][0].vm.remove(moved)
    S.ESXI["hosts"][1].vm.append(moved)
    asyncio.run(scheduler.run_check(c["id"]))
    assets2 = get(client, admin, "/api/assets")
    assert len(assets2) == len(assets)
    by2 = {a["name"]: a for a in assets2}
    assert by2["OLD-CENTOS"]["meta"].get("missing") is True and by2["OLD-CENTOS"]["status"] == "unknown"
    assert by2["DC01"]["parent_id"] == by["esx02.lab"]["id"], "VM vMotion sang host khác phải đổi cha trên bản đồ"

    client.put(f"/api/checks/{c['id']}", json={"enabled": True}, headers=admin)  # rủi ro chỉ tính từ check đang bật
    risks = get(client, admin, "/api/risks")
    kinds = {(r["kind"], r["title"]) for r in risks}
    assert ("No longer detected", "OLD-CENTOS") in kinds and ("Old snapshot", "ERP-DB") in kinds and ("Datastore full", "ds-ssd") in kinds

    # xoá check → tài sản giữ lại thành "manual"
    client.delete(f"/api/checks/{c['id']}", headers=admin)
    assert all(a["source"] == "manual" for a in get(client, admin, "/api/assets"))


def test_esxi_single_host_maps_onto_existing_asset(client, admin, clean, monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.esxi_default()
    S.ESXI["hosts"] = S.ESXI["hosts"][:1]
    h = mk(client, admin, "assets", name="ESXi-01 (đặt tay)", type="host")
    c = mk(client, admin, "checks", name="esx", type="esxi", target="10.0.10.11", asset_id=h["id"], enabled=False, config={"password": S.ESXI["password"]})
    asyncio.run(scheduler.run_check(c["id"]))
    hosts = get(client, admin, "/api/assets?type=host")
    assert len(hosts) == 1 and hosts[0]["name"] == "ESXi-01 (đặt tay)" and hosts[0]["model"] == "ProLiant DL380 Gen10"
    assert get(client, admin, f"/api/assets/{h['id']}")["children"].__len__() == 3


def test_live_metrics_persist_between_runs(client, admin, clean, sim_port):
    fw = mk(client, admin, "assets", name="pf", type="firewall")
    c = mk(client, admin, "checks", name="pf", type="pfsense", target=f"http://127.0.0.1:{sim_port}", asset_id=fw["id"], enabled=False,
           config={"api_key": S.STATE["api_key"]})
    asyncio.run(scheduler.run_check(c["id"]))
    assert get(client, admin, f"/api/assets/{fw['id']}")["meta"]["live"]["cpu"] == 12
    S.STATE["pf_cpu"] = 77
    try:
        asyncio.run(scheduler.run_check(c["id"]))
        assert get(client, admin, f"/api/assets/{fw['id']}")["meta"]["live"]["cpu"] == 77, "Chỉ số live phải được cập nhật lần chạy sau"
    finally:
        S.STATE["pf_cpu"] = 12


def test_concurrent_run_same_check_is_deduplicated(client, admin, clean, sim_port):
    c = mk(client, admin, "checks", name="slow", type="http", target=f"http://127.0.0.1:{sim_port}/web/slow", enabled=False)

    async def scenario():
        return await asyncio.gather(scheduler.run_check(c["id"]), scheduler.run_check(c["id"]))
    r1, r2 = asyncio.run(scenario())
    assert (r1 is None) != (r2 is None)
    assert len(get(client, admin, f"/api/checks/{c['id']}/history")) == 1


def test_scheduler_loop_runs_due_checks_only(client, admin, clean):
    on = mk(client, admin, "checks", name="on", type="ping", target="127.0.0.1", interval=10, enabled=True, config={"count": 1})
    off = mk(client, admin, "checks", name="off", type="ping", target="127.0.0.1", interval=10, enabled=False)

    async def scenario():
        task = asyncio.create_task(scheduler.loop())
        await asyncio.sleep(8)
        task.cancel()
    t0 = time.time()
    asyncio.run(scenario())
    assert time.time() - t0 < 15
    assert get(client, admin, f"/api/checks/{on['id']}")["status"] == "ok"
    assert get(client, admin, f"/api/checks/{off['id']}")["last_checked"] is None


def test_demo_checks_simulate(client, admin, clean):
    from app.seed import seed_demo
    db = SessionLocal()
    seed_demo(db)
    ids = [c.id for c in db.query(models.Check).all()]
    db.close()

    async def scenario():
        await asyncio.gather(*[scheduler.run_check(i) for i in ids])
    asyncio.run(scenario())
    checks = get(client, admin, "/api/checks")
    assert all(c["last_checked"] for c in checks)
    assert {c["status"] for c in checks} >= {"ok", "warn", "fail"}
    assert any(a["title"].startswith("AP-Tang5") for a in get(client, admin, "/api/alerts"))
