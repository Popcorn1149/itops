"""Chạy song song với v1: DISABLE_NOTIFY chặn gửi cảnh báo; báo cáo so sánh đánh dấu đúng chỗ lệch."""
import asyncio
import importlib.util
from datetime import datetime
from pathlib import Path

from app import notify as nt


def test_disable_notify_blocks_alerts_but_not_test_send(monkeypatch):
    sent = []

    async def fake(cfg, text):
        sent.append(text)
    monkeypatch.setattr(nt, "send_telegram", fake)
    monkeypatch.setattr(nt, "load_notify_settings", lambda: {"telegram": {"enabled": True, "bot_token": "x", "chat_id": "1"}})
    monkeypatch.setenv("DISABLE_NOTIFY", "1")
    r = asyncio.run(nt.notify("FW down", "msg"))
    assert "all" in r and sent == []
    assert asyncio.run(nt.notify("Gửi thử", "msg", only="telegram")) == {"telegram": "ok"} and len(sent) == 1
    monkeypatch.delenv("DISABLE_NOTIFY")
    assert asyncio.run(nt.notify("FW down", "msg")) == {"telegram": "ok"}


def _tool():
    p = Path(__file__).resolve().parents[1] / "tools" / "compare_v1_v2.py"
    spec = importlib.util.spec_from_file_location("compare_v1_v2", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_compare_flags():
    m = _tool()
    chk = {1: {"name": "A", "type": "ping", "asset": "X", "enabled": True}, 2: {"name": "B", "type": "ping", "asset": "Y", "enabled": True}}
    t = datetime(2026, 11, 9)
    a = {"checks": chk, "per": {1: {"n": 10, "down": 0, "uptime": 100.0, "last": "ok", "last_ts": t},
                                 2: {"n": 10, "down": 0, "uptime": 100.0, "last": "ok", "last_ts": t}}}
    b = {"checks": chk, "per": {1: {"n": 10, "down": 0, "uptime": 100.0, "last": "ok", "last_ts": t},
                                 2: {"n": 0, "down": 0, "uptime": None, "last": None, "last_ts": None}}}
    rows = {r["id"]: r for r in m.compare(a, b)}
    assert rows[1]["flags"] == [] and rows[2]["flags"] == ["v2 did not run check"]
