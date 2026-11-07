"""Gửi cảnh báo: Telegram, Email (SMTP), Webhook (Slack/Teams/Google Chat/Discord...)."""
import logging
import os
from email.message import EmailMessage

import aiosmtplib
import httpx

from .db import SessionLocal
from . import models
from .security import open_config

log = logging.getLogger("notify")

CHANNELS = ("telegram", "email", "webhook")
TELEGRAM_API = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org")


def load_notify_settings() -> dict:
    db = SessionLocal()
    try:
        s = db.get(models.Setting, "notify")
        raw = (s.value if s else {}) or {}
        return {k: open_config(raw.get(k, {})) for k in CHANNELS}
    finally:
        db.close()


async def send_telegram(cfg: dict, text: str):
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{TELEGRAM_API}/bot{cfg['bot_token']}/sendMessage",
                         json={"chat_id": cfg["chat_id"], "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
        r.raise_for_status()


async def send_email(cfg: dict, subject: str, text: str):
    msg = EmailMessage()
    msg["From"] = cfg.get("from") or cfg.get("username")
    msg["To"] = cfg["to"]
    msg["Subject"] = subject
    msg.set_content(text)
    port = int(cfg.get("port", 587))
    await aiosmtplib.send(msg, hostname=cfg["host"], port=port, username=cfg.get("username") or None,
                          password=cfg.get("password") or None, start_tls=port == 587 and cfg.get("security", "starttls") == "starttls",
                          use_tls=port == 465 or cfg.get("security") == "ssl", timeout=20)


async def send_webhook(cfg: dict, subject: str, text: str):
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(cfg["url"], json={"text": f"{subject}\n{text}", "content": f"{subject}\n{text}", "title": subject})
        r.raise_for_status()


async def notify(subject: str, text: str, severity: str = "critical", only: str | None = None) -> dict:
    """Trả về {kênh: 'ok' | lỗi}."""
    cfg = load_notify_settings()
    results = {}
    severity = {"down": "critical", "trouble": "warning", "attention": "warning"}.get(severity, severity)   # mức cảnh báo mới → kênh gửi
    icon = {"critical": "🔴", "warning": "🟠", "resolved": "🟢", "info": "🔵"}.get(severity, "🔔")
    for ch in CHANNELS:
        c = cfg.get(ch) or {}
        if only and ch != only:
            continue
        if not only and not c.get("enabled"):
            continue
        if not only and severity == "warning" and not c.get("include_warnings", True):
            continue
        try:
            if ch == "telegram" and c.get("bot_token") and c.get("chat_id"):
                await send_telegram(c, f"{icon} <b>{_esc(subject)}</b>\n{_esc(text)}")
            elif ch == "email" and c.get("host") and c.get("to"):
                await send_email(c, f"{icon} {subject}", text)
            elif ch == "webhook" and c.get("url"):
                await send_webhook(c, f"{icon} {subject}", text)
            else:
                results[ch] = "Chưa cấu hình đủ"
                continue
            results[ch] = "ok"
        except Exception as e:
            log.warning("notify %s failed: %s", ch, e)
            results[ch] = f"{type(e).__name__}: {e}"[:200]
    return results


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
