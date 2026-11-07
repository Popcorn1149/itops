"""Vòng lặp giám sát: chạy check đến hạn, lưu kết quả, mở/đóng cảnh báo, đồng bộ tài sản phát hiện được."""
import asyncio
import copy
import logging
import os
from datetime import timedelta

from .collectors import COLLECTORS, Result
from .collectors.base import SEV_NAME, SEV_RANK, classify, level_of, max_sev, res_threshold, status_of
from .db import SessionLocal
from . import models
from .models import now
from .security import open_config

log = logging.getLogger("scheduler")
MAX_PARALLEL = int(os.environ.get("MAX_PARALLEL_CHECKS", "20"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "14"))
STATUS_TO_ASSET = {"ok": "up", "warn": "warning", "fail": "down", "unknown": "unknown"}

_running: set[int] = set()
LAST_TICK: float | None = None       # nhịp của vòng lặp – /api/health dùng để biết bộ lập lịch còn chạy
_sem = asyncio.Semaphore(MAX_PARALLEL)


async def run_check(check_id: int) -> dict | None:
    if check_id in _running:
        return None
    _running.add(check_id)
    try:
        async with _sem:
            db = SessionLocal()
            try:
                chk = db.get(models.Check, check_id)
                if not chk:
                    return None
                fn = COLLECTORS.get(chk.type)
                cfg = open_config(chk.config or {})
                target, ctype = chk.target, chk.type
            finally:
                db.close()
            if cfg.get("demo"):
                from .seed import simulate
                await asyncio.sleep(0.05)
                res = simulate(cfg)
            elif not fn:
                res = Result("fail", f"Loại check không hỗ trợ: {ctype}")
            else:
                try:
                    res = await fn(target, cfg)
                except Exception as e:  # collector bug must not kill the loop
                    log.exception("check %s crashed", check_id)
                    res = Result("fail", f"Lỗi nội bộ: {type(e).__name__} {e}"[:300])
            return await _persist(check_id, res)
    finally:
        _running.discard(check_id)


async def _persist(check_id: int, res: Result) -> dict:
    db = SessionLocal()
    to_notify = []
    try:
        chk = db.get(models.Check, check_id)
        if not chk:
            return {}
        cfg = chk.config or {}
        prev = chk.status
        rs = (res.data or {}).get("res")
        avail_sev, is_down = classify(res)                       # kết nối / dịch vụ
        res_lv = (rs or {}).get("level")                          # tài nguyên (Attention/Trouble/Critical)
        sev = max_sev(avail_sev, res_lv if res_lv != "ok" else None)
        chk.status = status_of(sev, res.status)
        chk.severity = sev
        chk.last_checked = now()
        chk.last_message = res.message[:1000]
        chk.last_latency = res.latency
        chk.last_data = res.data or {}
        # chỉ đếm lỗi kết nối/dịch vụ; vượt threshold tài nguyên có bộ đếm riêng (xem _resource_alerts)
        chk.fail_count = (chk.fail_count + 1) if avail_sev else 0
        metrics = {k: rs.get(k) for k in ("cpu", "mem", "disk") if rs.get(k) is not None} if rs else None
        db.add(models.CheckResult(check_id=chk.id, status=chk.status, latency=res.latency, value=res.value,
                                  message=res.message[:500], metrics=metrics or None, down=is_down, severity=sev))
        db.flush()

        # ---- asset status ----
        if chk.asset_id:
            asset = db.get(models.Asset, chk.asset_id)
            if asset:
                sibling = db.query(models.Check).filter(models.Check.asset_id == asset.id,
                                                        (models.Check.enabled == True) | (models.Check.id == chk.id)).all()  # noqa: E712
                # tài sản chỉ "down" khi thật sự mất kết nối; vượt threshold / lỗi dịch vụ → "warning"
                w = max_sev(*[c.severity for c in sibling])
                if not (asset.type in ("vm",) and asset.source.startswith("check:")):
                    if w == "down":
                        asset.status = "down"
                    elif w:
                        asset.status = "warning"
                    else:
                        asset.status = "up" if any(c.status == "ok" for c in sibling) else "unknown"
                if not is_down:
                    asset.last_seen = now()
                meta = copy.deepcopy(asset.meta or {})
                snap = {k: v for k, v in (res.data or {}).items() if k in ("sys_descr", "uptime", "cpu", "mem", "mem_pct", "disk", "ports_up", "ports_total", "version", "os", "hostname", "temp", "platform", "load1")}
                if rs:
                    meta["res"] = {**rs, "check_id": chk.id, "ts": now().isoformat() + "Z"}
                if snap:
                    meta.setdefault("live", {}).update(snap)
                if snap or rs:
                    asset.meta = meta
                if not asset.os and res.data.get("os"):
                    asset.os = str(res.data["os"])[:128]

        # ---- discovery ----
        if res.discovered:
            _sync_discovered(db, chk, res.discovered)

        # ---- alerts ----
        threshold = int(cfg.get("alert_after", 2))
        asset_name = db.get(models.Asset, chk.asset_id).name if chk.asset_id and db.get(models.Asset, chk.asset_id) else chk.target
        open_alert = db.query(models.Alert).filter(models.Alert.check_id == chk.id, models.Alert.status != "resolved",
                                                   models.Alert.metric.is_(None)).first()
        if avail_sev and chk.fail_count >= threshold:
            title = f"{chk.name} DOWN" if avail_sev == "down" else f"{chk.name} · {SEV_NAME[avail_sev]}"
            if not open_alert:
                a = models.Alert(check_id=chk.id, asset_id=chk.asset_id, site_id=chk.site_id, severity=avail_sev,
                                 title=title, message=res.message)
                db.add(a)
                to_notify.append((title, f"{asset_name} ({chk.target})\n{res.message}", _nsev(avail_sev), {"kind": "open", "alert": a}))
            else:
                if SEV_RANK.get(avail_sev, 0) > SEV_RANK.get(open_alert.severity, 0):   # nặng hơn → báo lại
                    to_notify.append((title, f"{asset_name} ({chk.target})\n{res.message}", _nsev(avail_sev), {"kind": "escalate", "alert": open_alert}))
                open_alert.severity, open_alert.title = avail_sev, title
                open_alert.message = res.message
                open_alert.last_seen = now()
        elif not avail_sev and open_alert:
            open_alert.status = "resolved"
            open_alert.resolved_at = now()
            dur = open_alert.resolved_at - open_alert.opened_at
            to_notify.append((f"{chk.name} đã hoạt động lại", f"{asset_name} ({chk.target})\nGián đoạn {int(dur.total_seconds() // 60)} phút · {res.message}",
                              "resolved", {"kind": "resolve", "alert": open_alert}))
        if rs:
            to_notify += _resource_alerts(db, chk, cfg, rs, threshold, asset_name)
        db.commit()
        to_notify = [_ctx_ids(x, chk) for x in to_notify]       # đổi đối tượng → id trước khi đóng phiên DB
        out = {"status": chk.status, "severity": sev, "down": is_down, "message": res.message, "latency": res.latency, "data": res.data, "prev": prev}
    finally:
        db.close()
    if to_notify:
        from .automation.engine import dispatch
        try:
            await dispatch(to_notify)        # tự động hoá (bảo trì, gom nguyên nhân gốc, chống chập chờn, runbook) rồi gửi
        except Exception:
            log.exception("dispatch failed")
    return out


def _ctx_ids(item, chk):
    subj, text, sev, *rest = item
    c = dict(rest[0]) if rest else {}
    a = c.pop("alert", None)
    if a is not None:
        c.update(alert_id=a.id, asset_id=a.asset_id, site_id=a.site_id)
    c.setdefault("check_id", chk.id)
    c.setdefault("asset_id", chk.asset_id)
    return (subj, text, sev, c)


def _nsev(sev: str) -> str:
    """Mức gửi thông báo: down/critical = critical (luôn gửi); trouble/attention = warning (tuỳ chọn 'gửi cả cảnh báo')."""
    return "critical" if sev in ("down", "critical") else "warning"


RES_NAME = {"cpu": "CPU", "mem": "RAM", "disk": "Disk"}


def _resource_alerts(db, chk: models.Check, cfg: dict, rs: dict, threshold: int, asset_name: str) -> list:
    """Mỗi chỉ số CPU/RAM/Disk một cảnh báo riêng.

    - Mở khi vượt threshold (Attention trở lên) `threshold` lần liên tiếp.
    - Đổi mức theo giá trị hiện tại; chỉ gửi thông báo khi mức nặng lên.
    - Chỉ đóng khi giá trị xuống DƯỚI threshold Rearm (chống bật/tắt liên tục quanh threshold).
    """
    out = []
    recent = None
    for key in ("cpu", "mem", "disk"):
        v = rs.get(key)
        if v is None:
            continue
        lv = (rs.get("levels") or {}).get(key) or level_of(cfg, key, v)
        a = db.query(models.Alert).filter(models.Alert.check_id == chk.id, models.Alert.metric == key,
                                          models.Alert.status != "resolved").first()
        label = RES_NAME[key] + (f" {rs.get('disk_name')}" if key == "disk" and rs.get("disk_name") else "")
        rearm = res_threshold(cfg, key, "rearm")
        if lv not in (None, "ok"):
            if not a:
                if recent is None:
                    recent = [r.metrics or {} for r in db.query(models.CheckResult).filter(models.CheckResult.check_id == chk.id)
                              .order_by(models.CheckResult.id.desc()).limit(max(1, threshold)).all()]
                if len(recent) < threshold or any(level_of(cfg, key, m.get(key)) in (None, "ok") for m in recent):
                    continue                                   # chưa đủ số lần vượt threshold liên tiếp
            thr = res_threshold(cfg, key, lv)
            title = f"{asset_name}: {label} {v:g}% · {SEV_NAME[lv]}"
            msg = f"{label} {v:g}% ≥ {thr:g}% ({SEV_NAME[lv]})." + (f" Tự đóng khi < {rearm:g}% (Rearm)." if rearm else "")
            if not a:
                na = models.Alert(check_id=chk.id, asset_id=chk.asset_id, site_id=chk.site_id, severity=lv, metric=key,
                                  source="resource", dedupe_key=f"res:{chk.id}:{key}", title=title[:255], message=msg, last_seen=now())
                db.add(na)
                out.append((title, f"{chk.name} ({chk.target})\n{msg}", _nsev(lv), {"kind": "open", "alert": na}))
            else:
                if SEV_RANK.get(lv, 0) > SEV_RANK.get(a.severity, 0):
                    out.append((title, f"{chk.name} ({chk.target})\n{msg}", _nsev(lv), {"kind": "escalate", "alert": a}))
                a.severity, a.title, a.message, a.last_seen = lv, title[:255], msg, now()
                a.count = (a.count or 1) + 1
        elif a:
            if rearm is None or v < rearm:
                a.status, a.resolved_at = "resolved", now()
                mins = int((a.resolved_at - a.opened_at).total_seconds() // 60)
                out.append((f"{asset_name}: {label} đã về bình thường ({v:g}%)", f"{chk.name} ({chk.target})\nKéo dài {mins} phút", "resolved",
                            {"kind": "resolve", "alert": a}))
            else:
                a.message = f"{label} {v:g}% – dưới threshold nhưng chưa xuống dưới Rearm {rearm:g}%, cảnh báo vẫn giữ."
                a.last_seen = now()
    return out


def _sync_discovered(db, chk: models.Check, items: list[dict]):
    source = f"check:{chk.id}"
    existing = {a.external_id: a for a in db.query(models.Asset).filter(models.Asset.source == source).all()}
    site_id = chk.site_id
    anchor = db.get(models.Asset, chk.asset_id) if chk.asset_id else None
    if anchor and not site_id:
        site_id = anchor.site_id
    hosts = [i for i in items if i["type"] == "host"]
    if chk.type == "snmp" and anchor and db.query(models.Check).filter(
            models.Check.asset_id == anchor.id, models.Check.type == "esxi", models.Check.enabled == True).count():  # noqa: E712
        return   # đã có check ESXi (API) cho host này – nguồn đầy đủ hơn, không tạo VM trùng từ SNMP
    snmp_sources = {f"check:{c.id}" for c in db.query(models.Check.id).filter(models.Check.type == "snmp").all()}
    key_to_id: dict[str, int] = {}
    seen = set()
    # ESXi một host + check gắn vào host có sẵn → dùng luôn host đó
    for it in items:
        key = it["key"]
        seen.add(key)
        if it["type"] == "host" and anchor and anchor.type == "host" and len(hosts) == 1:
            a = anchor
            a.external_id = a.external_id or key
        else:
            a = existing.get(key)
            if not a and chk.type != "snmp" and anchor and snmp_sources:
                # VM đã được check SNMP tạo trước đó (cùng tên, cùng host) → nhận về, không tạo bản trùng
                a = db.query(models.Asset).filter(models.Asset.type == it["type"], models.Asset.name == it["name"],
                                                  models.Asset.parent_id == anchor.id, models.Asset.source.in_(snmp_sources)).first()
                if a:
                    a.source, a.external_id = source, key
            if not a:
                a = models.Asset(name=it["name"], type=it["type"], source=source, external_id=key, site_id=site_id)
                db.add(a)
            a.name = it.get("name") or a.name
        a.status = it.get("status", a.status)
        if it.get("ip"):
            a.ip = it["ip"]
        for f in ("vendor", "model", "os"):
            if it.get(f):
                setattr(a, f, str(it[f])[:128])
        meta = copy.deepcopy(a.meta or {})
        new_meta = dict(it.get("meta") or {})
        if new_meta.get("res"):
            new_meta["res"] = {**new_meta["res"], "via_check": chk.id, "ts": now().isoformat() + "Z"}
        if a is anchor and (meta.get("res") or {}).get("check_id") == chk.id:
            new_meta.pop("res", None)   # đã có số liệu đầy đủ (gồm datastore) từ chính check này
        meta.update(new_meta)
        meta.pop("missing", None)
        a.meta = meta
        a.last_seen = now()
        if a.site_id is None:
            a.site_id = site_id
        db.flush()
        key_to_id[key] = a.id
    for it in items:
        a = db.get(models.Asset, key_to_id[it["key"]])
        if a is anchor:
            continue
        pk = it.get("parent_key")
        if pk and pk in key_to_id:
            a.parent_id = key_to_id[pk]
        elif a.parent_id is None and anchor:
            a.parent_id = anchor.id
    for key, a in existing.items():
        if key not in seen:
            meta = copy.deepcopy(a.meta or {})
            meta["missing"] = True
            a.meta = meta
            a.status = "unknown"


async def loop():
    log.info("scheduler started")
    last_purge = now() - timedelta(hours=2)
    global LAST_TICK
    import time as _t
    while True:
        LAST_TICK = _t.time()
        try:
            db = SessionLocal()
            try:
                checks = db.query(models.Check.id, models.Check.interval, models.Check.last_checked).filter(models.Check.enabled == True).all()  # noqa: E712
            finally:
                db.close()
            t = now()
            for cid, interval, last in checks:
                if cid in _running:
                    continue
                if last is None or (t - last).total_seconds() >= max(10, interval or 60):
                    asyncio.create_task(run_check(cid))
            if (t - last_purge).total_seconds() > 3600:
                last_purge = t
                db = SessionLocal()
                try:
                    db.query(models.CheckResult).filter(models.CheckResult.ts < t - timedelta(days=RETENTION_DAYS)).delete()
                    db.commit()
                finally:
                    db.close()
        except Exception:
            log.exception("scheduler loop error")
        await asyncio.sleep(5)
