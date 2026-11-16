"""Process received logs/traps: attach assets by IP, prevent flooding, write in batches, apply rules → alerts."""
import asyncio
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import timedelta, timezone

from .db import SessionLocal
from . import models
from .models import now

log = logging.getLogger("events")
RATE_PER_SOURCE = int(os.environ.get("EVENTS_PER_SEC_PER_SOURCE", "200"))
RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", "90"))   # Cài đặt › Security Monitoring có thể đổi
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "2000000"))
QUEUE_MAX = 50000

queue: asyncio.Queue | None = None
DEFAULT_ALLOWED = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
_acl = {"nets": None, "cache": {}}
STATS = {"received": 0, "stored": 0, "dropped_rate": 0, "dropped_rule": 0, "dropped_queue": 0, "dropped_acl": 0, "blocked": {},
         "by_kind": defaultdict(int), "last": {}, "started": time.time(), "listeners": {}, "sources": {}}
_buckets: dict[str, list] = {}
_asset_cache = {"t": 0, "by_ip": {}, "by_name": {}}
_rules_cache = {"t": 0, "rules": []}
_window: dict[str, deque] = defaultdict(deque)
_tried_users: dict[str, set] = defaultdict(set)
IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
# Tách user đã thử from log sign-in sai: pfSense "for user 'x'", OpenSSH "for [invalid user] x", Synology "User [x]",
# PAM "user=x" (bỏ qua "ruser="), Cisco "[user: x]"
USER_RE = re.compile(r"(?:invalid user |(?<![a-z])user[ =:\[]+'?|for (?:invalid user |user '?)?|account[ =:]+'?|login[ =:]+'?)([\w.@\\-]{1,64})", re.I)


def get_queue() -> asyncio.Queue:
    global queue
    if queue is None:
        queue = asyncio.Queue(maxsize=QUEUE_MAX)
    return queue


def set_allowed(cidrs: list[str]):
    """List of IPs/subnets allowed to send logs/traps. Empty = accept all."""
    import ipaddress
    nets = []
    for c in cidrs or []:
        c = c.strip()
        if c:
            nets.append(ipaddress.ip_network(c, strict=False))
    _acl["nets"], _acl["cache"] = nets, {}


def allowed(ip: str) -> bool:
    nets = _acl["nets"]
    if nets is None:
        set_allowed(DEFAULT_ALLOWED)
        nets = _acl["nets"]
    if not nets:
        return True
    r = _acl["cache"].get(ip)
    if r is None:
        import ipaddress
        try:
            a = ipaddress.ip_address(ip)
            r = any(a in n for n in nets)
        except ValueError:
            r = False
        if len(_acl["cache"]) < 10000:
            _acl["cache"][ip] = r
    return r


def submit(ev: dict):
    """Called by the receiver (inside the event loop). Non-blocking: packets outside the allowlist, rate limit, or capacity are dropped and counted."""
    STATS["received"] += 1
    # Lọc / giới hạn tốc độ theo IP THỰC SỰ gửi gói tin. Với trap, source_ip có thể lấy from varbind agentAddress
    # (người gửi tự điền được) → không dùng nó để quyết định cho qua; agentAddress chỉ dùng để gắn ando assets.
    src = (ev.get("data") or {}).get("via") or ev.get("source_ip", "")
    srcs = STATS["sources"]   # chẩn đoán: nguồn nào đang gửi tới (kể cả bị chặn) – trả lời "log có tới IT Ops không"
    rec = srcs.get(src)
    if rec is None and len(srcs) < 500:
        rec = srcs[src] = {"count": 0, "first": time.time(), "last": 0, "kind": ev.get("kind", ""), "blocked": False}
    if rec is not None:
        rec["count"] += 1
        rec["last"] = time.time()
    if not allowed(src):
        if rec is not None:
            rec["blocked"] = True
        STATS["dropped_acl"] += 1
        b = STATS["blocked"]
        if src in b or len(b) < 50:
            b[src] = b.get(src, 0) + 1
        return
    t = time.monotonic()
    b = _buckets.get(src)
    if b is None:
        b = _buckets[src] = [float(RATE_PER_SOURCE), t]
    b[0] = min(RATE_PER_SOURCE, b[0] + (t - b[1]) * RATE_PER_SOURCE)
    b[1] = t
    if b[0] < 1:
        STATS["dropped_rate"] += 1
        return
    b[0] -= 1
    try:
        get_queue().put_nowait(ev)
    except asyncio.QueueFull:
        STATS["dropped_queue"] += 1


def invalidate_caches():
    _asset_cache["t"] = 0
    _rules_cache["t"] = 0


def _assets(db):
    if time.monotonic() - _asset_cache["t"] > 15:
        by_ip, by_name = {}, {}
        for a in db.query(models.Asset.id, models.Asset.ip, models.Asset.name, models.Asset.site_id).all():
            if a.ip:
                for ip in re.split(r"[,\s]+", a.ip):
                    if ip:
                        by_ip.setdefault(ip.strip(), (a.id, a.site_id))
            by_name.setdefault(a.name.lower(), (a.id, a.site_id))
        _asset_cache.update(t=time.monotonic(), by_ip=by_ip, by_name=by_name)
    return _asset_cache


class CompiledRule:
    def __init__(self, r: models.EventRule):
        self.r = r
        self.id, self.name, self.action, self.kind = r.id, r.name, r.action, r.kind
        self.max_sev = r.max_severity if r.max_severity is not None else 7
        self.pat = _re(r.pattern)
        self.app = _re(r.app_pattern)
        self.res = _re(r.resolve_pattern)
        self.oids = _oids(r.trap_oids)
        self.res_oids = _oids(r.resolve_trap_oids)
        self.asset_id, self.site_id = r.asset_id, r.site_id
        self.threshold, self.window = max(1, r.threshold or 1), max(1, r.window_min or 5)
        self.alert_severity, self.auto_resolve = r.alert_severity, r.auto_resolve_min or 0
        self.group_by = (getattr(r, "group_by", "") or "").strip()
        self.key_filter = {k.strip().lower() for k in (getattr(r, "key_filter", "") or "").split(",") if k.strip()}

    def scope_ok(self, ev):
        return (not self.asset_id or ev["asset_id"] == self.asset_id) and (not self.site_id or ev["site_id"] == self.site_id) \
            and (self.kind == "any" or self.kind == ev["kind"])

    def match(self, ev):
        """Trả (True, key) nếu khớp conditions mở; dùng nhóm (?P<key>) hoặc nhóm đầu tiên làm khoá gom."""
        if not self.scope_ok(ev):
            return False, ""
        if self.oids:
            if ev["kind"] != "trap" or not _oid_in(ev["data"].get("trap_oid", ""), self.oids):
                return False, ""
        elif ev["severity"] > self.max_sev:
            return False, ""
        if self.app and not self.app.search(ev["app"] or ""):
            return False, ""
        key = ev["data"].get("if_key", "") if ev["kind"] == "trap" else ""
        if self.pat:
            m = self.pat.search(ev["message"])
            if not m:
                return False, ""
            key = _key(m) or key
        if not (self.pat or self.oids or self.app) and self.max_sev >= 7:
            return False, ""  # rule rỗng không khớp tất cả
        if self.group_by == "src_ip":   # gộp theo IP source ghi trong log (e.g. IP đang password spraying), không theo user
            ips = [x for x in IPV4.findall(ev["message"]) if x != ev["source_ip"]]
            key = ips[0] if ips else (key or "?")
        if self.key_filter and (key or "").lower() not in self.key_filter:
            return False, ""   # chỉ áp dụng cho danh sách khoá đã khai báo (e.g. IP tĩnh quan trọng)
        return True, key

    def resolves(self, ev):
        if not self.scope_ok(ev):
            return False, ""
        if self.res_oids and ev["kind"] == "trap" and _oid_in(ev["data"].get("trap_oid", ""), self.res_oids):
            return True, ev["data"].get("if_key", "")
        if self.res and ev["kind"] == "syslog":
            m = self.res.search(ev["message"])
            if m:
                return True, _key(m)
        return False, ""


def _re(p):
    if not p:
        return None
    try:
        return re.compile(p, re.I)
    except re.error:
        log.warning("regex error: %s", p)
        return None


def _oids(s):
    return [o.strip().lstrip(".") for o in (s or "").split(",") if o.strip()]


def _oid_in(oid, lst):
    return any(oid == o or oid.startswith(o + ".") for o in lst)


def _key(m):
    gd = {k: v for k, v in m.groupdict().items() if v}
    if gd:
        return gd.get("key") or next(iter(gd.values()))
    return m.group(1) if m.lastindex else ""


def _rules(db):
    if time.monotonic() - _rules_cache["t"] > 10:
        rows = db.query(models.EventRule).filter(models.EventRule.enabled == True).order_by(models.EventRule.sort, models.EventRule.id).all()  # noqa: E712
        _rules_cache.update(t=time.monotonic(), rules=[CompiledRule(r) for r in rows])
    return _rules_cache["rules"]


def _expand(batch: list[dict]) -> list[dict]:
    """Parse a raw UDP packet (which may contain multiple lines) into events."""
    from .receivers import syslog_event
    out = []
    for ev in batch:
        raw = ev.get("raw")
        if raw is None:
            out.append(ev)
            continue
        text = raw.decode("utf-8", errors="replace")
        for line in text.splitlines() or [text]:
            if line.strip():
                out.append(syslog_event(line, ev["source_ip"]))
    return out


def process_batch(batch: list[dict]) -> list[tuple]:
    """Write an event batch and apply rules. Return notifications to send. Runs synchronously (call from a thread)."""
    batch = _expand(batch)
    db = SessionLocal()
    notes = []
    try:
        cache = _assets(db)
        rules = _rules(db)
        hit_counts = defaultdict(int)
        for ev in batch:
            a = cache["by_ip"].get(ev["source_ip"]) or (cache["by_name"].get(ev["host"].lower()) if ev.get("host") else None)
            ev["asset_id"], ev["site_id"] = (a if a else (None, None))
            dropped, matched_rule = False, None
            for r in rules:
                ok, key = r.match(ev)
                if ok:
                    hit_counts[r.id] += 1
                    if r.action == "drop":
                        dropped = True
                        break
                    matched_rule = r
                    notes += _open_alert(db, r, ev, key)
                    break
            for r in rules:  # recovery event (linkUp, "changed state to up", ...)
                ok, key = r.resolves(ev)
                if ok:
                    notes += _resolve(db, r, ev, key)
            if dropped:
                STATS["dropped_rule"] += 1
                continue
            db.add(models.Event(ts=_when(ev), kind=ev["kind"], source_ip=ev["source_ip"], asset_id=ev["asset_id"], site_id=ev["site_id"],
                                facility=ev.get("facility"), severity=ev["severity"], host=ev.get("host", "")[:128],
                                app=ev.get("app", "")[:64], message=ev["message"][:8000], device_ts=ev.get("device_ts", "")[:40],
                                data=ev.get("data") or {}, rule_id=matched_rule.id if matched_rule else None))
            STATS["stored"] += 1
            STATS["by_kind"][ev["kind"]] += 1
            STATS["last"][ev["kind"]] = time.time()
        if hit_counts:
            for rid, n in hit_counts.items():
                db.query(models.EventRule).filter_by(id=rid).update({models.EventRule.hits: models.EventRule.hits + n, models.EventRule.last_hit: now()})
        db.commit()
    except Exception:
        db.rollback()
        log.exception("Failed to write event")
    finally:
        db.close()
    return notes


def _when(ev):
    """Mốc thời gian of sự kiện. Log thật luôn là "bây hours"; chỉ bộ phát log mẫu (demo_logs) gắn sẵn _at để dựng lịch sử."""
    return ev.get("_at") or now()


def _epoch(ev) -> float:
    at = ev.get("_at")
    return at.replace(tzinfo=timezone.utc).timestamp() if at else time.time()


def _who(db, ev):
    if ev["asset_id"]:
        a = db.get(models.Asset, ev["asset_id"])
        if a:
            return a.name
    return ev.get("host") or ev["source_ip"]


def _open_alert(db, r: CompiledRule, ev, key) -> list:
    subject = ev["asset_id"] or ev["source_ip"]
    dkey = f"rule:{r.id}:{subject}:{key}"
    t = _epoch(ev)
    if len(_tried_users) > 5000:
        _tried_users.clear()
    if r.group_by == "src_ip":   # ghi lại user đã thử ngay from lần đầu (kể cả trước khi đủ threshold)
        tried = _tried_users[dkey]
        if len(tried) < 50:
            tried.update(u for u in USER_RE.findall(ev["message"]) if u.lower() not in ("from", "port", "ssh2", "failed", "success"))
    if r.threshold > 1:
        w = _window[dkey]
        w.append(t)
        while w and t - w[0] > r.window * 60:
            w.popleft()
        if len(w) < r.threshold:
            return []
    existing = db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved").first()
    who = _who(db, ev)
    users = ""
    if r.group_by == "src_ip":
        tried = _tried_users[dkey]
        if tried:
            users = "\nAttempted users: " + ", ".join(sorted(tried)[:20]) + (f" (+{len(tried) - 20})" if len(tried) > 20 else "")
    if existing:
        existing.count = (existing.count or 1) + 1
        existing.last_seen = _when(ev)
        existing.message = (ev["message"][:1500] + users)[:2000]
        return []
    title = f"{r.name}: {who}" + (f" ({key})" if key else "")
    na = models.Alert(source="event", event_rule_id=r.id, dedupe_key=dkey, asset_id=ev["asset_id"], site_id=ev["site_id"],
                      severity=r.alert_severity, title=title[:255], message=(ev["message"][:1500] + users)[:2000],
                      opened_at=_when(ev), last_seen=_when(ev), count=1)
    db.add(na)
    db.flush()  # để log kế tiếp trong cùng lô thấy alerts này (session autoflush=False)
    return [(title, f"Source: {who} ({ev['source_ip']})\n{ev['message'][:500]}", r.alert_severity,
             {"kind": "open", "alert_id": na.id, "asset_id": na.asset_id, "site_id": na.site_id})]


def _resolve(db, r: CompiledRule, ev, key) -> list:
    subject = ev["asset_id"] or ev["source_ip"]
    dkey = f"rule:{r.id}:{subject}:{key}"
    out = []
    for a in db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved"):
        a.status, a.resolved_at = "resolved", _when(ev)
        a.message = f"{a.message} · recovered: {ev['message'][:200]}"[:2000]
        out.append((f"{a.title} – recovered", ev["message"][:300], "resolved",
                    {"kind": "resolve", "alert_id": a.id, "asset_id": a.asset_id, "site_id": a.site_id}))
    if out:
        db.flush()
    _window.pop(dkey, None)
    _tried_users.pop(dkey, None)
    return out


async def consumer():
    q = get_queue()
    while True:
        batch = [await q.get()]
        t_end = time.monotonic() + 0.3
        while len(batch) < 2000 and time.monotonic() < t_end:
            try:
                batch.append(q.get_nowait())
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.05)
        notes = await asyncio.to_thread(process_batch, batch)
        if notes:
            from .automation.engine import dispatch
            try:
                await dispatch(notes)
            except Exception:
                log.exception("Notification failed")


async def housekeeping():
    """Auto-close alerts for silent log sources; delete logs that exceed age or count limits."""
    last_purge = 0
    while True:
        try:
            await asyncio.to_thread(_housekeep, time.time() - last_purge > 3600)
            if time.time() - last_purge > 3600:
                last_purge = time.time()
        except Exception:
            log.exception("Housekeeping failed")
        await asyncio.sleep(60)


def _housekeep(purge: bool):
    db = SessionLocal()
    try:
        rules = {r.id: r for r in db.query(models.EventRule).all()}
        for a in db.query(models.Alert).filter(models.Alert.source == "event", models.Alert.status != "resolved"):
            r = rules.get(a.event_rule_id)
            if r and r.auto_resolve_min and a.last_seen and now() - a.last_seen > timedelta(minutes=r.auto_resolve_min):
                a.status, a.resolved_at = "resolved", now()
                a.message = f"{a.message} · auto-resolved after {r.auto_resolve_min} minutes without recurrence"[:2000]
        if purge:
            db.query(models.Event).filter(models.Event.ts < now() - timedelta(days=RETENTION_DAYS)).delete()
            total = db.query(models.Event).count()
            if total > MAX_EVENTS:
                cut = db.query(models.Event.id).order_by(models.Event.id.desc()).offset(MAX_EVENTS).limit(1).scalar()
                if cut:
                    db.query(models.Event).filter(models.Event.id <= cut).delete()
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- rule mặc định
IF_KEY = r"(?:Interface |[Pp]ort )(?P<key>[\w/.:-]+?),?\s+"
DEFAULT_RULES = [
    dict(sort=10, name="Ignore firewall packet logs (filterlog)", action="drop", kind="syslog", app_pattern=r"^filterlog$",
         description="pfSense/OPNsense send one log per packet, which creates high volume. Disable this rule if you want to retain them."),
    dict(sort=20, name="Switch port down", kind="syslog", pattern=IF_KEY + r"(?:changed state to down|is now off-line|link down)",
         resolve_pattern=IF_KEY + r"(?:changed state to up|is now on-line|link up)", alert_severity="warning",
         description="Cisco %LINK-3-UPDOWN and HPE/Aruba port-offline messages. Automatically resolves when the interface comes back up."),
    dict(sort=21, name="Port down (SNMP trap)", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.3", resolve_trap_oids="1.3.6.1.6.3.1.1.5.4",
         alert_severity="warning", description="Standard linkDown/linkUp trap from switches, routers, and firewalls."),
    dict(sort=30, name="Gateway WAN down (pfSense)", kind="syslog", pattern=r"MONITOR: (?P<key>\S+) is down",
         resolve_pattern=r"MONITOR: (?P<key>\S+) is available now", alert_severity="critical",
         description="dpinger reports WAN loss; automatically resolves when the gateway becomes available again."),
    dict(sort=40, name="Datastore connection lost (ESXi)", kind="syslog",
         pattern=r"(?:Lost access to volume|All Paths Down|permanently inaccessible|\bAPD\b)",
         resolve_pattern=r"(?:Successfully restored access to volume|exited the All Paths Down)", alert_severity="critical"),
    dict(sort=50, name="Disk / RAID failure", kind="syslog",
         pattern=r"(?:(?:volume|disk|drive|raid|array|storage pool)\s*[\w/#.\-]*\s*(?:is |has |was )?(?:been )?(?:degraded|crashed|failed|failing)\b|bad sectors?\b)", alert_severity="critical",
         auto_resolve_min=0, description="Synology, QNAP, iLO/iDRAC, mdadm…"),
    dict(sort=60, name="UPS switched to battery", kind="any",
         pattern=r"(?:on battery|switched to battery|power failure|utility power fail)",
         resolve_pattern=r"(?:power (?:restored|returned)|returned from battery|utility power restored|on line)",
         trap_oids="", alert_severity="critical"),
    dict(sort=61, name="UPS on battery (SNMP trap)", kind="trap", trap_oids="1.3.6.1.2.1.33.2.0.1,1.3.6.1.4.1.318.0.5",
         resolve_trap_oids="1.3.6.1.4.1.318.0.9", alert_severity="critical", auto_resolve_min=120),
    dict(sort=70, name="Repeated failed sign-ins", kind="syslog",
         pattern=r"(?:Failed password|authentication (?:error|failure)|Authentication failed|login failed|Invalid user|bad password)",
         threshold=5, window_min=5, auto_resolve_min=30, alert_severity="trouble", group_by="src_ip",
         description="UC-01 · Five or more failures within five minutes from the same source IP may indicate password spraying. One alert is grouped per source IP and includes the attempted usernames."),
    dict(sort=72, name="IP-to-MAC address change (possible ARP spoofing)", kind="syslog", enabled=False, pattern=r"arp: (?P<key>\d+\.\d+\.\d+\.\d+) moved from",
         alert_severity="attention", auto_resolve_min=60,
         description="UC-10 · The firewall reports an IP-to-MAC change. Add important static IPs (gateway, server, DNS) to the key filter. "
                     "DHCP-assigned IPs may legitimately change MAC addresses; do not include them."),
    dict(sort=74, name="Windows: event log cleared", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=(?:1102|104)\b.*?Log=(?P<key>\w+)", alert_severity="critical",
         description="UC-07 · Event 1102 indicates that the Security log was cleared; Event 104 indicates that the System or Application log was cleared. Enable Windows Event Log collection in the SSH check."),
    dict(sort=75, name="Windows: event logging service stopped unexpectedly", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=1100\b.*planned=0", alert_severity="critical",
         description="UC-08 · Event 1100 occurred without a corresponding planned-shutdown event (1074 or 6006)."),
    dict(sort=76, name="Windows: account created", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=4720\b.*target=(?P<key>[^;|]+)", alert_severity="critical", description="UC-04 · Event 4720."),
    dict(sort=77, name="Windows: added to administrators group", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=(?:4728|4732|4756)\b.*group=(?P<key>(?:Administrators|Domain Admins|Enterprise Admins|Schema Admins|Remote Desktop Users)[^;|]*)",
         alert_severity="critical", description="UC-04 · Event 4728, 4732, or 4756 added a member to a privileged group."),
    dict(sort=78, name="Windows: abnormal RecordId", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"RecordId (?:decreased|has a gap).*Log=(?P<key>\w+)", alert_severity="trouble",
         description="Record ID decreased or skipped compared with the previous read; logs may have been cleared or overwritten."),
    dict(sort=80, name="Device rebooted", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.1,1.3.6.1.6.3.1.1.5.2",
         auto_resolve_min=30, alert_severity="warning"),
    dict(sort=81, name="Incorrect SNMP community string", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.5", auto_resolve_min=60, alert_severity="warning",
         description="A host is querying SNMP with an incorrect community string."),
    dict(sort=90, name="Critical error (crit or higher)", kind="syslog", max_severity=2, auto_resolve_min=60, alert_severity="critical",
         description="All logs at severity emerg/alert/crit that do not match any rule above."),
]


LEGACY_RULE_NAMES = {
    "B\u1ecf qua log g\xf3i tin firewall (filterlog)": 'Ignore firewall packet logs (filterlog)',
    "C\u1ed5ng switch down": 'Switch port down',
    "C\u1ed5ng down (SNMP trap)": 'Port down (SNMP trap)',
    "Gateway WAN down (pfSense)": 'Gateway WAN down (pfSense)',
    "M\u1ea5t k\u1ebft n\u1ed1i datastore (ESXi)": 'Datastore connection lost (ESXi)',
    "\u1ed4 c\u1ee9ng / RAID l\u1ed7i": 'Disk / RAID failure',
    "UPS chuy\u1ec3n sang ch\u1ea1y pin": 'UPS switched to battery',
    "UPS ch\u1ea1y pin (SNMP trap)": 'UPS on battery (SNMP trap)',
    "\u0110\u0103ng nh\u1eadp sai li\u00ean t\u1ee5c": 'Repeated failed sign-ins',
    "IP \u0111\u1ed5i MAC (nghi gi\u1ea3 m\u1ea1o ARP)": 'IP-to-MAC address change (possible ARP spoofing)',
    "Windows: x\xf3a event log": 'Windows: event log cleared',
    "Windows: xo\xe1 nh\u1eadt k\xfd s\u1ef1 ki\u1ec7n": 'Windows: event log cleared',
    "Windows: x\xf3a nh\u1eadt k\xfd s\u1ef1 ki\u1ec7n": 'Windows: event log cleared',
    "Windows: d\u1ecbch v\u1ee5 log d\u1eebng ngo\xe0i k\u1ebf ho\u1ea1ch": 'Windows: event logging service stopped unexpectedly',
    "Windows: t\u1ea1o t\xe0i kho\u1ea3n": 'Windows: account created',
    "Windows: th\xeam v\xe0o admin group": 'Windows: added to administrators group',
    "Windows: th\xeam v\xe0o nh\xf3m qu\u1ea3n tr\u1ecb": 'Windows: added to administrators group',
    "Windows: RecordId b\u1ea5t th\u01b0\u1eddng": 'Windows: abnormal RecordId',
    "Thi\u1ebft b\u1ecb kh\u1edfi \u0111\u1ed9ng l\u1ea1i": 'Device rebooted',
    "Sai community SNMP": 'Incorrect SNMP community string',
    "L\u1ed7i nghi\xeam tr\u1ecdng (crit tr\u1edf l\xean)": 'Critical error (crit or higher)',
}


# Built-in rule text saved by the Vietnamese release: rewritten in place to the English defaults, only when the
# stored value is still the untouched old default (administrator edits are preserved).
_VI_TEXT = re.compile("[\u0103\u00e2\u0111\u00ea\u00f4\u01a1\u01b0\u1ea0-\u1ef9]", re.I)   # Vietnamese letters

LEGACY_RULE_TEXT = {
    'Ignore firewall packet logs (filterlog)': {
        'description': ('pfSense/OPNsense g\u1eedi log t\u1eebng g\u00f3i tin \u2192 r\u1ea5t nhi\u1ec1u. T\u1eaft rule n\u00e0y n\u1ebfu mu\u1ed1n l\u01b0u l\u1ea1i.', 'pfSense/OPNsense send one log per packet, which creates high volume. Disable this rule if you want to retain them.'),
    },
    'Switch port down': {
        'description': ("Cisco %LINK-3-UPDOWN, HPE/Aruba 'port X is now off-line'. T\u1ef1 \u0111\u00f3ng khi c\u1ed5ng up l\u1ea1i.", 'Cisco %LINK-3-UPDOWN and HPE/Aruba port-offline messages. Automatically resolves when the interface comes back up.'),
    },
    'Port down (SNMP trap)': {
        'description': ('Trap linkDown/linkUp chu\u1ea9n t\u1eeb switch, router, firewall.', 'Standard linkDown/linkUp trap from switches, routers, and firewalls.'),
    },
    'Gateway WAN down (pfSense)': {
        'description': ('dpinger b\u00e1o m\u1ea5t WAN; t\u1ef1 \u0111\u00f3ng khi gateway available l\u1ea1i.', 'dpinger reports WAN loss; automatically resolves when the gateway becomes available again.'),
    },
    'Repeated failed sign-ins': {
        'description': ('UC-01 \u00b7 \u22655 l\u1ea7n trong 5 ph\u00fat t\u1eeb c\u00f9ng IP source \u2013 d\u00f2 m\u1eadt kh\u1ea9u. M\u1ed9t IP th\u1eed nhi\u1ec1u user ch\u1ec9 ra 1 c\u1ea3nh b\u00e1o, k\u00e8m danh s\u00e1ch user.', 'UC-01 \u00b7 Five or more failures within five minutes from the same source IP may indicate password spraying. One alert is grouped per source IP and includes the attempted usernames.'),
    },
    'IP-to-MAC address change (possible ARP spoofing)': {
        'description': ("UC-10 \u00b7 Firewall ghi khi m\u1ed9t IP chuy\u1ec3n sang MAC kh\u00e1c. Nh\u1eadp danh s\u00e1ch IP t\u0129nh quan tr\u1ecdng (gateway, server, DNS) v\u00e0o 'Ch\u1ec9 \u00e1p d\u1ee5ng cho kho\u00e1' r\u1ed3i b\u1eadt. IP c\u1ea5p qua DHCP th\u01b0\u1eddng \u0111\u1ed5i MAC h\u1ee3p l\u1ec7 n\u00ean kh\u00f4ng \u0111\u01b0a v\u00e0o.", 'UC-10 \u00b7 The firewall reports an IP-to-MAC change. Add important static IPs (gateway, server, DNS) to the key filter. DHCP-assigned IPs may legitimately change MAC addresses; do not include them.'),
    },
    'Windows: event log cleared': {
        'description': ("UC-07 \u00b7 1102 (xo\u00e1 log Security) v\u00e0 104 (xo\u00e1 log System/Application). C\u1ea7n b\u1eadt '\u0110\u1ecdc Windows Event' tr\u00ean check SSH.", 'UC-07 \u00b7 Event 1102 indicates that the Security log was cleared; Event 104 indicates that the System or Application log was cleared. Enable Windows Event Log collection in the SSH check.'),
    },
    'Windows: event logging service stopped unexpectedly': {
        'description': ('UC-08 \u00b7 1100 kh\u00f4ng c\u00f3 1074/6006 (t\u1eaft m\u00e1y c\u00f3 k\u1ebf ho\u1ea1ch) \u0111i k\u00e8m.', 'UC-08 \u00b7 Event 1100 occurred without a corresponding planned-shutdown event (1074 or 6006).'),
    },
    'Windows: added to administrators group': {
        'description': ('UC-04 \u00b7 Event 4728/4732/4756 v\u00e0o nh\u00f3m \u0111\u1eb7c quy\u1ec1n.', 'UC-04 \u00b7 Event 4728, 4732, or 4756 added a member to a privileged group.'),
    },
    'Windows: abnormal RecordId': {
        'pattern': ('RecordId (?:gi\u1ea3m|c\u00f3 kho\u1ea3ng tr\u1ed1ng).*Log=(?P<key>\\w+)', 'RecordId (?:decreased|has a gap).*Log=(?P<key>\\w+)'),
        'description': ('S\u1ed1 th\u1ee9 t\u1ef1 b\u1ea3n ghi gi\u1ea3m ho\u1eb7c b\u1ecb h\u1ee5t so v\u1edbi l\u1ea7n \u0111\u1ecdc tr\u01b0\u1edbc: log c\u00f3 th\u1ec3 \u0111\u00e3 b\u1ecb xo\u00e1 ho\u1eb7c b\u1ecb ghi \u0111\u00e8 v\u00f2ng.', 'Record ID decreased or skipped compared with the previous read; logs may have been cleared or overwritten.'),
    },
    'Incorrect SNMP community string': {
        'description': ('C\u00f3 m\u00e1y \u0111ang d\u00f2 SNMP v\u1edbi community sai.', 'A host is querying SNMP with an incorrect community string.'),
    },
    'Critical error (crit or higher)': {
        'description': ('M\u1ecdi log m\u1ee9c emerg/alert/crit ch\u01b0a kh\u1edbp rule n\u00e0o \u1edf tr\u00ean.', 'All logs at severity emerg/alert/crit that do not match any rule above.'),
    },
}


def seed_rules(db):
    """Migrate legacy built-in names, then seed missing defaults without duplicating rules.

    Existing legacy rows take precedence over duplicates created by earlier localization
    builds, preserving administrator-customized settings. User-created rules are untouched.
    """
    aliases_by_name = defaultdict(list)
    for legacy_name, canonical_name in LEGACY_RULE_NAMES.items():
        aliases_by_name[canonical_name].append(legacy_name)

    for canonical_name, legacy_names in aliases_by_name.items():
        legacy_rows = (db.query(models.EventRule)
                       .filter(models.EventRule.builtin.is_(True), models.EventRule.name.in_(legacy_names))
                       .order_by(models.EventRule.id)
                       .all())
        if not legacy_rows:
            continue

        canonical_rows = (db.query(models.EventRule)
                          .filter_by(builtin=True, name=canonical_name)
                          .order_by(models.EventRule.id)
                          .all())
        keeper = legacy_rows[0]
        legacy_ids = {r.id for r in legacy_rows}
        canonical_rows = [r for r in canonical_rows if r.id not in legacy_ids]   # same name in both languages → not a duplicate
        for duplicate in legacy_rows[1:] + canonical_rows:
            # Preserve historical event/alert references when collapsing duplicate IDs.
            db.query(models.Event).filter(models.Event.rule_id == duplicate.id).update(
                {models.Event.rule_id: keeper.id}, synchronize_session=False)
            linked_alerts = db.query(models.Alert).filter(models.Alert.event_rule_id == duplicate.id).all()
            for alert in linked_alerts:
                alert.event_rule_id = keeper.id
                old_prefix = f"rule:{duplicate.id}:"
                if alert.dedupe_key.startswith(old_prefix):
                    alert.dedupe_key = f"rule:{keeper.id}:" + alert.dedupe_key[len(old_prefix):]
            db.delete(duplicate)
        keeper.name = canonical_name

    db.flush()

    # Collapse any duplicate canonical built-ins left by previous startup runs.
    builtins = db.query(models.EventRule).filter_by(builtin=True).order_by(models.EventRule.id).all()
    have = {}
    for rule in builtins:
        if rule.name in have:
            db.delete(rule)
        else:
            have[rule.name] = rule

    for rule_data in DEFAULT_RULES:
        if rule_data["name"] not in have:
            rule = models.EventRule(builtin=True, **rule_data)
            db.add(rule)
            have[rule_data["name"]] = rule

    # Upgrade the failed-sign-in rule in place; retain its threshold and other settings.
    failed_signins = have.get("Repeated failed sign-ins")
    if failed_signins is not None:
        if not failed_signins.group_by:
            failed_signins.group_by = "src_ip"
        if failed_signins.alert_severity == "warning":
            failed_signins.alert_severity = "trouble"

    for rule in db.query(models.EventRule).filter(models.EventRule.builtin.is_(True),
                                                   models.EventRule.name.in_(list(LEGACY_RULE_TEXT))):
        for field, (old, new) in LEGACY_RULE_TEXT[rule.name].items():
            if getattr(rule, field) == old:
                setattr(rule, field, new)
    # Older releases (v1) stored other Vietnamese wordings of the built-in descriptions: reset those to the English default.
    default_desc = {r["name"]: r.get("description", "") for r in DEFAULT_RULES}
    for rule in db.query(models.EventRule).filter(models.EventRule.builtin.is_(True)):
        if rule.description and _VI_TEXT.search(rule.description) and rule.name in default_desc:
            rule.description = default_desc[rule.name]
    db.commit()
