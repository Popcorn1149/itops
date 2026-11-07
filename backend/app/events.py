"""Xử lý log/trap nhận về: gắn tài sản theo IP, chống flood, ghi theo lô, áp rule → cảnh báo."""
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
RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", "90"))   # Cài đặt › Giám sát an ninh có thể đổi
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
# Tách user đã thử từ log đăng nhập sai: pfSense "for user 'x'", OpenSSH "for [invalid user] x", Synology "User [x]",
# PAM "user=x" (bỏ qua "ruser="), Cisco "[user: x]"
USER_RE = re.compile(r"(?:invalid user |(?<![a-z])user[ =:\[]+'?|for (?:invalid user |user '?)?|account[ =:]+'?|login[ =:]+'?)([\w.@\\-]{1,64})", re.I)


def get_queue() -> asyncio.Queue:
    global queue
    if queue is None:
        queue = asyncio.Queue(maxsize=QUEUE_MAX)
    return queue


def set_allowed(cidrs: list[str]):
    """Danh sách IP/subnet được phép gửi log/trap. Rỗng = nhận tất cả."""
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
    """Gọi từ receiver (đang ở event loop). Không chặn: ngoài danh sách IP/quá tốc độ/hết chỗ thì bỏ và đếm."""
    STATS["received"] += 1
    src = ev.get("source_ip", "")
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
        """Trả (True, key) nếu khớp điều kiện mở; dùng nhóm (?P<key>) hoặc nhóm đầu tiên làm khoá gom."""
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
        if self.group_by == "src_ip":   # gộp theo IP source ghi trong log (vd. IP đang dò mật khẩu), không theo user
            ips = [x for x in IPV4.findall(ev["message"]) if x != ev["source_ip"]]
            key = ips[0] if ips else (key or "?")
        if self.key_filter and (key or "").lower() not in self.key_filter:
            return False, ""   # chỉ áp dụng cho danh sách khoá đã khai báo (vd. IP tĩnh quan trọng)
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
        log.warning("regex lỗi: %s", p)
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
    """Phân tích gói UDP thô (có thể chứa nhiều dòng) thành sự kiện."""
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
    """Ghi lô sự kiện + áp rule. Trả danh sách thông báo cần gửi. Chạy đồng bộ (gọi trong thread)."""
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
            for r in rules:  # sự kiện phục hồi (linkUp, "changed state to up", ...)
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
        log.exception("ghi sự kiện lỗi")
    finally:
        db.close()
    return notes


def _when(ev):
    """Mốc thời gian của sự kiện. Log thật luôn là "bây giờ"; chỉ bộ phát log mẫu (demo_logs) gắn sẵn _at để dựng lịch sử."""
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
    if r.group_by == "src_ip":   # ghi lại user đã thử ngay từ lần đầu (kể cả trước khi đủ threshold)
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
            users = "\nUser đã thử: " + ", ".join(sorted(tried)[:20]) + (f" (+{len(tried) - 20})" if len(tried) > 20 else "")
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
    db.flush()  # để log kế tiếp trong cùng lô thấy cảnh báo này (session autoflush=False)
    return [(title, f"Nguồn: {who} ({ev['source_ip']})\n{ev['message'][:500]}", r.alert_severity,
             {"kind": "open", "alert_id": na.id, "asset_id": na.asset_id, "site_id": na.site_id})]


def _resolve(db, r: CompiledRule, ev, key) -> list:
    subject = ev["asset_id"] or ev["source_ip"]
    dkey = f"rule:{r.id}:{subject}:{key}"
    out = []
    for a in db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved"):
        a.status, a.resolved_at = "resolved", _when(ev)
        a.message = f"{a.message} · phục hồi: {ev['message'][:200]}"[:2000]
        out.append((f"{a.title} – đã phục hồi", ev["message"][:300], "resolved",
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
                log.exception("notify lỗi")


async def housekeeping():
    """Tự đóng cảnh báo log đã im lặng; xoá log quá hạn / quá số lượng."""
    last_purge = 0
    while True:
        try:
            await asyncio.to_thread(_housekeep, time.time() - last_purge > 3600)
            if time.time() - last_purge > 3600:
                last_purge = time.time()
        except Exception:
            log.exception("housekeeping lỗi")
        await asyncio.sleep(60)


def _housekeep(purge: bool):
    db = SessionLocal()
    try:
        rules = {r.id: r for r in db.query(models.EventRule).all()}
        for a in db.query(models.Alert).filter(models.Alert.source == "event", models.Alert.status != "resolved"):
            r = rules.get(a.event_rule_id)
            if r and r.auto_resolve_min and a.last_seen and now() - a.last_seen > timedelta(minutes=r.auto_resolve_min):
                a.status, a.resolved_at = "resolved", now()
                a.message = f"{a.message} · tự đóng sau {r.auto_resolve_min} phút không lặp lại"[:2000]
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
    dict(sort=10, name="Bỏ qua log gói tin firewall (filterlog)", action="drop", kind="syslog", app_pattern=r"^filterlog$",
         description="pfSense/OPNsense gửi log từng gói tin → rất nhiều. Tắt rule này nếu muốn lưu lại."),
    dict(sort=20, name="Cổng switch down", kind="syslog", pattern=IF_KEY + r"(?:changed state to down|is now off-line|link down)",
         resolve_pattern=IF_KEY + r"(?:changed state to up|is now on-line|link up)", alert_severity="warning",
         description="Cisco %LINK-3-UPDOWN, HPE/Aruba 'port X is now off-line'. Tự đóng khi cổng up lại."),
    dict(sort=21, name="Cổng down (SNMP trap)", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.3", resolve_trap_oids="1.3.6.1.6.3.1.1.5.4",
         alert_severity="warning", description="Trap linkDown/linkUp chuẩn từ switch, router, firewall."),
    dict(sort=30, name="Gateway WAN down (pfSense)", kind="syslog", pattern=r"MONITOR: (?P<key>\S+) is down",
         resolve_pattern=r"MONITOR: (?P<key>\S+) is available now", alert_severity="critical",
         description="dpinger báo mất WAN; tự đóng khi gateway available lại."),
    dict(sort=40, name="Mất kết nối datastore (ESXi)", kind="syslog",
         pattern=r"(?:Lost access to volume|All Paths Down|permanently inaccessible|\bAPD\b)",
         resolve_pattern=r"(?:Successfully restored access to volume|exited the All Paths Down)", alert_severity="critical"),
    dict(sort=50, name="Ổ cứng / RAID lỗi", kind="syslog",
         pattern=r"(?:(?:volume|disk|drive|raid|array|storage pool)\s*[\w/#.\-]*\s*(?:is |has |was )?(?:been )?(?:degraded|crashed|failed|failing)\b|bad sectors?\b)", alert_severity="critical",
         auto_resolve_min=0, description="Synology, QNAP, iLO/iDRAC, mdadm…"),
    dict(sort=60, name="UPS chuyển sang chạy pin", kind="any",
         pattern=r"(?:on battery|switched to battery|power failure|utility power fail)",
         resolve_pattern=r"(?:power (?:restored|returned)|returned from battery|utility power restored|on line)",
         trap_oids="", alert_severity="critical"),
    dict(sort=61, name="UPS chạy pin (SNMP trap)", kind="trap", trap_oids="1.3.6.1.2.1.33.2.0.1,1.3.6.1.4.1.318.0.5",
         resolve_trap_oids="1.3.6.1.4.1.318.0.9", alert_severity="critical", auto_resolve_min=120),
    dict(sort=70, name="Đăng nhập sai liên tục", kind="syslog",
         pattern=r"(?:Failed password|authentication (?:error|failure)|Authentication failed|login failed|Invalid user|bad password)",
         threshold=5, window_min=5, auto_resolve_min=30, alert_severity="trouble", group_by="src_ip",
         description="UC-01 · ≥5 lần trong 5 phút từ cùng IP source – dò mật khẩu. Một IP thử nhiều user chỉ ra 1 cảnh báo, kèm danh sách user."),
    dict(sort=72, name="IP đổi MAC (nghi giả mạo ARP)", kind="syslog", enabled=False, pattern=r"arp: (?P<key>\d+\.\d+\.\d+\.\d+) moved from",
         alert_severity="attention", auto_resolve_min=60,
         description="UC-10 · Firewall ghi khi một IP chuyển sang MAC khác. Nhập danh sách IP tĩnh quan trọng (gateway, server, DNS) "
                     "vào 'Chỉ áp dụng cho khoá' rồi bật. IP cấp qua DHCP thường đổi MAC hợp lệ nên không đưa vào."),
    dict(sort=74, name="Windows: xóa event log", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=(?:1102|104)\b.*?Log=(?P<key>\w+)", alert_severity="critical",
         description="UC-07 · 1102 (xoá log Security) và 104 (xoá log System/Application). Cần bật 'Đọc Windows Event' trên check SSH."),
    dict(sort=75, name="Windows: dịch vụ log dừng ngoài kế hoạch", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=1100\b.*planned=0", alert_severity="critical",
         description="UC-08 · 1100 không có 1074/6006 (tắt máy có kế hoạch) đi kèm."),
    dict(sort=76, name="Windows: tạo tài khoản", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=4720\b.*target=(?P<key>[^;|]+)", alert_severity="critical", description="UC-04 · Event 4720."),
    dict(sort=77, name="Windows: thêm vào admin group", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"EventID=(?:4728|4732|4756)\b.*group=(?P<key>(?:Administrators|Domain Admins|Enterprise Admins|Schema Admins|Remote Desktop Users)[^;|]*)",
         alert_severity="critical", description="UC-04 · Event 4728/4732/4756 vào nhóm đặc quyền."),
    dict(sort=78, name="Windows: RecordId bất thường", kind="any", app_pattern=r"^WinEvent$",
         pattern=r"RecordId (?:giảm|có khoảng trống).*Log=(?P<key>\w+)", alert_severity="trouble",
         description="Số thứ tự bản ghi giảm hoặc bị hụt so với lần đọc trước: log có thể đã bị xoá hoặc bị ghi đè vòng."),
    dict(sort=80, name="Thiết bị khởi động lại", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.1,1.3.6.1.6.3.1.1.5.2",
         auto_resolve_min=30, alert_severity="warning"),
    dict(sort=81, name="Sai community SNMP", kind="trap", trap_oids="1.3.6.1.6.3.1.1.5.5", auto_resolve_min=60, alert_severity="warning",
         description="Có máy đang dò SNMP với community sai."),
    dict(sort=90, name="Lỗi nghiêm trọng (crit trở lên)", kind="syslog", max_severity=2, auto_resolve_min=60, alert_severity="critical",
         description="Mọi log mức emerg/alert/crit chưa khớp rule nào ở trên."),
]


def seed_rules(db):
    """Thêm rule mặc định còn thiếu (theo tên) – không đè rule người dùng đã sửa."""
    renames = {"Windows: xoá nhật ký sự kiện": "Windows: xóa event log", "Windows: thêm vào nhóm quản trị": "Windows: thêm vào admin group"}
    for old, new in renames.items():   # đổi tên theo thuật ngữ chuẩn (rule, log, admin group…)
        r0 = db.query(models.EventRule).filter_by(builtin=True, name=old).first()
        if r0 and not db.query(models.EventRule).filter_by(name=new).first():
            r0.name = new
    db.flush()
    have = {r.name: r for r in db.query(models.EventRule).filter_by(builtin=True)}
    for r in DEFAULT_RULES:
        if r["name"] not in have:
            db.add(models.EventRule(builtin=True, **r))
    lr = have.get("Đăng nhập sai liên tục")   # nâng cấp: gộp theo IP source (C11)
    if lr is not None and not lr.group_by:
        lr.group_by = "src_ip"
        if lr.alert_severity == "warning":
            lr.alert_severity = "trouble"
    db.commit()
