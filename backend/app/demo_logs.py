"""Log thiết bị "như thật" cho DỮ LIỆU MẪU (DEMO_DATA=true) – để test tính năng mà không cần thiết bị.

* seed_history(): một lần khi tạo dữ liệu mẫu – dựng 24 giờ log/trap đã qua (có sự cố đã tự đóng và còn mở).
* live_loop():   khi app chạy – log thường vài giây/lần, cứ vài phút một sự cố rồi tự phục hồi.

Mọi log đi qua ĐÚNG đường xử lý của log thật (syslog_parser → quy tắc → mở/đóng cảnh báo → thông báo),
chỉ khác: lịch sử được gắn sẵn mốc thời gian (_at). Chỉ chạy khi DEMO_DATA=true; tắt bằng DEMO_LOGS=0.
Thiết bị lấy theo tên trong dữ liệu mẫu (seed.py); không có trong CSDL thì bỏ qua.
"""
import asyncio
import logging
import os
import random
from datetime import datetime, timedelta, timezone

from .db import SessionLocal
from . import models

log = logging.getLogger("itops.demo_logs")
_TZ = timezone(timedelta(hours=float(os.environ.get("APP_TZ_OFFSET", "7"))))
ATTACKERS = ["185.220.101.47", "45.155.205.233", "193.32.162.71", "92.63.197.153"]
USERS_TRIED = ["admin", "root", "administrator", "test", "support", "ubnt", "guest", "oracle"]
STAFF = ["ketoan01", "ketoan02", "sale.lan", "sale.minh", "hr.thu", "it.hung", "nv.tam", "giamdoc"]
STATIC_IPS = ["10.0.20.31", "10.0.20.10"]          # ERP-DB, DC01 – IP tĩnh quan trọng cho UC-10 (IP đổi MAC)
MACS = ["3c:22:fb:1a:90:4e", "a4:83:e7:52:10:bb", "f0:18:98:6e:21:0c", "dc:a6:32:11:9f:7a", "9c:b6:d0:0e:44:12"]


def enabled() -> bool:
    return os.environ.get("DEMO_DATA", "false").lower() in ("1", "true", "yes") and os.environ.get("DEMO_LOGS", "1") != "0"


# ---------------------------------------------------------------- dựng 1 dòng log
def _ts(at_utc: datetime) -> str:
    t = at_utc.replace(tzinfo=timezone.utc).astimezone(_TZ)
    return t.strftime("%b ") + f"{t.day:>2}" + t.strftime(" %H:%M:%S")


def _line(at, pri, host, app, msg):
    return f"<{pri}>{_ts(at)} {host} {app}: {msg}"


class Devices:
    """Tra IP/tên thiết bị mẫu theo tên (đọc từ CSDL)."""

    def __init__(self):
        with SessionLocal() as db:
            self.by_name = {a.name: (a.ip or "") for a in db.query(models.Asset) if a.ip}

    def ip(self, name):
        return self.by_name.get(name)


def _syslog(dev, at, name, pri, app, msg):
    from .receivers import syslog_event
    ip = dev.ip(name)
    if not ip:
        return None
    ev = syslog_event(_line(at, pri, name, app, msg), ip)
    ev["_at"] = at
    return ev


def _winlog(dev, at, name, event_id, extra, text, rec):
    ip = dev.ip(name)
    if not ip:
        return None
    return {"kind": "winlog", "source_ip": ip, "severity": 4, "facility": None, "host": name, "app": "WinEvent",
            "message": f"EventID={event_id} Log=Security Record={rec} {extra} | {text}", "device_ts": _ts(at),
            "data": {"event_id": event_id, "log": "Security"}, "_at": at}


def _trap(dev, at, name, oid, varbinds):
    from .receivers import trap_event
    ip = dev.ip(name)
    if not ip:
        return None
    ev = trap_event([("1.3.6.1.2.1.1.3.0", str(random.randint(10 ** 6, 10 ** 9))), ("1.3.6.1.6.3.1.1.4.1.0", oid)] + varbinds, ip)
    ev["_at"] = at
    return ev


# ---------------------------------------------------------------- log thường ngày
def noise(dev, at, rnd=random):
    """Một log "bình thường" ngẫu nhiên của một thiết bị mẫu."""
    u, mac = rnd.choice(STAFF), rnd.choice(MACS)
    lan = f"10.0.{rnd.choice([30, 31, 32])}.{rnd.randint(20, 220)}"
    k = rnd.randrange(22)
    if k == 0:
        return _syslog(dev, at, "pfSense-HQ", 30, f"openvpn[{rnd.randint(30000, 40000)}]", f"user '{u}' authenticated")
    if k == 1:
        return _syslog(dev, at, "pfSense-HQ", 30, f"dhcpd[{rnd.randint(70000, 80000)}]", f"DHCPACK on {lan} to {mac} ({u}-laptop) via igb1")
    if k == 2:
        return _syslog(dev, at, "pfSense-HQ", 134, "filterlog[61324]",
                       f"5,,,1000000103,igb0,match,block,in,4,0x0,,50,0,0,DF,6,tcp,60,{rnd.choice(ATTACKERS)},203.0.113.10,{rnd.randint(30000, 60000)},{rnd.choice([22, 23, 3389, 445])},0,S")
    if k == 3:
        return _syslog(dev, at, "pfSense-HQ", 30, f"charon[{rnd.randint(50000, 60000)}]",
                       "09[IKE] <con1000|7> IKE_SA con1000[7] established between 203.0.113.10[HQ]...198.51.100.20[HN]")
    if k == 4:
        return _syslog(dev, at, "pfSense-HN", 30, f"dhcpd[{rnd.randint(70000, 80000)}]", f"DHCPACK on 10.1.0.{rnd.randint(100, 200)} to {mac} via igb1")
    if k == 5:
        return _syslog(dev, at, "SW-TANG3", 189, "%SEC_LOGIN-5-LOGIN_SUCCESS", "Login Success [user: netadmin] [Source: 10.0.20.15] [localport: 22]")
    if k == 6:
        return _syslog(dev, at, "SW-TANG3", 189, "%DOT1X-5-SUCCESS", f"Authentication successful for client ({mac}) on Interface Gi1/0/{rnd.randint(1, 24)}")
    if k == 7:
        return _syslog(dev, at, "SW-CORE", 134, "mgmt", "User 'admin' logged in from 10.0.20.15 via SSH")
    if k == 8:
        return _syslog(dev, at, "SW-CORE", 134, "lldp", f"Neighbor {rnd.choice(['ESXi-01', 'ESXi-02', 'AP-Tang3', 'AP-Tang5'])} updated on port 1/1/{rnd.randint(1, 24)}")
    if k == 9:
        return _syslog(dev, at, "AP-Tang3", 134, "stm", f"Station {mac} associated to AP AP-Tang3 SSID CongTy rssi -{rnd.randint(45, 75)}")
    if k == 10:
        return _syslog(dev, at, "AP-Tang5", 134, "stm", f"Station {mac} deauthenticated from AP AP-Tang5 reason 3")
    if k == 11:
        return _syslog(dev, at, rnd.choice(["ESXi-01", "ESXi-02"]), 14, "Hostd",
                       f"info hostd[{rnd.randint(2000000, 2100000)}] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event {rnd.randint(1000, 9999)} : User vpxuser@127.0.0.1 logged in as VMware-client/6.5.0")
    if k == 12:
        return _syslog(dev, at, "ESXi-01", 14, "vmkernel", f"cpu{rnd.randint(0, 31)}:{rnd.randint(2000000, 2100000)})NetPort: 1632: disabled port 0x40000{rnd.randint(10, 99)}")
    if k == 13:
        return _syslog(dev, at, "PVE-01", 30, f"pvedaemon[{rnd.randint(1000, 9000)}]", "<root@pam> successful auth for user 'root@pam'")
    if k == 14:
        return _syslog(dev, at, "NAS-Synology", 14, "Connection", f"User [{rnd.choice(['admin', 'veeam', 'it.hung'])}] from [10.0.20.{rnd.choice([15, 50])}] signed in to [DSM] successfully via [password]")
    if k == 15:
        return _syslog(dev, at, "NAS-Synology", 14, "System", f"[SMB] User [{u}] accessed shared folder [{rnd.choice(['KeToan', 'KinhDoanh', 'NhanSu', 'Chung'])}]")
    if k == 16:
        return _syslog(dev, at, rnd.choice(["ERP-APP", "WEB-INTRANET", "MONITOR"]), 86, f"sshd[{rnd.randint(1000, 60000)}]",
                       f"Accepted publickey for deploy from 10.0.20.15 port {rnd.randint(40000, 65000)} ssh2: ED25519 SHA256:3Fq…")
    if k == 17:
        return _syslog(dev, at, rnd.choice(["ERP-APP", "WEB-INTRANET", "MONITOR"]), 78, f"CRON[{rnd.randint(1000, 60000)}]",
                       "(root) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)")
    if k == 18:
        return _syslog(dev, at, "WEB-INTRANET", 30, "nginx", f"{lan} - - \"GET /portal/ HTTP/1.1\" 200 {rnd.randint(2000, 90000)}")
    if k == 19:
        return _syslog(dev, at, "UPS-RACK", 14, "UPS", f"Self-test passed. Battery charge {rnd.randint(97, 100)}%, runtime {rnd.randint(28, 35)} min")
    if k == 20:
        return _syslog(dev, at, "SW-HN", 134, "SYSTEM", f"User admin login from 10.1.0.{rnd.randint(100, 200)} via web")
    return _syslog(dev, at, "Camera NVR", 14, "NVR", f"Channel {rnd.randint(1, 16)}: motion detected")


# ---------------------------------------------------------------- sự cố (mở → đóng)
# Mỗi sự cố: danh sách (giây so với lúc bắt đầu, hàm(dev, at) → sự kiện)
def incidents(rnd=random):
    port = f"GigabitEthernet1/0/{rnd.randint(2, 24)}"
    wan = rnd.choice(["WAN_FPT", "WAN_VIETTEL"])
    att = rnd.choice(ATTACKERS)
    vol = rnd.choice(["DS-SSD01", "DS-SAS02"])
    lan_ip, mac1, mac2 = rnd.choice(STATIC_IPS), "00:50:56:9a:3c:" + f"{rnd.randint(16, 255):02x}", rnd.choice(MACS)   # IP tĩnh bị máy lạ nhận
    p_core = rnd.randint(1, 24)
    return {
        "port_flap": [
            (0, lambda d, t: _syslog(d, t, "SW-TANG3", 187, "%LINK-3-UPDOWN", f"Interface {port}, changed state to down")),
            (1, lambda d, t: _syslog(d, t, "SW-TANG3", 189, "%LINEPROTO-5-UPDOWN", f"Line protocol on Interface {port}, changed state to down")),
            (rnd.randint(90, 420), lambda d, t: _syslog(d, t, "SW-TANG3", 187, "%LINK-3-UPDOWN", f"Interface {port}, changed state to up")),
        ],
        "wan_down": [
            (0, lambda d, t: _syslog(d, t, "pfSense-HQ", 29, "dpinger[4321]", f"MONITOR: {wan} is down, omitting from routing group")),
            (5, lambda d, t: _syslog(d, t, "pfSense-HQ", 29, "rc.gateway_alarm[61744]", f">>> Gateway alarm: {wan} (Addr:1.1.1.1 Alarm:1 RTT:0ms RTTsd:0ms Loss:100%)")),
            (rnd.randint(120, 600), lambda d, t: _syslog(d, t, "pfSense-HQ", 29, "dpinger[4321]", f"MONITOR: {wan} is available now, adding to routing group")),
        ],
        "brute_force": [(i * rnd.randint(4, 9), (lambda u: lambda d, t: _syslog(
            d, t, "pfSense-HQ", 36, "php-fpm[33612]", f"/index.php: webConfigurator authentication error for user '{u}' from: {att}")) (rnd.choice(USERS_TRIED)))
            for i in range(rnd.randint(6, 12))],
        "datastore_apd": [
            (0, lambda d, t: _syslog(d, t, "ESXi-02", 11, "vobd", f"[vob.storage.apd.start] Device or filesystem with identifier [naa.6000c29{vol.lower()}] has entered the All Paths Down state.")),
            (2, lambda d, t: _syslog(d, t, "ESXi-02", 11, "Hostd", f"error hostd[2099578] Lost access to volume 5f3a1c22-{vol} ({vol}) due to connectivity issues.")),
            (rnd.randint(180, 900), lambda d, t: _syslog(d, t, "ESXi-02", 14, "Hostd", f"info hostd[2099578] Successfully restored access to volume 5f3a1c22-{vol} ({vol}) following connectivity issues.")),
        ],
        "ups_battery": [
            (0, lambda d, t: _syslog(d, t, "UPS-RACK", 10, "UPS", "On battery power in response to an input power problem.")),
            (0, lambda d, t: _trap(d, t, "UPS-RACK", "1.3.6.1.4.1.318.0.5", [])),
            (rnd.randint(40, 240), lambda d, t: _syslog(d, t, "UPS-RACK", 14, "UPS", "Returned from battery backup power.")),
            (rnd.randint(240, 260), lambda d, t: _trap(d, t, "UPS-RACK", "1.3.6.1.4.1.318.0.9", [])),
        ],
        "core_link_trap": [
            (0, lambda d, t: _trap(d, t, "SW-CORE", "1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1", str(p_core)), ("1.3.6.1.2.1.31.1.1.1.1", f"1/1/{p_core}"),
                                                                            ("1.3.6.1.2.1.2.2.1.8", "2")])),
            (rnd.randint(60, 300), lambda d, t: _trap(d, t, "SW-CORE", "1.3.6.1.6.3.1.1.5.4", [("1.3.6.1.2.1.2.2.1.1", str(p_core)),
                                                                                             ("1.3.6.1.2.1.31.1.1.1.1", f"1/1/{p_core}"), ("1.3.6.1.2.1.2.2.1.8", "1")])),
        ],
        "arp_moved": [(0, lambda d, t: _syslog(d, t, "pfSense-HQ", 4, "kernel", f"arp: {lan_ip} moved from {mac1} to {mac2} on igb1"))],
        "ap_reboot": [(0, lambda d, t: _trap(d, t, "AP-HN", "1.3.6.1.6.3.1.1.5.1", []))],
    }


# Sự cố kèm theo trong lịch sử 24h: (giờ trước "bây giờ", tên, có phục hồi không)
HISTORY_PLAN = [
    (22.6, "wan_down", True), (19.3, "port_flap", True), (17.8, "ups_battery", True), (15.1, "brute_force", True),
    (13.4, "core_link_trap", True), (11.2, "datastore_apd", True), (9.7, "port_flap", True), (8.2, "ap_reboot", True),
    (6.5, "arp_moved", True), (4.9, "wan_down", True), (3.1, "port_flap", False), (0.25, "brute_force", True),
]
# sự cố riêng (không phục hồi) để luôn có cảnh báo đang mở đúng kiểu thực tế
OPEN_ISSUES = [
    (6.0, lambda d, t: _syslog(d, t, "NAS-HN", 10, "System", "Storage Pool 1 has degraded. Please repair it as soon as possible.")),
    (6.0, lambda d, t: _syslog(d, t, "NAS-HN", 12, "kernel", "md2: Disk 3 [sdc] has been marked as failing (bad sectors: 128)")),
    (2.2, lambda d, t: _winlog(d, t, "DC01", 4732, "member=CONGTY\\nv.tam; group=Administrators; by=CONGTY\\it.hung",
                               "A member was added to a security-enabled local group.", 884213)),
    (1.4, lambda d, t: _winlog(d, t, "FILE-SRV", 4720, "target=svc_scan; by=CONGTY\\it.hung", "A user account was created.", 120994)),
]


def _expand_incident(name, start, rnd, resolve=True):
    steps = incidents(rnd)[name]
    if not resolve:
        steps = [s for s in steps if s[0] < 60] or steps[:1]   # chỉ phần "đang lỗi"
    return [(start + timedelta(seconds=sec), fn) for sec, fn in steps]


def _demo_rule_setup():
    """Dữ liệu mẫu: bật rule UC-10 với danh sách IP tĩnh quan trọng (mặc định rule này tắt, cần admin khai IP)."""
    with SessionLocal() as db:
        r = db.query(models.EventRule).filter(models.EventRule.name.like("IP đổi MAC%")).first()
        if r and not r.key_filter:
            r.enabled, r.key_filter = True, "10.0.0.1, 10.0.20.10, 10.0.20.11, 10.0.20.31"
            db.commit()


def seed_history(hours: int = 24, per_hour: int = 160, seed: int = 20261108) -> dict:
    """Dựng lịch sử log cho dữ liệu mẫu, xử lý qua pipeline thật (không gửi thông báo)."""
    from . import events
    _demo_rule_setup()
    rnd = random.Random(seed)
    dev = Devices()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start = now - timedelta(hours=hours)
    plan = []
    t = start
    while t < now:
        busy = 1.6 if 8 <= t.replace(tzinfo=timezone.utc).astimezone(_TZ).hour < 18 else 0.5   # giờ hành chính nhiều log hơn
        t += timedelta(seconds=rnd.expovariate(per_hour * busy / 3600))
        plan.append((t, lambda d, at: noise(d, at, rnd)))
    for h, name, resolve in HISTORY_PLAN:
        if h <= hours:
            plan += _expand_incident(name, now - timedelta(hours=h), rnd, resolve)
    for h, fn in OPEN_ISSUES:
        if h <= hours:
            plan.append((now - timedelta(hours=h), fn))
    plan = [(at, fn) for at, fn in plan if at <= now]
    plan.sort(key=lambda x: x[0])
    evs = [e for e in (fn(dev, at) for at, fn in plan) if e]
    for i in range(0, len(evs), 500):
        events.process_batch(evs[i:i + 500])
    events.invalidate_caches()
    _auto_resolve_history(now)
    with SessionLocal() as db:
        out = {"events": db.query(models.Event).count(),
               "alerts_open": db.query(models.Alert).filter(models.Alert.source == "event", models.Alert.status != "resolved").count(),
               "alerts_resolved": db.query(models.Alert).filter(models.Alert.source == "event", models.Alert.status == "resolved").count()}
    log.warning("Dữ liệu mẫu: đã dựng %d giờ log (%d sự kiện, %d cảnh báo đang mở, %d đã tự đóng)",
                hours, out["events"], out["alerts_open"], out["alerts_resolved"])
    return out


def _auto_resolve_history(now):
    """Rule có "tự đóng sau N phút không lặp lại": đóng đúng mốc last_seen + N trong quá khứ
    (giống như app đã chạy suốt 24 giờ), thay vì để housekeeping đóng tất cả vào lúc khởi động."""
    with SessionLocal() as db:
        rules = {r.id: r for r in db.query(models.EventRule)}
        for a in db.query(models.Alert).filter(models.Alert.source == "event", models.Alert.status != "resolved"):
            r = rules.get(a.event_rule_id)
            if r and r.auto_resolve_min and a.last_seen and a.last_seen + timedelta(minutes=r.auto_resolve_min) < now:
                a.status, a.resolved_at = "resolved", a.last_seen + timedelta(minutes=r.auto_resolve_min)
                a.message = f"{a.message} · tự đóng sau {r.auto_resolve_min} phút không lặp lại"[:2000]
        db.commit()


async def live_loop(min_gap: float = 8.0, max_gap: float = 25.0, incident_every=None):
    """Log trực tiếp: đưa vào hàng đợi chung như log nhận qua mạng → rule → cảnh báo → thông báo.
    DEMO_INCIDENT_EVERY="240,720" = mỗi 4–12 phút một sự cố (giây, có thể đổi cho dày/thưa hơn)."""
    from . import events
    if incident_every is None:
        try:
            lo, hi = (float(x) for x in os.environ.get("DEMO_INCIDENT_EVERY", "240,720").split(","))
        except ValueError:
            lo, hi = 240, 720
        incident_every = (min(lo, hi), max(lo, hi))
    rnd = random.Random()
    await asyncio.sleep(5)
    dev = Devices()
    next_incident = asyncio.get_running_loop().time() + rnd.uniform(incident_every[0] / 4, incident_every[0])
    names = ["port_flap", "wan_down", "brute_force", "datastore_apd", "ups_battery", "core_link_trap", "arp_moved", "ap_reboot"]
    weights = [5, 2, 4, 1, 1, 3, 1, 1]

    async def run_incident(name):
        base = datetime.now(timezone.utc).replace(tzinfo=None)
        steps = sorted(_expand_incident(name, base, rnd), key=lambda x: x[0])
        for at, fn in steps:
            delay = (at - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()
            if delay > 0:
                await asyncio.sleep(delay)
            ev = fn(dev, datetime.now(timezone.utc).replace(tzinfo=None))
            if ev:
                ev.pop("_at", None)          # log trực tiếp: thời gian = lúc nhận, như log thật
                events.submit(ev)

    while True:
        try:
            for _ in range(rnd.choice([1, 1, 1, 2, 3])):
                ev = noise(dev, datetime.now(timezone.utc).replace(tzinfo=None), rnd)
                if ev:
                    ev.pop("_at", None)
                    events.submit(ev)
            loop_t = asyncio.get_running_loop().time()
            if loop_t >= next_incident:
                name = rnd.choices(names, weights)[0]
                log.info("Dữ liệu mẫu: bắt đầu sự cố %s", name)
                asyncio.create_task(run_incident(name))
                next_incident = loop_t + rnd.uniform(*incident_every)
        except Exception:
            log.exception("bộ phát log mẫu lỗi")
        await asyncio.sleep(rnd.uniform(min_gap, max_gap))
