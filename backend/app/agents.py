"""Workstation agent module (ADR 0004).

Two API groups:
- /api/agent/v1/*  – called by agents. Authenticated with a per-machine key (header `Authorization: Agent <id>.<key>`); does NOT use
  user cookies/sessions. Agents only send data; the server has no API for issuing commands to workstations.
- /api/agents/*    – administration UI (signed in like other pages; changes require admin privileges)."""
import asyncio
import gzip
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from . import agent_catalog as cat
from . import inventory
from . import models
from .db import DATA_DIR, SessionLocal, get_db
from .security import admin_user, client_ip, current_user

log = logging.getLogger("itops.agents")
router = APIRouter()
PROTOCOL = 1
MAX_BODY = 8 * 1024 * 1024            # nén
MAX_INFLATED = 32 * 1024 * 1024       # sau giải nén – chặn "bom zip"
UPDATE_DIR = Path(DATA_DIR) / "agent-updates"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ================================================================ chính sách (Cài đặt → Máy trạm)
DEFAULTS = {
    "report_seconds": 60,            # gửi performance + sự kiện mới
    "services_minutes": 30,          # danh sách service
    "software_hours": 6,             # phần mềm đã cài
    "defender_minutes": 15,
    "backfill_hours": 24,            # lần chạy đầu: lấy events in N hours trước
    "offline_minutes": 10,           # machines có enabled "alerts mất kết nối" im lặng quá N minutes → alerts
    "disk_warn": 90, "disk_crit": 95,
    "av_signature_days": 3,          # mẫu nhận diện virus cũ hơn N days → alerts
    "group_minutes": 10,             # sự kiện giống nhau trong N minutes gộp thành 1 dòng (×số lần)
    "event_alert_quiet_hours": 24,   # alerts from sự kiện auto-resolved after N hours did not recur
    "retention": {"metrics_days": 30, "events_days": 90},
    "disabled_keys": [],             # disabled bớt loại sự kiện (catalog key)
    "update": {"enabled": False, "check_hours": 6},
}


def get_policy(db) -> dict:
    s = db.get(models.Setting, "agents")
    v = json.loads(json.dumps(DEFAULTS))
    for k, x in ((s.value if s else {}) or {}).items():
        if isinstance(x, dict) and isinstance(v.get(k), dict):
            v[k].update(x)
        elif k in v:
            v[k] = x
    return v


def save_policy(db, body: dict) -> dict:
    v = get_policy(db)
    for k in ("report_seconds", "services_minutes", "software_hours", "defender_minutes", "backfill_hours",
              "offline_minutes", "disk_warn", "disk_crit", "av_signature_days", "group_minutes", "event_alert_quiet_hours"):
        if k in body:
            v[k] = int(body[k])
    v["report_seconds"] = min(3600, max(30, v["report_seconds"]))
    v["backfill_hours"] = min(168, max(0, v["backfill_hours"]))
    v["disk_crit"] = max(v["disk_warn"], v["disk_crit"])
    for k in ("retention", "update"):
        if isinstance(body.get(k), dict):
            v[k].update(body[k])
    if isinstance(body.get("disabled_keys"), list):
        known = {c["key"] for c in cat.catalog_rows()}
        v["disabled_keys"] = [k for k in body["disabled_keys"] if k in known]
    s = db.get(models.Setting, "agents") or models.Setting(key="agents", value={})
    s.value = v
    db.merge(s)
    return v


def agent_config(pol: dict, os_family: str) -> dict:
    """Cấu hình gửi xuống agent – chỉ là tham số thu thập, không phải lệnh."""
    dis = set(pol["disabled_keys"])
    cfg = {"protocol": PROTOCOL, "report_seconds": pol["report_seconds"], "services_minutes": pol["services_minutes"],
           "software_hours": pol["software_hours"], "defender_minutes": pol["defender_minutes"],
           "backfill_hours": pol["backfill_hours"], "max_events_per_report": 500,
           "update": {"enabled": bool(pol["update"].get("enabled")), "check_hours": int(pol["update"].get("check_hours") or 6)}}
    if os_family == "windows":
        by = {}
        for c in cat.WINDOWS:
            if c["key"] not in dis:
                by.setdefault(c["channel"], set()).update(c["ids"])
        cfg["windows_events"] = [{"channel": ch, "ids": sorted(ids)} for ch, ids in sorted(by.items())]
    else:
        cfg["unix_events"] = sorted(c["kind"] for c in cat.UNIX if c["key"] not in dis)
    cfg["version"] = sha256(json.dumps(cfg, sort_keys=True))[:16]
    return cfg


# ================================================================ dữ liệu agent gửi lên (kiểm tra chặt)
class SystemInfo(BaseModel):
    hostname: str = Field("", max_length=255)
    domain: str = Field("", max_length=255)
    os_name: str = Field("", max_length=255)
    os_version: str = Field("", max_length=128)
    os_kind: str = Field("", max_length=16)
    arch: str = Field("", max_length=16)
    manufacturer: str = Field("", max_length=128)
    model: str = Field("", max_length=128)
    serial: str = Field("", max_length=128)
    cpu_model: str = Field("", max_length=255)
    cpu_cores: int = Field(0, ge=0, le=4096)
    ram_mb: int = Field(0, ge=0)
    boot_time: datetime | None = None
    ips: list[str] = Field(default_factory=list, max_length=64)
    logged_user: str = Field("", max_length=128)
    user_source: str = Field("", max_length=16)          # console | rdp (agent ≥ 1.0.2)
    machine_id: str = Field("", max_length=64)           # MachineGuid / /etc/machine-id (agent ≥ 1.0.2)
    macs: list[str] = Field(default_factory=list, max_length=64)   # MAC card mạng có IP (agent ≥ 1.0.4)

    @field_validator("macs")
    @classmethod
    def _norm_macs(cls, v):
        return normalize_macs(v)


_MAC_RE = re.compile(r"^[0-9A-F]{12}$")


def normalize_macs(v) -> list[str]:
    """'aa-bb-cc-dd-ee-ff' / 'aabb.ccdd.eeff' → 'AA:BB:CC:DD:EE:FF'; bỏ giá trị rác, trùng, 00:00:…; tối đa 16."""
    out = []
    for m in v or []:
        h = re.sub(r"[^0-9A-Fa-f]", "", str(m)).upper()
        if _MAC_RE.match(h) and h != "0" * 12:
            mac = ":".join(h[i:i + 2] for i in range(0, 12, 2))
            if mac not in out:
                out.append(mac)
    return out[:16]


class Disk(BaseModel):
    mount: str = Field(max_length=255)
    fs: str = Field("", max_length=32)
    total_gb: float = 0
    used_pct: float = Field(0, ge=0, le=100)


class Metrics(BaseModel):
    cpu: float | None = Field(None, ge=0, le=100)
    mem: float | None = Field(None, ge=0, le=100)
    disks: list[Disk] = Field(default_factory=list, max_length=64)
    uptime_s: int | None = None


class Service(BaseModel):
    name: str = Field(max_length=255)
    display: str = Field("", max_length=255)
    state: str = Field("", max_length=32)
    start: str = Field("", max_length=32)


class Software(BaseModel):
    name: str = Field(max_length=255)
    version: str = Field("", max_length=128)
    publisher: str = Field("", max_length=255)
    installed_on: str = Field("", max_length=32)
    source: str = Field("", max_length=32)
    source_pkg: str = Field("", max_length=255)          # gói nguồn Linux (agent ≥ 1.0.2)


class AgentEventIn(BaseModel):
    channel: str = Field("", max_length=128)
    provider: str = Field("", max_length=255)
    event_id: int = 0
    kind: str = Field("", max_length=32)               # Linux/macOS: loại agent received diện
    level: str = Field("", max_length=16)
    record_id: int = 0
    ts: datetime
    data: dict = Field(default_factory=dict)
    message: str = Field("", max_length=8000)


class Report(BaseModel):
    seq: int = 0
    agent_version: str = Field("", max_length=32)
    system: SystemInfo | None = None
    metrics: Metrics | None = None
    defender: dict | None = None
    services: list[Service] | None = Field(None, max_length=5000)
    software: list[Software] | None = Field(None, max_length=10000)
    updates: dict | None = None
    posture: dict | None = None                       # tường lửa, BitLocker/FileVault, Gatekeeper...
    events: list[AgentEventIn] | None = Field(default_factory=list, max_length=2000)


class Enroll(BaseModel):
    """Open enrollment (like Wazuh): only the server address is needed. Each machine gets its own key afterwards;
    an agent that matches an EXISTING machine (same hostname + machine-id/serial) still needs IT approval."""
    uid: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    os_family: str = Field(pattern=r"^(windows|linux|darwin)$")
    agent_version: str = Field("", max_length=32)
    system: SystemInfo
    site: str = Field("", max_length=128)        # tên site (tuỳ chọn, --site lúc cài) → gắn máy vào site có tên này
    tags: str = Field("", max_length=255)        # nhãn (tuỳ chọn, --tags lúc cài)


# ================================================================ xác thực agent + giới hạn tần suất
_rate: dict = defaultdict(deque)
_enroll_fail: dict = defaultdict(deque)
_enroll_new: dict = defaultdict(deque)       # máy MỚI đăng ký thành công theo IP nguồn (đăng ký mở → chặn tạo hàng loạt máy giả)
ENROLL_NEW_PER_IP = max(1, int(os.environ.get("AGENT_ENROLL_NEW_PER_IP", "60")))   # mỗi IP tối đa N máy mới / 10 phút (NAT, VPN)


def _limited(store, key, n, per_s, record=True) -> bool:
    q, t = store[key], time.monotonic()
    while q and t - q[0] > per_s:
        q.popleft()
    if len(q) >= n:
        return True
    if record:
        q.append(t)
    return False


def _agent_from_request(request: Request, db: Session) -> models.Agent:
    h = request.headers.get("authorization", "")
    m = re.fullmatch(r"Agent (\d{1,10})\.([A-Za-z0-9_-]{20,128})", h.strip())
    if not m:
        raise HTTPException(401, "Missing agent key")
    a = db.get(models.Agent, int(m.group(1)))
    if not a or not hmac.compare_digest(a.key_hash, sha256(m.group(2))):
        raise HTTPException(401, "Invalid agent key")
    if a.revoked_at:
        raise HTTPException(401, "revoked")          # agent thấy chữ này thì ngừng gửi
    if _limited(_rate, a.id, 30, 60):
        raise HTTPException(429, "Rate limit exceeded")
    return a


async def _read_json(request: Request) -> dict:
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        raise HTTPException(413, "Payload is too large")
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(413, "Payload is too large")
    if request.headers.get("content-encoding", "").lower() == "gzip":
        d = gzip.GzipFile(fileobj=__import__("io").BytesIO(raw))
        raw = d.read(MAX_INFLATED + 1)
        if len(raw) > MAX_INFLATED:
            raise HTTPException(413, "Decompressed payload is too large")
    try:
        return json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Invalid JSON") from None


def _parse(model, data):
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise HTTPException(422, f"Invalid agent payload: {e.errors()[0].get('loc')} {e.errors()[0].get('msg')}") from None


# ================================================================ alerts
def _open(db, a: models.Agent, dkey: str, severity: str, title: str, message: str, when=None) -> list:
    when = when or utcnow()
    ex = db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved").first()
    if ex:
        ex.count = (ex.count or 1) + 1
        ex.last_seen = when
        ex.message = message[:2000]
        if ex.severity != severity and severity in ("critical", "down"):
            ex.severity = severity
        return []
    al = models.Alert(source="agent", dedupe_key=dkey[:255], asset_id=a.asset_id, site_id=a.site_id, severity=severity,
                      title=title[:255], message=message[:2000], opened_at=when, last_seen=when, count=1)
    db.add(al)
    db.flush()
    return [(title, message[:600], severity, {"kind": "open", "alert_id": al.id, "asset_id": a.asset_id, "site_id": a.site_id})]


def _resolve(db, dkey: str, why: str) -> list:
    out = []
    for al in db.query(models.Alert).filter(models.Alert.dedupe_key == dkey, models.Alert.status != "resolved"):
        al.status, al.resolved_at = "resolved", utcnow()
        al.message = f"{al.message} · {why}"[:2000]
        out.append((f"{al.title} – has expired", why, "resolved",
                    {"kind": "resolve", "alert_id": al.id, "asset_id": al.asset_id, "site_id": al.site_id}))
    return out


_ev_window: dict = defaultdict(deque)


def _state_alerts(db, a: models.Agent, pol: dict, metrics: Metrics | None, defender: dict | None) -> list:
    notes = []
    name = a.hostname
    if metrics is not None:
        seen = set()
        for d in metrics.disks:
            k = f"agent:{a.id}:disk:{d.mount.lower()}"
            seen.add(k)
            if d.used_pct >= pol["disk_warn"]:
                sev = "critical" if d.used_pct >= pol["disk_crit"] else "trouble"
                notes += _open(db, a, k, sev, f"Drive {d.mount} is almost full: {name}",
                               f"Drive {d.mount} on {name} is {d.used_pct:.0f}% (capacity {d.total_gb:.0f} GB). "
                               "Recommended action: clean up Temp/Downloads, the Recycle Bin, and log files. A full system drive can slow Windows down and cause update failures.")
            elif d.used_pct < pol["disk_warn"] - 5:
                notes += _resolve(db, k, f"disk {d.mount} remaining {d.used_pct:.0f}%")
        for al in db.query(models.Alert).filter(models.Alert.dedupe_key.like(f"agent:{a.id}:disk:%"),
                                                models.Alert.status != "resolved"):
            if al.dedupe_key not in seen:              # disk đã tháo / không remaining theo dõi
                notes += _resolve(db, al.dedupe_key, "disk is no longer in the reported inventory")
    if defender:
        mode = str(defender.get("running_mode") or "").lower()
        passive = "passive" in mode or bool(defender.get("other_av"))     # có phần mềm diệt virus khác làm chính
        k_rtp, k_sig = f"agent:{a.id}:av-rtp", f"agent:{a.id}:av-sig"
        if defender.get("realtime") is False and not passive:
            notes += _open(db, a, k_rtp, "critical", f"Defender real-time protection is disabled: {name}",
                           f"Windows Defender on {name} has REAL-TIME PROTECTION turned OFF. Recommended action: enable it; if it turns off again → "
                           "check for a GPO or malware disabling Defender.")
        elif defender.get("realtime") is True or passive:
            notes += _resolve(db, k_rtp, "real-time protection is enabled")
        age = defender.get("signature_age_days")
        if isinstance(age, (int, float)) and age > pol["av_signature_days"] and not passive:
            notes += _open(db, a, k_sig, "trouble", f"Outdated Defender signatures: {name}",
                           f"Defender signatures on {name} have not been updated for {int(age)} days since last update. "
                           "Recommended action: verify Internet/WSUS connectivity and run a manual update.")
        elif isinstance(age, (int, float)) and age <= pol["av_signature_days"]:
            notes += _resolve(db, k_sig, "signatures have been updated")
    return notes


def _event_alert(db, a: models.Agent, c: dict, d: dict, e: models.AgentEvent) -> list:
    al = c.get("alert")
    if not al or (al.get("when") and not al["when"](d)):
        return []
    by = al["by"](d)
    dkey = f"agent-ev:{a.id}:{c['key']}:{by}"[:255]
    th, win = int(al.get("threshold") or 1), int(al.get("window") or 10)
    if th > 1:
        q, t = _ev_window[dkey], e.last_ts.timestamp()
        q.append(t)
        while q and t - q[0] > win * 60:
            q.popleft()
        if len(q) < th:
            return []
    if th > 1:   # alerts theo ngưỡng (password spraying): nêu NGUỒN đang thử, không phải account of lần cuối
        title = f"{al['name']}: {a.hostname}" + (f" (from {by})" if by and by != "?" else "")
    else:
        title = f"{al['name']}: {a.hostname}" + (f" ({e.who})" if e.who and e.who not in ("System", "(unknown)") else "")
    msg = f"{e.what}\nAi: {e.who} · Source: {e.where}\nRecommended action: {e.advice}"
    if th > 1:
        msg = f"{len(_ev_window[dkey])}  times within {win}  minutes. " + msg
    return _open(db, a, dkey, al["severity"], title, msg, e.last_ts)


# ================================================================ xử lý báo cáo
def _ensure_asset(db, a: models.Agent):
    """Gắn machines ando assets có sẵn (trùng tên hoặc IP) hoặc tạo mới loại 'Máy trạm'/'Máy chủ' để hiện trên bản đồ/tìm kiếm."""
    if a.asset_id and db.get(models.Asset, a.asset_id):
        return
    short = a.hostname.split(".")[0].lower()
    mine = or_(~models.Asset.source.like("agent:%"), models.Asset.source == f"agent:{a.id}")   # không giành assets of agent khác
    asset = db.query(models.Asset).filter(func.lower(models.Asset.name).in_([a.hostname.lower(), short]), mine).first()
    if not asset and a.ips:
        # chỉ theo IP do agent báo (IP server thấy có thể là NAT/VPN chung) and không lấy assets of agent khác
        asset = db.query(models.Asset).filter(models.Asset.ip == a.ips[0], mine).first()
    if not asset:
        asset = models.Asset(name=a.hostname[:128], type="server" if a.os_kind == "server" else "workstation",
                             site_id=a.site_id, ip=(a.ips[0] if a.ips else a.ip)[:128], source=f"agent:{a.id}", status="up")
        db.add(asset)
        db.flush()
    a.asset_id = asset.id


def _apply_system(a: models.Agent, s: SystemInfo):
    for k in ("hostname", "domain", "os_name", "os_version", "arch", "manufacturer", "model", "serial", "cpu_model",
              "cpu_cores", "ram_mb", "machine_id"):
        v = getattr(s, k)
        if v not in ("", None):
            setattr(a, k, v)
    # User: logged_user = ĐANG sign-in (rỗng khi không ai); last_user giữ người gần nhất để biết machines of ai.
    prev = a.logged_user
    a.logged_user = s.logged_user
    # báo cáo rút gọn (hệ thống không đổi) có thể missing user_source → giữ nguồn cũ nếu vẫn là người đó
    a.user_source = (s.user_source or (a.user_source if s.logged_user == prev else "")) if s.logged_user else ""
    if s.logged_user:
        a.last_user, a.last_user_at = s.logged_user, utcnow()
    if a.os_version or a.os_name:
        for k, v in inventory.parse_os(a.os_family, a.os_name, a.os_version).items():
            setattr(a, k, v)
    if s.os_kind in ("client", "server"):
        a.os_kind = s.os_kind
    if s.boot_time:
        a.boot_time = s.boot_time.astimezone(timezone.utc).replace(tzinfo=None) if s.boot_time.tzinfo else s.boot_time
    a.ips = [i for i in s.ips if i][:16]
    if s.macs:                       # agent cũ (< 1.0.4) không gửi MAC → giữ giá trị đã có
        a.macs = s.macs


def _matched_by(s: "SystemInfo", o: models.Agent) -> str:
    if s.machine_id and o.machine_id and s.machine_id.lower() == o.machine_id.lower():
        return "machine_id"
    return "serial"


def _find_same_machine(db, body) -> models.Agent | None:
    """Máy cũ cùng tên + cùng machine-id hoặc serial hợp lệ (cài lại agent, xoá thư items agent, cài lại Windows).
    Bắt buộc trùng TÊN and trùng định danh phần cứng để không gộp nhầm 2 machines khác nhau."""
    s = body.system
    if not s.hostname or not (s.machine_id or inventory.valid_serial(s.serial)):
        return None
    for o in (db.query(models.Agent).filter(func.lower(models.Agent.hostname) == s.hostname.lower(),
                                           models.Agent.os_family == body.os_family, models.Agent.revoked_at.is_(None))
              .order_by(models.Agent.last_seen.desc().nullslast())):
        if inventory.same_machine(s.machine_id, s.serial, o.machine_id, o.serial):
            return o
    return None


def duplicate_groups(agents: list) -> dict[int, list[int]]:
    """Các bản ghi nghi là cùng một machines (đăng ký trước khi có machine-id): id → danh sách id trùng."""
    by_name = defaultdict(list)
    for a in agents:
        if not a.revoked_at:
            by_name[(a.hostname.lower(), a.os_family)].append(a)
    out = {}
    for group in by_name.values():
        for a in group:
            dup = [o.id for o in group if o.id != a.id and inventory.same_machine(a.machine_id, a.serial, o.machine_id, o.serial)]
            if dup:
                out[a.id] = dup
    return out


def _naive_utc(t: datetime) -> datetime:
    return t.astimezone(timezone.utc).replace(tzinfo=None) if t.tzinfo else t


def ingest_events(db, a: models.Agent, events: list[AgentEventIn], pol: dict) -> tuple[int, int, list]:
    stored = dropped = 0
    notes = []
    dis = set(pol["disabled_keys"])
    now = utcnow()
    # Mốc received theo fromng kênh (record id increasing by dần + thời điểm): agent gửi lại lô cũ khi mất mạng giữa chừng → bỏ trùng.
    # So cả thời điểm để không bỏ nhầm khi log bị xoá and đánh số lại from đầu.
    summ = dict(a.summary or {})
    marks = dict(summ.get("marks") or {})
    for ev in sorted(events, key=lambda e: (e.channel or e.kind, e.record_id)):
        ts = min(_naive_utc(ev.ts), now + timedelta(minutes=5))
        ch = (ev.channel or ev.kind or "")[:64]
        if ev.record_id:
            mk = marks.get(ch)
            if mk and ev.record_id <= mk[0] and ts.isoformat() <= mk[1]:
                dropped += 1
                continue
            if not mk or ev.record_id > mk[0] or ts.isoformat() > mk[1]:
                marks[ch] = [ev.record_id, ts.isoformat()]
        if a.os_family == "windows" and ev.event_id in cat.NOISE_IDS:
            dropped += 1
            continue
        c = cat.lookup(a.os_family, ev.model_dump())
        if not c or c["key"] in dis:
            dropped += 1
            continue
        d = {str(k)[:64]: (v if isinstance(v, (int, float, bool)) or v is None else str(v)[:1000])
             for k, v in list(ev.data.items())[:80]}
        if c.get("skip") and c["skip"](d):
            dropped += 1
            continue
        who, where, what, advice = c["render"](d, a.hostname)
        sev = c["severity_fn"](d) if c.get("severity_fn") else c["severity"]
        title = c["title_fn"](d) if c.get("title_fn") else c["title"]
        gkey = f"{c['key']}|{c['group'](d)}"[:255]
        ex = (db.query(models.AgentEvent)
              .filter(models.AgentEvent.agent_id == a.id, models.AgentEvent.group_key == gkey,
                      models.AgentEvent.last_ts >= ts - timedelta(minutes=pol["group_minutes"]))
              .order_by(models.AgentEvent.id.desc()).first())
        if ex:
            ex.count += 1
            ex.last_ts = max(ex.last_ts, ts)
            ex.record_id = max(ex.record_id or 0, ev.record_id or 0)
            ex.what, ex.where = what[:4000], where[:255]
            e = ex
        else:
            e = models.AgentEvent(agent_id=a.id, ts=ts, last_ts=ts, catalog_key=c["key"], group_key=gkey,
                                  category=c["category"], severity=sev, title=title[:255], who=who[:255], where=where[:255],
                                  what=what[:4000], advice=advice[:4000], channel=ev.channel or ev.kind, provider=ev.provider,
                                  event_id=ev.event_id, record_id=ev.record_id, message=cat.clean_message(ev.message), data=d)
            db.add(e)
            db.flush()
        stored += 1
        notes += _event_alert(db, a, c, d, e)
    if marks != (summ.get("marks") or {}):
        summ["marks"] = marks
        a.summary = summ
    return stored, dropped, notes


def _inventory(db, a: models.Agent, kind: str, data) -> bool:
    blob = json.dumps(data, sort_keys=True, default=str)
    h = sha256(blob)
    row = db.get(models.AgentInventory, (a.id, kind))
    if row and row.hash == h:
        row.updated_at = utcnow()
        return False
    if not row:
        row = models.AgentInventory(agent_id=a.id, kind=kind)
        db.add(row)
    row.data, row.hash, row.updated_at = json.loads(blob), h, utcnow()
    return True


def process_report(agent_id: int, rep: Report, ip: str) -> tuple[dict, list]:
    with SessionLocal() as db:
        a = db.get(models.Agent, agent_id)
        pol = get_policy(db)
        now = utcnow()
        was_offline = bool(db.query(models.Alert.id).filter(models.Alert.dedupe_key == f"agent:{a.id}:offline",
                                                             models.Alert.status != "resolved").first())
        a.last_seen, a.ip = now, ip[:64]
        if rep.agent_version:
            a.agent_version = rep.agent_version
        a.last_report_seq = max(a.last_report_seq or 0, rep.seq)
        if rep.system:
            _apply_system(a, rep.system)
        summ = dict(a.summary or {})
        if rep.metrics:
            m = rep.metrics
            dmax = max((d.used_pct for d in m.disks), default=None)
            summ.update(cpu=m.cpu, mem=m.mem, disk=dmax, disks=[d.model_dump() for d in m.disks], uptime_s=m.uptime_s,
                        metrics_at=now.isoformat() + "Z")
            db.add(models.AgentMetric(agent_id=a.id, ts=now, cpu=m.cpu, mem=m.mem, disk=dmax))
        if rep.defender is not None:
            dfd = {k: rep.defender.get(k) for k in list(rep.defender)[:40]}
            _inventory(db, a, "defender", dfd)
            summ["defender"] = {k: dfd.get(k) for k in ("realtime", "antivirus_enabled", "signature_age_days",
                                                         "running_mode", "other_av", "tamper_protection")}
        if rep.services is not None:
            _inventory(db, a, "services", [s.model_dump() for s in rep.services])
            summ["services_stopped_auto"] = sum(1 for s in rep.services if s.start.lower().startswith("auto")
                                                and s.state.lower() not in ("running", "active", "exited", "starting"))
        if rep.posture is not None:
            _inventory(db, a, "posture", {k: rep.posture.get(k) for k in list(rep.posture)[:20]})
        if rep.updates is not None:
            _inventory(db, a, "updates", rep.updates)
            summ["reboot_pending"] = bool(rep.updates.get("reboot_pending"))
        if rep.software is not None:
            if _inventory(db, a, "software_hash", {"n": len(rep.software), "h": sha256(json.dumps(
                    [s.model_dump() for s in rep.software], sort_keys=True))}):
                db.query(models.AgentSoftware).filter(models.AgentSoftware.agent_id == a.id).delete()
                db.add_all([models.AgentSoftware(agent_id=a.id, **s) for s in
                            inventory.normalize_software([x.model_dump() for x in rep.software])])
            summ["software_count"] = len(rep.software)
            if any(x.source_pkg for x in rep.software):
                _inventory(db, a, "software_srcpkg", {"n": sum(1 for x in rep.software if x.source_pkg)})
        a.summary = summ
        _ensure_asset(db, a)
        asset = db.get(models.Asset, a.asset_id)
        if asset:
            asset.status, asset.last_seen = "up", now
            if not asset.os and a.os_name:
                asset.os = a.os_name[:128]
        notes = []
        if was_offline:
            notes += _resolve(db, f"agent:{a.id}:offline", "machine has reconnected")
        notes += _state_alerts(db, a, pol, rep.metrics, rep.defender)
        stored, dropped, ev_notes = ingest_events(db, a, rep.events or [], pol)
        notes += ev_notes
        cfg = agent_config(pol, a.os_family)
        db.commit()
        return {"ok": True, "events_stored": stored, "events_dropped": dropped, "config_version": cfg["version"],
                "report_seconds": cfg["report_seconds"]}, notes


async def _dispatch(notes):
    if notes:
        from .automation.engine import dispatch
        try:
            await dispatch(notes)
        except Exception:      # notification failures must not interrupt data ingestion
            log.exception("send agent error alerts")


# ================================================================ API cho agent
# Đăng ký ĐÈ lên máy đã có (agent mới, uid khác, nhưng trùng tên + machine-id/serial) → chờ IT duyệt.
# Lý do: đăng ký mở, tên máy và số serial không phải bí mật – ai biết 2 thông tin này có thể chiếm hồ sơ máy thật
# (khoá của agent thật bị thay, kẻ giả gửi dữ liệu "mọi thứ bình thường"). Agent thật vẫn chạy tới khi IT duyệt.
# Cùng uid (chính bản cài đó đăng ký lại, vd. đổi địa chỉ server) thì KHÔNG cần duyệt: uid nằm cạnh khoá trong agent.json.
ENROLL_RETRY_SECONDS = max(60, int(os.environ.get("AGENT_ENROLL_RETRY_SECONDS", "300")))   # agent hỏi lại mỗi 5 phút khi chờ duyệt
ENROLL_REQUEST_DAYS = 7               # yêu cầu chờ quá 7 ngày → hết hạn; duyệt xong agent có 7 ngày để nhận khoá
MAX_PENDING_PER_MACHINE = 10


def _req_dict(r: models.AgentEnrollRequest, target: models.Agent | None, pol: dict) -> dict:
    sysd = r.system or {}
    out = {"id": r.id, "agent_id": r.agent_id, "status": r.status, "hostname": r.hostname, "os_family": r.os_family,
           "agent_version": r.agent_version, "ip": r.ip, "matched_by": r.matched_by,
           "attempts": r.attempts, "reason": r.reason, "decided_by": r.decided_by,
           "created_at": r.created_at.isoformat() + "Z", "last_attempt_at": r.last_attempt_at.isoformat() + "Z",
           "decided_at": r.decided_at.isoformat() + "Z" if r.decided_at else None,
           "completed_at": r.completed_at.isoformat() + "Z" if r.completed_at else None,
           "new": {k: sysd.get(k) for k in ("hostname", "os_name", "os_version", "manufacturer", "model", "serial", "machine_id",
                                             "macs", "ips", "logged_user")}}
    if target:
        out["current"] = {"hostname": target.hostname, "os_name": target.os_name, "os_version": target.os_version,
                          "manufacturer": target.manufacturer, "model": target.model, "serial": target.serial,
                          "machine_id": target.machine_id, "macs": target.macs or [], "ips": target.ips or [], "ip": target.ip,
                          "logged_user": target.logged_user or target.last_user, "agent_version": target.agent_version,
                          "status": _online(target, pol), "last_seen": target.last_seen.isoformat() + "Z" if target.last_seen else None}
    return out


def _expire_requests(db) -> None:
    lim = utcnow() - timedelta(days=ENROLL_REQUEST_DAYS)
    for r in db.query(models.AgentEnrollRequest).filter(models.AgentEnrollRequest.status.in_(["pending", "approved"])):
        if (r.status == "pending" and r.last_attempt_at < lim) or (r.status == "approved" and r.decided_at and r.decided_at < lim):
            r.status = "expired"
    db.flush()                       # SessionLocal autoflush=False → các truy vấn sau phải thấy trạng thái mới


def _site_id(db, name: str) -> int | None:
    """--site lúc cài: tên site (không phân biệt hoa thường). Không khớp → máy không gắn site, IT gán tay sau."""
    name = (name or "").strip()
    if not name:
        return None
    s = db.query(models.Site).filter(func.lower(models.Site.name) == name.lower()).first()
    return s.id if s else None


@router.post("/api/agent/v1/enroll")
async def agent_enroll(request: Request):
    ip = client_ip(request)
    if _limited(_enroll_fail, ip, 10, 600, record=False):     # chỉ đếm lần SAI
        raise HTTPException(429, "Too many failed enrollment attempts. Try again in 10 minutes.")
    body = _parse(Enroll, await _read_json(request))

    def work():
        with SessionLocal() as db:
            now = utcnow()
            a = db.query(models.Agent).filter_by(uid=body.uid).first()
            if a and a.revoked_at:
                return None, "This machine has been revoked. Remove it from the Endpoints page before enrolling it again.", None
            merged = None
            notes = []
            if not a and (target := _find_same_machine(db, body)):
                # ---- đè lên máy đã có → cần IT duyệt
                _expire_requests(db)
                q = db.query(models.AgentEnrollRequest).filter_by(agent_id=target.id, uid=body.uid)
                req = q.filter(models.AgentEnrollRequest.status.in_(["pending", "approved", "rejected"])) \
                       .order_by(models.AgentEnrollRequest.id.desc()).first()
                if req and req.status == "rejected":
                    return None, f"IT rejected this enrollment request for {target.hostname}. Contact IT.", None
                if req and req.status == "approved":
                    merged = a = target            # IT đã duyệt → gộp như cài lại
                    a.uid = body.uid
                    req.status, req.completed_at = "completed", now
                    notes += _resolve(db, f"agent-enroll:{target.id}", "IT approved the re-enrolment")
                else:
                    sysd = json.loads(body.system.model_dump_json())
                    if req:                         # agent hỏi lại trong lúc chờ
                        req.attempts += 1
                        req.last_attempt_at, req.ip, req.system = now, ip[:64], sysd
                        req.agent_version = body.agent_version
                    else:
                        n = db.query(models.AgentEnrollRequest).filter_by(agent_id=target.id, status="pending").count()
                        if n >= MAX_PENDING_PER_MACHINE:
                            return None, None, {"msg": "Too many pending requests for this machine – waiting for IT", "pending": True,
                                                "retry_seconds": ENROLL_RETRY_SECONDS}
                        req = models.AgentEnrollRequest(
                            agent_id=target.id, uid=body.uid, hostname=(body.system.hostname or "")[:255], os_family=body.os_family,
                            agent_version=body.agent_version, system=sysd, ip=ip[:64],
                            matched_by=_matched_by(body.system, target), status="pending", attempts=1,
                            created_at=now, last_attempt_at=now, decided_by="", reason="")
                        db.add(req)
                        db.flush()
                        macs = ", ".join(body.system.macs) or "not reported"
                        db.add(models.AuditLog(user=f"agent:{body.system.hostname or '?'}"[:64], action="enroll_pending", entity="agent",
                                               entity_id=target.id, ip=ip[:64],
                                               detail=f"New agent asks to take over existing machine {target.hostname} "
                                                      f"(same hostname + {req.matched_by}) from {ip}, MAC {macs} "
                                                      f"– waiting for IT approval (request #{req.id})"))
                        notes += _open(db, target, f"agent-enroll:{target.id}", "trouble",
                                       f"Re-enrolment waiting for approval: {target.hostname}",
                                       f"A new agent from {ip} (MAC {macs}) wants to replace the existing record of {target.hostname} "
                                       f"(matched by {req.matched_by}). If you approve, the current agent's key stops working. "
                                       "Recommended action: confirm that this machine was really reinstalled, then approve or reject it "
                                       "on Endpoints → Pending approvals.")
                    db.commit()
                    return None, None, {"msg": f"This machine matches existing endpoint {target.hostname}; waiting for IT approval "
                                               f"(request #{req.id})", "pending": True, "request_id": req.id,
                                        "retry_seconds": ENROLL_RETRY_SECONDS, "notes": notes}
            elif not a and _limited(_enroll_new, ip, ENROLL_NEW_PER_IP, 600):
                return None, None, {"msg": f"Too many new machines from {ip} – try again later", "pending": False,
                                    "retry_seconds": 600}
            key = secrets.token_urlsafe(32)
            reenroll = a is not None
            if not a:
                a = models.Agent(uid=body.uid, hostname=body.system.hostname or body.uid, os_family=body.os_family,
                                 site_id=_site_id(db, body.site), tags=body.tags.strip()[:255], key_hash="", ips=[], macs=[], summary={})
                db.add(a)
            a.key_hash, a.os_family, a.agent_version, a.ip, a.last_seen = sha256(key), body.os_family, body.agent_version, ip[:64], now
            _apply_system(a, body.system)
            if not a.os_kind:
                a.os_kind = "client"
            db.flush()
            _ensure_asset(db, a)
            how = (" – IT-approved re-enrolment over the existing machine record (machine-id/serial); history kept" if merged else "")
            db.add(models.AuditLog(user=f"agent:{a.hostname}"[:64], action="re-enroll" if reenroll else "enroll", entity="agent",
                                   entity_id=a.id, detail=f"{a.hostname} ({a.os_name}) registered from {ip}"
                                                          f"{' – site ' + body.site if body.site else ''}{how}", ip=ip[:64]))
            cfg = agent_config(get_policy(db), a.os_family)
            db.commit()
            return {"agent_id": a.id, "key": key, "config": cfg, "notes": notes}, None, None

    res, err, pending = await run_in_threadpool(work)
    if pending:
        await _dispatch(pending.pop("notes", []))
        raise HTTPException(429, pending, headers={"Retry-After": str(pending["retry_seconds"])})
    if err:
        _enroll_fail[ip].append(time.monotonic())
        raise HTTPException(403, err)
    await _dispatch(res.pop("notes", []))
    return res


@router.post("/api/agent/v1/report")
async def agent_report(request: Request):
    body = await _read_json(request)

    def auth():
        with SessionLocal() as db:
            return _agent_from_request(request, db).id
    aid = await run_in_threadpool(auth)
    rep = _parse(Report, body)
    res, notes = await run_in_threadpool(process_report, aid, rep, client_ip(request))
    await _dispatch(notes)
    return res


@router.get("/api/agent/v1/config")
def agent_get_config(request: Request, db: Session = Depends(get_db)):
    a = _agent_from_request(request, db)
    return agent_config(get_policy(db), a.os_family)


@router.get("/api/agent/v1/update")
def agent_update_manifest(request: Request, db: Session = Depends(get_db)):
    """Bản tin cập nhật đã KÝ bằng khoá Ed25519 giữ ngoài server (tools/agent-release). Server chỉ chuyển tiếp:
    agent tự kiểm chữ ký bằng khoá công khai gắn trong file chạy → server bị chiếm cũng không đẩy được bản giả."""
    _agent_from_request(request, db)
    if not get_policy(db)["update"].get("enabled"):
        return Response(status_code=204)
    f = UPDATE_DIR / "manifest.json"
    if not f.exists():
        return Response(status_code=204)
    return JSONResponse(json.loads(f.read_text(encoding="utf-8")))


@router.get("/api/agent/v1/update/file/{name}")
def agent_update_file(name: str, request: Request, db: Session = Depends(get_db)):
    _agent_from_request(request, db)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name):
        raise HTTPException(400, "Invalid file name")
    f = UPDATE_DIR / name
    if not f.is_file():
        raise HTTPException(404, "File not found")
    return FileResponse(f, media_type="application/octet-stream")


# ================================================================ nền: mất kết nối, dọn dữ liệu cũ
def _offline_pass() -> list:
    notes = []
    with SessionLocal() as db:
        pol = get_policy(db)
        now = utcnow()
        limit = now - timedelta(minutes=pol["offline_minutes"])
        for a in db.query(models.Agent).filter(models.Agent.revoked_at.is_(None)):
            want = a.alert_offline if a.alert_offline is not None else a.os_kind == "server"
            stale = a.last_seen is None or a.last_seen < limit
            asset = db.get(models.Asset, a.asset_id) if a.asset_id else None
            if asset and asset.source.startswith("agent:"):
                asset.status = "down" if stale and want else ("off" if stale else "up")
            if stale and want:
                mins = int((now - (a.last_seen or a.enrolled_at)).total_seconds() // 60)
                notes += _open(db, a, f"agent:{a.id}:offline", "down", f"Agent disconnected: {a.hostname}",
                               f"{a.hostname} ({a.ip}) has not sent data {mins}  minutes. The machine may be disabled, offline, or its agent service may be stopped.")
        quiet = now - timedelta(hours=pol["event_alert_quiet_hours"])
        for al in db.query(models.Alert).filter(models.Alert.source == "agent", models.Alert.status != "resolved",
                                                models.Alert.dedupe_key.like("agent-ev:%"),
                                                func.coalesce(models.Alert.last_seen, models.Alert.opened_at) < quiet):
            al.status, al.resolved_at = "resolved", now
            al.message = f"{al.message} · auto-resolved: did not recur for {pol['event_alert_quiet_hours']} hours"[:2000]
        db.commit()
    return notes


def _purge():
    with SessionLocal() as db:
        pol = get_policy(db)
        now = utcnow()
        db.query(models.AgentMetric).filter(models.AgentMetric.ts < now - timedelta(days=int(pol["retention"]["metrics_days"]))).delete()
        db.query(models.AgentEvent).filter(models.AgentEvent.last_ts < now - timedelta(days=int(pol["retention"]["events_days"]))).delete()
        db.commit()


async def loop():
    last_purge = 0.0
    while True:
        try:
            await _dispatch(await asyncio.to_thread(_offline_pass))
            if time.monotonic() - last_purge > 6 * 3600:
                await asyncio.to_thread(_purge)
                last_purge = time.monotonic()
        except Exception:
            log.exception("agent health-check cycle failed")
        await asyncio.sleep(60)


# ================================================================ API cho giao diện quản trị
def _online(a: models.Agent, pol: dict) -> str:
    if a.revoked_at:
        return "revoked"
    if not a.last_seen:
        return "never"
    age = (utcnow() - a.last_seen).total_seconds()
    return "online" if age <= max(180, 3 * pol["report_seconds"]) else "offline"


def _agent_dict(a: models.Agent, pol: dict, sites: dict | None = None) -> dict:
    s = a.summary or {}
    return {"id": a.id, "hostname": a.hostname, "domain": a.domain, "os_family": a.os_family, "os_name": a.os_name,
            "os_version": a.os_version, "os_kind": a.os_kind, "arch": a.arch, "agent_version": a.agent_version, "ip": a.ip,
            "ips": a.ips or [], "macs": a.macs or [], "logged_user": a.logged_user, "user_source": a.user_source, "last_user": a.last_user,
            "last_user_at": a.last_user_at.isoformat() + "Z" if a.last_user_at else None,
            "os_release": a.os_release, "os_build": a.os_build, "os_ubr": a.os_ubr, "machine_id": a.machine_id,
            "manufacturer": a.manufacturer, "model": a.model,
            "serial": a.serial, "cpu_model": a.cpu_model, "cpu_cores": a.cpu_cores, "ram_mb": a.ram_mb,
            "boot_time": a.boot_time.isoformat() + "Z" if a.boot_time else None,
            "last_seen": a.last_seen.isoformat() + "Z" if a.last_seen else None,
            "enrolled_at": a.enrolled_at.isoformat() + "Z" if a.enrolled_at else None,
            "status": _online(a, pol), "site_id": a.site_id, "site_name": (sites or {}).get(a.site_id, ""),
            "asset_id": a.asset_id, "tags": a.tags, "note": a.note,
            "alert_offline": a.alert_offline if a.alert_offline is not None else a.os_kind == "server",
            "alert_offline_auto": a.alert_offline is None,
            "cpu": s.get("cpu"), "mem": s.get("mem"), "disk": s.get("disk"), "disks": s.get("disks") or [],
            "uptime_s": s.get("uptime_s"), "defender": s.get("defender"), "software_count": s.get("software_count"),
            "reboot_pending": s.get("reboot_pending"), "services_stopped_auto": s.get("services_stopped_auto"),
            "revoked_at": a.revoked_at.isoformat() + "Z" if a.revoked_at else None}


@router.get("/api/agents")
def list_agents(user=Depends(current_user), db: Session = Depends(get_db)):
    pol = get_policy(db)
    sites = {s.id: s.name for s in db.query(models.Site)}
    open_alerts = defaultdict(int)
    for asset_id, n in (db.query(models.Alert.asset_id, func.count()).filter(models.Alert.status != "resolved")
                        .group_by(models.Alert.asset_id)):
        open_alerts[asset_id] = n
    since = utcnow() - timedelta(hours=24)
    ev24 = dict(db.query(models.AgentEvent.agent_id, func.sum(models.AgentEvent.count))
                .filter(models.AgentEvent.last_ts >= since, models.AgentEvent.severity.in_(["attention", "trouble", "critical"]))
                .group_by(models.AgentEvent.agent_id).all())
    out = []
    agents = db.query(models.Agent).order_by(func.lower(models.Agent.hostname)).all()
    dups = duplicate_groups(agents)
    for a in agents:
        d = _agent_dict(a, pol, sites)
        d["duplicates"] = dups.get(a.id, [])
        d["alerts"] = open_alerts.get(a.asset_id, 0) if a.asset_id else 0
        d["events_24h"] = int(ev24.get(a.id) or 0)
        out.append(d)
    return out


def _get(db, aid) -> models.Agent:
    a = db.get(models.Agent, aid)
    if not a:
        raise HTTPException(404, "Agent not found")
    return a


@router.get("/api/agents/{aid}")
def agent_detail(aid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    a = _get(db, aid)
    pol = get_policy(db)
    d = _agent_dict(a, pol, {s.id: s.name for s in db.query(models.Site)})
    inv = {r.kind: r for r in db.query(models.AgentInventory).filter_by(agent_id=a.id)}
    d["defender_detail"] = inv["defender"].data if "defender" in inv else None
    d["updates"] = inv["updates"].data if "updates" in inv else None
    d["posture"] = inv["posture"].data if "posture" in inv else None
    d["inventory_at"] = {k: r.updated_at.isoformat() + "Z" for k, r in inv.items()}
    d["quality"] = data_quality(a, inv)
    d["alerts_open"] = [{"id": x.id, "title": x.title, "severity": x.severity, "opened_at": x.opened_at.isoformat() + "Z",
                         "count": x.count} for x in db.query(models.Alert).filter(
        models.Alert.status != "resolved", or_(models.Alert.dedupe_key.like(f"agent:{a.id}:%"),
                                               models.Alert.dedupe_key.like(f"agent-ev:{a.id}:%"))).order_by(models.Alert.id.desc())]
    return d


@router.get("/api/agents/{aid}/metrics")
def agent_metrics(aid: int, hours: int = 24, user=Depends(current_user), db: Session = Depends(get_db)):
    _get(db, aid)
    since = utcnow() - timedelta(hours=min(max(hours, 1), 24 * 30))
    rows = (db.query(models.AgentMetric).filter(models.AgentMetric.agent_id == aid, models.AgentMetric.ts >= since)
            .order_by(models.AgentMetric.ts))
    pts = [(r.ts, r.cpu, r.mem, r.disk) for r in rows]
    step = max(1, len(pts) // 600)               # tối đa ~600 điểm cho biểu đồ
    return [{"ts": t.isoformat() + "Z", "cpu": c, "mem": m, "disk": dk} for t, c, m, dk in pts[::step]]


@router.get("/api/agents/{aid}/services")
def agent_services(aid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    _get(db, aid)
    r = db.get(models.AgentInventory, (aid, "services"))
    return {"updated_at": r.updated_at.isoformat() + "Z" if r else None, "items": (r.data if r else []) or []}


@router.get("/api/agents/{aid}/software")
def agent_software(aid: int, user=Depends(current_user), db: Session = Depends(get_db)):
    _get(db, aid)
    rows = db.query(models.AgentSoftware).filter_by(agent_id=aid).order_by(func.lower(models.AgentSoftware.name))
    return [{"name": s.name, "version": s.version, "publisher": s.publisher, "installed_on": s.installed_on, "source": s.source,
             "source_pkg": s.source_pkg, "norm_name": s.norm_name, "norm_vendor": s.norm_vendor, "norm_version": s.norm_version}
            for s in rows]


def data_quality(a: models.Agent, inv: dict) -> dict:
    """Khối "chất lượng dữ liệu" cho every machines: dữ liệu nào đủ tin để khớp CVE, cái gì remaining missing and vì sao."""
    sw = inv.get("software_hash")
    checks = []

    def add(key, ok, label, hint=""):
        checks.append({"key": key, "ok": bool(ok), "label": label, "hint": "" if ok else hint})
    add("hostname", a.hostname, "Hostname", "agent has not sent system information")
    if a.os_family == "windows":
        add("os_build", a.os_build and a.os_ubr is not None, f"Windows build {a.os_build}.{a.os_ubr}" if a.os_build else "Windows build",
            "no build/UBR; Windows patches cannot be matched")
    else:
        add("os_build", a.os_release, f"Operating system version {a.os_release}".strip(), "release could not be determined")
    add("user", a.last_user, "User" + (f" ({a.last_user})" if a.last_user else ""),
        "no sign-in has been observed")
    n = (a.summary or {}).get("software_count")
    add("software", n, f"Software inventory ({n or 0})", "agent has not sent a software inventory")
    stale = sw and (utcnow() - sw.updated_at) > timedelta(days=3)
    add("software_fresh", sw and not stale, "Software inventory is current",
        "not updated for more than 3 days" if sw else "none")
    add("identity", a.machine_id or inventory.valid_serial(a.serial), "Machine identifier (machine-id / serial)",
        "older agent did not send a machine-id; reinstalling will create a new machine (update agent to ≥ 1.0.2)")
    if a.os_family == "linux":
        has_src = n and inv.get("software_srcpkg")
        add("source_pkg", has_src, "Linux source packages", "older agent did not send source packages; Ubuntu CVE matching may produce false positives")
    ok = sum(c["ok"] for c in checks)
    return {"score": round(100 * ok / len(checks)), "checks": checks,
            "user_source": a.user_source or ("unknown (older agent)" if a.logged_user else ""),
            "software_at": sw.updated_at.isoformat() + "Z" if sw else None}


def _event_dict(e: models.AgentEvent, hosts: dict | None = None) -> dict:
    return {"id": e.id, "agent_id": e.agent_id, "hostname": (hosts or {}).get(e.agent_id, ""), "ts": e.ts.isoformat() + "Z",
            "last_ts": e.last_ts.isoformat() + "Z", "count": e.count, "key": e.catalog_key, "category": e.category,
            "severity": e.severity, "title": e.title, "who": e.who, "where": e.where, "what": e.what, "advice": e.advice,
            "event_id": e.event_id, "channel": e.channel, "provider": e.provider, "message": e.message, "data": e.data}


@router.get("/api/agent-events")
def list_agent_events(agent_id: int | None = None, severity: str = "", category: str = "", q: str = "", hours: int = 72,
                      limit: int = 300, user=Depends(current_user), db: Session = Depends(get_db)):
    qq = db.query(models.AgentEvent).filter(models.AgentEvent.last_ts >= utcnow() - timedelta(hours=min(max(hours, 1), 24 * 90)))
    if agent_id:
        qq = qq.filter(models.AgentEvent.agent_id == agent_id)
    if severity:
        qq = qq.filter(models.AgentEvent.severity.in_(severity.split(",")))
    if category:
        qq = qq.filter(models.AgentEvent.category.in_(category.split(",")))
    if q:
        like = f"%{q[:100]}%"
        qq = qq.filter(or_(models.AgentEvent.title.ilike(like), models.AgentEvent.who.ilike(like),
                           models.AgentEvent.where.ilike(like), models.AgentEvent.what.ilike(like)))
    rows = qq.order_by(models.AgentEvent.last_ts.desc()).limit(min(limit, 2000)).all()
    hosts = {a.id: a.hostname for a in db.query(models.Agent.id, models.Agent.hostname)}
    return [_event_dict(e, hosts) for e in rows]


@router.get("/api/agent-software")
def search_software(q: str = "", user=Depends(current_user), db: Session = Depends(get_db)):
    """Tìm phần mềm trên toàn bộ machines: gom theo tên + sessions bản, kèm danh sách machines."""
    qq = db.query(models.AgentSoftware.name, models.AgentSoftware.version, models.AgentSoftware.publisher,
                  func.count(models.AgentSoftware.agent_id.distinct()), func.array_agg(models.AgentSoftware.agent_id.distinct()))
    if q:
        qq = qq.filter(or_(models.AgentSoftware.name.ilike(f"%{q[:100]}%"), models.AgentSoftware.publisher.ilike(f"%{q[:100]}%")))
    rows = (qq.group_by(models.AgentSoftware.name, models.AgentSoftware.version, models.AgentSoftware.publisher)
            .order_by(func.count(models.AgentSoftware.agent_id.distinct()).desc(), models.AgentSoftware.name).limit(500).all())
    hosts = {a.id: a.hostname for a in db.query(models.Agent.id, models.Agent.hostname)}
    return [{"name": n, "version": v, "publisher": p, "machines": c, "hosts": sorted(hosts.get(i, "?") for i in ids)[:200]}
            for n, v, p, c, ids in rows]


@router.patch("/api/agents/{aid}")
def update_agent(aid: int, body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    a = _get(db, aid)
    before = {k: getattr(a, k) for k in ("tags", "note", "site_id", "alert_offline", "os_kind")}
    if "tags" in body:
        a.tags = str(body["tags"])[:255]
    if "note" in body:
        a.note = str(body["note"])[:5000]
    if "site_id" in body:
        a.site_id = int(body["site_id"]) if body["site_id"] else None
        if a.asset_id and (asset := db.get(models.Asset, a.asset_id)):
            asset.site_id = a.site_id
    if "alert_offline" in body:
        a.alert_offline = None if body["alert_offline"] is None else bool(body["alert_offline"])
    if body.get("os_kind") in ("client", "server"):
        a.os_kind = body["os_kind"]
    after = {k: getattr(a, k) for k in before}
    audit(db, user.username, "update", "agent", a.id, a.hostname,
          {k: {"before": before[k], "after": after[k]} for k in before if before[k] != after[k]})
    db.commit()
    return _agent_dict(a, get_policy(db))


@router.post("/api/agents/{aid}/revoke")
def revoke_agent(aid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    a = _get(db, aid)
    a.revoked_at, a.revoked_by = utcnow(), user.username
    audit(db, user.username, "revoke", "agent", a.id, f"Revoke agent key for {a.hostname} – the machine will no longer be able to send data")
    db.commit()
    return {"ok": True}


@router.delete("/api/agents/{aid}")
def delete_agent(aid: int, user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    a = _get(db, aid)
    name = a.hostname
    asset = db.get(models.Asset, a.asset_id) if a.asset_id else None
    if asset and asset.source == f"agent:{a.id}":
        db.delete(asset)                                   # chỉ xoá assets do agent tự tạo
    db.delete(a)
    audit(db, user.username, "delete", "agent", aid, f"Delete machine {name} and its metrics/events")
    db.commit()
    return {"ok": True}


# ---- yêu cầu đăng ký đè chờ duyệt
@router.get("/api/agent-enroll-requests")
def list_enroll_requests(all: bool = False, user=Depends(admin_user), db: Session = Depends(get_db)):
    """Mặc định: đang chờ duyệt. all=1: kèm các yêu cầu đã xử lý trong 30 ngày (để tra lại)."""
    _expire_requests(db)
    db.commit()
    q = db.query(models.AgentEnrollRequest)
    if all:
        q = q.filter(or_(models.AgentEnrollRequest.status == "pending",
                         models.AgentEnrollRequest.last_attempt_at >= utcnow() - timedelta(days=30)))
    else:
        q = q.filter_by(status="pending")
    pol = get_policy(db)
    targets = {}
    out = []
    for r in q.order_by(models.AgentEnrollRequest.id.desc()).limit(200):
        if r.agent_id not in targets:
            targets[r.agent_id] = db.get(models.Agent, r.agent_id)
        out.append(_req_dict(r, targets[r.agent_id], pol))
    return out


def _decision_reason(body: dict) -> str:
    """Lý do: trong body, hoặc ô "Reason" của hộp xác nhận trên giao diện (header X-Audit-Reason → REQ_CTX)."""
    from .security import REQ_CTX
    return str(body.get("reason") or (REQ_CTX.get() or {}).get("reason") or "")[:2000]


def _get_req(db, rid) -> models.AgentEnrollRequest:
    r = db.get(models.AgentEnrollRequest, rid)
    if not r:
        raise HTTPException(404, "Request not found")
    return r


@router.post("/api/agent-enroll-requests/{rid}/approve")
async def approve_enroll_request(rid: int, body: dict = Body(default={}), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    _expire_requests(db)
    r = _get_req(db, rid)
    if r.status != "pending":
        raise HTTPException(400, f"This request is already {r.status}")
    target = db.get(models.Agent, r.agent_id)
    if not target or target.revoked_at:
        raise HTTPException(400, "The existing machine was removed or revoked – the new agent can enroll as a new machine after it is deleted")
    r.status, r.decided_at, r.decided_by = "approved", utcnow(), user.username
    r.reason = _decision_reason(body)
    db.flush()
    # các yêu cầu khác đang chờ cho CÙNG máy → từ chối luôn (chỉ một agent được thay)
    for o in db.query(models.AgentEnrollRequest).filter(models.AgentEnrollRequest.agent_id == r.agent_id,
                                                        models.AgentEnrollRequest.status == "pending",
                                                        models.AgentEnrollRequest.id != r.id):
        o.status, o.decided_at, o.decided_by, o.reason = "rejected", utcnow(), user.username, f"Superseded by request #{r.id}"
    macs = ", ".join((r.system or {}).get("macs") or []) or "not reported"
    audit(db, user.username, "approve", "agent_enroll_request", r.id,
          f"Approve re-enrolment over {target.hostname}: new agent from {r.ip}, MAC {macs}. The current agent key stops working "
          "once the new agent picks up its key (within about 5 minutes)")
    notes = _resolve(db, f"agent-enroll:{target.id}", f"approved by {user.username}")
    db.commit()
    await _dispatch(notes)
    return _req_dict(r, target, get_policy(db))


@router.post("/api/agent-enroll-requests/{rid}/reject")
async def reject_enroll_request(rid: int, body: dict = Body(default={}), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    r = _get_req(db, rid)
    if r.status not in ("pending", "approved"):
        raise HTTPException(400, f"This request is already {r.status}")
    target = db.get(models.Agent, r.agent_id)
    r.status, r.decided_at, r.decided_by = "rejected", utcnow(), user.username
    r.reason = _decision_reason(body)
    audit(db, user.username, "reject", "agent_enroll_request", r.id,
          f"Reject re-enrolment over {target.hostname if target else '?'} from {r.ip} – the current agent keeps working"
          + (f". Reason: {r.reason}" if r.reason else ""))
    notes = []
    db.flush()
    if target and not db.query(models.AgentEnrollRequest).filter_by(agent_id=target.id, status="pending").count():
        notes = _resolve(db, f"agent-enroll:{target.id}", f"rejected by {user.username}")
    db.commit()
    await _dispatch(notes)
    return _req_dict(r, target, get_policy(db))


# ---- chính sách + danh items
@router.get("/api/agent-policy")
def read_policy(user=Depends(current_user), db: Session = Depends(get_db)):
    return {"policy": get_policy(db), "catalog": cat.catalog_rows(), "update_manifest": _manifest_info()}


@router.put("/api/agent-policy")
def write_policy(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    before = get_policy(db)
    v = save_policy(db, body)
    audit(db, user.username, "update", "agent_policy", None, "Agent collection policy",
          {k: {"before": before[k], "after": v[k]} for k in v if before.get(k) != v[k]})
    db.commit()
    return v


def _manifest_info() -> dict | None:
    f = UPDATE_DIR / "manifest.json"
    if not f.exists():
        return None
    try:
        m = json.loads(f.read_text(encoding="utf-8"))
        return {"version": m.get("version"), "platforms": sorted((m.get("files") or {}).keys())}
    except ValueError:
        return {"version": "Error reading manifest.json", "platforms": []}


@router.get("/api/agent-summary")
def fleet_summary(user=Depends(current_user), db: Session = Depends(get_db)):
    pol = get_policy(db)
    agents = db.query(models.Agent).filter(models.Agent.revoked_at.is_(None)).all()
    st = defaultdict(int)
    for a in agents:
        st[_online(a, pol)] += 1
    by_os = defaultdict(int)
    for a in agents:
        by_os[a.os_family] += 1
    risky = sum(1 for a in agents if (a.summary or {}).get("defender", {}) and (a.summary["defender"].get("realtime") is False))
    full = sum(1 for a in agents if ((a.summary or {}).get("disk") or 0) >= pol["disk_warn"])
    return {"total": len(agents), "online": st["online"], "offline": st["offline"] + st["never"], "by_os": by_os,
            "defender_off": risky, "disk_full": full, "version": os.environ.get("ITOPS_AGENT_VERSION", ""),
            "pending_enroll": db.query(models.AgentEnrollRequest).filter_by(status="pending").count()}


# ---- tải agent + lệnh cài (trang Máy trạm → Cài đặt agent)
DIST_DIR = Path(__file__).resolve().parent.parent / "agent_dist"


def _server_pin() -> str:
    """SHA-256 khoá công khai chứng chỉ HTTPS of chính server (data/tls/cert.pem) – để điền sẵn --ca-pin."""
    f = Path(DATA_DIR) / "tls" / "cert.pem"
    if not f.exists():
        return ""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        c = x509.load_pem_x509_certificate(f.read_bytes())
        spki = c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(spki).hexdigest()
    except Exception:       # chứng chỉ hỏng → không gợi ý pin
        return ""


@router.get("/api/agent-downloads")
def agent_downloads(user=Depends(current_user)):
    files = []
    sums = {}
    sf = DIST_DIR / "SHA256SUMS.txt"
    if sf.exists():
        for line in sf.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2:
                sums[parts[1].lstrip("*")] = parts[0]
    if DIST_DIR.is_dir():
        for f in sorted(DIST_DIR.iterdir()):
            if f.is_file() and f.name != "VERSION":
                files.append({"name": f.name, "size": f.stat().st_size, "sha256": sums.get(f.name, "")})
    ver = (DIST_DIR / "VERSION").read_text().strip() if (DIST_DIR / "VERSION").exists() else ""
    return {"version": ver, "files": files, "ca_pin": _server_pin()}


@router.get("/api/agent-downloads/{name}")
def agent_download_file(name: str, user=Depends(current_user)):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name):
        raise HTTPException(400, "Invalid file name")
    f = DIST_DIR / name
    if not f.is_file():
        raise HTTPException(404, "File not found")
    return FileResponse(f, filename=name, media_type="application/octet-stream")
