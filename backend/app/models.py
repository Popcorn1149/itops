from datetime import datetime, timezone
from sqlalchemy import BigInteger, String, Integer, Boolean, DateTime, ForeignKey, JSON, Text, Float, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16), default="admin")  # admin | viewer
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    # 2FA (TOTP). Bí mật lưu đã mã hoá (AES-256-GCM, tiền tố enc2:), không bao hours trả ra API sau khi đã enabled.
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_pending: Mapped[str | None] = mapped_column(Text, nullable=True)   # bí mật đang chờ xác nhận khi enabled 2FA
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, server_default="0")   # chống dùng lại mã OTP


class LoginSession(Base):
    """Phiên sign-in phía server: revoked được, hết hạn khi không thao tác (idle timeout)."""
    __tablename__ = "login_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)          # jti trong JWT
    username: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    mfa: Mapped[bool] = mapped_column(Boolean, default=False)              # đã qua step OTP
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[str] = mapped_column(String(64), default="")


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), default="datacenter")  # datacenter|branch|office|vps|cloud|internet
    location: Mapped[str] = mapped_column(String(255), default="")
    wan: Mapped[str] = mapped_column(String(255), default="")
    vpn: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    sort: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Asset(Base):
    """Mọi thứ có thể hosted on bản đồ: firewall, switch, host, VM, NAS, AP, UPS, service, website..."""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(32), default="other")
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    ip: Mapped[str] = mapped_column(String(128), default="")
    vendor: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    os: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    location: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # up|down|warning|unknown|off
    backup: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_note: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(64), default="manual")  # manual | esxi:<check_id> ...
    external_id: Mapped[str] = mapped_column(String(128), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class CriticalSystem(Base):
    __tablename__ = "critical_systems"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    layer: Mapped[str] = mapped_column(String(64), default="Application")
    level: Mapped[str] = mapped_column(String(16), default="High")  # High|Medium|Low
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    hosted_externally: Mapped[bool] = mapped_column(Boolean, default=False)
    external_note: Mapped[str] = mapped_column(String(128), default="")
    backup: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_note: Mapped[str] = mapped_column(String(255), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    url: Mapped[str] = mapped_column(String(255), default="")
    depends_on: Mapped[list] = mapped_column(JSON, default=list)  # list of critical system ids
    check_ids: Mapped[list] = mapped_column(JSON, default=list)
    runbook: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Check(Base):
    __tablename__ = "checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(32))  # ping|tcp|http|snmp|ssh|esxi|pfsense
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    interval: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # ok|warn|fail|unknown
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)  # attention|trouble|critical|down
    last_checked: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_message: Mapped[str] = mapped_column(Text, default="")
    last_latency: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_data: Mapped[dict] = mapped_column(JSON, default=dict)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class CheckResult(Base):
    __tablename__ = "check_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    status: Mapped[str] = mapped_column(String(16))
    latency: Mapped[float | None] = mapped_column(Float, nullable=True)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str] = mapped_column(String(500), default="")
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {cpu, mem, disk} – lịch sử tài nguyên
    down: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # True = DOWN thật (tính uptime). NULL = bản ghi cũ
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    __table_args__ = (Index("ix_results_check_ts", "check_id", "ts"),)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_opened", "status", "opened_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(16), default="check")  # check | event
    event_rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    check_id: Mapped[int | None] = mapped_column(ForeignKey("checks.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="critical")  # down|critical|trouble|attention (+ warning: log rule cũ)
    metric: Mapped[str | None] = mapped_column(String(16), nullable=True)   # cpu|mem|disk – alerts tài nguyên
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|resolved
    acked_by: Mapped[str] = mapped_column(String(64), default="")
    acked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)          # để tính MTTA
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)                   # tự động hoá đã chặn gửi tin
    suppress_reason: Mapped[str] = mapped_column(String(255), default="")
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)                  # INC-03: đã leo thang tới step nào
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False)                  # đã báo quá hạn SLA ack
    actor: Mapped[str] = mapped_column(String(64), default="")                          # alerts audit: người thực hiện thao tác
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_ts", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    user: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(32))
    entity: Mapped[str] = mapped_column(String(32), default="")
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    # 5W1H: Ở đâu (ip, user_agent) · Như thế nào (changes: trước/sau) · Tại sao (reason)
    ip: Mapped[str] = mapped_column(String(64), default="", server_default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="", server_default="")
    changes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="", server_default="")


class Event(Base):
    """Log/trap do devices đẩy về (syslog, SNMP trap)."""
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)          # lúc nhận
    device_ts: Mapped[str] = mapped_column(String(40), default="")     # thời gian devices ghi (nguyên văn)
    kind: Mapped[str] = mapped_column(String(8), default="syslog")     # syslog | trap
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    site_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    facility: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[int] = mapped_column(Integer, default=6)          # 0 emerg … 7 debug
    host: Mapped[str] = mapped_column(String(128), default="")
    app: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_events_ts", "ts"), Index("ix_events_asset_ts", "asset_id", "ts"),
                      Index("ix_events_sev_ts", "severity", "ts"), Index("ix_events_src", "source_ip"))


class EventRule(Base):
    __tablename__ = "event_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    action: Mapped[str] = mapped_column(String(8), default="alert")     # alert | drop
    kind: Mapped[str] = mapped_column(String(8), default="any")        # any | syslog | trap
    max_severity: Mapped[int] = mapped_column(Integer, default=7)      # khớp khi severity <= value (0=emerg)
    pattern: Mapped[str] = mapped_column(String(500), default="")      # regex, có thể có nhóm (?P<key>...)
    app_pattern: Mapped[str] = mapped_column(String(200), default="")
    trap_oids: Mapped[str] = mapped_column(String(500), default="")    # danh sách OID, cách nhau dấu phẩy
    resolve_pattern: Mapped[str] = mapped_column(String(500), default="")
    resolve_trap_oids: Mapped[str] = mapped_column(String(500), default="")
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    site_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_severity: Mapped[str] = mapped_column(String(16), default="warning")
    threshold: Mapped[int] = mapped_column(Integer, default=1)          # số times within window
    window_min: Mapped[int] = mapped_column(Integer, default=5)
    auto_resolve_min: Mapped[int] = mapped_column(Integer, default=0)   # 0 = không auto-resolved theo thời gian
    group_by: Mapped[str] = mapped_column(String(16), default="")       # "" = khoá from regex | src_ip = gộp theo IP source trong log
    key_filter: Mapped[str] = mapped_column(String(1000), default="")   # chỉ báo khi khoá nằm trong danh sách (cách nhau dấu phẩy)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=now, nullable=True)
    sort: Mapped[int] = mapped_column(Integer, default=100)


# ---------------------------------------------------------------- tự động hoá
class Automation(Base):
    """Một workflow tự động hoá: from template (code = RPT-01...) hoặc tự tạo (code = CUSTOM)."""
    __tablename__ = "automations"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(16), default="CUSTOM")
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    spec: Mapped[dict] = mapped_column(JSON, default=dict)        # trigger / scope / params / actions / level
    state: Mapped[dict] = mapped_column(JSON, default=dict)       # bộ nhớ nội bộ (đã nhắc, đã báo flapping...)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="")
    last_summary: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class AutomationRun(Base):
    __tablename__ = "automation_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    automation_id: Mapped[int] = mapped_column(ForeignKey("automations.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")   # schedule|event|interval|hook|manual|test
    status: Mapped[str] = mapped_column(String(16), default="ok")          # ok|skipped|error
    summary: Mapped[str] = mapped_column(String(500), default="")
    output: Mapped[str] = mapped_column(Text, default="")
    sent: Mapped[dict] = mapped_column(JSON, default=dict)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)


class DailyUptime(Base):
    """Gộp theo days (hours VN) để làm báo cáo tuần/tháng mà không phải giữ mọi bản ghi thô."""
    __tablename__ = "daily_uptime"
    check_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)        # YYYY-MM-DD
    total: Mapped[int] = mapped_column(Integer, default=0)
    down: Mapped[int] = mapped_column(Integer, default=0)
    down_minutes: Mapped[float] = mapped_column(Float, default=0)


# ================================================================ AGENT MÁY TRẠM (ADR 0004)
# Agent chỉ GỬI LÊN, chỉ đọc. Server không có kênh ra lệnh cho machines trạm.
class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True)             # định danh machines do agent tạo (giữ qua cài lại)
    key_hash: Mapped[str] = mapped_column(String(64))                     # SHA-256 khoá riêng of machines
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    os_family: Mapped[str] = mapped_column(String(16), default="")         # windows | linux | darwin
    os_name: Mapped[str] = mapped_column(String(255), default="")
    os_version: Mapped[str] = mapped_column(String(128), default="")
    os_kind: Mapped[str] = mapped_column(String(16), default="client")     # client | server
    arch: Mapped[str] = mapped_column(String(16), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")                # IP nguồn server thấy
    ips: Mapped[list] = mapped_column(JSON, default=list)                  # IP các card mạng do agent báo
    macs: Mapped[list] = mapped_column(JSON, default=list, server_default="[]")   # MAC các card mạng có IP (agent ≥ 1.0.4)
    manufacturer: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    cpu_model: Mapped[str] = mapped_column(String(255), default="")
    cpu_cores: Mapped[int] = mapped_column(Integer, default=0)
    ram_mb: Mapped[int] = mapped_column(Integer, default=0)
    logged_user: Mapped[str] = mapped_column(String(128), default="")      # người đang dùng machines (sessions console/RDP)
    # --- chuẩn hoá cho module CVE (app/inventory.py)
    machine_id: Mapped[str] = mapped_column(String(64), default="", index=True)   # MachineGuid / /etc/machine-id
    os_release: Mapped[str] = mapped_column(String(32), default="")       # 23H2 | 22.04
    os_build: Mapped[str] = mapped_column(String(32), default="")         # 22631
    os_ubr: Mapped[int | None] = mapped_column(Integer, nullable=True)    # 4317 = mức bản vá tích luỹ Windows
    last_user: Mapped[str] = mapped_column(String(128), default="")       # người dùng gần nhất (giữ khi đã sign-out)
    last_user_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    user_source: Mapped[str] = mapped_column(String(16), default="")      # console | rdp | "" (agent cũ không báo)
    boot_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)             # số liệu mới nhất: cpu, mem, disks, defender...
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    tags: Mapped[str] = mapped_column(String(255), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    alert_offline: Mapped[bool | None] = mapped_column(Boolean, nullable=True)   # None = theo loại machines (server: có)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_report_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[str] = mapped_column(String(64), default="")


class AgentEnrollRequest(Base):
    """Yêu cầu đăng ký ĐÈ lên một máy ĐÃ CÓ (agent mới – uid khác – nhưng trùng tên + machine-id/serial):
    cài lại agent / cài lại Windows, hoặc kẻ giả làm máy thật (đăng ký mở). Máy cũ giữ nguyên khoá tới khi IT duyệt."""
    __tablename__ = "agent_enroll_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)   # máy sẽ bị đè
    uid: Mapped[str] = mapped_column(String(64), index=True)             # uid của agent mới xin đăng ký
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os_family: Mapped[str] = mapped_column(String(16), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    system: Mapped[dict] = mapped_column(JSON, default=dict)               # thông tin máy agent mới gửi (để IT so sánh)
    ip: Mapped[str] = mapped_column(String(64), default="")                # IP nguồn server thấy
    matched_by: Mapped[str] = mapped_column(String(32), default="")        # machine_id | serial
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)   # pending|approved|rejected|expired|completed
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentMetric(Base):
    __tablename__ = "agent_metrics"
    __table_args__ = (Index("ix_agent_metrics_agent_ts", "agent_id", "ts"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    cpu: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk: Mapped[float | None] = mapped_column(Float, nullable=True)       # % disk đầy nhất


class AgentInventory(Base):
    """Ảnh chụp mới nhất theo loại: services | defender | updates | system. Phần mềm nằm ở agent_software (tìm kiếm)."""
    __tablename__ = "agent_inventory"
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    hash: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class AgentSoftware(Base):
    __tablename__ = "agent_software"
    __table_args__ = (Index("ix_agent_software_name", "name"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(128), default="")
    publisher: Mapped[str] = mapped_column(String(255), default="")
    installed_on: Mapped[str] = mapped_column(String(32), default="")
    source: Mapped[str] = mapped_column(String(32), default="")           # registry | msi | dpkg | rpm | app ...
    source_pkg: Mapped[str] = mapped_column(String(255), default="")      # gói nguồn (dpkg source / SRPM) – khớp OVAL/USN
    norm_name: Mapped[str] = mapped_column(String(255), default="", index=True)
    norm_vendor: Mapped[str] = mapped_column(String(128), default="")
    norm_version: Mapped[str] = mapped_column(String(128), default="")


class AgentEvent(Base):
    """Sự kiện ĐÃ LỌC (ADR 0004) – đã dịch sang tiếng Việt and gom các lần lặp lại."""
    __tablename__ = "agent_events"
    __table_args__ = (Index("ix_agent_events_agent_ts", "agent_id", "ts"), Index("ix_agent_events_key_ts", "catalog_key", "ts"),
                      Index("ix_agent_events_group", "agent_id", "group_key", "last_ts"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)                        # lần đầu (hours UTC of machines trạm)
    last_ts: Mapped[datetime] = mapped_column(DateTime)                   # lần gần nhất trong nhóm
    count: Mapped[int] = mapped_column(Integer, default=1)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    catalog_key: Mapped[str] = mapped_column(String(48), default="")      # e.g. win:security:4625
    group_key: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(32), default="")         # account | system | security | disk | service
    severity: Mapped[str] = mapped_column(String(16), default="info")     # info | attention | trouble | critical
    title: Mapped[str] = mapped_column(String(255), default="")
    who: Mapped[str] = mapped_column(String(255), default="")             # Ai
    where: Mapped[str] = mapped_column(String(255), default="")           # Source
    what: Mapped[str] = mapped_column(Text, default="")                   # Chuyện gì
    advice: Mapped[str] = mapped_column(Text, default="")                 # Recommended action gì
    channel: Mapped[str] = mapped_column(String(128), default="")
    provider: Mapped[str] = mapped_column(String(255), default="")
    event_id: Mapped[int] = mapped_column(Integer, default=0)
    record_id: Mapped[int] = mapped_column(BigInteger, default=0)
    message: Mapped[str] = mapped_column(Text, default="")                # câu gốc of hệ điều hành (rút gọn)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)


class Cve(Base):
    """CVE catalogue (CVE module part 2): NVD details + CISA KEV + FIRST EPSS, refreshed by app/cve.py."""
    __tablename__ = "cves"
    __table_args__ = (Index("ix_cves_published", "published"), Index("ix_cves_kev", "kev"),
                      Index("ix_cves_severity", "cvss_severity"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    published: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="")              # NVD vulnStatus (Analyzed, Awaiting Analysis…)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str] = mapped_column(String(16), default="")      # critical | high | medium | low | none | ""
    cvss_version: Mapped[str] = mapped_column(String(8), default="")
    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    products: Mapped[list] = mapped_column(JSON, default=list)               # ["vendor:product", …] from NVD CPE / KEV
    references: Mapped[list] = mapped_column(JSON, default=list)             # [{url, tags}] (max 15)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)                # in CISA Known Exploited Vulnerabilities
    kev_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_due: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_name: Mapped[str] = mapped_column(String(255), default="")
    kev_action: Mapped[str] = mapped_column(Text, default="")
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)         # probability of exploitation in 30 days (0–1)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpe_match: Mapped[list] = mapped_column(JSON, default=list)              # vulnerable NVD CPE criteria + version ranges (part 3)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Advisory(Base):
    """Remediation Mapping: structured vendor advisory data per (source, CVE) – e.g. Microsoft MSRC (KB, fixed build).
    A cache: rebuilt from the vendor API at any time; never the only copy of anything."""
    __tablename__ = "advisories"
    __table_args__ = (Index("ux_advisories_source_cve", "source", "cve_id", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(16))                           # msrc | …
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    doc_id: Mapped[str] = mapped_column(String(64), default="")               # MSRC: release document, e.g. 2024-Aug
    data: Mapped[dict] = mapped_column(JSON, default=dict)                    # parsed, source-neutral fields
    found: Mapped[bool] = mapped_column(Boolean, default=True)                # False = vendor has no record (cached miss)
    error: Mapped[str] = mapped_column(String(300), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class VulnSource(Base):
    """CVE module part 3: a replaceable source of vulnerability results (Wazuh, file import, IT Ops CPE matching…).
    Sources only feed detections; priority is always computed by IT Ops from the CVE catalogue (never from the source)."""
    __tablename__ = "vuln_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))                             # wazuh | file | cpe
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[str] = mapped_column(String(8), default="high")        # high | medium | low – how sure a detection is true
    config: Mapped[dict] = mapped_column(JSON, default=dict)                  # secrets sealed (enc2:)
    state: Mapped[dict] = mapped_column(JSON, default=dict)                   # last run, counts, unmatched hosts, version
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class VulnFinding(Base):
    """One CVE on one machine. Keyed by (target, CVE) – NOT by source – so changing tools keeps first_seen, triage and history."""
    __tablename__ = "vuln_findings"
    __table_args__ = (Index("ux_vuln_findings_target_cve", "target", "cve_id", unique=True),
                      Index("ix_vuln_findings_status", "status"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    target: Mapped[str] = mapped_column(String(32))                           # agent:<id> | asset:<id>
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open")           # open | fixed | source_off
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reopened: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(8), default="high")        # best confidence among active detections
    sources_active: Mapped[int] = mapped_column(Integer, default=0)           # distinct enabled sources seeing it now
    verified: Mapped[bool] = mapped_column(Boolean, default=False)            # confirmed by a person
    triage: Mapped[str] = mapped_column(String(16), default="")               # "" | false_positive | accepted
    triage_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triage_note: Mapped[str] = mapped_column(Text, default="")
    triage_by: Mapped[str] = mapped_column(String(64), default="")
    triage_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    provider_score: Mapped[float | None] = mapped_column(Float, nullable=True)   # reference only – not used for priority
    provider_severity: Mapped[str] = mapped_column(String(16), default="")
    packages: Mapped[list] = mapped_column(JSON, default=list)                # ["openssl 3.0.2", …]
    # part 4 – computed by IT Ops (app/vuln_policy.py), never taken from a source
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)     # 0–100
    sla_category: Mapped[str] = mapped_column(String(16), default="")         # kev | critical | high | medium | low | unscored
    sla_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   # when the finding was confirmed
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class VulnDetection(Base):
    """What one source says about one finding (one row per package)."""
    __tablename__ = "vuln_detections"
    __table_args__ = (Index("ux_vuln_det", "finding_id", "source_id", "package", unique=True),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("vuln_findings.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("vuln_sources.id", ondelete="CASCADE"), index=True)
    package: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    fixed_version: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   # as reported by the source


# ---------------------------------------------------------------- monitoring reports
# Raw check_results are kept RETENTION_DAYS (default 14). These small summaries are kept ~1 year so
# 7/14/30-day uptime reports work after the raw rows are gone (1 row per check per day + 1 row per outage).
class CheckDaily(Base):
    __tablename__ = "check_daily"
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[datetime] = mapped_column(DateTime, primary_key=True)        # 00:00 UTC of that day
    total: Mapped[int] = mapped_column(Integer, default=0)                   # check runs
    down: Mapped[int] = mapped_column(Integer, default=0)                    # runs that were DOWN (counted against uptime)
    lat_n: Mapped[int] = mapped_column(Integer, default=0)
    lat_sum: Mapped[float] = mapped_column(Float, default=0.0)
    lat_min: Mapped[float | None] = mapped_column(Float, nullable=True)
    lat_max: Mapped[float | None] = mapped_column(Float, nullable=True)


class CheckOutage(Base):
    __tablename__ = "check_outages"
    id: Mapped[int] = mapped_column(primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    start: Mapped[datetime] = mapped_column(DateTime, index=True)            # first DOWN result
    end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)    # first result back UP; NULL = still down
    message: Mapped[str] = mapped_column(String(500), default="")


# ---------------------------------------------------------------- Network traffic (NetFlow / IPFIX via GoFlow2) – 2.10.0
# Flow records are summed per minute in memory (app/flows.py) and written here. Only traffic with at least one
# local address is kept (post-NAT / WAN copies are dropped). Not part of the daily backup (dbdump.SKIP_TABLES).
class FlowMinute(Base):
    """1-minute totals per (exporter, interface, local IP, remote IP, protocol, service port, direction). Kept FLOW keep_minute_days."""
    __tablename__ = "flow_1m"
    __table_args__ = (Index("ix_flow_1m_ts", "ts", postgresql_using="brin"),
                      Index("ix_flow_1m_local_ts", "local_ip", "ts"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime)                       # start of the minute (UTC)
    exporter: Mapped[str] = mapped_column(String(45))                    # IP that sent the flow (pfSense)
    if_index: Mapped[int] = mapped_column(Integer, default=0)            # interface number as the exporter reports it
    local_ip: Mapped[str] = mapped_column(String(45))
    remote_ip: Mapped[str] = mapped_column(String(45))
    proto: Mapped[int] = mapped_column(Integer, default=0)
    port: Mapped[int] = mapped_column(Integer, default=0)                # service port (the lower of the two ports)
    direction: Mapped[str] = mapped_column(String(1))                   # o = with the Internet (both ways) · l = local ↔ local
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)        # local → remote
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)         # remote → local
    pkts_out: Mapped[int] = mapped_column(BigInteger, default=0)
    pkts_in: Mapped[int] = mapped_column(BigInteger, default=0)
    flows: Mapped[int] = mapped_column(Integer, default=0)


class FlowHour(Base):
    """Hourly roll-up without the remote IP (keeps long history small). Kept FLOW keep_hour_days."""
    __tablename__ = "flow_1h"
    __table_args__ = (Index("ix_flow_1h_ts", "ts", postgresql_using="brin"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime)
    exporter: Mapped[str] = mapped_column(String(45))
    if_index: Mapped[int] = mapped_column(Integer, default=0)
    local_ip: Mapped[str] = mapped_column(String(45))
    proto: Mapped[int] = mapped_column(Integer, default=0)
    port: Mapped[int] = mapped_column(Integer, default=0)
    direction: Mapped[str] = mapped_column(String(1))
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)
    pkts_out: Mapped[int] = mapped_column(BigInteger, default=0)
    pkts_in: Mapped[int] = mapped_column(BigInteger, default=0)
    flows: Mapped[int] = mapped_column(Integer, default=0)
    remotes: Mapped[int] = mapped_column(Integer, default=0)            # distinct remote IPs in that hour


class FlowExporter(Base):
    """A device that sends flows (e.g. pfSense) and the interfaces it reported, with names IT gave them."""
    __tablename__ = "flow_exporters"
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    flows_total: Mapped[int] = mapped_column(BigInteger, default=0)
    interfaces: Mapped[dict] = mapped_column(JSON, default=dict)        # {"15": {"last_seen": iso, "bytes": n}}
    if_names: Mapped[dict] = mapped_column(JSON, default=dict)          # {"15": "em0.15 TTS_Vlan15"} – set by IT
