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
    # 2FA (TOTP). Bí mật lưu đã mã hoá (AES-256-GCM, tiền tố enc2:), không bao giờ trả ra API sau khi đã bật.
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_pending: Mapped[str | None] = mapped_column(Text, nullable=True)   # bí mật đang chờ xác nhận khi bật 2FA
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, server_default="0")   # chống dùng lại mã OTP


class LoginSession(Base):
    """Phiên đăng nhập phía server: thu hồi được, hết hạn khi không thao tác (idle timeout)."""
    __tablename__ = "login_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)          # jti trong JWT
    username: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    mfa: Mapped[bool] = mapped_column(Boolean, default=False)              # đã qua bước OTP
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
    """Mọi thứ có thể nằm trên bản đồ: firewall, switch, host, VM, NAS, AP, UPS, dịch vụ, website..."""
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
    layer: Mapped[str] = mapped_column(String(64), default="Ứng dụng")
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
    severity: Mapped[str] = mapped_column(String(16), default="critical")  # down|critical|trouble|attention (+ warning: rule log cũ)
    metric: Mapped[str | None] = mapped_column(String(16), nullable=True)   # cpu|mem|disk – cảnh báo tài nguyên
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|resolved
    acked_by: Mapped[str] = mapped_column(String(64), default="")
    acked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)          # để tính MTTA
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)                   # tự động hoá đã chặn gửi tin
    suppress_reason: Mapped[str] = mapped_column(String(255), default="")
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)                  # INC-03: đã leo thang tới bước nào
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False)                  # đã báo quá hạn SLA ack
    actor: Mapped[str] = mapped_column(String(64), default="")                          # cảnh báo audit: người thực hiện thao tác
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
    """Log/trap do thiết bị đẩy về (syslog, SNMP trap)."""
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)          # lúc nhận
    device_ts: Mapped[str] = mapped_column(String(40), default="")     # thời gian thiết bị ghi (nguyên văn)
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
    max_severity: Mapped[int] = mapped_column(Integer, default=7)      # khớp khi severity <= giá trị (0=emerg)
    pattern: Mapped[str] = mapped_column(String(500), default="")      # regex, có thể có nhóm (?P<key>...)
    app_pattern: Mapped[str] = mapped_column(String(200), default="")
    trap_oids: Mapped[str] = mapped_column(String(500), default="")    # danh sách OID, cách nhau dấu phẩy
    resolve_pattern: Mapped[str] = mapped_column(String(500), default="")
    resolve_trap_oids: Mapped[str] = mapped_column(String(500), default="")
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    site_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_severity: Mapped[str] = mapped_column(String(16), default="warning")
    threshold: Mapped[int] = mapped_column(Integer, default=1)          # số lần trong window
    window_min: Mapped[int] = mapped_column(Integer, default=5)
    auto_resolve_min: Mapped[int] = mapped_column(Integer, default=0)   # 0 = không tự đóng theo thời gian
    group_by: Mapped[str] = mapped_column(String(16), default="")       # "" = khoá từ regex | src_ip = gộp theo IP source trong log
    key_filter: Mapped[str] = mapped_column(String(1000), default="")   # chỉ báo khi khoá nằm trong danh sách (cách nhau dấu phẩy)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=now, nullable=True)
    sort: Mapped[int] = mapped_column(Integer, default=100)


# ---------------------------------------------------------------- tự động hoá
class Automation(Base):
    """Một kịch bản tự động hoá: từ template (code = RPT-01...) hoặc tự tạo (code = CUSTOM)."""
    __tablename__ = "automations"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(16), default="CUSTOM")
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    spec: Mapped[dict] = mapped_column(JSON, default=dict)        # trigger / scope / params / actions / level
    state: Mapped[dict] = mapped_column(JSON, default=dict)       # bộ nhớ nội bộ (đã nhắc, đã báo chập chờn...)
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
    """Gộp theo ngày (giờ VN) để làm báo cáo tuần/tháng mà không phải giữ mọi bản ghi thô."""
    __tablename__ = "daily_uptime"
    check_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)        # YYYY-MM-DD
    total: Mapped[int] = mapped_column(Integer, default=0)
    down: Mapped[int] = mapped_column(Integer, default=0)
    down_minutes: Mapped[float] = mapped_column(Float, default=0)


# ================================================================ AGENT MÁY TRẠM (ADR 0004)
# Agent chỉ GỬI LÊN, chỉ đọc. Server không có kênh ra lệnh cho máy trạm.
class AgentEnrollToken(Base):
    """Token đăng ký dùng chung cho một đợt cài (GPO/script). Chỉ lưu SHA-256; chuỗi gốc hiện đúng 1 lần lúc tạo."""
    __tablename__ = "agent_enroll_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(12), default="")            # vài ký tự đầu để nhận diện
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    tags: Mapped[str] = mapped_column(String(255), default="")             # gắn cho máy đăng ký bằng token này
    max_uses: Mapped[int] = mapped_column(Integer, default=0)              # 0 = không giới hạn
    uses: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True)             # định danh máy do agent tạo (giữ qua cài lại)
    key_hash: Mapped[str] = mapped_column(String(64))                     # SHA-256 khoá riêng của máy
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
    manufacturer: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    cpu_model: Mapped[str] = mapped_column(String(255), default="")
    cpu_cores: Mapped[int] = mapped_column(Integer, default=0)
    ram_mb: Mapped[int] = mapped_column(Integer, default=0)
    logged_user: Mapped[str] = mapped_column(String(128), default="")      # người đang dùng máy (phiên console)
    boot_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)             # số liệu mới nhất: cpu, mem, disks, defender...
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    token_id: Mapped[int | None] = mapped_column(ForeignKey("agent_enroll_tokens.id", ondelete="SET NULL"), nullable=True)
    tags: Mapped[str] = mapped_column(String(255), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    alert_offline: Mapped[bool | None] = mapped_column(Boolean, nullable=True)   # None = theo loại máy (server: có)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_report_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[str] = mapped_column(String(64), default="")


class AgentMetric(Base):
    __tablename__ = "agent_metrics"
    __table_args__ = (Index("ix_agent_metrics_agent_ts", "agent_id", "ts"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime, default=now)
    cpu: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk: Mapped[float | None] = mapped_column(Float, nullable=True)       # % ổ đầy nhất


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


class AgentEvent(Base):
    """Sự kiện ĐÃ LỌC (ADR 0004) – đã dịch sang tiếng Việt và gom các lần lặp lại."""
    __tablename__ = "agent_events"
    __table_args__ = (Index("ix_agent_events_agent_ts", "agent_id", "ts"), Index("ix_agent_events_key_ts", "catalog_key", "ts"),
                      Index("ix_agent_events_group", "agent_id", "group_key", "last_ts"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)                        # lần đầu (giờ UTC của máy trạm)
    last_ts: Mapped[datetime] = mapped_column(DateTime)                   # lần gần nhất trong nhóm
    count: Mapped[int] = mapped_column(Integer, default=1)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    catalog_key: Mapped[str] = mapped_column(String(48), default="")      # vd. win:security:4625
    group_key: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(32), default="")         # account | system | security | disk | service
    severity: Mapped[str] = mapped_column(String(16), default="info")     # info | attention | trouble | critical
    title: Mapped[str] = mapped_column(String(255), default="")
    who: Mapped[str] = mapped_column(String(255), default="")             # Ai
    where: Mapped[str] = mapped_column(String(255), default="")           # Từ đâu
    what: Mapped[str] = mapped_column(Text, default="")                   # Chuyện gì
    advice: Mapped[str] = mapped_column(Text, default="")                 # Nên làm gì
    channel: Mapped[str] = mapped_column(String(128), default="")
    provider: Mapped[str] = mapped_column(String(255), default="")
    event_id: Mapped[int] = mapped_column(Integer, default=0)
    record_id: Mapped[int] = mapped_column(BigInteger, default=0)
    message: Mapped[str] = mapped_column(Text, default="")                # câu gốc của hệ điều hành (rút gọn)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
