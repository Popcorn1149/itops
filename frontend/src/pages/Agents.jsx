import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import {
  Laptop, Server, Search, ShieldCheck, ShieldAlert, HardDrive, Wifi, WifiOff, Download, KeyRound, Plus, Copy, Trash2,
  Ban, AlertTriangle, Package, ListChecks, Settings2, User, MapPin, Lightbulb, Info, Monitor,
} from "lucide-react";
import { useApp } from "../App";
import { api } from "../api";
import { useUi, chartColors } from "../theme";
import {
  useApi, PageHead, Stat, Table, Tabs, Drawer, Modal, Field, Input, Select, Toggle, Empty, UsageBar, SevBadge, timeAgo, fmtTime,
  useToast, askConfirm,
} from "../ui";

const OS_LABEL = { windows: "Windows", linux: "Linux", darwin: "macOS" };
const STATUS = { online: ["Đang kết nối", "ok"], offline: ["Mất kết nối", "fail"], never: ["Chưa gửi dữ liệu", ""], revoked: ["Đã thu hồi", "warn"] };
const CAT = { account: "Tài khoản", security: "Bảo mật", system: "Hệ thống", service: "Dịch vụ", disk: "Ổ đĩa" };
const lvl = (p, warn = 85, crit = 95) => (p == null ? undefined : p >= crit ? "fail" : p >= warn ? "warn" : "ok");
const fmtSize = (b) => (b > 1 << 20 ? `${(b / (1 << 20)).toFixed(1)} MB` : `${Math.round(b / 1024)} KB`);
const uptime = (s) => (s == null ? "—" : s >= 86400 ? `${Math.floor(s / 86400)} ngày ${Math.floor((s % 86400) / 3600)} giờ` : `${Math.floor(s / 3600)} giờ ${Math.floor((s % 3600) / 60)} phút`);

function StatusBadge({ s, last }) {
  const [l, c] = STATUS[s] || [s, ""];
  return <span className={`badge ${c}`} title={last ? `Lần cuối: ${fmtTime(last)}` : ""}>{l}</span>;
}

function DefenderBadge({ d, os }) {
  if (os !== "windows") return <span className="faint small">—</span>;
  if (!d) return <span className="faint small">chưa có</span>;
  if (d.other_av) return <span className="badge info" title={`Phần mềm diệt virus khác: ${d.other_av}`}>{d.other_av.split(",")[0]}</span>;
  if (d.realtime === false) return <span className="badge fail">Defender TẮT</span>;
  if (d.signature_age_days > 3) return <span className="badge warn">Mẫu cũ {d.signature_age_days} ngày</span>;
  return <span className="badge ok">Defender bật</span>;
}

// CPU · RAM · ổ đầy nhất – gọn trong một cột, tô màu khi cao
function Perf({ a }) {
  const on = a.status === "online";
  const cell = (v, l, name) => (v == null ? <span className="faint">—</span>
    : <span title={name} style={{ color: l === "fail" ? "var(--critical)" : l === "warn" ? "var(--trouble)" : undefined, fontWeight: l === "ok" ? 400 : 600 }}>{Math.round(v)}%</span>);
  return (
    <span className="small mono" style={{ whiteSpace: "nowrap" }}>
      {cell(on ? a.cpu : null, lvl(a.cpu), "CPU")} · {cell(on ? a.mem : null, lvl(a.mem, 90, 97), "RAM")} · {cell(a.disk, lvl(a.disk, 90, 95), "Ổ đầy nhất")}
    </span>
  );
}

function MachineIcon({ a }) {
  const I = a.os_kind === "server" ? Server : a.os_family === "darwin" ? Laptop : Monitor;
  return <I size={16} style={{ color: a.status === "online" ? "var(--ok)" : "var(--muted)", flexShrink: 0 }} />;
}

// ---------------------------------------------------------------- sự kiện dễ đọc
export function EventCard({ e, showHost }) {
  const [raw, setRaw] = useState(false);
  return (
    <div className="card card-pad" style={{ marginBottom: 10, borderLeft: `3px solid var(--${e.severity === "info" ? "border" : e.severity === "attention" ? "attention" : e.severity === "trouble" ? "trouble" : "critical"})` }}>
      <div className="row wrap" style={{ gap: 8, marginBottom: 6 }}>
        {e.severity !== "info" ? <SevBadge sev={e.severity}>{({ attention: "Cần chú ý", trouble: "Có vấn đề", critical: "Nghiêm trọng" })[e.severity]}</SevBadge> : <span className="badge">Thông tin</span>}
        <b>{e.title}</b>
        {e.count > 1 && <span className="badge info" title="Các lần giống nhau trong thời gian ngắn được gộp lại">×{e.count}</span>}
        {showHost && <span className="chip">{e.hostname}</span>}
        <span className="small muted" style={{ marginLeft: "auto" }} title={e.count > 1 ? `Lần đầu ${fmtTime(e.ts)} · lần cuối ${fmtTime(e.last_ts)}` : fmtTime(e.ts)}>
          {e.count > 1 ? `${fmtTime(e.ts)} → ${fmtTime(e.last_ts)}` : fmtTime(e.ts)}
        </span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 10px", fontSize: 13.5 }}>
        <span className="muted row" style={{ gap: 4 }}><User size={13} />Ai</span><span>{e.who || "—"}</span>
        <span className="muted row" style={{ gap: 4 }}><MapPin size={13} />Từ đâu</span><span>{e.where || "—"}</span>
        <span className="muted row" style={{ gap: 4 }}><Info size={13} />Chuyện gì</span><span>{e.what}</span>
        <span className="muted row" style={{ gap: 4 }}><Lightbulb size={13} />Nên làm gì</span><span>{e.advice}</span>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <span className="small faint">{CAT[e.category] || e.category}{e.event_id ? ` · Event ID ${e.event_id}` : ""}{e.channel ? ` · ${e.channel}` : ""}</span>
        {(e.message || Object.keys(e.data || {}).length > 0) && <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={() => setRaw(!raw)}>{raw ? "Ẩn" : "Xem"} bản gốc</button>}
      </div>
      {raw && <pre className="small mono" style={{ whiteSpace: "pre-wrap", maxHeight: 260, overflow: "auto", background: "var(--subtle)", padding: 8, borderRadius: 8 }}>
        {e.message ? e.message + "\n\n" : ""}{JSON.stringify(e.data, null, 1)}</pre>}
    </div>
  );
}

function EventsView({ agentId, hostCol }) {
  const [sev, setSev] = useState("attention,trouble,critical");
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const [hours, setHours] = useState(72);
  const qs = new URLSearchParams({ hours, limit: 300, ...(agentId ? { agent_id: agentId } : {}), ...(sev ? { severity: sev } : {}), ...(cat ? { category: cat } : {}), ...(q ? { q } : {}) });
  const { data } = useApi(`/agent-events?${qs}`, { interval: 30000, deps: [sev, cat, q, hours] });
  return (
    <>
      <div className="toolbar wrap">
        <div className="search" style={{ width: 260 }}><Search size={16} /><input placeholder="Tìm người dùng, máy, nội dung..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Select value={sev} onChange={setSev} options={[["attention,trouble,critical", "Cần xử lý"], ["critical", "Chỉ nghiêm trọng"], ["", "Tất cả (cả thông tin)"]]} />
        <Select value={cat} onChange={setCat} placeholder="Mọi nhóm" options={Object.entries(CAT)} />
        <div className="seg">{[[24, "24 giờ"], [72, "3 ngày"], [168, "7 ngày"], [720, "30 ngày"]].map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}</div>
      </div>
      <div className="small muted" style={{ margin: "4px 0 10px" }}>Chỉ gồm sự kiện cần người xử lý – không có đăng nhập/đăng xuất thường ngày. Sự kiện giống nhau trong thời gian ngắn được gộp (×số lần).</div>
      {data && !data.length && <Empty icon={ShieldCheck} title="Không có sự kiện nào trong khoảng này" />}
      {(data || []).map((e) => <EventCard key={e.id} e={e} showHost={hostCol} />)}
    </>
  );
}

// ---------------------------------------------------------------- biểu đồ hiệu năng
function MetricChart({ id }) {
  const { theme } = useUi();
  const [hours, setHours] = useState(24);
  const { data } = useApi(`/agents/${id}/metrics?hours=${hours}`, { deps: [hours], interval: 60000 });
  const el = useRef();
  useEffect(() => {
    if (!el.current || !data?.length) return;
    const c = echarts.init(el.current);
    const T = chartColors();
    const col = { cpu: "#2563eb", mem: "#9333ea", disk: "#d97706" };
    c.setOption({
      grid: { left: 36, right: 12, top: 28, bottom: 24 },
      tooltip: { ...T.tooltip, trigger: "axis", valueFormatter: (v) => (v == null ? "—" : `${v}%`) },
      legend: { top: 0, left: 0, itemWidth: 14, itemHeight: 3, textStyle: { color: T.text2, fontSize: 11 } },
      xAxis: { type: "time", min: Date.now() - hours * 3600e3, max: Date.now(), axisLabel: { color: T.muted, fontSize: 10, hideOverlap: true } },
      yAxis: { type: "value", min: 0, max: 100, interval: 25, axisLabel: { color: T.muted, fontSize: 10, formatter: "{value}%" }, splitLine: { lineStyle: { color: T.line } } },
      series: [["cpu", "CPU"], ["mem", "RAM"], ["disk", "Ổ đầy nhất"]].map(([k, n]) => ({
        name: n, type: "line", showSymbol: data.length < 30, symbolSize: 4, smooth: 0.2, connectNulls: true,
        lineStyle: { width: 1.8, color: col[k] }, itemStyle: { color: col[k] }, data: data.map((p) => [p.ts, p[k]]),
      })),
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [data, theme, hours]);
  return (
    <div>
      <div className="row" style={{ marginBottom: 4 }}>
        <span className="small muted grow">Hiệu năng</span>
        <div className="seg">{[[6, "6 giờ"], [24, "24 giờ"], [168, "7 ngày"]].map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}</div>
      </div>
      {data && !data.length ? <div className="small faint" style={{ padding: 20 }}>Chưa có số liệu</div> : <div ref={el} style={{ height: 200 }} />}
    </div>
  );
}

// ---------------------------------------------------------------- chi tiết máy
function Overview({ a }) {
  const d = a.defender_detail;
  const p = a.posture || {};
  const fw = Array.isArray(p.firewall) ? p.firewall : null;
  return (
    <>
      <div className="kv" style={{ marginBottom: 14 }}>
        <div>Trạng thái</div><div><StatusBadge s={a.status} /> <span className="small muted">{a.last_seen ? `gửi lần cuối ${timeAgo(a.last_seen)}` : ""}</span></div>
        <div>Người đang dùng</div><div>{a.logged_user || <span className="faint">không có ai đăng nhập</span>}</div>
        <div>Hệ điều hành</div><div>{a.os_name} <span className="muted small">{a.os_version}</span> · {a.os_kind === "server" ? "máy chủ" : "máy trạm"}</div>
        <div>Phần cứng</div><div>{[a.manufacturer, a.model].filter(Boolean).join(" ") || "—"}{a.serial && <span className="muted small"> · S/N {a.serial}</span>}</div>
        <div>CPU · RAM</div><div>{a.cpu_model || "—"} · {a.cpu_cores} luồng · {a.ram_mb ? `${(a.ram_mb / 1024).toFixed(1)} GB` : "—"}</div>
        <div>Mạng</div><div className="mono small">{(a.ips || []).join(", ") || "—"} <span className="muted">(server thấy {a.ip})</span></div>
        <div>Chạy liên tục</div><div>{uptime(a.uptime_s)}{a.reboot_pending && <span className="badge warn" style={{ marginLeft: 8 }}>Chờ khởi động lại</span>}</div>
        <div>Agent</div><div className="small">{a.agent_version} · đăng ký {fmtTime(a.enrolled_at)}{a.site_name && ` · ${a.site_name}`}</div>
      </div>
      {a.alerts_open?.length > 0 && (
        <div className="alert-box" style={{ marginBottom: 14 }}>
          <b>Cảnh báo đang mở</b>
          {a.alerts_open.map((x) => <div key={x.id} className="row" style={{ gap: 8, marginTop: 4 }}><SevBadge sev={x.severity} /><span>{x.title}</span>{x.count > 1 && <span className="small muted">×{x.count}</span>}</div>)}
        </div>
      )}
      <div className="section-title" style={{ marginBottom: 8 }}>Ổ đĩa</div>
      {(a.disks || []).map((x) => (
        <div key={x.mount} className="row" style={{ gap: 10, marginBottom: 6 }}>
          <HardDrive size={15} className="muted" /><b style={{ width: 120 }}>{x.mount}</b>
          <UsageBar pct={x.used_pct} level={lvl(x.used_pct, 90, 95)} width={180} sub={`${x.total_gb} GB`} />
        </div>
      ))}
      <div style={{ margin: "14px 0" }}><MetricChart id={a.id} /></div>
      {a.os_family === "windows" && (
        <>
          <div className="section-title" style={{ marginBottom: 8 }}>Windows Defender</div>
          {!d ? <div className="small faint">Chưa có dữ liệu (agent gửi mỗi 15 phút).</div> : (
            <div className="kv">
              <div>Bảo vệ thời gian thực</div><div>{d.realtime ? <span className="badge ok">Bật</span> : <span className="badge fail">Tắt</span>}{d.running_mode && <span className="small muted"> · chế độ {d.running_mode}</span>}</div>
              {d.other_av && <><div>Phần mềm diệt virus khác</div><div>{d.other_av}</div></>}
              <div>Mẫu nhận diện virus</div><div>{d.signature_version || "—"} · {d.signature_age_days != null ? `${d.signature_age_days} ngày tuổi` : ""}</div>
              <div>Quét nhanh / toàn bộ</div><div>{d.quick_scan_age_days != null ? `${d.quick_scan_age_days} ngày trước` : "—"} / {d.full_scan_age_days != null && d.full_scan_age_days < 10000 ? `${d.full_scan_age_days} ngày trước` : "chưa quét"}</div>
              <div>Chống can thiệp (Tamper)</div><div>{d.tamper_protection ? "Bật" : "Tắt"}</div>
            </div>
          )}
        </>
      )}
      {(fw || p.bitlocker || p.filevault !== undefined || a.updates?.last_hotfix) && (
        <>
          <div className="section-title" style={{ marginTop: 14 }}>Bảo mật khác</div>
          <div className="kv">
            {fw && <><div>Tường lửa</div><div>{fw.map((f) => <span key={f.name} className={`badge ${f.enabled ? "ok" : "fail"}`} style={{ marginRight: 4 }}>{f.name}: {f.enabled ? "bật" : "TẮT"}</span>)}</div></>}
            {p.firewall === true || p.firewall === false ? <><div>Tường lửa</div><div>{p.firewall ? "Bật" : "Tắt"} {p.firewall_tool && <span className="muted small">({p.firewall_tool})</span>}</div></> : null}
            {p.bitlocker && <><div>BitLocker (ổ hệ thống)</div><div>{p.bitlocker.protection === "On" ? <span className="badge ok">Đã mã hoá</span> : <span className="badge warn">Chưa bật</span>} <span className="small muted">{p.bitlocker.status}</span></div></>}
            {p.filevault !== undefined && <><div>FileVault</div><div>{p.filevault ? "Bật" : "Tắt"}</div><div>Gatekeeper · SIP</div><div>{p.gatekeeper ? "Bật" : "Tắt"} · {p.sip ? "Bật" : "Tắt"}</div></>}
            {a.updates?.last_hotfix && <><div>Bản vá gần nhất</div><div>{a.updates.last_hotfix.id} · {a.updates.last_hotfix.installed_on}</div></>}
          </div>
        </>
      )}
    </>
  );
}

function Services({ id }) {
  const { data } = useApi(`/agents/${id}/services`);
  const [q, setQ] = useState("");
  const [only, setOnly] = useState(false);
  const rows = (data?.items || []).filter((s) => (!q || `${s.name} ${s.display}`.toLowerCase().includes(q.toLowerCase()))
    && (!only || (s.start?.startsWith("auto") && !["running", "exited"].includes(s.state))));
  return (
    <>
      <div className="toolbar">
        <div className="search" style={{ width: 240 }}><Search size={16} /><input placeholder="Tìm dịch vụ..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Toggle checked={only} onChange={setOnly} label="Chỉ dịch vụ tự chạy nhưng đang dừng" />
        <span className="small muted" style={{ marginLeft: "auto" }}>{data?.updated_at ? `cập nhật ${timeAgo(data.updated_at)}` : ""}</span>
      </div>
      <Table rowKey="name" rows={rows} empty={<Empty title="Chưa có danh sách dịch vụ" />} columns={[
        { key: "display", label: "Dịch vụ", render: (s) => <div><b>{s.display || s.name}</b>{s.display && <div className="small faint mono">{s.name}</div>}</div> },
        { key: "state", label: "Trạng thái", render: (s) => <span className={`badge ${s.state === "running" ? "ok" : s.state === "failed" ? "fail" : s.start?.startsWith("auto") && s.state !== "exited" ? "warn" : ""}`}>{({ running: "Đang chạy", stopped: "Đã dừng", failed: "Lỗi", exited: "Đã chạy xong" })[s.state] || s.state}</span> },
        { key: "start", label: "Khởi động", render: (s) => <span className="small">{({ auto: "Tự động", "auto-delayed": "Tự động (trễ)", manual: "Thủ công", disabled: "Tắt", static: "Theo dịch vụ khác", system: "Hệ thống" })[s.start] || s.start || "—"}</span> },
      ]} />
    </>
  );
}

function SoftwareOf({ id }) {
  const { data } = useApi(`/agents/${id}/software`);
  const [q, setQ] = useState("");
  const rows = (data || []).filter((s) => !q || `${s.name} ${s.publisher}`.toLowerCase().includes(q.toLowerCase())).map((s, i) => ({ ...s, id: i }));
  return (
    <>
      <div className="toolbar"><div className="search" style={{ width: 260 }}><Search size={16} /><input placeholder="Tìm phần mềm, nhà phát hành..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <span className="small muted" style={{ marginLeft: "auto" }}>{data ? `${data.length} phần mềm` : ""}</span></div>
      <Table rows={rows} empty={<Empty title="Chưa có danh sách phần mềm" />} columns={[
        { key: "name", label: "Tên", render: (s) => <b>{s.name}</b> },
        { key: "version", label: "Phiên bản", render: (s) => <span className="small mono">{s.version}</span> },
        { key: "publisher", label: "Nhà phát hành", render: (s) => <span className="small">{s.publisher}</span> },
        { key: "installed_on", label: "Ngày cài", render: (s) => <span className="small muted">{s.installed_on}</span> },
      ]} />
    </>
  );
}

function Manage({ a, onChanged, onClose }) {
  const { isAdmin } = useApp();
  const toast = useToast();
  const { data: sites } = useApi("/sites");
  const [f, setF] = useState({ tags: a.tags, note: a.note, site_id: a.site_id || "", os_kind: a.os_kind, alert_offline: a.alert_offline_auto ? "" : a.alert_offline ? "1" : "0" });
  const patch = async () => {
    try {
      await api.patch(`/agents/${a.id}`, { tags: f.tags, note: f.note, site_id: f.site_id || null, os_kind: f.os_kind,
        alert_offline: f.alert_offline === "" ? null : f.alert_offline === "1" });
      toast("Đã lưu"); onChanged();
    } catch (e) { toast(e.message, true); }
  };
  const revoke = async () => {
    if (!(await askConfirm({ title: `Thu hồi khoá agent của ${a.hostname}?`, message: "Máy sẽ không gửi được dữ liệu nữa (dữ liệu cũ giữ nguyên). Muốn dùng lại: xoá máy rồi cài lại agent với token mới.", okText: "Thu hồi", danger: true }))) return;
    try { await api.post(`/agents/${a.id}/revoke`); toast("Đã thu hồi"); onChanged(); } catch (e) { toast(e.message, true); }
  };
  const del = async () => {
    if (!(await askConfirm({ title: `Xoá máy ${a.hostname}?`, message: "Xoá máy cùng số liệu, sự kiện, danh sách phần mềm của máy. Nếu agent trên máy còn chạy, hãy gỡ agent trước (itops-agent uninstall).", requireText: "XOA", okText: "Xoá", danger: true }))) return;
    try { await api.del(`/agents/${a.id}`); toast("Đã xoá"); onClose(); } catch (e) { toast(e.message, true); }
  };
  if (!isAdmin) return <div className="small muted">Chỉ admin được thay đổi.</div>;
  return (
    <>
      <div className="form-grid">
        <Field label="Site"><Select value={f.site_id} onChange={(v) => setF({ ...f, site_id: v })} placeholder="(không)" options={(sites || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Loại máy" hint="Máy chủ: mặc định cảnh báo khi mất kết nối"><Select value={f.os_kind} onChange={(v) => setF({ ...f, os_kind: v })} options={[["client", "Máy trạm"], ["server", "Máy chủ"]]} /></Field>
        <Field label="Cảnh báo mất kết nối" hint="Máy trạm tắt buổi tối là bình thường → mặc định không báo"><Select value={f.alert_offline} onChange={(v) => setF({ ...f, alert_offline: v })} options={[["", "Theo loại máy"], ["1", "Luôn báo"], ["0", "Không báo"]]} /></Field>
        <Field label="Nhãn"><Input value={f.tags} onChange={(v) => setF({ ...f, tags: v })} placeholder="vd. ke-toan, tang-3" /></Field>
        <Field label="Ghi chú" full><textarea className="input" rows={3} value={f.note || ""} onChange={(e) => setF({ ...f, note: e.target.value })} /></Field>
      </div>
      <div className="row" style={{ marginTop: 10 }}><button className="btn primary" onClick={patch}>Lưu</button></div>
      <div className="section-title" style={{ marginTop: 24 }}>Nguy hiểm</div>
      <div className="row wrap" style={{ gap: 8 }}>
        {!a.revoked_at && <button className="btn" onClick={revoke}><Ban size={15} />Thu hồi khoá agent</button>}
        <button className="btn danger" onClick={del}><Trash2 size={15} />Xoá máy</button>
      </div>
    </>
  );
}

function AgentDrawer({ id, onClose, onChanged }) {
  const { data: a, reload } = useApi(`/agents/${id}`, { interval: 30000 });
  const [tab, setTab] = useState("overview");
  if (!a) return <Drawer title="Đang tải..." onClose={onClose} wide><div className="small muted">Đang tải…</div></Drawer>;
  return (
    <Drawer wide onClose={onClose} title={<><MachineIcon a={a} />{a.hostname}<span className="small muted">{a.domain}</span></>}>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "overview", label: "Tổng quan", icon: Info }, { key: "events", label: "Sự kiện", icon: AlertTriangle },
        { key: "services", label: "Dịch vụ", icon: ListChecks }, { key: "software", label: "Phần mềm", icon: Package, count: a.software_count ?? undefined },
        { key: "manage", label: "Quản lý", icon: Settings2 }]} />
      <div style={{ marginTop: 14 }}>
        {tab === "overview" && <Overview a={a} />}
        {tab === "events" && <EventsView agentId={a.id} />}
        {tab === "services" && <Services id={a.id} />}
        {tab === "software" && <SoftwareOf id={a.id} />}
        {tab === "manage" && <Manage a={a} onChanged={() => { reload(); onChanged(); }} onClose={() => { onClose(); onChanged(); }} />}
      </div>
    </Drawer>
  );
}

// ---------------------------------------------------------------- danh sách máy
function MachineList({ open }) {
  const { data, reload } = useApi("/agents", { interval: 30000 });
  const [q, setQ] = useState("");
  const [st, setSt] = useState("");
  const [os, setOs] = useState("");
  const [sel, setSel] = useState(null);
  const rows = (data || []).filter((a) => (!q || `${a.hostname} ${a.logged_user} ${a.ip} ${(a.ips || []).join(" ")} ${a.os_name} ${a.tags} ${a.model} ${a.serial}`.toLowerCase().includes(q.toLowerCase()))
    && (!st || (st === "problem" ? a.alerts > 0 || a.defender?.realtime === false || (a.disk || 0) >= 90 : a.status === st)) && (!os || a.os_family === os));
  useEffect(() => { if (open) setSel(open); }, [open]);
  return (
    <>
      <div className="toolbar wrap">
        <div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm tên máy, người dùng, IP, model, S/N..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Select value={st} onChange={setSt} placeholder="Mọi trạng thái" options={[["online", "Đang kết nối"], ["offline", "Mất kết nối"], ["problem", "Có vấn đề"], ["revoked", "Đã thu hồi"]]} />
        <Select value={os} onChange={setOs} placeholder="Mọi hệ điều hành" options={Object.entries(OS_LABEL)} />
        <span className="small muted" style={{ marginLeft: "auto" }}>{rows.length} / {data?.length ?? 0} máy</span>
      </div>
      <Table rows={rows} onRow={(a) => setSel(a.id)} empty={<Empty icon={Monitor} title="Chưa có máy nào">Vào tab <b>Cài đặt agent</b> để tạo token và cài agent lên máy.</Empty>} columns={[
        { key: "hostname", label: "Máy", render: (a) => <div className="row" style={{ gap: 8, whiteSpace: "nowrap" }}><MachineIcon a={a} /><div><b>{a.hostname}</b><div className="small faint">{a.os_name || OS_LABEL[a.os_family]}</div></div></div> },
        { key: "logged_user", label: "Người dùng · IP", render: (a) => <div style={{ whiteSpace: "nowrap" }}><span className="small">{a.logged_user || <span className="faint">không ai đăng nhập</span>}</span><div className="small mono faint">{(a.ips || [])[0] || a.ip}</div></div> },
        { key: "disk", label: "CPU · RAM · Ổ", sort: (a) => Math.max(a.cpu || 0, a.mem || 0, a.disk || 0), render: (a) => <Perf a={a} /> },
        { key: "defender", label: "Diệt virus", sort: (a) => (a.defender?.realtime === false ? 0 : 1), render: (a) => <DefenderBadge d={a.defender} os={a.os_family} /> },
        { key: "alerts", label: "Cảnh báo", sort: (a) => a.alerts * 1000 + a.events_24h, render: (a) => (
          <span title={`${a.alerts} cảnh báo đang mở · ${a.events_24h} sự kiện cần chú ý trong 24 giờ`}>
            {a.alerts > 0 ? <span className="badge fail">{a.alerts}</span> : a.events_24h > 0 ? <span className="badge warn">{a.events_24h} sự kiện</span> : <span className="faint small">—</span>}
          </span>) },
        { key: "status", label: "Trạng thái", sort: (a) => a.last_seen || "", render: (a) => <div style={{ whiteSpace: "nowrap" }}><StatusBadge s={a.status} last={a.last_seen} /><div className="small faint">{a.last_seen ? timeAgo(a.last_seen) : ""}</div></div> },
      ]} />
      {sel && <AgentDrawer id={sel} onClose={() => setSel(null)} onChanged={reload} />}
    </>
  );
}

// ---------------------------------------------------------------- phần mềm toàn bộ máy
function SoftwareFleet() {
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  useEffect(() => { const t = setTimeout(() => setTerm(q), 350); return () => clearTimeout(t); }, [q]);
  const { data } = useApi(`/agent-software?q=${encodeURIComponent(term)}`, { deps: [term] });
  const [open, setOpen] = useState(null);
  const rows = (data || []).map((r, i) => ({ ...r, id: i }));
  return (
    <>
      <div className="toolbar"><div className="search" style={{ width: 340 }}><Search size={16} /><input placeholder="vd. AnyDesk, TeamViewer, Chrome, Office, 7-Zip..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <span className="small muted">Dùng để tìm phần mềm cấm/không bản quyền, kiểm tra phiên bản lỗi bảo mật.</span></div>
      <Table rows={rows} onRow={(r) => setOpen(open === r.id ? null : r.id)} empty={<Empty icon={Package} title={term ? "Không máy nào có phần mềm này" : "Chưa có dữ liệu phần mềm"} />} columns={[
        { key: "name", label: "Phần mềm", render: (r) => <div><b>{r.name}</b>{open === r.id && <div className="small" style={{ marginTop: 6 }}>{r.hosts.map((h) => <span key={h} className="chip" style={{ margin: 2 }}>{h}</span>)}</div>}</div> },
        { key: "version", label: "Phiên bản", render: (r) => <span className="small mono">{r.version}</span> },
        { key: "publisher", label: "Nhà phát hành", render: (r) => <span className="small">{r.publisher}</span> },
        { key: "machines", label: "Số máy", render: (r) => <b>{r.machines}</b> },
      ]} />
    </>
  );
}

// ---------------------------------------------------------------- cài đặt agent: tải về, token, chính sách
function CopyBox({ text, label }) {
  const toast = useToast();
  return (
    <div style={{ marginBottom: 10 }}>
      {label && <div className="small muted" style={{ marginBottom: 4 }}>{label}</div>}
      <div className="row" style={{ gap: 6, alignItems: "stretch" }}>
        <pre className="mono small grow" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", background: "var(--subtle)", padding: "8px 10px", borderRadius: 8 }}>{text}</pre>
        <button className="btn sm" title="Chép" onClick={() => { navigator.clipboard?.writeText(text); toast("Đã chép"); }}><Copy size={14} /></button>
      </div>
    </div>
  );
}

function NewToken({ onClose, onDone, dl }) {
  const toast = useToast();
  const { data: sites } = useApi("/sites");
  const [f, setF] = useState({ name: "", days: 7, max_uses: 250, site_id: "", tags: "" });
  const [tok, setTok] = useState(null);
  const create = async () => {
    try { const r = await api.post("/agent-tokens", { ...f, site_id: f.site_id || null }); setTok(r.token); onDone(); } catch (e) { toast(e.message, true); }
  };
  const server = window.location.origin;
  const pin = server.startsWith("https") && dl?.ca_pin ? dl.ca_pin : "";
  const http = server.startsWith("http:");
  return (
    <Modal title={tok ? "Token đăng ký đã tạo" : "Tạo token đăng ký"} onClose={onClose} width={720}
      footer={tok ? <button className="btn primary" onClick={onClose}>Đã lưu, đóng</button> : <><button className="btn" onClick={onClose}>Huỷ</button><button className="btn primary" onClick={create}>Tạo</button></>}>
      {!tok ? (
        <div className="form-grid">
          <Field label="Tên" full hint="Để biết token dùng cho đợt cài nào"><Input value={f.name} onChange={(v) => setF({ ...f, name: v })} placeholder="vd. GPO toàn công ty tháng 11" /></Field>
          <Field label="Hiệu lực (ngày)"><Input type="number" value={f.days} onChange={(v) => setF({ ...f, days: v })} /></Field>
          <Field label="Tối đa số máy" hint="0 = không giới hạn"><Input type="number" value={f.max_uses} onChange={(v) => setF({ ...f, max_uses: v })} /></Field>
          <Field label="Gán vào site"><Select value={f.site_id} onChange={(v) => setF({ ...f, site_id: v })} placeholder="(không)" options={(sites || []).map((s) => [s.id, s.name])} /></Field>
          <Field label="Nhãn cho máy"><Input value={f.tags} onChange={(v) => setF({ ...f, tags: v })} /></Field>
        </div>
      ) : (
        <>
          <div className="alert-box" style={{ marginBottom: 12 }}><b>Token chỉ hiện MỘT lần.</b> Chép vào script cài/GPO ngay. Token chỉ dùng để đăng ký – mỗi máy nhận khoá riêng, hết hạn token không ảnh hưởng máy đã cài.</div>
          <CopyBox label="Token" text={tok} />
          {http && <div className="alert-box" style={{ marginBottom: 10 }}>Server đang chạy <b>http://</b> – chỉ dùng để demo (khoá máy đi dạng rõ trên mạng). Chạy thật: dùng HTTPS (cấu hình VS Code "HTTPS" hoặc Docker).</div>}
          <CopyBox label="Windows – chạy PowerShell bằng quyền Administrator, trong thư mục có file agent" text={`.\\itops-agent-windows-amd64.exe install --server ${server} --token ${tok}${pin ? ` --ca-pin ${pin}` : ""}${http ? " --allow-http" : ""}`} />
          <CopyBox label="Windows qua GPO (Startup Script, chạy mỗi lần bật máy, đã cài thì bỏ qua)" text={`install-windows.ps1 -Server ${server} -Token ${tok}${pin ? ` -CaPin ${pin}` : ""}${http ? " -AllowHttp" : ""} -Source \\\\FILESERVER\\itops$\\itops-agent-windows-amd64.exe`} />
          <CopyBox label="Linux (root)" text={`sudo ./install-linux.sh ${server} ${tok}${pin ? ` ${pin}` : ""}`} />
          <CopyBox label="macOS (sudo)" text={`sudo ./install-macos.sh ${server} ${tok}${pin ? ` ${pin}` : ""}`} />
        </>
      )}
    </Modal>
  );
}

function Policy() {
  const { isAdmin } = useApp();
  const toast = useToast();
  const { data, reload } = useApi("/agent-policy");
  const [p, setP] = useState(null);
  useEffect(() => { if (data) setP(data.policy); }, [data]);
  if (!p) return null;
  const set = (k) => (v) => setP({ ...p, [k]: v });
  const dis = new Set(p.disabled_keys);
  const save = async () => {
    try { await api.put("/agent-policy", p); toast("Đã lưu – agent nhận cấu hình mới ở lần gửi kế tiếp"); reload(); } catch (e) { toast(e.message, true); }
  };
  const num = (k, label, hint) => <Field label={label} hint={hint}><Input type="number" value={p[k]} onChange={set(k)} disabled={!isAdmin} /></Field>;
  return (
    <div className="card card-pad" style={{ marginTop: 16 }}>
      <div className="card-head" style={{ padding: 0, marginBottom: 12 }}><b>Chính sách thu thập</b></div>
      <div className="form-grid">
        {num("report_seconds", "Gửi hiệu năng + sự kiện mỗi (giây)", "30–3600")}
        {num("services_minutes", "Danh sách dịch vụ mỗi (phút)")}
        {num("software_hours", "Danh sách phần mềm mỗi (giờ)")}
        {num("defender_minutes", "Defender / bảo mật mỗi (phút)")}
        {num("disk_warn", "Cảnh báo ổ đầy từ (%)")}
        {num("disk_crit", "Nghiêm trọng từ (%)")}
        {num("av_signature_days", "Mẫu virus cũ hơn (ngày) → cảnh báo")}
        {num("offline_minutes", "Mất kết nối sau (phút)", "Chỉ máy bật cảnh báo mất kết nối")}
        {num("group_minutes", "Gộp sự kiện giống nhau trong (phút)")}
        {num("backfill_hours", "Lần đầu lấy sự kiện của (giờ) trước")}
      </div>
      <div className="section-title" style={{ marginTop: 16 }}>Sự kiện được thu thập</div>
      <div className="small muted" style={{ marginBottom: 8 }}>Không thu đăng nhập/đăng xuất thành công, đăng nhập của dịch vụ, tiến trình… (chiếm phần lớn khối lượng, gần như luôn bình thường). Bỏ chọn để tắt thêm loại không cần.</div>
      <Table rowKey="key" rows={data.catalog} columns={[
        { key: "on", label: "Thu", render: (c) => <input type="checkbox" disabled={!isAdmin} checked={!dis.has(c.key)} onChange={(e) => setP({ ...p, disabled_keys: e.target.checked ? p.disabled_keys.filter((k) => k !== c.key) : [...p.disabled_keys, c.key] })} /> },
        { key: "title", label: "Sự kiện", render: (c) => <div><b>{c.title}</b><div className="small faint">{c.os} · {c.ids.length ? `Event ID ${c.ids.join(", ")}` : c.channel} {c.os === "windows" && `· ${c.channel}`}</div></div> },
        { key: "category", label: "Nhóm", render: (c) => <span className="small">{CAT[c.category]}</span> },
        { key: "alert", label: "Cảnh báo", render: (c) => (c.alert ? <span className="small">{c.alert}{c.threshold > 1 ? ` (≥${c.threshold} lần / 10 phút)` : ""}</span> : <span className="faint small">chỉ ghi nhận</span>) },
      ]} />
      <div className="section-title" style={{ marginTop: 16 }}>Tự cập nhật agent</div>
      <Toggle checked={p.update?.enabled} onChange={(v) => setP({ ...p, update: { ...p.update, enabled: v } })} label="Cho agent tự cài bản mới (bản cập nhật phải được ký bằng khoá của bạn – xem README agent)" />
      <div className="small muted">{data.update_manifest ? `Bản phát hành trên server: ${data.update_manifest.version} (${data.update_manifest.platforms.join(", ")})` : "Chưa có bản phát hành nào trong <DATA_DIR>/agent-updates."}</div>
      {isAdmin && <div className="row" style={{ marginTop: 14 }}><button className="btn primary" onClick={save}>Lưu chính sách</button></div>}
    </div>
  );
}

function Setup() {
  const { isAdmin } = useApp();
  const toast = useToast();
  const { data: dl } = useApi("/agent-downloads");
  const { data: tokens, reload } = useApi(isAdmin ? "/agent-tokens" : null);
  const [creating, setCreating] = useState(false);
  const revoke = async (t) => {
    if (!(await askConfirm({ title: `Thu hồi token "${t.name}"?`, message: "Không đăng ký thêm máy mới bằng token này được nữa. Máy đã cài vẫn chạy bình thường.", okText: "Thu hồi", danger: true }))) return;
    try { await api.post(`/agent-tokens/${t.id}/revoke`); toast("Đã thu hồi"); reload(); } catch (e) { toast(e.message, true); }
  };
  const TSTATE = { active: ["Còn hiệu lực", "ok"], expired: ["Hết hạn", ""], used_up: ["Hết lượt", ""], revoked: ["Đã thu hồi", "warn"] };
  return (
    <>
      <div className="grid2">
        <div className="card card-pad">
          <div className="row" style={{ marginBottom: 8 }}><Download size={16} /><b>Tải agent</b><span className="small muted" style={{ marginLeft: "auto" }}>{dl?.version && `phiên bản ${dl.version}`}</span></div>
          {!dl?.files?.length ? <div className="small muted">Chưa có file agent trong backend/agent_dist (build bằng agent/scripts/build.sh).</div> : dl.files.map((f) => (
            <div key={f.name} className="row" style={{ gap: 8, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
              <a className="grow" href={`/api/agent-downloads/${f.name}`} download>{f.name}</a>
              <span className="small faint">{fmtSize(f.size)}</span>
              {f.sha256 && <span className="small mono faint" title={`SHA-256: ${f.sha256}`}>{f.sha256.slice(0, 10)}…</span>}
            </div>
          ))}
          <div className="small muted" style={{ marginTop: 8 }}>File chưa ký số (chưa có chứng chỉ code signing) → Windows SmartScreen có thể cảnh báo khi chạy tay; cài qua GPO thì không. Đối chiếu SHA-256 trước khi đưa lên thư mục chia sẻ.</div>
        </div>
        <div className="card card-pad">
          <div className="row" style={{ marginBottom: 8 }}><ShieldCheck size={16} /><b>Agent làm gì / không làm gì</b></div>
          <div className="small" style={{ lineHeight: 1.6 }}>
            ✔ Đọc hiệu năng, ổ đĩa, dịch vụ, phần mềm đã cài, trạng thái Defender/BitLocker/tường lửa, người đang dùng máy.<br />
            ✔ Đọc sự kiện cần xử lý: đăng nhập sai, khoá tài khoản, thêm quyền admin, xoá nhật ký, mã độc, tắt máy đột ngột, dịch vụ/ổ đĩa lỗi.<br />
            ✘ Không chạy lệnh từ xa, không cài/gỡ phần mềm, không đọc file người dùng, không chụp màn hình, không ghi lại thao tác bàn phím.<br />
            ✘ Không thu đăng nhập/đăng xuất thường ngày.
          </div>
          {dl?.ca_pin && <div style={{ marginTop: 10 }}><CopyBox label="ca_pin của chứng chỉ HTTPS server này (tự điền vào lệnh cài)" text={dl.ca_pin} /></div>}
        </div>
      </div>
      {isAdmin && (
        <div className="card card-pad" style={{ marginTop: 16 }}>
          <div className="row" style={{ marginBottom: 10 }}><KeyRound size={16} /><b>Token đăng ký</b>
            <button className="btn primary sm" style={{ marginLeft: "auto" }} onClick={() => setCreating(true)}><Plus size={14} />Tạo token</button></div>
          <Table rows={tokens || []} empty={<Empty icon={KeyRound} title="Chưa có token">Tạo token để cài agent lên máy.</Empty>} columns={[
            { key: "name", label: "Tên", render: (t) => <div><b>{t.name}</b><div className="small faint mono">{t.prefix}…</div></div> },
            { key: "state", label: "Trạng thái", render: (t) => { const [l, c] = TSTATE[t.state]; return <span className={`badge ${c}`}>{l}</span>; } },
            { key: "uses", label: "Đã dùng", render: (t) => <span className="small">{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ""} máy</span> },
            { key: "expires_at", label: "Hết hạn", render: (t) => <span className="small">{fmtTime(t.expires_at)}</span> },
            { key: "created_by", label: "Tạo bởi", render: (t) => <span className="small">{t.created_by} · {timeAgo(t.created_at)}</span> },
            { key: "act", label: "", render: (t) => t.state === "active" && <button className="btn sm" onClick={(e) => { e.stopPropagation(); revoke(t); }}>Thu hồi</button> },
          ]} />
        </div>
      )}
      <Policy />
      {creating && <NewToken dl={dl} onClose={() => setCreating(false)} onDone={reload} />}
    </>
  );
}

// ---------------------------------------------------------------- trang
export default function Agents() {
  const { route, nav } = useApp();
  const tab = route.params?.tab || "machines";
  const { data: s } = useApi("/agent-summary", { interval: 30000 });
  const setTab = (t) => nav("agents", null, t === "machines" ? undefined : { tab: t });
  return (
    <>
      <PageHead crumb="Vận hành › Máy trạm" title="Máy trạm"
        desc="Thông tin do agent trên từng máy gửi lên: hiệu năng, ổ đĩa, Defender, dịch vụ, phần mềm và các sự kiện cần xử lý. Agent chỉ đọc, không nhận lệnh từ xa." />
      <div className="stats">
        <Stat icon={Monitor} label="Tổng số máy" value={s?.total} sub={s ? Object.entries(s.by_os || {}).map(([k, v]) => `${v} ${OS_LABEL[k] || k}`).join(" · ") : ""} />
        <Stat icon={s?.offline ? WifiOff : Wifi} label="Đang kết nối" value={s ? `${s.online}/${s.total}` : null} sub={s?.offline ? `${s.offline} máy tắt / mất mạng / agent dừng` : "tất cả đang gửi dữ liệu"} />
        <Stat icon={ShieldAlert} label="Defender tắt" value={s?.defender_off} tone={s?.defender_off ? "fail" : ""} />
        <Stat icon={HardDrive} label="Ổ sắp đầy" value={s?.disk_full} tone={s?.disk_full ? "warn" : ""} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "machines", label: "Danh sách máy", icon: Monitor }, { key: "events", label: "Sự kiện", icon: AlertTriangle },
        { key: "software", label: "Phần mềm", icon: Package }, { key: "setup", label: "Cài đặt agent", icon: Settings2 }]} />
      <div style={{ marginTop: 14 }}>
        {tab === "machines" && <div className="card"><MachineList open={route.id ? Number(route.id) : null} /></div>}
        {tab === "events" && <EventsView hostCol />}
        {tab === "software" && <div className="card"><SoftwareFleet /></div>}
        {tab === "setup" && <Setup />}
      </div>
    </>
  );
}
