import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import {
  Laptop, Server, Search, ShieldCheck, ShieldAlert, HardDrive, Wifi, WifiOff, Download, KeyRound, Copy, Trash2,
  Ban, AlertTriangle, Package, ListChecks, Settings2, User, MapPin, Lightbulb, Info, Monitor, UserCheck, Check, X,
} from "lucide-react";
import { useApp } from "../App";
import { api } from "../api";
import { useUi, chartColors } from "../theme";
import { useApi, PageHead, Stat, Table, Tabs, Drawer, Field, Input, Select, Toggle, Empty, UsageBar, SevBadge, timeAgo, fmtTime, useToast, askConfirm, CapNote } from "../ui";

const OS_LABEL = { windows: "Windows", linux: "Linux", darwin: "macOS" };
const STATUS = { online: ["Connected", "ok"], offline: ["Disconnected", "fail"], never: ["No data received", ""], revoked: ["Revoked", "warn"] };
const CAT = { account: "Account", security: "Security", system: "System", service: "Service", disk: "Disk" };
const lvl = (p, warn = 85, crit = 95) => (p == null ? undefined : p >= crit ? "fail" : p >= warn ? "warn" : "ok");
const fmtSize = (b) => (b > 1 << 20 ? `${(b / (1 << 20)).toFixed(1)} MB` : `${Math.round(b / 1024)} KB`);
const uptime = (s) => (s == null ? "—" : s >= 86400 ? `${Math.floor(s / 86400)} days ${Math.floor((s % 86400) / 3600)} hours` : `${Math.floor(s / 3600)} hours ${Math.floor((s % 3600) / 60)} minutes`);

function StatusBadge({ s, last }) {
  const [l, c] = STATUS[s] || [s, ""];
  return <span className={`badge ${c}`} title={last ? `Last seen: ${fmtTime(last)}` : ""}>{l}</span>;
}

function DefenderBadge({ d, os }) {
  if (os !== "windows") return <span className="faint small">—</span>;
  if (!d) return <span className="faint small">Not available</span>;
  if (d.other_av) return <span className="badge info" title={`Other antivirus software: ${d.other_av}`}>{d.other_av.split(",")[0]}</span>;
  if (d.realtime === false) return <span className="badge fail">Defender Disabled</span>;
  if (d.signature_age_days > 3) return <span className="badge warn">Outdated definitions {d.signature_age_days} days</span>;
  return <span className="badge ok">Defender Enabled</span>;
}

// CPU · RAM · most-used disk – compact single-column view, highlighted when usage is high
function Perf({ a }) {
  const on = a.status === "online";
  const cell = (v, l, name) => (v == null ? <span className="faint">—</span>
    : <span title={name} style={{ color: l === "fail" ? "var(--critical)" : l === "warn" ? "var(--trouble)" : undefined, fontWeight: l === "ok" ? 400 : 600 }}>{Math.round(v)}%</span>);
  return (
    <span className="small mono" style={{ whiteSpace: "nowrap" }}>
      {cell(on ? a.cpu : null, lvl(a.cpu), "CPU")} · {cell(on ? a.mem : null, lvl(a.mem, 90, 97), "RAM")} · {cell(a.disk, lvl(a.disk, 90, 95), "Highest disk usage")}
    </span>
  );
}

function MachineIcon({ a }) {
  const I = a.os_kind === "server" ? Server : a.os_family === "darwin" ? Laptop : Monitor;
  return <I size={16} style={{ color: a.status === "online" ? "var(--ok)" : "var(--muted)", flexShrink: 0 }} />;
}

// ---------------------------------------------------------------- Readable events
export function EventCard({ e, showHost }) {
  const [raw, setRaw] = useState(false);
  const { t } = useApp();
  return (
    <div className="card card-pad" style={{ marginBottom: 10, borderLeft: `3px solid var(--${e.severity === "info" ? "border" : e.severity === "attention" ? "attention" : e.severity === "trouble" ? "trouble" : "critical"})` }}>
      <div className="row wrap" style={{ gap: 8, marginBottom: 6 }}>
        {e.severity !== "info" ? <SevBadge sev={e.severity}>{({ attention: "Attention", trouble: "Trouble", critical: "Critical" })[e.severity]}</SevBadge> : <span className="badge">Information</span>}
        <b>{e.title}</b>
        {e.count > 1 && <span className="badge info" title="Repeated events within a short period are grouped">×{e.count}</span>}
        {showHost && <span className="chip">{e.hostname}</span>}
        <span className="small muted" style={{ marginLeft: "auto" }} title={e.count > 1 ? `First seen ${fmtTime(e.ts)} · Last seen ${fmtTime(e.last_ts)}` : fmtTime(e.ts)}>
          {e.count > 1 ? `${fmtTime(e.ts)} → ${fmtTime(e.last_ts)}` : fmtTime(e.ts)}
        </span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 10px", fontSize: 13.5 }}>
        <span className="muted row" style={{ gap: 4 }}><User size={13} />{t("agents.who")}</span><span>{e.who || "—"}</span>
        <span className="muted row" style={{ gap: 4 }}><MapPin size={13} />{t("agents.where")}</span><span>{e.where || "—"}</span>
        <span className="muted row" style={{ gap: 4 }}><Info size={13} />{t("agents.what")}</span><span>{e.what}</span>
        <span className="muted row" style={{ gap: 4 }}><Lightbulb size={13} />{t("agents.recommendation")}</span><span>{e.advice}</span>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <span className="small faint">{t(`agents.${e.category}`) || e.category}{e.event_id ? ` · Event ID ${e.event_id}` : ""}{e.channel ? ` · ${e.channel}` : ""}</span>
        {(e.message || Object.keys(e.data || {}).length > 0) && <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={() => setRaw(!raw)}>{raw ? t("agents.hideRaw") : t("agents.viewRaw")}</button>}
      </div>
      {raw && <pre className="small mono" style={{ whiteSpace: "pre-wrap", maxHeight: 260, overflow: "auto", background: "var(--subtle)", padding: 8, borderRadius: 8 }}>
        {e.message ? e.message + "\n\n" : ""}{JSON.stringify(e.data, null, 1)}</pre>}
    </div>
  );
}

function EventsView({ agentId, hostCol }) {
  const { lang, t } = useApp();
  const [sev, setSev] = useState("attention,trouble,critical");
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const [hours, setHours] = useState(72);
  const qs = new URLSearchParams({ hours, limit: 300, locale: lang, ...(agentId ? { agent_id: agentId } : {}), ...(sev ? { severity: sev } : {}), ...(cat ? { category: cat } : {}), ...(q ? { q } : {}) });
  const { data } = useApi(`/agent-events?${qs}`, { interval: 30000, deps: [sev, cat, q, hours, lang] });
  return (
    <>
      <div className="toolbar wrap">
        <div className="search" style={{ width: 260 }}><Search size={16} /><input placeholder="Search users, endpoints, and event details..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Select value={sev} onChange={setSev} options={[["attention,trouble,critical", t("agents.needsAction")], ["critical", t("agents.criticalOnly")], ["", t("agents.allIncludingInfo")]]} />
        <Select value={cat} onChange={setCat} placeholder={t("agents.allGroups")} options={Object.entries(CAT)} />
        <div className="seg">{[[24, t("agents.hours24")], [72, t("agents.days3")], [168, t("agents.days7")], [720, t("agents.days30")]].map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}</div>
      </div>
      <div className="small muted" style={{ margin: "4px 0 10px" }}>{t("agents.eventHint")}</div>
      {data && !data.length && <Empty icon={ShieldCheck} title={t("agents.noEvents")} />}
      {(data || []).map((e) => <EventCard key={e.id} e={e} showHost={hostCol} />)}
      <CapNote shown={(data || []).length} limit={300} what="events" />
    </>
  );
}

// ---------------------------------------------------------------- Performance charts
function MetricChart({ id }) {
  const { t } = useApp();
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
      series: [["cpu", "CPU"], ["mem", "RAM"], ["disk", "Highest disk usage"]].map(([k, n]) => ({
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
        <span className="small muted grow">Performance</span>
        <div className="seg">{[[6, "6 hours"], [24, t("agents.hours24")], [168, t("agents.days7")]].map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}</div>
      </div>
      {data && !data.length ? <div className="small faint" style={{ padding: 20 }}>No data available</div> : <div ref={el} style={{ height: 200 }} />}
    </div>
  );
}

// ---------------------------------------------------------------- Device details
const USER_SRC = { console: "Local console", rdp: "Remote Desktop", ssh: "SSH" };

// Data quality (CVE module – part 1): which data is reliable enough for vulnerability matching, what is missing, and why.
function Quality({ q }) {
  if (!q) return null;
  const bad = q.checks.filter((c) => !c.ok);
  return (
    <div className="card" style={{ padding: 12, marginBottom: 14 }}>
      <div className="row" style={{ gap: 8, marginBottom: bad.length ? 8 : 0 }}>
        <b>Data quality</b>
        <span className={`badge ${q.score === 100 ? "ok" : q.score >= 70 ? "warn" : "fail"}`}>{q.score}%</span>
        <span className="small muted">{q.checks.length - bad.length}/{q.checks.length} items have sufficient data for CVE matching{q.software_at && ` · software Updated ${timeAgo(q.software_at)}`}</span>
      </div>
      {bad.map((c) => <div key={c.key} className="small" style={{ color: "var(--warn, #b45309)" }}>• {c.label}: {c.hint}</div>)}
    </div>
  );
}

function Overview({ a }) {
  const d = a.defender_detail;
  const p = a.posture || {};
  const fw = Array.isArray(p.firewall) ? p.firewall : null;
  return (
    <>
      <div className="kv" style={{ marginBottom: 14 }}>
        <div>Status</div><div><StatusBadge s={a.status} /> <span className="small muted">{a.last_seen ? `Last seen ${timeAgo(a.last_seen)}` : ""}</span></div>
        <div>Current user</div><div>{a.logged_user ? <>{a.logged_user}{a.user_source && <span className="badge" style={{ marginLeft: 6 }}>{USER_SRC[a.user_source] || a.user_source}</span>}</> : <span className="faint">No user currently logged in</span>}
          {!a.logged_user && a.last_user && <span className="small muted"> · Last logged-in user: <b>{a.last_user}</b>{a.last_user_at && ` (${timeAgo(a.last_user_at)})`}</span>}</div>
        <div>Operating system</div><div>{a.os_name} <span className="muted small">{a.os_release && !(a.os_name || "").includes(a.os_release) ? `${a.os_release} · ` : ""}{a.os_build && `build ${a.os_build}${a.os_ubr != null ? `.${a.os_ubr}` : ""}`}</span> · {a.os_kind === "server" ? "Server" : "Workstation"}</div>
        <div>Hardware</div><div>{[a.manufacturer, a.model].filter(Boolean).join(" ") || "—"}{a.serial && <span className="muted small"> · S/N {a.serial}</span>}</div>
        <div>CPU · RAM</div><div>{a.cpu_model || "—"} · {a.cpu_cores} threads · {a.ram_mb ? `${(a.ram_mb / 1024).toFixed(1)} GB` : "—"}</div>
        <div>Network</div><div className="mono small">{(a.ips || []).join(", ") || "—"} <span className="muted">(server sees {a.ip})</span></div>
        <div>MAC</div><div className="mono small">{(a.macs || []).join(", ") || <span className="faint" style={{ fontFamily: "inherit" }}>Not reported (agent older than 1.0.4)</span>}</div>
        <div>Uptime</div><div>{uptime(a.uptime_s)}{a.reboot_pending && <span className="badge warn" style={{ marginLeft: 8 }}>Reboot pending</span>}</div>
        <div>Agent</div><div className="small">{a.agent_version} · enrolled {fmtTime(a.enrolled_at)}{a.site_name && ` · ${a.site_name}`}</div>
      </div>
      <Quality q={a.quality} />
      {a.alerts_open?.length > 0 && (
        <div className="alert-box" style={{ marginBottom: 14 }}>
          <b>Open alerts</b>
          {a.alerts_open.map((x) => <div key={x.id} className="row" style={{ gap: 8, marginTop: 4 }}><SevBadge sev={x.severity} /><span>{x.title}</span>{x.count > 1 && <span className="small muted">×{x.count}</span>}</div>)}
        </div>
      )}
      <div className="section-title" style={{ marginBottom: 8 }}>Disks</div>
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
          {!d ? <div className="small faint">No data available (agent reports every 15 minutes).</div> : (
            <div className="kv">
              <div>Real-time protection</div><div>{d.realtime ? <span className="badge ok">Enable</span> : <span className="badge fail">Disable</span>}{d.running_mode && <span className="small muted"> · mode {d.running_mode}</span>}</div>
              {d.other_av && <><div>Other antivirus software</div><div>{d.other_av}</div></>}
              <div>Antivirus definitions</div><div>{d.signature_version || "—"} · {d.signature_age_days != null ? `${d.signature_age_days} days old` : ""}</div>
              <div>Quick / full scan</div><div>{d.quick_scan_age_days != null ? `${d.quick_scan_age_days} days ago` : "—"} / {d.full_scan_age_days != null && d.full_scan_age_days < 10000 ? `${d.full_scan_age_days} days ago` : "Never scanned"}</div>
              <div>Tamper protection</div><div>{d.tamper_protection ? "Enable" : "Disable"}</div>
            </div>
          )}
        </>
      )}
      {(fw || p.bitlocker || p.filevault !== undefined || a.updates?.last_hotfix) && (
        <>
          <div className="section-title" style={{ marginTop: 14 }}>Other security settings</div>
          <div className="kv">
            {fw && <><div>Firewall</div><div>{fw.map((f) => <span key={f.name} className={`badge ${f.enabled ? "ok" : "fail"}`} style={{ marginRight: 4 }}>{f.name}: {f.enabled ? "Enabled" : "Disabled"}</span>)}</div></>}
            {p.firewall === true || p.firewall === false ? <><div>Firewall</div><div>{p.firewall ? "Enable" : "Disable"} {p.firewall_tool && <span className="muted small">({p.firewall_tool})</span>}</div></> : null}
            {p.bitlocker && <><div>BitLocker (system drive)</div><div>{p.bitlocker.protection === "On" ? <span className="badge ok">Encrypted</span> : <span className="badge warn">Not enabled</span>} <span className="small muted">{p.bitlocker.status}</span></div></>}
            {p.filevault !== undefined && <><div>FileVault</div><div>{p.filevault ? "Enable" : "Disable"}</div><div>Gatekeeper · SIP</div><div>{p.gatekeeper ? "Enable" : "Disable"} · {p.sip ? "Enable" : "Disable"}</div></>}
            {a.updates?.last_hotfix && <><div>Latest patch</div><div>{a.updates.last_hotfix.id} · {a.updates.last_hotfix.installed_on}</div></>}
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
        <div className="search" style={{ width: 240 }}><Search size={16} /><input placeholder="Search services..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Toggle checked={only} onChange={setOnly} label="Only show automatic services that are stopped" />
        <span className="small muted" style={{ marginLeft: "auto" }}>{data?.updated_at ? `Updated ${timeAgo(data.updated_at)}` : ""}</span>
      </div>
      <Table rowKey="name" rows={rows} empty={<Empty title="No service inventory available" />} columns={[
        { key: "display", label: "Service", render: (s) => <div><b>{s.display || s.name}</b>{s.display && <div className="small faint mono">{s.name}</div>}</div> },
        { key: "state", label: "Status", render: (s) => <span className={`badge ${s.state === "running" ? "ok" : s.state === "failed" ? "fail" : s.start?.startsWith("auto") && s.state !== "exited" ? "warn" : ""}`}>{({ running: "Running", stopped: "Stopped", failed: "Error", exited: "Exited" })[s.state] || s.state}</span> },
        { key: "start", label: "Startup type", render: (s) => <span className="small">{({ auto: "Automatic", "auto-delayed": "Automatic (delayed)", manual: "Manual", disabled: "Disable", static: "Triggered by another service", system: "System" })[s.start] || s.start || "—"}</span> },
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
      <div className="toolbar"><div className="search" style={{ width: 260 }}><Search size={16} /><input placeholder="Search software or publisher..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <span className="small muted" style={{ marginLeft: "auto" }}>{data ? `${data.length} software` : ""}</span></div>
      <Table rows={rows} empty={<Empty title="No software inventory available" />} columns={[
        { key: "name", label: "Name", render: (s) => <b>{s.name}</b> },
        { key: "version", label: "Version", render: (s) => <span className="small mono">{s.version}</span> },
        { key: "publisher", label: "Publisher", render: (s) => <span className="small">{s.publisher}</span> },
        { key: "installed_on", label: "Install date", render: (s) => <span className="small muted">{s.installed_on}</span> },
      ]} />
    </>
  );
}

function Manage({ a, onChanged, onClose }) {
  const { isAdmin, t } = useApp();
  const toast = useToast();
  const { data: sites } = useApi("/sites");
  const [f, setF] = useState({ tags: a.tags, note: a.note, site_id: a.site_id || "", os_kind: a.os_kind, alert_offline: a.alert_offline_auto ? "" : a.alert_offline ? "1" : "0" });
  const patch = async () => {
    try {
      await api.patch(`/agents/${a.id}`, { tags: f.tags, note: f.note, site_id: f.site_id || null, os_kind: f.os_kind,
        alert_offline: f.alert_offline === "" ? null : f.alert_offline === "1" });
      toast("Saved"); onChanged();
    } catch (e) { toast(e.message, true); }
  };
  const revoke = async () => {
    if (!(await askConfirm({ title: `Revoke agent key for ${a.hostname}?`, message: "The device will stop sending data (existing data will be retained). To use it again, delete the device and reinstall the agent.", okText: "Revoke", danger: true }))) return;
    try { await api.post(`/agents/${a.id}/revoke`); toast("Revoked"); onChanged(); } catch (e) { toast(e.message, true); }
  };
  const del = async () => {
    if (!(await askConfirm({ title: `Delete device ${a.hostname}?`, message: "Delete the device along with its metrics, events, and software inventory. If the agent is still running on the device, uninstall it first (itops-agent uninstall).", requireText: "XOA", okText: "Delete", danger: true }))) return;
    try { await api.del(`/agents/${a.id}`); toast("Deleted"); onClose(); } catch (e) { toast(e.message, true); }
  };
  if (!isAdmin) return <div className="small muted">Only administrators can make changes.</div>;
  return (
    <>
      <div className="form-grid">
        <Field label="Site"><Select value={f.site_id} onChange={(v) => setF({ ...f, site_id: v })} placeholder="(none)" options={(sites || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Device type" hint="Server: alerts on disconnection by default"><Select value={f.os_kind} onChange={(v) => setF({ ...f, os_kind: v })} options={[["client", t("agents.workstation")], ["server", t("agents.server")]]} /></Field>
        <Field label="Offline alert" hint="Workstations being offline overnight is normal, so alerts are disabled by default"><Select value={f.alert_offline} onChange={(v) => setF({ ...f, alert_offline: v })} options={[["", "Use device type default"], ["1", "Always alert"], ["0", "Never alert"]]} /></Field>
        <Field label="Tags"><Input value={f.tags} onChange={(v) => setF({ ...f, tags: v })} placeholder="e.g. accounting, floor-3" /></Field>
        <Field label="Notes" full><textarea className="input" rows={3} value={f.note || ""} onChange={(e) => setF({ ...f, note: e.target.value })} /></Field>
      </div>
      <div className="row" style={{ marginTop: 10 }}><button className="btn primary" onClick={patch}>Save</button></div>
      <div className="section-title" style={{ marginTop: 24 }}>Danger zone</div>
      <div className="row wrap" style={{ gap: 8 }}>
        {!a.revoked_at && <button className="btn" onClick={revoke}><Ban size={15} />Revoke agent key</button>}
        <button className="btn danger" onClick={del}><Trash2 size={15} />Delete device</button>
      </div>
    </>
  );
}

function AgentDrawer({ id, onClose, onChanged }) {
  const { t } = useApp();
  const { data: a, reload } = useApi(`/agents/${id}`, { interval: 30000 });
  const [tab, setTab] = useState("overview");
  if (!a) return <Drawer title="Loading..." onClose={onClose} wide><div className="small muted">Loading…</div></Drawer>;
  return (
    <Drawer wide onClose={onClose} title={<><MachineIcon a={a} />{a.hostname}<span className="small muted">{a.domain}</span></>}>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "overview", label: "Overview", icon: Info }, { key: "events", label: t("agents.events"), icon: AlertTriangle },
        { key: "services", label: "Service", icon: ListChecks }, { key: "software", label: t("agents.software"), icon: Package, count: a.software_count ?? undefined },
        { key: "manage", label: "Management", icon: Settings2 }]} />
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

// ---------------------------------------------------------------- device inventory
function MachineList({ open }) {
  const { t } = useApp();
  const { data, reload } = useApi("/agents", { interval: 30000 });
  const [q, setQ] = useState("");
  const [st, setSt] = useState("");
  const [os, setOs] = useState("");
  const [sel, setSel] = useState(null);
  const rows = (data || []).filter((a) => (!q || `${a.hostname} ${a.logged_user} ${a.ip} ${(a.ips || []).join(" ")} ${(a.macs || []).join(" ")} ${a.os_name} ${a.tags} ${a.model} ${a.serial}`.toLowerCase().includes(q.toLowerCase()))
    && (!st || (st === "problem" ? a.alerts > 0 || a.defender?.realtime === false || (a.disk || 0) >= 90 : a.status === st)) && (!os || a.os_family === os));
  useEffect(() => { if (open) setSel(open); }, [open]);
  return (
    <>
      <div className="toolbar wrap">
        <div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder={t("agents.machineSearch")} value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Select value={st} onChange={setSt} placeholder={t("agents.allStatuses")} options={[["online", "Connected"], ["offline", "Disconnected"], ["problem", "Issues"], ["revoked", "Revoked"]]} />
        <Select value={os} onChange={setOs} placeholder={t("agents.allOperatingSystems")} options={Object.entries(OS_LABEL)} />
        <span className="small muted" style={{ marginLeft: "auto" }}>{rows.length} / {data?.length ?? 0} devices</span>
      </div>
      <Table rows={rows} onRow={(a) => setSel(a.id)} empty={<Empty icon={Monitor} title="No devices yet">Go to <b>Agent Settings</b> for the install command, then run it on the device.</Empty>} columns={[
        { key: "hostname", label: "Device", render: (a) => <div className="row" style={{ gap: 8, whiteSpace: "nowrap" }}><MachineIcon a={a} /><div><b>{a.hostname}</b>{a.duplicates?.length > 0 && <span className="badge warn" style={{ marginLeft: 6 }} title="Same hostname and machine ID/serial as another device – often caused by reinstalling an older agent. Remove records for devices that no longer report.">Duplicate?</span>}<div className="small faint">{a.os_name || OS_LABEL[a.os_family]}</div></div></div> },
        { key: "logged_user", label: "User", sort: (a) => (a.logged_user || a.last_user || "").toLowerCase(), render: (a) => <span className="small" style={{ whiteSpace: "nowrap" }}>{a.logged_user || (a.last_user ? <span className="muted" title="Most recent user — nobody is currently logged in">{a.last_user} (most recent)</span> : <span className="faint">No user logged in</span>)}</span> },
        { key: "ip", label: "IP", sort: (a) => (a.ips || [])[0] || a.ip || "", render: (a) => {
          const ips = (a.ips || []).length ? a.ips : [a.ip].filter(Boolean);
          return <span className="small mono" style={{ whiteSpace: "nowrap" }} title={[...ips, a.ip && `server sees ${a.ip}`].filter(Boolean).join("\n")}>{ips[0] || "—"}{ips.length > 1 && <span className="faint"> +{ips.length - 1}</span>}</span>;
        } },
        { key: "mac", label: "MAC", sort: (a) => (a.macs || [])[0] || "", render: (a) => (a.macs || []).length
          ? <span className="small mono" style={{ whiteSpace: "nowrap" }} title={a.macs.join("\n")}>{a.macs[0]}{a.macs.length > 1 && <span className="faint"> +{a.macs.length - 1}</span>}</span>
          : <span className="faint small" title="Agent older than 1.0.4 does not report MAC">—</span> },
        { key: "disk", label: "CPU · RAM · Disk", sort: (a) => Math.max(a.cpu || 0, a.mem || 0, a.disk || 0), render: (a) => <Perf a={a} /> },
        { key: "defender", label: "Antivirus", sort: (a) => (a.defender?.realtime === false ? 0 : 1), render: (a) => <DefenderBadge d={a.defender} os={a.os_family} /> },
        { key: "alerts", label: "Warning", sort: (a) => a.alerts * 1000 + a.events_24h, render: (a) => (
          <span title={`${a.alerts} open alerts · ${a.events_24h} events requiring attention in the last 24 hours`}>
            {a.alerts > 0 ? <span className="badge fail">{a.alerts}</span> : a.events_24h > 0 ? <span className="badge warn">{a.events_24h} events</span> : <span className="faint small">—</span>}
          </span>) },
        { key: "status", label: "Status", sort: (a) => a.last_seen || "", render: (a) => <div style={{ whiteSpace: "nowrap" }}><StatusBadge s={a.status} last={a.last_seen} /><div className="small faint">{a.last_seen ? timeAgo(a.last_seen) : ""}</div></div> },
      ]} />
      {sel && <AgentDrawer id={sel} onClose={() => setSel(null)} onChanged={reload} />}
    </>
  );
}

// ---------------------------------------------------------------- Software inventory across all devices
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
        <span className="small muted">Use this to find prohibited or unlicensed software and identify vulnerable versions.</span></div>
      <Table rows={rows} onRow={(r) => setOpen(open === r.id ? null : r.id)} empty={<Empty icon={Package} title={term ? "No devices have this software" : "No software data available"} />} columns={[
        { key: "name", label: "Software", render: (r) => <div><b>{r.name}</b>{open === r.id && <div className="small" style={{ marginTop: 6 }}>{r.hosts.map((h) => <span key={h} className="chip" style={{ margin: 2 }}>{h}</span>)}</div>}</div> },
        { key: "version", label: "Version", render: (r) => <span className="small mono">{r.version}</span> },
        { key: "publisher", label: "Publisher", render: (r) => <span className="small">{r.publisher}</span> },
        { key: "machines", label: "Device count", render: (r) => <b>{r.machines}</b> },
      ]} />
      <CapNote shown={rows.length} limit={500} what="software entries (most installed first)" hint="Search by name to find the rest." />
    </>
  );
}

// ---------------------------------------------------------------- Agent setup: downloads, install commands, and policy
function CopyBox({ text, label }) {
  const toast = useToast();
  return (
    <div style={{ marginBottom: 10 }}>
      {label && <div className="small muted" style={{ marginBottom: 4 }}>{label}</div>}
      <div className="row" style={{ gap: 6, alignItems: "stretch" }}>
        <pre className="mono small grow" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", background: "var(--subtle)", padding: "8px 10px", borderRadius: 8 }}>{text}</pre>
        <button className="btn sm" title="Copy" onClick={() => { navigator.clipboard?.writeText(text); toast("Copied"); }}><Copy size={14} /></button>
      </div>
    </div>
  );
}

function InstallCommands({ dl }) {
  const { data: sites } = useApi("/sites");
  const [siteName, setSiteName] = useState("");
  const server = window.location.origin;
  const pin = server.startsWith("https") && dl?.ca_pin ? dl.ca_pin : "";
  const http = server.startsWith("http:");
  const opt = (flag) => (siteName ? ` ${flag} "${siteName}"` : "");
  return (
    <>
      <div className="small muted" style={{ marginBottom: 10, lineHeight: 1.5 }}>
        Enrollment is open, like Wazuh: the install command only needs the server address — no registration token. Each device
        receives its own key on enrollment. A device that matches an existing one (same hostname and machine ID or serial)
        waits in <b>Pending approvals</b> below until IT approves it, so a real device cannot be taken over silently.
      </div>
      <div className="row" style={{ marginBottom: 10, gap: 8 }}>
        <span className="small">Assign new devices to site</span>
        <Select value={siteName} onChange={setSiteName} placeholder="(none — assign later)"
          options={(sites || []).map((x) => [x.name, x.name])} />
      </div>
      {http && <div className="alert-box" style={{ marginBottom: 10 }}>Server is running <b>http://</b> — for demonstration only (device keys are transmitted in cleartext). For production, use HTTPS (configure HTTPS in your deployment or Docker).</div>}
      <CopyBox label="Windows — run PowerShell as Administrator from the directory containing the agent file" text={`.\\itops-agent-windows-amd64.exe install --server ${server}${opt("--site")}${pin ? ` --ca-pin ${pin}` : ""}${http ? " --allow-http" : ""}`} />
      <CopyBox label="Windows via GPO (Startup Script, runs at startup and skips devices where the agent is already installed)" text={`install-windows.ps1 -Server ${server}${siteName ? ` -Site "${siteName}"` : ""}${pin ? ` -CaPin ${pin}` : ""}${http ? " -AllowHttp" : ""} -Source \\\\FILESERVER\\itops$\\itops-agent-windows-amd64.exe`} />
      <CopyBox label="Linux (root)" text={`sudo ./install-linux.sh ${server}${pin ? ` ${pin}` : " \"\""}${siteName ? ` "${siteName}"` : ""}`} />
      <CopyBox label="macOS (sudo)" text={`sudo ./install-macos.sh ${server}${pin ? ` ${pin}` : " \"\""}${siteName ? ` "${siteName}"` : ""}`} />
      <CopyBox label="Test run: simulate 3 Windows devices and 2 macOS devices reporting data (no admin rights or installation required; press Ctrl+C to stop)"
        text={`.\\itops-agent-windows-amd64.exe simulate --server ${server} --windows 3 --macos 2${pin ? ` --ca-pin ${pin}` : ""}${http ? " --allow-http" : ""}`} />
    </>
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
    try { await api.put("/agent-policy", p); toast("Saved — the agent will receive the updated configuration on its next report"); reload(); } catch (e) { toast(e.message, true); }
  };
  const num = (k, label, hint) => <Field label={label} hint={hint}><Input type="number" value={p[k]} onChange={set(k)} disabled={!isAdmin} /></Field>;
  return (
    <div className="card card-pad" style={{ marginTop: 16 }}>
      <div className="card-head" style={{ padding: 0, marginBottom: 12 }}><b>Collection policy</b></div>
      <div className="form-grid">
        {num("report_seconds", "Send performance data and events every (seconds)", "30–3600")}
        {num("services_minutes", "Service inventory interval (minutes)")}
        {num("software_hours", "Software inventory interval (hours)")}
        {num("defender_minutes", "Defender/security status interval (minutes)")}
        {num("disk_warn", "Warn when disk usage reaches (%)")}
        {num("disk_crit", "Critical when disk usage reaches (%)")}
        {num("av_signature_days", "Alert when antivirus definitions are older than (days)")}
        {num("offline_minutes", "Mark offline after (minutes)", "Only enabled devices trigger alerts when disconnected")}
        {num("group_minutes", "Group identical events within (minutes)")}
        {num("backfill_hours", "First-seen event lookback (hours)")}
      </div>
      <div className="section-title" style={{ marginTop: 16 }}>Collected events</div>
      <div className="small muted" style={{ marginBottom: 8 }}>Successful logons/logoffs, service logons, process events, and similar high-volume events are not collected by default because they are usually benign. Select additional event types to disable collection.</div>
      <Table rowKey="key" rows={data.catalog} columns={[
        { key: "on", label: "Thu", render: (c) => <input type="checkbox" disabled={!isAdmin} checked={!dis.has(c.key)} onChange={(e) => setP({ ...p, disabled_keys: e.target.checked ? p.disabled_keys.filter((k) => k !== c.key) : [...p.disabled_keys, c.key] })} /> },
        { key: "title", label: "Event", render: (c) => <div><b>{c.title}</b><div className="small faint">{c.os} · {c.ids.length ? `Event ID ${c.ids.join(", ")}` : c.channel} {c.os === "windows" && `· ${c.channel}`}</div></div> },
        { key: "category", label: "Category", render: (c) => <span className="small">{CAT[c.category]}</span> },
        { key: "alert", label: "Warning", render: (c) => (c.alert ? <span className="small">{c.alert}{c.threshold > 1 ? ` (≥${c.threshold} times / 10 minutes)` : ""}</span> : <span className="faint small">Record only</span>) },
      ]} />
      <div className="section-title" style={{ marginTop: 16 }}>Automatic agent updates</div>
      <Toggle checked={p.update?.enabled} onChange={(v) => setP({ ...p, update: { ...p.update, enabled: v } })} label="Allow agents to install updates automatically (updates must be signed with your key; see the agent README)" />
      <div className="small muted">{data.update_manifest ? `Server release: ${data.update_manifest.version} (${data.update_manifest.platforms.join(", ")})` : "No releases found in <DATA_DIR>/agent-updates."}</div>
      {isAdmin && <div className="row" style={{ marginTop: 14 }}><button className="btn primary" onClick={save}>Save policy</button></div>}
    </div>
  );
}

function Setup() {
  const { isAdmin } = useApp();
  const { data: dl } = useApi("/agent-downloads");
  return (
    <>
      <div className="grid2">
        <div className="card card-pad">
          <div className="row" style={{ marginBottom: 8 }}><Download size={16} /><b>Download agent</b><span className="small muted" style={{ marginLeft: "auto" }}>{dl?.version && `version ${dl.version}`}</span></div>
          {!dl?.files?.length ? <div className="small muted">No agent files found in backend/agent_dist (build with agent/scripts/build.sh).</div> : dl.files.map((f) => (
            <div key={f.name} className="row" style={{ gap: 8, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
              <a className="grow" href={`/api/agent-downloads/${f.name}`} download>{f.name}</a>
              <span className="small faint">{fmtSize(f.size)}</span>
              {f.sha256 && <span className="small mono faint" title={`SHA-256: ${f.sha256}`}>{f.sha256.slice(0, 10)}…</span>}
            </div>
          ))}
          <div className="small muted" style={{ marginTop: 8 }}>The file is unsigned (no code-signing certificate), so Windows SmartScreen may display a warning when run manually; GPO deployment does not trigger this warning. Verify the SHA-256 checksum before placing it in a shared folder.</div>
        </div>
        <div className="card card-pad">
          <div className="row" style={{ marginBottom: 8 }}><ShieldCheck size={16} /><b>What the agent does and does not do</b></div>
          <div className="small" style={{ lineHeight: 1.6 }}>
            ✔ Collects performance, disk, service, and installed-software inventory; Defender/BitLocker/firewall status; and the currently logged-in user.<br />
            ✔ Collects actionable events: failed logons, account lockouts, admin privilege changes, log clearing, malware detections, unexpected device shutdowns, and service/disk errors.<br />
            ✘ Does not execute remote commands, install or remove software, read user files, capture screenshots, or record keystrokes.<br />
            ✘ Does not collect routine logon/logoff events.
          </div>
          {dl?.ca_pin && <div style={{ marginTop: 10 }}><CopyBox label="CA pin for this HTTPS server certificate (automatically included in the install command)" text={dl.ca_pin} /></div>}
        </div>
      </div>
      {isAdmin && (
        <div className="card card-pad" style={{ marginTop: 16 }}>
          <div className="row" style={{ marginBottom: 10 }}><KeyRound size={16} /><b>Install the agent</b></div>
          <InstallCommands dl={dl} />
        </div>
      )}
      <Policy />
    </>
  );
}
// ---------------------------------------------------------------- re-enrolment over an existing device: IT approval
const MATCH = { machine_id: "same hostname + machine ID", serial: "same hostname + serial number" };
const REQ_STATE = { pending: ["Waiting", "warn"], approved: ["Approved – waiting for the agent", "ok"], completed: ["Completed", "ok"],
  rejected: ["Rejected", "fail"], expired: ["Expired", ""] };

function Cmp({ label, cur, nxt, mono }) {
  const show = (v) => (Array.isArray(v) ? v.join(", ") : v) || "—";
  const diff = show(cur) !== show(nxt);
  return (
    <tr>
      <td className="small muted" style={{ whiteSpace: "nowrap", padding: "3px 12px 3px 0" }}>{label}</td>
      <td className={`small ${mono ? "mono" : ""}`} style={{ padding: "3px 12px 3px 0" }}>{show(cur)}</td>
      <td className={`small ${mono ? "mono" : ""}`} style={{ padding: "3px 0", ...(diff ? { color: "var(--warn)", fontWeight: 600 } : {}) }}>{show(nxt)}</td>
    </tr>
  );
}

function EnrollRequests({ onChanged }) {
  const toast = useToast();
  const [all, setAll] = useState(false);
  const { data, reload } = useApi(`/agent-enroll-requests${all ? "?all=1" : ""}`, { interval: 30000, deps: [all] });
  const rows = data || [];
  const pending = rows.filter((r) => r.status === "pending");
  if (!all && pending.length === 0) return null;
  const decide = async (r, verb) => {
    const approve = verb === "approve";
    const name = r.current?.hostname || r.hostname;
    const ok = await askConfirm({
      title: approve ? `Approve the new agent for ${name}?` : `Reject the request for ${name}?`,
      message: approve
        ? `The new agent (from ${r.ip}) takes over this device record and its history. The agent currently reporting for ${name} stops working as soon as the new agent picks up its key (within about 5 minutes). Approve only if you know this device was reinstalled.`
        : "The new agent is refused and stops trying. The current agent keeps working normally.",
      okText: approve ? "Approve" : "Reject", danger: true });
    if (!ok) return;
    try { await api.post(`/agent-enroll-requests/${r.id}/${verb}`, {}); toast(approve ? "Approved" : "Rejected"); reload(); onChanged?.(); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card card-pad" style={{ marginBottom: 16, ...(pending.length ? { borderColor: "var(--warn)" } : {}) }} data-testid="enroll-requests">
      <div className="row" style={{ marginBottom: 6 }}>
        <UserCheck size={16} /><b>Pending approvals{pending.length ? ` (${pending.length})` : ""}</b>
        <label className="small muted row" style={{ marginLeft: "auto", gap: 6, cursor: "pointer" }}>
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />Show decided (30 days)</label>
      </div>
      <div className="small muted" style={{ marginBottom: 10, lineHeight: 1.5 }}>
        A new agent is trying to enroll as a device that already exists (same hostname and machine ID or serial). This is normal after
        reinstalling the agent or Windows, but because enrollment is open, anyone who knows the hostname and serial could also try to impersonate a real device.
        The current agent keeps working until you approve. Compare the details below — differences are highlighted.
      </div>
      {rows.length === 0 && <div className="small faint">No requests in the last 30 days.</div>}
      <div className="stack" style={{ gap: 12 }}>
        {rows.map((r) => {
          const c = r.current || {};
          const n = r.new || {};
          const [sl, sc] = REQ_STATE[r.status] || [r.status, ""];
          return (
            <div key={r.id} className="card" style={{ padding: 12 }} data-testid={`enroll-request-${r.id}`}>
              <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
                <b>{c.hostname || r.hostname}</b><span className={`badge ${sc}`}>{sl}</span>
                <span className="small muted">#{r.id} · matched by {MATCH[r.matched_by] || r.matched_by} ·
                  first seen {timeAgo(r.created_at)}{r.attempts > 1 && ` · ${r.attempts} attempts, last ${timeAgo(r.last_attempt_at)}`}
                  {r.decided_by && ` · ${r.status === "rejected" ? "rejected" : "approved"} by ${r.decided_by} ${timeAgo(r.decided_at)}`}
                  {r.reason && ` · reason: ${r.reason}`}</span>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr><th />
                    <th className="small" style={{ textAlign: "left", paddingBottom: 4 }}>Current device{c.status && <> · <StatusBadge s={c.status} /> <span className="faint">{c.last_seen ? timeAgo(c.last_seen) : ""}</span></>}</th>
                    <th className="small" style={{ textAlign: "left", paddingBottom: 4 }}>New agent asking to replace it</th></tr></thead>
                  <tbody>
                    <Cmp label="Source IP" cur={c.ip} nxt={r.ip} mono />
                    <Cmp label="MAC" cur={c.macs} nxt={n.macs} mono />
                    <Cmp label="Network IPs" cur={c.ips} nxt={n.ips} mono />
                    <Cmp label="Serial" cur={c.serial} nxt={n.serial} mono />
                    <Cmp label="Machine ID" cur={c.machine_id} nxt={n.machine_id} mono />
                    <Cmp label="Hardware" cur={[c.manufacturer, c.model].filter(Boolean).join(" ")} nxt={[n.manufacturer, n.model].filter(Boolean).join(" ")} />
                    <Cmp label="OS" cur={c.os_name} nxt={n.os_name} />
                    <Cmp label="User" cur={c.logged_user} nxt={n.logged_user} />
                    <Cmp label="Agent version" cur={c.agent_version} nxt={r.agent_version} />
                  </tbody>
                </table>
              </div>
              {r.status === "pending" && (
                <div className="row" style={{ gap: 8, marginTop: 10, justifyContent: "flex-end" }}>
                  <button className="btn sm" onClick={() => decide(r, "reject")}><X size={14} />Reject</button>
                  <button className="btn primary sm" onClick={() => decide(r, "approve")}><Check size={14} />Approve</button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- trang
export default function Agents() {
  const { route, nav, t, isAdmin } = useApp();
  const tab = route.params?.tab || "machines";
  const { data: s, reload: reloadSummary } = useApi("/agent-summary", { interval: 30000 });
  const setTab = (t) => nav("agents", null, t === "machines" ? undefined : { tab: t });
  return (
    <>
      <PageHead crumb={t("agents.breadcrumb")} title={t("agents.title")}
        desc={t("agents.description")} />
      <div className="stats">
        <Stat icon={Monitor} label={t("agents.totalMachines")} value={s?.total} sub={s ? Object.entries(s.by_os || {}).map(([k, v]) => `${v} ${OS_LABEL[k] || k}`).join(" · ") : ""} />
        <Stat icon={s?.offline ? WifiOff : Wifi} label={t("agents.connected")} value={s ? `${s.online}/${s.total}` : null} sub={s?.offline ? `${s.offline} devices disabled, disconnected, or with stopped agents` : "All devices are reporting"} />
        <Stat icon={ShieldAlert} label={t("agents.defenderOff")} value={s?.defender_off} tone={s?.defender_off ? "fail" : ""} />
        <Stat icon={HardDrive} label={t("agents.diskNearlyFull")} value={s?.disk_full} tone={s?.disk_full ? "warn" : ""} />
      </div>
      {isAdmin && <EnrollRequests onChanged={reloadSummary} />}
      {!isAdmin && s?.pending_enroll > 0 && <div className="alert-box warn" style={{ marginBottom: 16 }}>{s.pending_enroll} re-enrolment request(s) are waiting for an administrator to approve.</div>}
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "machines", label: t("agents.machineList"), icon: Monitor }, { key: "events", label: t("agents.events"), icon: AlertTriangle },
        { key: "software", label: t("agents.software"), icon: Package }, { key: "setup", label: t("agents.agentSetup"), icon: Settings2 }]} />
      <div style={{ marginTop: 14 }}>
        {tab === "machines" && <div className="card"><MachineList open={route.id ? Number(route.id) : null} /></div>}
        {tab === "events" && <EventsView hostCol />}
        {tab === "software" && <div className="card"><SoftwareFleet /></div>}
        {tab === "setup" && <Setup />}
      </div>
    </>
  );
}
