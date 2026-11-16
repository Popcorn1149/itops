import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { useUi, chartColors } from "../theme";
import { Plus, Play, Trash2, Search, FlaskConical, Power, Info, FileText } from "lucide-react";
import { api, SECRET } from "../api";
import { useApp, go } from "../App";
import {
  useApi, PageHead, Table, Tabs, StatusBadge, Modal, Field, Input, Select, Toggle, useToast, timeAgo, Dot, CHECK_TYPES,
  typeMeta, Empty, confirmDelete, UsageBar, SevBadge, SEV,
} from "../ui";
import { ResourcePanel, ResourceChart } from "../components/Resources";

const T = (key, label, type = "text", extra = {}) => ({ key, label, type, ...extra });
const isV3 = (c) => String(c.version) === "3";
const SNMP_FIELDS = [
  T("version", "SNMP Version", "select", { options: [["2c", "v2c"], ["3", "v3"]], default: "2c" }),
  T("community", "Community", "password", { show: (c) => !isV3(c), hint: "Default is public — change this on the devices" }),
  T("username", "SNMPv3 user", "text", { show: isV3 }),
  T("password", "Auth password", "password", { show: isV3 }),
  T("auth_protocol", "Auth protocol", "select", { options: ["SHA", "SHA256", "MD5"], show: isV3, default: "SHA" }),
  T("priv_key", "Privacy password", "password", { show: isV3 }),
  T("priv_protocol", "Privacy protocol", "select", { options: ["AES", "DES"], show: isV3, default: "AES" }),
  T("port", "UDP Port", "number", { default: 161 }),
];
// CPU / RAM / disk thresholds (backend: collectors/base.py RES_DEFAULTS). Three levels plus rearm, similar to OpManager. Leave empty to disable a level.
export const RES_DEF = {
  cpu: { attention: 80, trouble: 90, critical: 95, rearm: 75 },
  mem: { attention: 85, trouble: 92, critical: 97, rearm: 80 },
  disk: { attention: 80, trouble: 90, critical: 95, rearm: 75 },
};
const RES_FIELDS = (show, diskLabel = "Disk") => [
  T("_res", "Resource thresholds – Attention / Trouble / Critical (≥ %) · Rearm: resolve alert when usage drops below (%)", "section", { show }),
  ...[["cpu", "CPU"], ["mem", "RAM"], ["disk", diskLabel]].map(([k, l]) => T(`_${k}`, l, "res4", { show, keys: ["attention", "trouble", "critical", "rearm"].map((x) => `${k}_${x}`) })),
];
const RES_KEYS = Object.entries(RES_DEF).flatMap(([k, v]) => Object.keys(v).map((x) => `${k}_${x}`));
const RES_DEFAULTS = Object.fromEntries(Object.entries(RES_DEF).flatMap(([k, v]) => Object.entries(v).map(([x, n]) => [`${k}_${x}`, n])));
const FIELDS = {
  ping: [T("count", "Packet Count", "number", { default: 3 }), T("warn_ms", "Alert when > (ms)", "number", { default: 200 }), T("warn_loss", "Alert when packet loss > (%)", "number", { default: 20 })],
  internet: [
    T("count", "Ping packets per target", "number", { default: 5 }),
    T("warn_ms", "Alert when latency > (ms)", "number", { default: 150 }),
    T("warn_loss", "Alert when packet loss > (%)", "number", { default: 10 }),
    T("warn_jitter", "Alert when jitter > (ms)", "number", { default: 30 }),
    T("dns_name", "DNS name to resolve", "text", { default: "google.com", hint: "Leave blank to skip DNS checks" }),
    T("http_url", "HTTP test URL", "text", { default: "http://www.gstatic.com/generate_204", hint: "Similar to Android/Chrome captive portal checks. Leave empty to skip" }),
    T("public_ip", "Check public IP (api.ipify.org) to identify the active WAN path", "bool", { default: true }),
    T("warn_ip_change", "Warn when the public IP changes (WAN failover)", "bool", { default: true, show: (c) => c.public_ip !== false }),
  ],
  tcp: [T("port", "Port", "number", { default: 443 }), T("timeout", "Timeout (seconds)", "number", { default: 5 })],
  http: [
    T("method", "Method", "select", { options: ["GET", "HEAD", "POST"], default: "GET" }),
    T("expected_status", "Expected HTTP status codes", "text", { default: "200-399", hint: "e.g. 200-399 or 200,301" }),
    T("keyword", "Required response content", "text", { hint: "Leave empty if not required" }),
    T("warn_ms", "Warn when response time exceeds (ms)", "number", { default: 3000 }),
    T("cert_warn_days", "Warn when SSL certificate expires in less than (days)", "number", { default: 14 }),
    T("verify_ssl", "Verify SSL certificate", "bool", { default: false }),
    T("check_cert", "Monitor certificate expiration", "bool", { default: true }),
  ],
  snmp: [
    ...SNMP_FIELDS,
    T("profile", "Type devices", "select", { options: [["generic", "Chung (switch, router, AP, server...)"], ["ups", "UPS (RFC1628 – APC, Eaton...)"], ["synology", "Synology NAS"]], default: "generic" }),
    T("interfaces", "Read interface table", "bool", { default: true }),
    T("vm_inventory", "Read virtual machine inventory (ESXi)", "bool", { default: true, hint: "Automatically retrieve ESXi inventory via SNMP: VM name, power state, vCPU, and allocated RAM. To retrieve per-VM CPU/RAM/disk, snapshots, and IP addresses, use an ESXi (API) check." }),
    T("esxi_user", "Read-only ESXi username (for per-VM CPU/RAM/disk metrics)", "text", { hint: "ESXi SNMP does not provide VM performance metrics. Enter an ESXi user with the Read-only role to retrieve CPU/RAM/disk and IP data through the API (port 443). Leave empty if not required. ESXi.", show: (c) => c.vm_inventory !== false }),
    T("esxi_password", "Password ESXi", "password", { show: (c) => c.vm_inventory !== false && !!c.esxi_user }),
    T("watch_ports", "Monitored ports", "text", { hint: "Port names/aliases, comma-separated (e.g. Gi1/0/48, uplink-fw). DOWN triggers an alert." }),
    T("resources", "Collect CPU / RAM / disk metrics", "bool", { default: true, hint: "HOST-RESOURCES-MIB; automatically tries UCD (Linux), Cisco, and HP/Aruba extensions" }),
    ...RES_FIELDS((c) => c.resources !== false),
  ],
  ssh: [
    T("platform", "Operating system", "select", { options: [["linux", "Linux"], ["windows", "Windows (OpenSSH Server)"], ["freebsd", "FreeBSD / pfSense / OPNsense"]], default: "linux" }),
    T("port", "Port SSH", "number", { default: 22 }),
    T("username", "User", "text", { default: "root" }),
    T("password", "Password", "password", { hint: "Or use the private key below" }),
    T("private_key", "Private key (OpenSSH)", "textarea", { secret: true }),
    T("watch_containers", "Required running containers", "text", { hint: "Container names, comma-separated", show: (c) => !["windows", "freebsd"].includes(c.platform) }),
    T("discover_containers", "Show containers on the system map", "bool", { default: true, show: (c) => !["windows", "freebsd"].includes(c.platform) }),
    T("hyperv", "Read Hyper-V virtual machines", "bool", { default: false, hint: "Lists VMs (status, vCPU, RAM, CPU %, snapshots, IP). The SSH user must belong to the Hyper-V Administrators group.", show: (c) => c.platform === "windows" }),
    T("win_events", "Collect Windows security events", "bool", { default: false, hint: "Reads events by RecordId: log cleared (1102, 104), logging service stopped (1100), account created (4720), and added to an admin group (4728/4732/4756). The SSH user requires Administrator privileges or membership in the Event Log Readers group.", show: (c) => c.platform === "windows" }),
    T("watch_services", "Required running services", "text", { hint: "Windows service names, comma-separated (e.g. MSSQLSERVER, VeeamBackupSvc)", show: (c) => c.platform === "windows" }),
    T("command", "Custom command (advanced)", "textarea", { hint: "Disabled by default (device accounts should be read-only). Leave empty to use the built-in collectors. Available only when the server has ALLOW_SSH_COMMAND=1. Exit code 0=OK, 1=alert, any other value=error.", show: (c) => c.platform === "linux" || !c.platform }),
    ...RES_FIELDS((c) => !c.command),
  ],
  esxi: [
    T("username", "User", "text", { default: "root", hint: "Create a read-only user (Read-only role)" }),
    T("password", "Password", "password"),
    T("port", "Port", "number", { default: 443 }),
    T("snapshot_warn_days", "Warn when snapshots are older than (days)", "number", { default: 7 }),
    T("verify_ssl", "Verify SSL certificate", "bool", { default: false }),
    ...RES_FIELDS(undefined, "Datastore"),
  ],
  proxmox: [
    T("token_id", "API token ID", "text", { default: "itops@pve!monitor", hint: "Datacenter › Permissions › API Tokens. Format: user@realm!token-name" }),
    T("token_secret", "Token secret", "password", { hint: "Assign the PVEAuditor role on '/' to the token (or disable Privilege Separation)" }),
    T("port", "Port", "number", { default: 8006 }),
    T("guest_agent", "Read IP / disk via QEMU guest agent", "bool", { default: true, hint: "Requires the guest agent in the VM and VM.GuestAgent.Audit (PVE 9) / VM.Monitor (PVE 8) permissions; skipped if unavailable" }),
    T("snapshot_check", "Check snapshots", "bool", { default: true }),
    T("snapshot_warn_days", "Warn when snapshots are older than (days)", "number", { default: 7 }),
    T("verify_ssl", "Verify SSL certificate", "bool", { default: false }),
    ...RES_FIELDS(undefined, "Storage"),
  ],
  pfsense: [
    T("flavor", "Type", "select", { options: [["pfsense", "pfSense"], ["opnsense", "OPNsense"]], default: "pfsense" }),
    T("mode", "Data collection method", "select", { options: [["api", "REST API (recommended)"], ["snmp", "SNMP"]], default: "api", show: (c) => c.flavor !== "opnsense" }),
    T("api_key", "API key", "password", { show: (c) => c.mode !== "snmp", hint: "pfSense: System › REST API › Keys. OPNsense: System › Access › Users › API keys." }),
    T("client_secret", "API secret (OPNsense)", "password", { show: (c) => c.flavor === "opnsense" }),
    T("username", "Username (if not using an API key)", "text", { show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    T("password", "Password", "password", { show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    ...SNMP_FIELDS.map((f) => ({ ...f, show: (c) => c.mode === "snmp" && (!f.show || f.show(c)) })),
    T("cli_enabled", "Read CPU/RAM/disk via SSH (CLI) — matches the pfSense dashboard", "bool", { default: false, show: (c) => c.mode === "snmp",
      hint: "pfSense SNMP does not report accurate RAM usage. Enable SSH under System › Advanced › Secure Shell. Use a dedicated monitoring account." }),
    T("cli_username", "SSH user", "text", { default: "admin", show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("cli_password", "SSH password", "password", { show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("cli_port", "Port SSH", "number", { default: 22, show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("watch_interfaces", "Monitored interfaces", "text", { show: (c) => c.mode !== "snmp", hint: "e.g. WAN, LAN, OPT1 — DOWN triggers an alert" }),
    T("check_vpn", "Monitor VPN (IPsec/OpenVPN)", "bool", { default: true, show: (c) => c.mode !== "snmp" }),
    T("discover_dhcp", "Show DHCP devices on the system map", "bool", { default: false, show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    T("verify_ssl", "Verify SSL certificate", "bool", { default: false, show: (c) => c.mode !== "snmp" }),
    ...RES_FIELDS(),
  ],
};
const TARGET_HINT = {
  internet: "One check per Internet link. Enter comma-separated ping targets: the ISP gateway/IP for this link (e.g. 113.161.119.25), or an external public IP.",
  ping: "IP or hostname", tcp: "IP or hostname", http: "https://erp.congty.local", snmp: "IP devices",
  ssh: "IP devices Linux / Windows", esxi: "IP ESXi or vCenter", proxmox: "IP/hostname node Proxmox (VD: 10.0.10.21)", pfsense: "IP/hostname web GUI (VD: 10.0.0.1 or 10.0.0.1:8443)",
};
const INET_DEFAULT = "1.1.1.1, 8.8.8.8, 208.67.222.222";
// Public IP (excluding 10.x, 172.16–31.x, 192.168.x, 100.64/10, 127.x, and 169.254.x) – suggestion only
function isPublicIp(t) {
  const m = String(t || "").trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254));
}
const INTERVALS = [[30, "30 seconds"], [60, "1 minutes"], [120, "2 minutes"], [300, "5 minutes"], [600, "10 minutes"], [1800, "30 minutes"]];

function defaults(type) {
  const f = FIELDS[type] || [];
  const d = Object.fromEntries(f.filter((x) => x.default !== undefined).map((x) => [x.key, x.default]));
  if (f.some((x) => x.type === "res4")) Object.assign(d, RES_DEFAULTS);
  return d;
}
// Stale checks: map the two thresholds (warn/fail, datastore_*) to Trouble/Critical; use default values when keys are missing
function upgradeResCfg(cfg, type) {
  if (!(FIELDS[type] || []).some((x) => x.type === "res4")) return cfg;
  const c = { ...cfg };
  for (const k of ["cpu", "mem", "disk"]) {
    const w = c[`${k}_warn`] ?? (k === "disk" ? c.datastore_warn : undefined), f = c[`${k}_fail`] ?? (k === "disk" ? c.datastore_fail : undefined);
    if (w !== undefined && c[`${k}_trouble`] === undefined) { c[`${k}_trouble`] = w; if (c[`${k}_attention`] === undefined) c[`${k}_attention`] = ""; }
    if (f !== undefined && c[`${k}_critical`] === undefined) c[`${k}_critical`] = f;
    delete c[`${k}_warn`]; delete c[`${k}_fail`];
    if (k === "disk") { delete c.datastore_warn; delete c.datastore_fail; }
  }
  for (const k of RES_KEYS) if (c[k] === undefined) c[k] = RES_DEFAULTS[k];
  return c;
}

const HCOL = { attention: "#ca8a04", trouble: "#ea580c", warning: "#ea580c", critical: "#dc2626" };
function HistoryChart({ id }) {
  const { theme } = useUi();
  const { data } = useApi(`/checks/${id}/history?hours=24`);
  const el = useRef();
  useEffect(() => {
    if (!data || !data.length || !el.current) return;
    const c = echarts.init(el.current);
    const T = chartColors();   // text, grid, and tooltip colors based on the Light/Dark theme
    const hasVal = data.some((r) => r.value != null && r.value !== r.latency) && !data.some((r) => r.metrics);   // dedicated resource history is available → hide the "Value" series
    c.setOption({
      grid: { left: 40, right: hasVal ? 40 : 12, top: 24, bottom: 24 },
      tooltip: { ...T.tooltip, trigger: "axis" },
      legend: { top: 0, right: 0, textStyle: { color: T.text2, fontSize: 11 } },
      xAxis: { type: "time", axisLabel: { color: T.muted, fontSize: 10 } },
      yAxis: [{ type: "value", name: "ms", nameTextStyle: { color: T.muted, fontSize: 10 }, axisLabel: { color: T.muted, fontSize: 10 }, splitLine: { lineStyle: { color: T.line } } },
        ...(hasVal ? [{ type: "value", axisLabel: { color: T.muted, fontSize: 10 }, splitLine: { show: false } }] : [])],
      visualMap: { show: false, seriesIndex: 0, dimension: 2, pieces: [{ value: 0, color: "#16a34a" }, { value: 1, color: "#ea580c" }, { value: 2, color: "#991b1b" }] },
      series: [
        { name: "Latency", type: "line", showSymbol: false, data: data.map((r) => [r.ts, r.latency, r.down ? 2 : r.severity ? 1 : 0]), lineStyle: { width: 1.5 } },
        ...(hasVal ? [{ name: "Value", type: "line", yAxisIndex: 1, showSymbol: false, data: data.map((r) => [r.ts, r.value]), lineStyle: { width: 1.2, type: "dashed", color: "#6366f1" }, itemStyle: { color: "#6366f1" } }] : []),
      ],
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [data, theme]);
  if (!data) return null;
  if (!data.length) return <div className="small muted">No historical data available.</div>;
  const bad = data.filter((r) => r.down).length;
  return <>
    <div className="small muted" style={{ marginBottom: 4 }}>In the last 24 hours · {data.length} runs · uptime {(((data.length - bad) / data.length) * 100).toFixed(2)}% <span className="faint">(counts DOWN events only (loss of connectivity))</span></div>
    <div className="row" style={{ gap: 1, marginBottom: 4 }}>{data.slice(-90).map((r, i) => <div key={i} title={`${new Date(r.ts).toLocaleTimeString("vi-VN")} · ${r.down ? "DOWN" : SEV[r.severity]?.label || "OK"} · ${r.message}`}
      style={{ flex: 1, height: 18, borderRadius: 2, background: r.down ? "#991b1b" : HCOL[r.severity] || (r.status === "unknown" ? "#ccc" : "#16a34a") }} />)}</div>
    <div className="row small faint" style={{ gap: 12, marginBottom: 10 }}>{[["#16a34a", "OK"], ["#ca8a04", "Attention"], ["#ea580c", "Trouble"], ["#dc2626", "Critical"], ["#991b1b", "DOWN"]].map(([c, l]) => <span key={l} className="row" style={{ gap: 4 }}><i style={{ width: 9, height: 9, borderRadius: 2, background: c, display: "inline-block" }} />{l}</span>)}</div>
    <div ref={el} style={{ height: 170 }} />
  </>;
}

function SnmpDiag({ d }) {
  return (
    <details className="card card-pad small">
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>SNMP diagnostics (raw data — share this section if RAM/disk metrics appear incorrect)</summary>
      <div className="kv" style={{ marginTop: 10 }}>
        <div>sysObjectID</div><div className="mono">{d.sys_object_id || "—"}</div>
        <div>RAM data source</div><div>{d.mem_source || "Not available"}</div>
        <div>hrMemorySize</div><div>{d.hr_memory_mb != null ? `${d.hr_memory_mb} MB` : "Not available"}</div>
        <div>UCD (net-snmp)</div><div className="mono">{d.ucd_mb ? Object.entries(d.ucd_mb).map(([k, v]) => `${k}=${v}MB`).join(" · ") : "Not available"}</div>
        <div>hrStorage</div><div>{d.storage_count} rows</div>
      </div>
      {d.storage?.length > 0 && <MiniTable title="" rows={d.storage} cols={[["descr", "Description"], ["type", "Type"], ["size_mb", "Total (MB)"], ["used_mb", "Used (MB)"]]} />}
    </details>
  );
}

// Signal = SNR in dB (signal above the noise floor). Rough guide used by Wi-Fi vendors:
// ≥ 40 excellent · 25–39 good · 20–24 fair (slower, occasional drops) · < 20 poor (drops, retries, very slow).
const SNR_LEVELS = [[40, "Excellent", "ok"], [25, "Good", "ok"], [20, "Fair", "warn"], [-999, "Poor", "fail"]];
function snrLevel(snr) {
  return snr == null ? null : SNR_LEVELS.find(([min]) => snr >= min);
}
function wifiHint(c) {
  const lvl = snrLevel(c.snr);
  if (lvl && lvl[2] === "fail") return "Weak signal: the device is too far from the AP or blocked by walls – expect drops and slow speed.";
  const rate = Math.min(c.tx_rate || 0, c.rx_rate || 0);
  if (lvl && lvl[2] === "ok" && rate > 0 && rate < 54) return "Good signal but low speed: old Wi-Fi standard (802.11b/g), power-saving mode, or channel interference.";
  if (lvl && lvl[2] === "warn") return "Signal is borderline: move closer to the AP or add an AP in this area if the user complains.";
  return "";
}

// Wi-Fi clients reported by an Aruba Instant AP / virtual controller (SNMP AI-AP-MIB), refreshed on every check run.
function WifiClients({ clients, info }) {
  const [q, setQ] = useState("");
  const [essid, setEssid] = useState("");
  const essids = Object.entries(info.by_essid || {}).sort((a, b) => b[1] - a[1]);
  const t = q.trim().toLowerCase();
  const rows = clients.filter((c) => (!essid || (c.essid || "?") === essid)
    && (!t || [c.name, c.ip, c.mac, c.os, c.essid, c.ap].some((v) => (v || "").toLowerCase().includes(t))))
    .map((c) => ({ ...c, id: c.mac }));
  const dash = (v) => v || <span className="faint">—</span>;
  return (
    <div className="card card-pad" style={{ maxWidth: "100%", minWidth: 0, overflow: "hidden" }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <b>Wi-Fi clients ({clients.length})</b>
        {info.weak_signal > 0 && <span className="badge fail" title="Clients with SNR below 20 dB">{info.weak_signal} weak signal</span>}
        {essids.map(([e, n]) => (
          <button key={e} className={`btn sm ${essid === e ? "primary" : ""}`} onClick={() => setEssid(essid === e ? "" : e)}>{e} · {n}</button>
        ))}
        <input className="input" style={{ marginLeft: "auto", maxWidth: 240 }} placeholder="Search name, IP, MAC, OS…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {info.error && <div className="small" style={{ color: "var(--fail)", marginBottom: 8 }}>Could not read the client list: {info.error}</div>}
      <div className="wifi-tbl">
      <Table rows={rows} empty={<span className="muted small">{clients.length ? "No client matches the filter." : "No client is connected."}</span>} columns={[
        { key: "name", label: "Name", render: (c) => dash(c.name) },
        { key: "ip", label: "IP Address", render: (c) => <span className="mono small">{dash(c.ip)}</span> },
        { key: "mac", label: "MAC address", render: (c) => <span className="mono small">{c.mac}</span> },
        { key: "os", label: "OS", render: (c) => dash(c.os) },
        { key: "essid", label: "ESSID", render: (c) => <span style={{ whiteSpace: "nowrap" }}>{dash(c.essid)}</span> },
        { key: "ap", label: "Access Point", render: (c) => <span title={c.ap_ip}>{dash(c.ap)}</span> },
        { key: "snr", label: "Signal", sort: (c) => c.snr ?? -1, render: (c) => {
          const lvl = snrLevel(c.snr);
          return lvl ? <span style={{ whiteSpace: "nowrap" }} title={wifiHint(c) || "SNR: signal above the noise floor"}><span className={`badge ${lvl[2]}`}>{lvl[1]} · {c.snr} dB</span></span> : dash(null);
        } },
        { key: "tx_rate", label: "Speed (Mbps)", sort: (c) => Math.min(c.tx_rate ?? 0, c.rx_rate ?? 0), render: (c) => (c.tx_rate == null && c.rx_rate == null) ? dash(null)
          : <span className="small" style={{ whiteSpace: "nowrap" }} title={`Link rate negotiated with the AP (not actual throughput)\nDevice → AP: ${c.tx_rate ?? "?"} Mbps\nAP → device: ${c.rx_rate ?? "?"} Mbps${wifiHint(c) ? "\n\n" + wifiHint(c) : ""}`}>
            ↑{c.tx_rate ?? "?"} / ↓{c.rx_rate ?? "?"}</span> },
      ]} />
      </div>
      <div className="small muted" style={{ marginTop: 8 }}>
        Signal = SNR (dB above noise): ≥ 40 excellent · 25–39 good · 20–24 fair · &lt; 20 poor. Speed = link rate negotiated with the AP, not actual throughput.
        Hover a row value for a likely cause.
      </div>
    </div>
  );
}

function DataView({ data }) {
  if (!data || !Object.keys(data).length) return null;
  const { ports, gateways, datastores, containers, disks, hosts, interfaces, ipsec, res, stopped_services, snmp_diag, targets, dns, http: web, wifi_clients, wifi, ...rest } = data;
  const LABELS = { sys_name: "Device name", sys_descr: "Description", location: "Location", uptime: "Uptime", cpu: "CPU (%)", mem: "RAM (%)", mem_pct: "RAM (%)",
    disk: "Disk (%)", temp: "Temperature (°C)", version: "Version", platform: "Platform", hostname: "Hostname", os: "Operating system", load1: "Load 1 minutes",
    nproc: "CPU count", vm_total: "Total VMs", vm_on: "Running VMs", product: "Product", openvpn_clients: "OpenVPN client", code: "HTTP status", cert_days: "SSL days remaining",
    loss: "Packet loss (%)", battery_charge: "Battery (%)", runtime_min: "Battery runtime (minutes)", temperature: "Temperature (°C)", dsm_version: "DSM",
    wan_in_mbps: "WAN download (Mbps)", wan_out_mbps: "WAN upload (Mbps)",
    latency_ms: "Best latency (ms)", jitter_ms: "Jitter (ms)", public_ip: "Public IP (egress)", public_ip_prev: "Previous public IP" };
  const HIDE = new Set(["reachable", "total", "ports_up", "ports_total", "wan_up", "wan_total", "traffic_ready", "snmp_uptime", "output", "fields", "via",
    ...(res ? ["cpu", "mem", "mem_pct", "disk"] : [])]);
  const simple = Object.entries(rest).filter(([k, v]) => (typeof v !== "object" || v === null) && !HIDE.has(k) && v !== "" && v != null)
    .map(([k, v]) => [LABELS[k] || k, v]);
  return (
    <div className="stack" style={{ gap: 12 }}>
      {res && <div className="card card-pad"><div className="small" style={{ fontWeight: 600, marginBottom: 8 }}>Resources</div><ResourcePanel res={res} /></div>}
      {(wifi_clients || wifi) && <WifiClients clients={wifi_clients || []} info={wifi || {}} />}
      {simple.length > 0 && <div className="kv">{simple.map(([k, v]) => <React.Fragment key={k}><div>{k}</div><div className="small">{String(v)}</div></React.Fragment>)}</div>}
      {targets?.length > 0 && <MiniTable title={`Ping targets (${data.reachable}/${data.total} responding)`} rows={targets} cols={[["target", "Target"],
        ["loss", "Packet loss", (v) => <span style={{ color: v >= 100 ? "var(--fail)" : v > 0 ? "var(--warn)" : undefined }}>{v}%</span>],
        ["rtt", "TB (ms)", (v) => v ?? "—"], ["min", "Min", (v) => v ?? "—"], ["max", "Max", (v) => v ?? "—"], ["jitter", "Jitter", (v) => v ?? "—"]]} />}
      {(dns || web) && <div className="kv">
        {dns && <><div>DNS {dns.name}</div><div className="small">{dns.ok ? `${dns.ms} ms → ${dns.addr}` : <span style={{ color: "var(--fail)" }}>error ({dns.error})</span>}</div></>}
        {web && <><div>HTTP</div><div className="small">{web.ok ? `${web.code} · ${web.ms} ms` : <span style={{ color: "var(--fail)" }}>error ({web.code || web.error})</span>} <span className="faint">{web.url}</span></div></>}
      </div>}
      {gateways?.length > 0 && <MiniTable title="Gateway / WAN" rows={gateways} cols={[["name", "Name"], ["status", "Status", (v) => <StatusBadge status={["online", "none"].includes(v) ? "ok" : "fail"}>{v}</StatusBadge>], ["delay", "Latency"], ["loss", "Packet loss"]]} />}
      {interfaces?.length > 0 && <MiniTable title="Interface" rows={interfaces} cols={[["name", "Name"], ["if", "Port"], ["ip", "IP"], ["status", "Status"]]} />}
      {ipsec?.length > 0 && <MiniTable title="IPsec" rows={ipsec} cols={[["name", "Tunnel"], ["remote", "Remote"], ["state", "Status"]]} />}
      {hosts?.length > 0 && <MiniTable title="Host" rows={hosts} cols={[["name", "Host"], ["cpu_pct", "CPU", (v) => <UsageBar pct={v} />], ["mem_pct", "RAM", (v) => <UsageBar pct={v} />], ["status", "Status", (v) => <StatusBadge status={v} />]]} />}
      {!res && datastores?.length > 0 && <MiniTable title="Datastore" rows={datastores} cols={[["name", "Name"], ["used_pct", "Used", (v) => <UsageBar pct={v} />], ["free_gb", "Free (GB)"], ["capacity_gb", "Total (GB)"]]} />}
      {stopped_services?.length > 0 && <div className="small"><b>Automatically started services that are currently stopped:</b> <span className="muted">{stopped_services.join(", ")}</span></div>}
      {!res && disks?.length > 0 && <MiniTable title="Disks" rows={disks} cols={[["mount", "Mount"], ["pct", "Used", (v) => <UsageBar pct={v} />]]} />}
      {containers?.length > 0 && <MiniTable title="Container" rows={containers} cols={[["name", "Name"], ["image", "Image"], ["status", "Status", (v) => <span className={`badge ${String(v).startsWith("Up") ? "ok" : "fail"}`}>{v}</span>]]} />}
      {ports?.length > 0 && <PortsTable data={data} ports={ports} />}
      {snmp_diag && <SnmpDiag d={snmp_diag} />}
    </div>
  );
}
const STATE = { up: ["Up", "ok"], active: ["Up (traffic detected)", "ok"], down: ["Down", "fail"], disabled: ["Disabled", ""] };
const mbps = (v) => (v == null ? <span className="faint">—</span> : v >= 100 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v.toFixed(3));
function PortsTable({ data, ports }) {
  const [all, setAll] = useState(false);
  const rows = ports.filter((p) => all || (!p.virtual && p.admin === "up"))
    .sort((a, b) => (b.wan - a.wan) || ((b.in_mbps || 0) + (b.out_mbps || 0)) - ((a.in_mbps || 0) + (a.out_mbps || 0)));
  const hasRate = ports.some((p) => p.in_mbps != null);
  return (
    <div>
      <div className="row" style={{ marginBottom: 4 }}>
        <div className="small grow" style={{ fontWeight: 600 }}>Port ({data.ports_up}/{data.ports_total} up{data.wan_total ? ` · WAN ${data.wan_up}/${data.wan_total}` : ""})</div>
        <Toggle checked={all} onChange={setAll} label={<span className="small">Show virtual/disabled interfaces</span>} />
      </div>
      {!hasRate && <div className="small muted" style={{ marginBottom: 4 }}>Traffic rates (Mbps) appear after the second collection — click Run now again or wait for the next interval.</div>}
      <div className="card" style={{ maxHeight: 320, overflow: "auto" }}><table className="tbl"><thead><tr>
        {["Port", "Description", "Status", "↓ Inbound (Mbps)", "↑ Outbound (Mbps)", "Speed"].map((h) => <th key={h} style={{ padding: "7px 10px" }}>{h}</th>)}</tr></thead>
        <tbody>{rows.map((p) => {
          const [label, cls] = STATE[p.state || (p.oper === "up" ? "up" : "down")] || ["?", ""];
          return (
            <tr key={p.idx}>
              <td style={{ padding: "6px 10px", fontSize: 13 }}><span className="mono">{p.name}</span>{p.wan && <span className="badge accent" style={{ fontSize: 10, marginLeft: 4 }}>WAN</span>}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }}>{p.alias}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }} title={p.state === "active" ? "SNMP reports the port as down, but traffic is detected (common with PPPoE/tunnels) → treat it as running" : ""}><span className={`badge ${cls}`}>{label}</span></td>
              <td style={{ padding: "6px 10px", fontSize: 13 }} className="mono">{mbps(p.in_mbps)}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }} className="mono">{mbps(p.out_mbps)}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }} className="muted">{p.speed ? `${p.speed >= 1000 ? p.speed / 1000 + " G" : p.speed + " M"}` : "—"}</td>
            </tr>);
        })}</tbody></table></div>
    </div>
  );
}

function MiniTable({ title, rows, cols }) {
  return <div><div className="small" style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>
    <div className="card" style={{ maxHeight: 240, overflow: "auto" }}><table className="tbl"><thead><tr>{cols.map(([k, l]) => <th key={k} style={{ padding: "7px 10px" }}>{l}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{cols.map(([k, , fn]) => <td key={k} style={{ padding: "6px 10px", fontSize: 13 }}>{fn ? fn(r[k]) : String(r[k] ?? "")}</td>)}</tr>)}</tbody></table></div></div>;
}

export function CheckForm({ edit, onClose, onSaved }) {
  const { isAdmin } = useApp();
  const toast = useToast();
  const sites = useApi("/sites");
  const assets = useApi("/assets");
  const [f, setF] = useState(null);
  const [test, setTest] = useState(null);
  const [busy, setBusy] = useState(false);
  const origType = useRef(null);
  useEffect(() => {
    if (edit.id) api.get(`/checks/${edit.id}`).then((c) => {
      origType.current = c.type;
      setF({ ...c, config: upgradeResCfg(c.config || {}, c.type) });
    }).catch((e) => toast(e.message, true));
    else {
      const type = edit.preset?.type || "ping";
      const { _config, ...preset } = edit.preset || {};
      setF({ type, interval: 60, enabled: true, ...preset, name: preset.name ? `${preset.name} (${{ ssh: "SSH", snmp: "SNMP", esxi: "ESXi", proxmox: "Proxmox", pfsense: "pfSense", ping: "Ping", http: "HTTP", tcp: "TCP" }[type] || type})` : "", config: { alert_after: 2, ...defaults(type), ..._config } });
    }
  }, [edit.id]);
  if (!f) return null;
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const setC = (k) => (v) => setF({ ...f, config: { ...f.config, [k]: v } });
  // When editing built-in checks, preserve shared optional settings (consecutive failures before alerting, Internet line mapping, and resource thresholds)
  const keepCfg = (cfg) => Object.fromEntries(Object.entries(cfg || {}).filter(([k]) =>
    k === "alert_after" || k === "map_role" || /^(cpu|mem|disk)_(attention|trouble|critical|rearm)$/.test(k)));
  const changeType = (type) => setF({ ...f, type, target: type === "internet" && !f.target ? INET_DEFAULT : f.target,
    name: type === "internet" && !f.name ? "Line Internet" : f.name, interval: type === "internet" ? 30 : f.interval,
    config: f.id
      ? (type === origType.current ? { ...f.config } : { ...defaults(type), ...keepCfg(f.config), alert_after: f.config.alert_after ?? 2 })
      : { alert_after: f.config.alert_after ?? 2, ...defaults(type) } });
  const typeChanged = !!f.id && origType.current && f.type !== origType.current;
  const body = () => ({ ...f, site_id: f.site_id ? Number(f.site_id) : null, asset_id: f.asset_id ? Number(f.asset_id) : null, interval: Number(f.interval) });
  const save = async () => {
    try {
      f.id ? await api.put(`/checks/${f.id}`, body()) : await api.post("/checks", body());
      toast("Checks saved – they will run shortly"); onSaved();
    } catch (e) { toast(e.message, true); }
  };
  const runTest = async () => {
    setBusy(true); setTest(null);
    try { setTest(f.id && !isAdmin ? await api.post(`/checks/${f.id}/run`) : await api.post("/checks-test", body())); }
    catch (e) { setTest({ status: "fail", message: e.message }); }
    finally { setBusy(false); }
  };
  const runNow = async () => {
    setBusy(true);
    try { const r = await api.post(`/checks/${f.id}/run`); setTest(r); const n = await api.get(`/checks/${f.id}`); setF(n); }
    catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };
  const remove = async () => {
    if (!(await confirmDelete(f.name))) return;
    await api.del(`/checks/${f.id}`); toast("Deleted checks"); onSaved();
  };
  const fields = (FIELDS[f.type] || []).filter((x) => !x.show || x.show(f.config));
  const demo = f.config?.demo;

  return (
    <Modal title={f.id ? f.name : "Add monitoring check"} onClose={onClose} width={820}
      footer={<>
        {f.id && isAdmin && <button className="btn danger" style={{ marginRight: "auto" }} onClick={remove}><Trash2 size={14} />Delete</button>}
        {f.id && <button className="btn" onClick={runNow} disabled={busy}><Play size={14} />Run now</button>}
        {isAdmin && <button className="btn" onClick={runTest} disabled={busy}><FlaskConical size={14} />{busy ? "Running..." : "Test run"}</button>}
        <button className="btn" onClick={onClose}>Close</button>
        {isAdmin && <button className="btn primary" onClick={save}>Save</button>}
      </>}>
      {f.id && (
        <div className="card card-pad" style={{ marginBottom: 16 }}>
          <div className="row wrap" style={{ marginBottom: 8 }}>{f.severity ? <SevBadge sev={f.severity} /> : <StatusBadge status={f.status} />}<span className="small muted grow" style={{ minWidth: 200 }}>{f.last_message}</span><span className="small faint">{timeAgo(f.last_checked)}</span></div>
          <HistoryChart id={f.id} />
          {f.last_data?.res && <div style={{ marginTop: 14 }}><ResourceChart checkId={f.id} thresholds={f.config} height={170} current={f.last_data.res} /></div>}
        </div>
      )}
      {typeChanged && <div className="alert-box warn" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> Change type <b>{CHECK_TYPES[origType.current] || origType.current} → {CHECK_TYPES[f.type] || f.type}</b>. Check history will be preserved. When saved, open alerts for the previous Stale check type will be closed, status measurements will restart, and the change will be recorded in the audit log. We recommend clicking <b>Test run</b> before saving.</div>}
      {demo && <div className="alert-box info" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> This is a <b>sample (simulated) check</b>. Enter the real device details, then turn off “Simulation mode” to start live monitoring.</div>}
      <div className="form-grid">
        <Field label="Check type" hint={f.id ? "Can be changed; history is preserved and the change is recorded in the audit log" : undefined}><Select value={f.type} onChange={changeType} options={Object.entries(CHECK_TYPES)} disabled={!isAdmin} /></Field>
        <Field label="Display name *"><Input value={f.name} onChange={set("name")} placeholder="VD: pfSense HQ, SW-CORE" /></Field>
        <Field label="Target address *" full hint={TARGET_HINT[f.type]}><Input value={f.target} onChange={set("target")} placeholder={TARGET_HINT[f.type]} /></Field>
        <Field label="Link to asset" hint="The asset status will follow this check">
          <Select value={f.asset_id} onChange={set("asset_id")} placeholder="— None —" options={(assets.data || []).filter((a) => a.type !== "container").map((a) => [a.id, `${a.name} · ${typeMeta(a.type).label}`])} />
        </Field>
        <Field label="Site"><Select value={f.site_id} onChange={set("site_id")} placeholder="— Inherit from asset —" options={(sites.data || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Interval"><Select value={f.interval} onChange={(v) => set("interval")(Number(v))} options={INTERVALS} /></Field>
        <Field label="Line Internet" hint={f.type === "internet" ? "Internet line checks are always counted as one line on the map"
          : f.config.map_role === "wan" ? "This check counts as one Internet line for the site (the map shows the number of active lines / total lines)"
            : isPublicIp(f.target) ? "Public IP – if this is the ISP gateway/IP, select “Counts as an Internet line”" : "Not counted as an Internet line"}>
          <Select value={f.type === "internet" || f.config.map_role === "wan" ? "wan" : "none"} onChange={setC("map_role")} disabled={f.type === "internet"}
            options={[["none", "None"], ["wan", "Counts as an Internet line"]]} />
        </Field>
        <Field label="Alert after" hint="Number of consecutive failures before opening an alert"><Select value={f.config.alert_after ?? 2} onChange={(v) => setC("alert_after")(Number(v))} options={[[1, "1 failure"], [2, "2 failures"], [3, "3 failures"], [5, "5 failures"]]} /></Field>
        <Field full><div className="row" style={{ gap: 24 }}><Toggle checked={f.enabled} onChange={set("enabled")} label="Enabled" />{demo !== undefined && <Toggle checked={!!demo} onChange={setC("demo")} label="Simulation mode (sample data)" />}</div></Field>
        {fields.length > 0 && <div className="section-title">Configuration {CHECK_TYPES[f.type]}</div>}
        {fields.map((x) => {
          const v = f.config[x.key];
          if (x.type === "section") return <div key={x.key} className="section-title">{x.label}</div>;
          if (x.type === "res4") return <Field key={x.key} label={x.label} full>
            <div className="res4">{x.keys.map((k, i) => <label key={k} className={`res4-cell lv-${["attention", "trouble", "critical", "rearm"][i]}`}>
              <span>{["Attention", "Trouble", "Critical", "Rearm"][i]}</span>
              <input className="input" type="number" min="0" max="100" value={f.config[k] ?? ""} placeholder="Disabled"
                onChange={(e) => setC(k)(e.target.value === "" ? "" : Number(e.target.value))} />
            </label>)}</div></Field>;
          if (x.type === "bool") return <Field key={x.key} hint={x.hint}><Toggle checked={v} onChange={setC(x.key)} label={x.label} /></Field>;
          if (x.type === "select") return <Field key={x.key} label={x.label} hint={x.hint}><Select value={v} onChange={setC(x.key)} options={x.options} /></Field>;
          if (x.type === "textarea") return <Field key={x.key} label={x.label} hint={x.hint} full>
            <textarea className="input mono" value={v === SECRET ? "" : v || ""} placeholder={v === SECRET ? "•••••• (saved – enter a new value to replace)" : ""} onChange={(e) => setC(x.key)(e.target.value || (x.secret && f.id ? SECRET : ""))} /></Field>;
          if (x.type === "password") return <Field key={x.key} label={x.label} hint={x.hint}>
            <input className="input" type="password" autoComplete="new-password" value={v === SECRET ? "" : v || ""} placeholder={v === SECRET ? "•••••• (saved)" : ""} onChange={(e) => setC(x.key)(e.target.value || (f.id ? SECRET : ""))} /></Field>;
          return <Field key={x.key} label={x.label} hint={x.hint}><Input type={x.type === "number" ? "number" : "text"} value={v} onChange={(val) => setC(x.key)(x.type === "number" && val !== "" ? Number(val) : val)} /></Field>;
        })}
      </div>
      {f.type === "pfsense" && f.config.mode !== "snmp" && f.config.flavor !== "opnsense" && (
        <div className="alert-box info" style={{ marginTop: 14 }}>pfSense does not include a REST API by default. Go to <b>System › Package Manager</b> and install the <b>REST API</b> package (pfrest.org), then create an API key under <b>System › REST API › Keys</b>. If you cannot install it, select “Data collection method: SNMP” and enable <b>Services › SNMP</b>.</div>
      )}
      {test && (
        <div style={{ marginTop: 16 }}>
          <div className={`alert-box ${test.status === "ok" ? "ok" : test.status === "warn" ? "warn" : "fail"}`}>
            <b>{test.down ? "✗ DOWN – connection failed" : test.severity ? `⚠ ${SEV[test.severity]?.label}` : test.status === "ok" ? "✓ Success" : test.status === "warn" ? "⚠ Has alerts" : "✗ Error"}</b> · {test.message}{test.latency ? ` · ${test.latency.toFixed(0)} ms` : ""}
            {test.discovered > 0 && <div>Discovered {test.discovered} items (VM/host/container) – they will appear on the map after saving.</div>}
          </div>
        </div>
      )}
      {(test?.data || f.last_data) && Object.keys(test?.data || f.last_data || {}).length > 0 && (
        <div style={{ marginTop: 16 }}><h4 style={{ marginTop: 0 }}>Collected data</h4><DataView data={test?.data || f.last_data} /></div>
      )}
    </Modal>
  );
}

export default function Checks() {
  const { openCheck, newCheck, isAdmin, tick } = useApp();
  const { data, reload } = useApi("/checks", { interval: 15000, deps: [tick] });
  const assets = useApi("/assets", { deps: [tick] });
  const sites = useApi("/sites");
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const toast = useToast();
  const all = data || [];
  const aName = Object.fromEntries((assets.data || []).map((a) => [a.id, a.name]));
  const sName = Object.fromEntries((sites.data || []).map((s) => [s.id, s.name]));
  const rows = all.filter((c) => (tab === "all" || (tab === "off" ? !c.enabled : c.status === tab)) && (!q || `${c.name} ${c.target} ${c.type}`.toLowerCase().includes(q.toLowerCase())));
  const runAll = async () => {
    toast("Running all checks...");
    await Promise.all(all.filter((c) => c.enabled).map((c) => api.post(`/checks/${c.id}/run`).catch(() => {})));
    reload(); toast("Exited");
  };
  const toggle = async (c) => { await api.put(`/checks/${c.id}`, { enabled: !c.enabled }); reload(); };
  return (
    <>
      <PageHead crumb="Operations › Monitoring" title="Monitoring" desc="Integrations and checks: pfSense, ESXi/vCenter, switches via SNMP, Linux devices via SSH, websites, ping, and TCP ports.">
        <button className="btn" onClick={() => go("report?days=30")}><FileText size={15} />Uptime report</button>
        <button className="btn" onClick={runAll}><Play size={15} />Run all</button>
        {isAdmin && <button className="btn primary" onClick={() => newCheck()}><Plus size={15} />Add check</button>}
      </PageHead>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "All", count: all.length },
        { key: "fail", label: "Critical / DOWN", count: all.filter((c) => c.status === "fail").length },
        { key: "warn", label: "Attention / Trouble", count: all.filter((c) => c.status === "warn").length },
        { key: "ok", label: "Healthy", count: all.filter((c) => c.status === "ok").length },
        { key: "off", label: "Disabled", count: all.filter((c) => !c.enabled).length },
      ]} />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Search by name, address, or type..." value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} onRow={(c) => openCheck(c.id)} empty={<Empty title="No checks yet">Click “Add check” to start monitoring pfSense, ESXi, switches, and more.</Empty>} columns={[
          { key: "status", label: "", width: 30, sort: (c) => ({ fail: 0, warn: 1, unknown: 2, ok: 3 }[c.status]), render: (c) => <Dot status={c.enabled ? c.severity || c.status : "off"} pulse /> },
          { key: "name", label: "Check", render: (c) => <div><div className="cell-title">{c.name}{c.config?.demo && <span className="badge" style={{ fontSize: 11 }}>Sample</span>}
            {c.wan_role && <span className="badge info" style={{ fontSize: 11 }} title="Counted as one Internet line on the map">LINE</span>}</div><div className="cell-sub">{CHECK_TYPES[c.type]}</div></div> },
          { key: "target", label: "Target", render: (c) => <span className="mono small">{c.target}</span> },
          { key: "asset_id", label: "Assets / Site", sort: (c) => aName[c.asset_id] || "", render: (c) => <div className="small">{aName[c.asset_id] || <span className="faint">—</span>}<div className="muted">{sName[c.site_id]}</div></div> },
          { key: "last_message", label: "Latest result", render: (c) => <div className="small" style={{ maxWidth: 400 }}>{c.enabled && c.severity && <><SevBadge sev={c.severity} /> </>}{c.enabled ? c.last_message || <span className="faint">Not running</span> : <span className="faint">Disabled</span>}</div> },
          { key: "uptime_24h", label: "Uptime 24h", render: (c) => c.uptime_24h == null ? <span className="faint">—</span> : <span className={c.uptime_24h < 99 ? "" : "muted"} style={{ color: c.uptime_24h < 95 ? "var(--fail)" : undefined }}>{c.uptime_24h}%</span> },
          { key: "last_checked", label: "Last run", render: (c) => <span className="small muted">{timeAgo(c.last_checked)}</span> },
          ...(isAdmin ? [{ key: "act", label: "", sortable: false, render: (c) => <button className="btn ghost sm" title={c.enabled ? "Disabled" : "Enable"} onClick={(e) => { e.stopPropagation(); toggle(c); }}><Power size={14} color={c.enabled ? "#16a34a" : "#a8a29e"} /></button> }] : []),
        ]} />
      </div>
    </>
  );
}
