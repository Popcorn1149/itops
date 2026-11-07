import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { Plus, Play, Trash2, Search, FlaskConical, Power, Info } from "lucide-react";
import { api, SECRET } from "../api";
import { useApp } from "../App";
import {
  useApi, PageHead, Table, Tabs, StatusBadge, Modal, Field, Input, Select, Toggle, useToast, timeAgo, Dot, CHECK_TYPES,
  typeMeta, Empty, confirmDelete, UsageBar, SevBadge, SEV,
} from "../ui";
import { ResourcePanel, ResourceChart } from "../components/Resources";

const T = (key, label, type = "text", extra = {}) => ({ key, label, type, ...extra });
const isV3 = (c) => String(c.version) === "3";
const SNMP_FIELDS = [
  T("version", "Phiên bản SNMP", "select", { options: [["2c", "v2c"], ["3", "v3"]], default: "2c" }),
  T("community", "Community", "password", { show: (c) => !isV3(c), hint: "Mặc định public – nên đổi trên thiết bị" }),
  T("username", "SNMPv3 user", "text", { show: isV3 }),
  T("password", "Auth password", "password", { show: isV3 }),
  T("auth_protocol", "Auth protocol", "select", { options: ["SHA", "SHA256", "MD5"], show: isV3, default: "SHA" }),
  T("priv_key", "Privacy password", "password", { show: isV3 }),
  T("priv_protocol", "Privacy protocol", "select", { options: ["AES", "DES"], show: isV3, default: "AES" }),
  T("port", "Cổng UDP", "number", { default: 161 }),
];
// Threshold CPU / RAM / Disk (backend: collectors/base.py RES_DEFAULTS). 3 mức + Rearm như OpManager. Để trống = tắt mức đó.
export const RES_DEF = {
  cpu: { attention: 80, trouble: 90, critical: 95, rearm: 75 },
  mem: { attention: 85, trouble: 92, critical: 97, rearm: 80 },
  disk: { attention: 80, trouble: 90, critical: 95, rearm: 75 },
};
const RES_FIELDS = (show, diskLabel = "Disk") => [
  T("_res", "Threshold tài nguyên – Attention / Trouble / Critical (≥ %) · Rearm: đóng cảnh báo khi xuống dưới (%)", "section", { show }),
  ...[["cpu", "CPU"], ["mem", "RAM"], ["disk", diskLabel]].map(([k, l]) => T(`_${k}`, l, "res4", { show, keys: ["attention", "trouble", "critical", "rearm"].map((x) => `${k}_${x}`) })),
];
const RES_KEYS = Object.entries(RES_DEF).flatMap(([k, v]) => Object.keys(v).map((x) => `${k}_${x}`));
const RES_DEFAULTS = Object.fromEntries(Object.entries(RES_DEF).flatMap(([k, v]) => Object.entries(v).map(([x, n]) => [`${k}_${x}`, n])));
const FIELDS = {
  ping: [T("count", "Số gói", "number", { default: 3 }), T("warn_ms", "Cảnh báo khi > (ms)", "number", { default: 200 }), T("warn_loss", "Cảnh báo khi mất gói > (%)", "number", { default: 20 })],
  internet: [
    T("count", "Số gói ping mỗi đích", "number", { default: 5 }),
    T("warn_ms", "Cảnh báo độ trễ > (ms)", "number", { default: 150 }),
    T("warn_loss", "Cảnh báo mất gói > (%)", "number", { default: 10 }),
    T("warn_jitter", "Cảnh báo jitter > (ms)", "number", { default: 30 }),
    T("dns_name", "Tên miền thử phân giải DNS", "text", { default: "google.com", hint: "Để trống = bỏ kiểm tra DNS" }),
    T("http_url", "URL thử HTTP", "text", { default: "http://www.gstatic.com/generate_204", hint: "Kiểu “captive check” của Android/Chrome. Để trống = bỏ" }),
    T("public_ip", "Xem IP public (api.ipify.org) – biết đang ra bằng đường WAN nào", "bool", { default: true }),
    T("warn_ip_change", "Cảnh báo khi IP public đổi (WAN failover)", "bool", { default: true, show: (c) => c.public_ip !== false }),
  ],
  tcp: [T("port", "Cổng", "number", { default: 443 }), T("timeout", "Timeout (giây)", "number", { default: 5 })],
  http: [
    T("method", "Method", "select", { options: ["GET", "HEAD", "POST"], default: "GET" }),
    T("expected_status", "Mã HTTP hợp lệ", "text", { default: "200-399", hint: "VD: 200-399 hoặc 200,301" }),
    T("keyword", "Nội dung phải có", "text", { hint: "Để trống nếu không cần" }),
    T("warn_ms", "Cảnh báo khi chậm hơn (ms)", "number", { default: 3000 }),
    T("cert_warn_days", "Cảnh báo SSL còn < (ngày)", "number", { default: 14 }),
    T("verify_ssl", "Xác thực chứng chỉ SSL", "bool", { default: false }),
    T("check_cert", "Theo dõi hạn chứng chỉ", "bool", { default: true }),
  ],
  snmp: [
    ...SNMP_FIELDS,
    T("profile", "Loại thiết bị", "select", { options: [["generic", "Chung (switch, router, AP, server...)"], ["ups", "UPS (RFC1628 – APC, Eaton...)"], ["synology", "Synology NAS"]], default: "generic" }),
    T("interfaces", "Đọc bảng cổng (interface)", "bool", { default: true }),
    T("vm_inventory", "Đọc danh sách máy ảo (ESXi)", "bool", { default: true, hint: "Tự nhận ESXi qua SNMP: tên VM, bật/tắt, vCPU, RAM cấp phát. Muốn có CPU/RAM/disk từng VM, snapshot và IP thì dùng check loại ESXi (API)." }),
    T("esxi_user", "Tài khoản ESXi chỉ đọc (để lấy CPU/RAM/Disk từng VM)", "text", { hint: "SNMP của ESXi không có hiệu năng VM. Nhập user role Read-only của ESXi để check này lấy thêm CPU/RAM/Disk, IP qua API (cổng 443). Để trống nếu không phải ESXi.", show: (c) => c.vm_inventory !== false }),
    T("esxi_password", "Mật khẩu ESXi", "password", { show: (c) => c.vm_inventory !== false && !!c.esxi_user }),
    T("watch_ports", "Cổng quan trọng", "text", { hint: "Tên/alias cổng, cách nhau dấu phẩy (VD: Gi1/0/48, uplink-fw). Down → lỗi." }),
    T("resources", "Đọc CPU / RAM / Disk", "bool", { default: true, hint: "HOST-RESOURCES-MIB; tự thử thêm UCD (Linux), Cisco, HP/Aruba" }),
    ...RES_FIELDS((c) => c.resources !== false),
  ],
  ssh: [
    T("platform", "Hệ điều hành", "select", { options: [["linux", "Linux"], ["windows", "Windows (OpenSSH Server)"], ["freebsd", "FreeBSD / pfSense / OPNsense"]], default: "linux" }),
    T("port", "Cổng SSH", "number", { default: 22 }),
    T("username", "User", "text", { default: "root" }),
    T("password", "Mật khẩu", "password", { hint: "Hoặc dùng private key bên dưới" }),
    T("private_key", "Private key (OpenSSH)", "textarea", { secret: true }),
    T("watch_containers", "Container bắt buộc chạy", "text", { hint: "Tên container, cách nhau dấu phẩy", show: (c) => !["windows", "freebsd"].includes(c.platform) }),
    T("discover_containers", "Đưa container lên bản đồ", "bool", { default: true, show: (c) => !["windows", "freebsd"].includes(c.platform) }),
    T("hyperv", "Đọc máy ảo Hyper-V", "bool", { default: false, hint: "Liệt kê VM (status, vCPU, RAM, CPU %, snapshot, IP). Tài khoản SSH cần thuộc nhóm Hyper-V Administrators.", show: (c) => c.platform === "windows" }),
    T("win_events", "Đọc Windows Event (bảo mật)", "bool", { default: false, hint: "Đọc theo RecordId: xoá log (1102, 104), dịch vụ log dừng (1100), tạo tài khoản (4720), thêm vào admin group (4728/4732/4756). Tài khoản SSH cần quyền Administrator hoặc nhóm Event Log Readers.", show: (c) => c.platform === "windows" }),
    T("watch_services", "Service bắt buộc chạy", "text", { hint: "Tên service Windows, cách nhau dấu phẩy (VD: MSSQLSERVER, VeeamBackupSvc)", show: (c) => c.platform === "windows" }),
    T("command", "Lệnh tuỳ chỉnh (nâng cao)", "textarea", { hint: "Mặc định BỊ KHOÁ (tài khoản thiết bị chỉ để đọc) – bỏ trống để dùng bộ đo mặc định. Chỉ dùng được khi máy chủ bật ALLOW_SSH_COMMAND=1. Exit 0=OK, 1=cảnh báo, khác=lỗi.", show: (c) => c.platform === "linux" || !c.platform }),
    ...RES_FIELDS((c) => !c.command),
  ],
  esxi: [
    T("username", "User", "text", { default: "root", hint: "Nên tạo user chỉ đọc (Read-only role)" }),
    T("password", "Mật khẩu", "password"),
    T("port", "Cổng", "number", { default: 443 }),
    T("snapshot_warn_days", "Cảnh báo snapshot cũ hơn (ngày)", "number", { default: 7 }),
    T("verify_ssl", "Xác thực chứng chỉ SSL", "bool", { default: false }),
    ...RES_FIELDS(undefined, "Datastore"),
  ],
  proxmox: [
    T("token_id", "API token ID", "text", { default: "itops@pve!monitor", hint: "Datacenter › Permissions › API Tokens. Dạng user@realm!tên-token" }),
    T("token_secret", "Token secret", "password", { hint: "Gán role PVEAuditor trên '/' cho token (hoặc bỏ Privilege Separation)" }),
    T("port", "Cổng", "number", { default: 8006 }),
    T("guest_agent", "Đọc IP / disk qua QEMU guest agent", "bool", { default: true, hint: "Cần guest agent trong VM và quyền VM.GuestAgent.Audit (PVE 9) / VM.Monitor (PVE 8); thiếu thì bỏ qua" }),
    T("snapshot_check", "Kiểm tra snapshot", "bool", { default: true }),
    T("snapshot_warn_days", "Cảnh báo snapshot cũ hơn (ngày)", "number", { default: 7 }),
    T("verify_ssl", "Xác thực chứng chỉ SSL", "bool", { default: false }),
    ...RES_FIELDS(undefined, "Storage"),
  ],
  pfsense: [
    T("flavor", "Loại", "select", { options: [["pfsense", "pfSense"], ["opnsense", "OPNsense"]], default: "pfsense" }),
    T("mode", "Cách lấy dữ liệu", "select", { options: [["api", "REST API (khuyến nghị)"], ["snmp", "SNMP"]], default: "api", show: (c) => c.flavor !== "opnsense" }),
    T("api_key", "API key", "password", { show: (c) => c.mode !== "snmp", hint: "pfSense: System › REST API › Keys. OPNsense: System › Access › Users › API keys." }),
    T("client_secret", "API secret (OPNsense)", "password", { show: (c) => c.flavor === "opnsense" }),
    T("username", "User (nếu không dùng API key)", "text", { show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    T("password", "Mật khẩu", "password", { show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    ...SNMP_FIELDS.map((f) => ({ ...f, show: (c) => c.mode === "snmp" && (!f.show || f.show(c)) })),
    T("cli_enabled", "Đọc CPU/RAM/Disk qua SSH (CLI) – chính xác như Dashboard pfSense", "bool", { default: false, show: (c) => c.mode === "snmp",
      hint: "SNMP của pfSense không báo đúng RAM. Bật SSH: System › Advanced › Secure Shell. Nên dùng user riêng chỉ để giám sát." }),
    T("cli_username", "SSH user", "text", { default: "admin", show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("cli_password", "SSH mật khẩu", "password", { show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("cli_port", "Cổng SSH", "number", { default: 22, show: (c) => c.mode === "snmp" && c.cli_enabled }),
    T("watch_interfaces", "Interface quan trọng", "text", { show: (c) => c.mode !== "snmp", hint: "VD: WAN, LAN, OPT1 – down → lỗi" }),
    T("check_vpn", "Theo dõi VPN (IPsec/OpenVPN)", "bool", { default: true, show: (c) => c.mode !== "snmp" }),
    T("discover_dhcp", "Đưa thiết bị DHCP lên bản đồ", "bool", { default: false, show: (c) => c.mode !== "snmp" && c.flavor !== "opnsense" }),
    T("verify_ssl", "Xác thực chứng chỉ SSL", "bool", { default: false, show: (c) => c.mode !== "snmp" }),
    ...RES_FIELDS(),
  ],
};
const TARGET_HINT = {
  internet: "Mỗi check = 1 line. Đích ping, cách nhau dấu phẩy: gateway/IP của nhà mạng cho line này (VD 113.161.119.25), hoặc IP public bên ngoài",
  ping: "IP hoặc hostname", tcp: "IP hoặc hostname", http: "https://erp.congty.local", snmp: "IP thiết bị",
  ssh: "IP máy Linux / Windows", esxi: "IP ESXi hoặc vCenter", proxmox: "IP/hostname node Proxmox (VD: 10.0.10.21)", pfsense: "IP/hostname web GUI (VD: 10.0.0.1 hoặc 10.0.0.1:8443)",
};
const INET_DEFAULT = "1.1.1.1, 8.8.8.8, 208.67.222.222";
// IP public (không phải 10.x, 172.16–31.x, 192.168.x, 100.64/10, 127.x, 169.254.x) – chỉ để gợi ý
function isPublicIp(t) {
  const m = String(t || "").trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254));
}
const INTERVALS = [[30, "30 giây"], [60, "1 phút"], [120, "2 phút"], [300, "5 phút"], [600, "10 phút"], [1800, "30 phút"]];

function defaults(type) {
  const f = FIELDS[type] || [];
  const d = Object.fromEntries(f.filter((x) => x.default !== undefined).map((x) => [x.key, x.default]));
  if (f.some((x) => x.type === "res4")) Object.assign(d, RES_DEFAULTS);
  return d;
}
// check cũ: đổi threshold 2 mức (warn/fail, datastore_*) sang Trouble/Critical; khoá thiếu thì hiện giá trị mặc định
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
  const { data } = useApi(`/checks/${id}/history?hours=24`);
  const el = useRef();
  useEffect(() => {
    if (!data || !data.length || !el.current) return;
    const c = echarts.init(el.current);
    const hasVal = data.some((r) => r.value != null && r.value !== r.latency) && !data.some((r) => r.metrics);   // có lịch sử tài nguyên riêng → bỏ đường "Giá trị"
    c.setOption({
      grid: { left: 40, right: hasVal ? 40 : 12, top: 24, bottom: 24 },
      tooltip: { trigger: "axis" },
      legend: { top: 0, right: 0, textStyle: { fontSize: 11 } },
      xAxis: { type: "time", axisLabel: { fontSize: 10 } },
      yAxis: [{ type: "value", name: "ms", nameTextStyle: { fontSize: 10 }, axisLabel: { fontSize: 10 }, splitLine: { lineStyle: { color: "#f1efec" } } },
        ...(hasVal ? [{ type: "value", axisLabel: { fontSize: 10 }, splitLine: { show: false } }] : [])],
      visualMap: { show: false, seriesIndex: 0, dimension: 2, pieces: [{ value: 0, color: "#16a34a" }, { value: 1, color: "#ea580c" }, { value: 2, color: "#991b1b" }] },
      series: [
        { name: "Độ trễ", type: "line", showSymbol: false, data: data.map((r) => [r.ts, r.latency, r.down ? 2 : r.severity ? 1 : 0]), lineStyle: { width: 1.5 } },
        ...(hasVal ? [{ name: "Giá trị", type: "line", yAxisIndex: 1, showSymbol: false, data: data.map((r) => [r.ts, r.value]), lineStyle: { width: 1.2, type: "dashed", color: "#6366f1" }, itemStyle: { color: "#6366f1" } }] : []),
      ],
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [data]);
  if (!data) return null;
  if (!data.length) return <div className="small muted">Chưa có dữ liệu lịch sử.</div>;
  const bad = data.filter((r) => r.down).length;
  return <>
    <div className="small muted" style={{ marginBottom: 4 }}>24 giờ qua · {data.length} lần chạy · uptime {(((data.length - bad) / data.length) * 100).toFixed(2)}% <span className="faint">(chỉ tính lần DOWN – mất kết nối)</span></div>
    <div className="row" style={{ gap: 1, marginBottom: 4 }}>{data.slice(-90).map((r, i) => <div key={i} title={`${new Date(r.ts).toLocaleTimeString("vi-VN")} · ${r.down ? "DOWN" : SEV[r.severity]?.label || "OK"} · ${r.message}`}
      style={{ flex: 1, height: 18, borderRadius: 2, background: r.down ? "#991b1b" : HCOL[r.severity] || (r.status === "unknown" ? "#ccc" : "#16a34a") }} />)}</div>
    <div className="row small faint" style={{ gap: 12, marginBottom: 10 }}>{[["#16a34a", "OK"], ["#ca8a04", "Attention"], ["#ea580c", "Trouble"], ["#dc2626", "Critical"], ["#991b1b", "DOWN"]].map(([c, l]) => <span key={l} className="row" style={{ gap: 4 }}><i style={{ width: 9, height: 9, borderRadius: 2, background: c, display: "inline-block" }} />{l}</span>)}</div>
    <div ref={el} style={{ height: 170 }} />
  </>;
}

function SnmpDiag({ d }) {
  return (
    <details className="card card-pad small">
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>Chẩn đoán SNMP (dữ liệu thô – gửi ảnh phần này khi số liệu RAM/Disk bị lệch)</summary>
      <div className="kv" style={{ marginTop: 10 }}>
        <div>sysObjectID</div><div className="mono">{d.sys_object_id || "—"}</div>
        <div>Nguồn RAM đang dùng</div><div>{d.mem_source || "không có"}</div>
        <div>hrMemorySize</div><div>{d.hr_memory_mb != null ? `${d.hr_memory_mb} MB` : "không có"}</div>
        <div>UCD (net-snmp)</div><div className="mono">{d.ucd_mb ? Object.entries(d.ucd_mb).map(([k, v]) => `${k}=${v}MB`).join(" · ") : "không có"}</div>
        <div>hrStorage</div><div>{d.storage_count} dòng</div>
      </div>
      {d.storage?.length > 0 && <MiniTable title="" rows={d.storage} cols={[["descr", "Mô tả"], ["type", "Kiểu"], ["size_mb", "Tổng (MB)"], ["used_mb", "Dùng (MB)"]]} />}
    </details>
  );
}

function DataView({ data }) {
  if (!data || !Object.keys(data).length) return null;
  const { ports, gateways, datastores, containers, disks, hosts, interfaces, ipsec, res, stopped_services, snmp_diag, targets, dns, http: web, ...rest } = data;
  const LABELS = { sys_name: "Tên thiết bị", sys_descr: "Mô tả", location: "Vị trí", uptime: "Uptime", cpu: "CPU (%)", mem: "RAM (%)", mem_pct: "RAM (%)",
    disk: "Disk (%)", temp: "Nhiệt độ (°C)", version: "Phiên bản", platform: "Nền tảng", hostname: "Hostname", os: "Hệ điều hành", load1: "Load 1 phút",
    nproc: "Số CPU", vm_total: "Tổng VM", vm_on: "VM đang chạy", product: "Sản phẩm", openvpn_clients: "OpenVPN client", code: "Mã HTTP", cert_days: "SSL còn (ngày)",
    loss: "Mất gói (%)", battery_charge: "Pin (%)", runtime_min: "Thời gian pin (phút)", temperature: "Nhiệt độ (°C)", dsm_version: "DSM",
    wan_in_mbps: "WAN tải về (Mbps)", wan_out_mbps: "WAN tải lên (Mbps)",
    latency_ms: "Độ trễ tốt nhất (ms)", jitter_ms: "Jitter (ms)", public_ip: "IP public (đường ra)", public_ip_prev: "IP public trước đó" };
  const HIDE = new Set(["reachable", "total", "ports_up", "ports_total", "wan_up", "wan_total", "traffic_ready", "snmp_uptime", "output", "fields", "via",
    ...(res ? ["cpu", "mem", "mem_pct", "disk"] : [])]);
  const simple = Object.entries(rest).filter(([k, v]) => (typeof v !== "object" || v === null) && !HIDE.has(k) && v !== "" && v != null)
    .map(([k, v]) => [LABELS[k] || k, v]);
  return (
    <div className="stack" style={{ gap: 12 }}>
      {res && <div className="card card-pad"><div className="small" style={{ fontWeight: 600, marginBottom: 8 }}>Tài nguyên</div><ResourcePanel res={res} /></div>}
      {simple.length > 0 && <div className="kv">{simple.map(([k, v]) => <React.Fragment key={k}><div>{k}</div><div className="small">{String(v)}</div></React.Fragment>)}</div>}
      {targets?.length > 0 && <MiniTable title={`Đích ping (${data.reachable}/${data.total} phản hồi)`} rows={targets} cols={[["target", "Đích"],
        ["loss", "Mất gói", (v) => <span style={{ color: v >= 100 ? "var(--fail)" : v > 0 ? "var(--warn)" : undefined }}>{v}%</span>],
        ["rtt", "TB (ms)", (v) => v ?? "—"], ["min", "Min", (v) => v ?? "—"], ["max", "Max", (v) => v ?? "—"], ["jitter", "Jitter", (v) => v ?? "—"]]} />}
      {(dns || web) && <div className="kv">
        {dns && <><div>DNS {dns.name}</div><div className="small">{dns.ok ? `${dns.ms} ms → ${dns.addr}` : <span style={{ color: "var(--fail)" }}>lỗi ({dns.error})</span>}</div></>}
        {web && <><div>HTTP</div><div className="small">{web.ok ? `${web.code} · ${web.ms} ms` : <span style={{ color: "var(--fail)" }}>lỗi ({web.code || web.error})</span>} <span className="faint">{web.url}</span></div></>}
      </div>}
      {gateways?.length > 0 && <MiniTable title="Gateway / WAN" rows={gateways} cols={[["name", "Tên"], ["status", "Status", (v) => <StatusBadge status={["online", "none"].includes(v) ? "ok" : "fail"}>{v}</StatusBadge>], ["delay", "Độ trễ"], ["loss", "Mất gói"]]} />}
      {interfaces?.length > 0 && <MiniTable title="Interface" rows={interfaces} cols={[["name", "Tên"], ["if", "Port"], ["ip", "IP"], ["status", "Status"]]} />}
      {ipsec?.length > 0 && <MiniTable title="IPsec" rows={ipsec} cols={[["name", "Tunnel"], ["remote", "Remote"], ["state", "Status"]]} />}
      {hosts?.length > 0 && <MiniTable title="Host" rows={hosts} cols={[["name", "Host"], ["cpu_pct", "CPU", (v) => <UsageBar pct={v} />], ["mem_pct", "RAM", (v) => <UsageBar pct={v} />], ["status", "Status", (v) => <StatusBadge status={v} />]]} />}
      {!res && datastores?.length > 0 && <MiniTable title="Datastore" rows={datastores} cols={[["name", "Tên"], ["used_pct", "Đã dùng", (v) => <UsageBar pct={v} />], ["free_gb", "Còn trống (GB)"], ["capacity_gb", "Tổng (GB)"]]} />}
      {stopped_services?.length > 0 && <div className="small"><b>Service tự khởi động nhưng đang dừng:</b> <span className="muted">{stopped_services.join(", ")}</span></div>}
      {!res && disks?.length > 0 && <MiniTable title="Ổ đĩa" rows={disks} cols={[["mount", "Mount"], ["pct", "Đã dùng", (v) => <UsageBar pct={v} />]]} />}
      {containers?.length > 0 && <MiniTable title="Container" rows={containers} cols={[["name", "Tên"], ["image", "Image"], ["status", "Status", (v) => <span className={`badge ${String(v).startsWith("Up") ? "ok" : "fail"}`}>{v}</span>]]} />}
      {ports?.length > 0 && <PortsTable data={data} ports={ports} />}
      {snmp_diag && <SnmpDiag d={snmp_diag} />}
    </div>
  );
}
const STATE = { up: ["Up", "ok"], active: ["Up (có lưu lượng)", "ok"], down: ["Down", "fail"], disabled: ["Tắt", ""] };
const mbps = (v) => (v == null ? <span className="faint">—</span> : v >= 100 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v.toFixed(3));
function PortsTable({ data, ports }) {
  const [all, setAll] = useState(false);
  const rows = ports.filter((p) => all || (!p.virtual && p.admin === "up"))
    .sort((a, b) => (b.wan - a.wan) || ((b.in_mbps || 0) + (b.out_mbps || 0)) - ((a.in_mbps || 0) + (a.out_mbps || 0)));
  const hasRate = ports.some((p) => p.in_mbps != null);
  return (
    <div>
      <div className="row" style={{ marginBottom: 4 }}>
        <div className="small grow" style={{ fontWeight: 600 }}>Cổng ({data.ports_up}/{data.ports_total} up{data.wan_total ? ` · WAN ${data.wan_up}/${data.wan_total}` : ""})</div>
        <Toggle checked={all} onChange={setAll} label={<span className="small">Hiện cả cổng ảo/tắt</span>} />
      </div>
      {!hasRate && <div className="small muted" style={{ marginBottom: 4 }}>Lưu lượng (Mbps) hiện sau lần đọc thứ 2 – bấm Chạy ngay thêm lần nữa hoặc đợi 1 chu kỳ.</div>}
      <div className="card" style={{ maxHeight: 320, overflow: "auto" }}><table className="tbl"><thead><tr>
        {["Cổng", "Mô tả", "Status", "↓ Vào (Mbps)", "↑ Ra (Mbps)", "Tốc độ"].map((h) => <th key={h} style={{ padding: "7px 10px" }}>{h}</th>)}</tr></thead>
        <tbody>{rows.map((p) => {
          const [label, cls] = STATE[p.state || (p.oper === "up" ? "up" : "down")] || ["?", ""];
          return (
            <tr key={p.idx}>
              <td style={{ padding: "6px 10px", fontSize: 13 }}><span className="mono">{p.name}</span>{p.wan && <span className="badge accent" style={{ fontSize: 10, marginLeft: 4 }}>WAN</span>}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }}>{p.alias}</td>
              <td style={{ padding: "6px 10px", fontSize: 13 }} title={p.state === "active" ? "SNMP báo down nhưng cổng đang có lưu lượng (thường gặp với PPPoE/tunnel) → coi là đang chạy" : ""}><span className={`badge ${cls}`}>{label}</span></td>
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
  // Khi sửa check có sẵn: giữ các tuỳ chọn dùng chung (số lần lỗi trước khi báo, gán Line Internet, threshold tài nguyên)
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
      toast("Đã lưu check – sẽ chạy trong giây lát"); onSaved();
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
    await api.del(`/checks/${f.id}`); toast("Đã xoá check"); onSaved();
  };
  const fields = (FIELDS[f.type] || []).filter((x) => !x.show || x.show(f.config));
  const demo = f.config?.demo;

  return (
    <Modal title={f.id ? f.name : "Thêm check giám sát"} onClose={onClose} width={820}
      footer={<>
        {f.id && isAdmin && <button className="btn danger" style={{ marginRight: "auto" }} onClick={remove}><Trash2 size={14} />Xoá</button>}
        {f.id && <button className="btn" onClick={runNow} disabled={busy}><Play size={14} />Chạy ngay</button>}
        {isAdmin && <button className="btn" onClick={runTest} disabled={busy}><FlaskConical size={14} />{busy ? "Đang chạy..." : "Chạy thử"}</button>}
        <button className="btn" onClick={onClose}>Đóng</button>
        {isAdmin && <button className="btn primary" onClick={save}>Lưu</button>}
      </>}>
      {f.id && (
        <div className="card card-pad" style={{ marginBottom: 16 }}>
          <div className="row wrap" style={{ marginBottom: 8 }}>{f.severity ? <SevBadge sev={f.severity} /> : <StatusBadge status={f.status} />}<span className="small muted grow" style={{ minWidth: 200 }}>{f.last_message}</span><span className="small faint">{timeAgo(f.last_checked)}</span></div>
          <HistoryChart id={f.id} />
          {f.last_data?.res && <div style={{ marginTop: 14 }}><ResourceChart checkId={f.id} thresholds={f.config} height={170} current={f.last_data.res} /></div>}
        </div>
      )}
      {typeChanged && <div className="alert-box warn" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> Đổi loại <b>{CHECK_TYPES[origType.current] || origType.current} → {CHECK_TYPES[f.type] || f.type}</b>. Lịch sử kết quả được giữ. Khi lưu: cảnh báo đang mở của loại cũ sẽ đóng, status đo lại từ đầu, thao tác được ghi vào audit log. Nên bấm <b>Chạy thử</b> trước khi lưu.</div>}
      {demo && <div className="alert-box info" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> Đây là check <b>mẫu (mô phỏng)</b>. Nhập thông tin thiết bị thật rồi bỏ chọn “Chế độ mô phỏng” để giám sát thật.</div>}
      <div className="form-grid">
        <Field label="Loại check" hint={f.id ? "Đổi được: lịch sử giữ nguyên, ghi vào audit log" : undefined}><Select value={f.type} onChange={changeType} options={Object.entries(CHECK_TYPES)} disabled={!isAdmin} /></Field>
        <Field label="Tên hiển thị *"><Input value={f.name} onChange={set("name")} placeholder="VD: pfSense HQ, SW-CORE" /></Field>
        <Field label="Địa chỉ *" full hint={TARGET_HINT[f.type]}><Input value={f.target} onChange={set("target")} placeholder={TARGET_HINT[f.type]} /></Field>
        <Field label="Gắn vào tài sản" hint="Status tài sản sẽ theo check này">
          <Select value={f.asset_id} onChange={set("asset_id")} placeholder="— Không —" options={(assets.data || []).filter((a) => a.type !== "container").map((a) => [a.id, `${a.name} · ${typeMeta(a.type).label}`])} />
        </Field>
        <Field label="Site"><Select value={f.site_id} onChange={set("site_id")} placeholder="— Theo tài sản —" options={(sites.data || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Chu kỳ"><Select value={f.interval} onChange={(v) => set("interval")(Number(v))} options={INTERVALS} /></Field>
        <Field label="Line Internet" hint={f.type === "internet" ? "Check loại Line Internet luôn được tính là 1 line trên bản đồ"
          : f.config.map_role === "wan" ? "Check này được tính là 1 line Internet của site (bản đồ hiển thị số line up / tổng)"
            : isPublicIp(f.target) ? "IP public – nếu đây là gateway/IP của nhà mạng, chọn “Là 1 line Internet”" : "Không tính vào số line Internet"}>
          <Select value={f.type === "internet" || f.config.map_role === "wan" ? "wan" : "none"} onChange={setC("map_role")} disabled={f.type === "internet"}
            options={[["none", "Không"], ["wan", "Là 1 line Internet"]]} />
        </Field>
        <Field label="Báo động sau" hint="Số lần lỗi liên tiếp trước khi mở cảnh báo"><Select value={f.config.alert_after ?? 2} onChange={(v) => setC("alert_after")(Number(v))} options={[[1, "1 lần"], [2, "2 lần"], [3, "3 lần"], [5, "5 lần"]]} /></Field>
        <Field full><div className="row" style={{ gap: 24 }}><Toggle checked={f.enabled} onChange={set("enabled")} label="Đang bật" />{demo !== undefined && <Toggle checked={!!demo} onChange={setC("demo")} label="Chế độ mô phỏng (dữ liệu mẫu)" />}</div></Field>
        {fields.length > 0 && <div className="section-title">Cấu hình {CHECK_TYPES[f.type]}</div>}
        {fields.map((x) => {
          const v = f.config[x.key];
          if (x.type === "section") return <div key={x.key} className="section-title">{x.label}</div>;
          if (x.type === "res4") return <Field key={x.key} label={x.label} full>
            <div className="res4">{x.keys.map((k, i) => <label key={k} className={`res4-cell lv-${["attention", "trouble", "critical", "rearm"][i]}`}>
              <span>{["Attention", "Trouble", "Critical", "Rearm"][i]}</span>
              <input className="input" type="number" min="0" max="100" value={f.config[k] ?? ""} placeholder="tắt"
                onChange={(e) => setC(k)(e.target.value === "" ? "" : Number(e.target.value))} />
            </label>)}</div></Field>;
          if (x.type === "bool") return <Field key={x.key} hint={x.hint}><Toggle checked={v} onChange={setC(x.key)} label={x.label} /></Field>;
          if (x.type === "select") return <Field key={x.key} label={x.label} hint={x.hint}><Select value={v} onChange={setC(x.key)} options={x.options} /></Field>;
          if (x.type === "textarea") return <Field key={x.key} label={x.label} hint={x.hint} full>
            <textarea className="input mono" value={v === SECRET ? "" : v || ""} placeholder={v === SECRET ? "•••••• (đã lưu – nhập để thay)" : ""} onChange={(e) => setC(x.key)(e.target.value || (x.secret && f.id ? SECRET : ""))} /></Field>;
          if (x.type === "password") return <Field key={x.key} label={x.label} hint={x.hint}>
            <input className="input" type="password" autoComplete="new-password" value={v === SECRET ? "" : v || ""} placeholder={v === SECRET ? "•••••• (đã lưu)" : ""} onChange={(e) => setC(x.key)(e.target.value || (f.id ? SECRET : ""))} /></Field>;
          return <Field key={x.key} label={x.label} hint={x.hint}><Input type={x.type === "number" ? "number" : "text"} value={v} onChange={(val) => setC(x.key)(x.type === "number" && val !== "" ? Number(val) : val)} /></Field>;
        })}
      </div>
      {f.type === "pfsense" && f.config.mode !== "snmp" && f.config.flavor !== "opnsense" && (
        <div className="alert-box info" style={{ marginTop: 14 }}>pfSense chưa có API sẵn: vào <b>System › Package Manager</b> cài gói <b>REST API</b> (pfrest.org), rồi tạo API key ở <b>System › REST API › Keys</b>. Nếu không cài được, chọn “Cách lấy dữ liệu: SNMP” và bật <b>Services › SNMP</b>.</div>
      )}
      {test && (
        <div style={{ marginTop: 16 }}>
          <div className={`alert-box ${test.status === "ok" ? "ok" : test.status === "warn" ? "warn" : "fail"}`}>
            <b>{test.down ? "✗ DOWN – không kết nối được" : test.severity ? `⚠ ${SEV[test.severity]?.label}` : test.status === "ok" ? "✓ Thành công" : test.status === "warn" ? "⚠ Có cảnh báo" : "✗ Lỗi"}</b> · {test.message}{test.latency ? ` · ${test.latency.toFixed(0)} ms` : ""}
            {test.discovered > 0 && <div>Phát hiện {test.discovered} mục (VM/host/container) – sẽ đưa lên bản đồ khi lưu.</div>}
          </div>
        </div>
      )}
      {(test?.data || f.last_data) && Object.keys(test?.data || f.last_data || {}).length > 0 && (
        <div style={{ marginTop: 16 }}><h4 style={{ marginTop: 0 }}>Dữ liệu thu được</h4><DataView data={test?.data || f.last_data} /></div>
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
    toast("Đang chạy tất cả check...");
    await Promise.all(all.filter((c) => c.enabled).map((c) => api.post(`/checks/${c.id}/run`).catch(() => {})));
    reload(); toast("Đã chạy xong");
  };
  const toggle = async (c) => { await api.put(`/checks/${c.id}`, { enabled: !c.enabled }); reload(); };
  return (
    <>
      <PageHead crumb="Vận hành › Giám sát" title="Giám sát" desc="Các nguồn đồng bộ & check: pfSense, ESXi/vCenter, switch qua SNMP, máy Linux qua SSH, website, ping, cổng TCP.">
        <button className="btn" onClick={runAll}><Play size={15} />Chạy tất cả</button>
        {isAdmin && <button className="btn primary" onClick={() => newCheck()}><Plus size={15} />Thêm check</button>}
      </PageHead>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "Tất cả", count: all.length },
        { key: "fail", label: "Critical / DOWN", count: all.filter((c) => c.status === "fail").length },
        { key: "warn", label: "Attention / Trouble", count: all.filter((c) => c.status === "warn").length },
        { key: "ok", label: "Bình thường", count: all.filter((c) => c.status === "ok").length },
        { key: "off", label: "Đang tắt", count: all.filter((c) => !c.enabled).length },
      ]} />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm tên, địa chỉ, loại..." value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} onRow={(c) => openCheck(c.id)} empty={<Empty title="Chưa có check nào">Bấm “Thêm check” để bắt đầu giám sát pfSense, ESXi, switch...</Empty>} columns={[
          { key: "status", label: "", width: 30, sort: (c) => ({ fail: 0, warn: 1, unknown: 2, ok: 3 }[c.status]), render: (c) => <Dot status={c.enabled ? c.severity || c.status : "off"} pulse /> },
          { key: "name", label: "Check", render: (c) => <div><div className="cell-title">{c.name}{c.config?.demo && <span className="badge" style={{ fontSize: 11 }}>mẫu</span>}
            {c.wan_role && <span className="badge info" style={{ fontSize: 11 }} title="Được tính là 1 line Internet trên bản đồ">LINE</span>}</div><div className="cell-sub">{CHECK_TYPES[c.type]}</div></div> },
          { key: "target", label: "Địa chỉ", render: (c) => <span className="mono small">{c.target}</span> },
          { key: "asset_id", label: "Tài sản / Site", sort: (c) => aName[c.asset_id] || "", render: (c) => <div className="small">{aName[c.asset_id] || <span className="faint">—</span>}<div className="muted">{sName[c.site_id]}</div></div> },
          { key: "last_message", label: "Kết quả gần nhất", render: (c) => <div className="small" style={{ maxWidth: 400 }}>{c.enabled && c.severity && <><SevBadge sev={c.severity} /> </>}{c.enabled ? c.last_message || <span className="faint">chưa chạy</span> : <span className="faint">đang tắt</span>}</div> },
          { key: "uptime_24h", label: "Uptime 24h", render: (c) => c.uptime_24h == null ? <span className="faint">—</span> : <span className={c.uptime_24h < 99 ? "" : "muted"} style={{ color: c.uptime_24h < 95 ? "var(--fail)" : undefined }}>{c.uptime_24h}%</span> },
          { key: "last_checked", label: "Lần chạy", render: (c) => <span className="small muted">{timeAgo(c.last_checked)}</span> },
          ...(isAdmin ? [{ key: "act", label: "", sortable: false, render: (c) => <button className="btn ghost sm" title={c.enabled ? "Tắt" : "Bật"} onClick={(e) => { e.stopPropagation(); toggle(c); }}><Power size={14} color={c.enabled ? "#16a34a" : "#a8a29e"} /></button> }] : []),
        ]} />
      </div>
    </>
  );
}
