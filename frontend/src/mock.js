/* Chế độ DEMO: giả lập toàn bộ API trong trình duyệt bằng dữ liệu mẫu chụp từ server thật.
   Thêm/sửa/xoá, chạy thử, nhận/đóng cảnh báo đều hoạt động (lưu trong bộ nhớ, tải lại trang sẽ về như cũ). */
import SNAP from "./demo-snapshot.json";

const clone = (o) => JSON.parse(JSON.stringify(o));
const S = clone(SNAP);
const now = () => new Date().toISOString();
let nextId = 1000;
let role = "admin";
const USERS = [
  { id: 1, username: "admin", full_name: "Quản trị viên", role: "admin", created_at: "2026-10-31T14:00:00Z" },
  { id: 2, username: "helpdesk", full_name: "Nhân viên Helpdesk", role: "viewer", created_at: "2026-10-31T14:05:00Z" },
];
const me = () => USERS.find((u) => u.role === role) || USERS[0];

// lịch sử 24h giả lập cho biểu đồ đẹp hơn
function synthHistory(c) {
  const out = [];
  const base = c.last_latency || 5;
  const t0 = Date.now() - 24 * 3600e3;
  for (let i = 0; i < 288; i++) {
    let st = c.status === "unknown" ? "ok" : c.status;
    if (c.status === "fail" && i < 250) st = "ok";
    if (c.status === "warn" && i % 7) st = "ok";
    if (c.status === "ok" && (i === 97 || i === 98)) st = "warn";
    const lat = st === "fail" ? null : Math.max(0.3, base * (0.8 + Math.random() * 0.4 + (i > 140 && i < 170 ? 0.5 : 0)));
    const val = c.last_data && typeof c.last_data.cpu === "number" ? c.last_data.cpu : null;
    out.push({ ts: new Date(t0 + i * 300e3).toISOString(), status: st, latency: lat, value: val, message: c.last_message });
  }
  return out;
}

function liveCritical() {
  return S.critical.map((c) => {
    const a = S.assets.find((x) => x.id === c.asset_id);
    const checks = S.checks.filter((k) => (c.check_ids || []).includes(k.id) || (a && k.asset_id === a.id))
      .map((k) => ({ id: k.id, name: k.name, type: k.type, status: k.status, last_message: k.last_message }));
    const ids = new Set(checks.map((k) => k.id));
    const alerts = S.alerts.filter((x) => x.status !== "resolved" && (ids.has(x.check_id) || (a && x.asset_id === a.id))).length;
    const order = { ok: 0, unknown: 1, warn: 2, fail: 3 };
    const status = checks.length ? checks.reduce((w, k) => (order[k.status] > order[w] ? k.status : w), "ok") : "unknown";
    const host = a && a.parent_id ? S.assets.find((x) => x.id === a.parent_id) : null;
    return {
      ...c, asset: a ? { id: a.id, name: a.name, type: a.type, ip: a.ip, status: a.status, backup: a.backup } : null,
      host: host ? { id: host.id, name: host.name, type: host.type } : null, checks, alerts, status,
      backup_ok: !!(c.hosted_externally || c.backup || (a && a.backup)),
    };
  });
}

// lịch sử CPU/RAM/Disk mô phỏng quanh giá trị hiện tại (có chu kỳ ngày – đêm)
function resHistory(checkId, hours) {
  const row = (S.resources?.rows || []).find((r) => r.check_id === checkId);
  if (!row) return { points: [], stats: {} };
  const n = Math.min(300, hours * 12), step = (hours * 3600e3) / n, t0 = Date.now() - hours * 3600e3;
  let seed = checkId * 9301;
  const rnd = () => ((seed = (seed * 9301 + 49297) % 233280) / 233280);
  const points = [];
  for (let i = 0; i <= n; i++) {
    const t = t0 + i * step, h = new Date(t).getHours() + new Date(t).getMinutes() / 60;
    const day = Math.max(0, Math.sin(((h - 7) / 12) * Math.PI));
    const p = { ts: new Date(t).toISOString() };
    if (row.cpu != null) p.cpu = Math.round(Math.max(1, Math.min(100, row.cpu * (0.45 + 0.75 * day) + (rnd() - 0.5) * 12)) * 10) / 10;
    if (row.mem != null) p.mem = Math.round(Math.max(1, Math.min(100, row.mem - 4 + 5 * day + (rnd() - 0.5) * 2)) * 10) / 10;
    if (row.disk != null) p.disk = Math.round((row.disk - 1.5 * (1 - i / n)) * 10) / 10;
    points.push(p);
  }
  const stats = {};
  for (const k of ["cpu", "mem", "disk"]) {
    const v = points.map((p) => p[k]).filter((x) => x != null);
    if (v.length) stats[k] = { avg: Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 10) / 10, max: Math.max(...v), min: Math.min(...v) };
  }
  return { points, stats };
}

function dashboard() {
  const d = clone(S.dashboard);
  const crit = liveCritical();
  const open = S.alerts.filter((a) => a.status !== "resolved");
  Object.assign(d, {
    alerts_open: open.length, alerts_critical: open.filter((a) => a.severity === "critical").length, alerts: open.slice(0, 10),
    critical_total: crit.length, critical_high: crit.filter((c) => c.level === "High").length,
    critical_no_backup: crit.filter((c) => !c.backup_ok).length, critical_alerting: crit.filter((c) => c.alerts > 0).length,
    critical_unmapped: crit.filter((c) => !c.asset_id && !c.hosted_externally).length,
    assets_total: S.assets.length, sources: S.checks.filter((c) => c.enabled).map((c) => ({ id: c.id, name: c.name, type: c.type, status: c.status, site_id: c.site_id })),
    sites: S.sites.map((s) => ({ id: s.id, name: s.name, kind: s.kind })),
  });
  return d;
}

function assetDetail(id) {
  const base = S.asset_detail[id] ? clone(S.asset_detail[id]) : null;
  const a = S.assets.find((x) => x.id === id);
  if (!a) throw err(404, "Không tìm thấy");
  const d = { ...(base || {}), ...a };
  d.children = S.assets.filter((x) => x.parent_id === id);
  d.checks = S.checks.filter((c) => c.asset_id === id);
  d.alerts = S.alerts.filter((x) => x.asset_id === id);
  d.critical = S.critical.filter((c) => c.asset_id === id);
  d.events = (S.events || []).filter((e) => e.asset_id === id).slice(0, 15);
  const path = [];
  let p = a.parent_id;
  while (p && path.length < 10) { const pa = S.assets.find((x) => x.id === p); if (!pa) break; path.unshift({ id: pa.id, name: pa.name, type: pa.type }); p = pa.parent_id; }
  d.path = path;
  return d;
}

function simulateTest(body) {
  const t = body.type, target = body.target || "";
  const ms = +(Math.random() * 20 + 1).toFixed(1);
  const bad = /^(0\.|192\.0\.2\.|sai|x$)/.test(target) || !target;
  if (bad) return { status: "fail", message: "Không phản hồi (mô phỏng)", latency: null, data: {}, discovered: 0 };
  const R = {
    ping: { message: `${ms} ms · mất 0%`, data: { loss: 0 } },
    tcp: { message: `Cổng ${body.config?.port || 443} mở · ${ms} ms`, data: {} },
    http: { message: `HTTP 200 · ${Math.round(ms * 10)} ms · SSL còn 64 ngày`, data: { code: 200, cert_days: 64 } },
    snmp: { message: `${target} · uptime 87d 3h · 22/28 cổng up · CPU 6%`, data: { sys_name: "SW-DEMO", sys_descr: "Aruba 2930F (mô phỏng)", ports_up: 22, ports_total: 28, ports: Array.from({ length: 8 }, (_, i) => ({ idx: String(i + 1), name: `1/1/${i + 1}`, alias: i === 0 ? "uplink-fw" : "", oper: i % 3 ? "up" : "down", admin: "up", speed: 1000 })) } },
    ssh: { message: "srv-demo · up 41d · RAM 38% · Disk / 52% · 4/4 container chạy", data: { hostname: "srv-demo", os: "Ubuntu 24.04", disks: [{ mount: "/", pct: 52 }, { mount: "/data", pct: 71 }], containers: [{ name: "nginx", image: "nginx:latest", status: "Up 3 days" }, { name: "app", image: "erp:2.1", status: "Up 3 days" }] } },
    esxi: { message: "2 host · 11/12 VM chạy · CPU 31%", data: { hosts: [{ name: "esx01", cpu_pct: 34, mem_pct: 66, status: "up" }, { name: "esx02", cpu_pct: 28, mem_pct: 59, status: "up" }], datastores: [{ name: "ds-ssd", used_pct: 71, free_gb: 580, capacity_gb: 2000 }] }, discovered: 14 },
    pfsense: { message: "2/2 WAN online · CPU 9% · RAM 31% · IPsec 1/1 · 6 OpenVPN client", data: { version: "2.7.2-RELEASE", gateways: [{ name: "WAN_FPT", status: "online", delay: "3.1ms", loss: "0%" }, { name: "WAN_VIETTEL", status: "online", delay: "4.4ms", loss: "0%" }], interfaces: [{ name: "WAN", if: "igb0", ip: "113.161.x.x", status: "up" }, { name: "LAN", if: "igb1", ip: "10.0.0.1", status: "up" }] } },
  }[t] || { message: "OK" };
  return { status: "ok", latency: ms, discovered: 0, ...R };
}

// ---------------- log thiết bị (syslog/trap) giả lập ----------------
const A = (n) => S.assets.find((a) => a.name === n) || {};
const SRC = [
  [A("pfSense-HQ"), "pfSense-HQ", [[6, "openvpn", "user 'ketoan01' authenticated"], [6, "dhcpd", "DHCPACK on 10.0.30.55 to aa:bb:cc:dd:ee:ff (iphone-sale) via igb1"], [5, "dpinger", "WAN_VIETTEL 1.1.1.1: Alarm latency 58ms stddev 12ms loss 3%"], [4, "sshd", "Failed password for invalid user admin from 45.13.2.9 port 51234 ssh2"], [6, "php-fpm", "/index.php: Successful login for user 'admin' from: 10.0.20.15"]]],
  [A("SW-CORE"), "SW-CORE", [[5, "LINK-UPDOWN", "Interface GigabitEthernet1/0/31, changed state to up"], [5, "SEC_LOGIN-SUCCESS", "Login Success [user: admin] [Source: 10.0.20.15]"], [3, "LINK-UPDOWN", "Interface GigabitEthernet1/0/12, changed state to down"], [6, "SYS-CONFIG_I", "Configured from console by admin on vty0"]]],
  [A("ESXi-01"), "ESXi-01", [[6, "Hostd", "Task Completed : haTask-vim.VirtualMachine.createSnapshot"], [5, "vmkernel", "NMP: nmp_ThrottleLogForDevice: Cmd 0x2a to dev naa.600 failed, H:0x0 D:0x2 P:0x0"], [6, "vpxa", "Event 1234 : User root@10.0.20.15 logged in as VMware-client"]]],
  [A("ESXi-02"), "ESXi-02", [[4, "vmkernel", "Device naa.6000c29 performance has deteriorated. I/O latency increased from 1534 to 31882 microseconds"]]],
  [A("NAS-Synology"), "NAS-Synology", [[6, "System", "Backup task [VM-Daily] completed"], [2, "System", "Volume 2 has been degraded. Please replace disk 3"]]],
  [A("UPS-RACK"), "UPS-RACK", [[6, "apcupsd", "Self test completed: Battery OK"]]],
  [{ ip: "10.0.30.88" }, "camera-kho01", [[6, "rtsp", "stream started"], [4, "rtsp", "client 10.0.30.5 timeout"]]],
];
let evId = 9000;
function mkEvent(src, line, ts) {
  const [a, host, ] = src;
  const [sev, app, msg] = line;
  return { id: ++evId, ts, kind: "syslog", source_ip: a.ip || "10.0.0.250", asset_id: a.id || null, asset_name: a.name || "", site_id: a.site_id || null,
    facility: 1, severity: sev, host, app, message: msg, device_ts: "", data: {}, rule_id: null };
}
S.events = [];
for (let i = 0; i < 260; i++) {
  const src = SRC[Math.floor(Math.random() * SRC.length)];
  const line = src[2][Math.floor(Math.random() * src[2].length)];
  S.events.push(mkEvent(src, line, new Date(Date.now() - (260 - i) * (24 * 3600e3 / 260) - Math.random() * 60e3).toISOString()));
}
S.events.push({ ...mkEvent([A("SW-CORE"), "SW-CORE"], [3, "linkDown", "linkDown · ifIndex=12 · ifName=Gi1/0/12"], new Date(Date.now() - 50 * 60e3).toISOString()), kind: "trap", data: { trap_oid: "1.3.6.1.6.3.1.1.5.3", if_key: "Gi1/0/12", varbinds: [["1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.3"], ["1.3.6.1.2.1.2.2.1.1.12", "12"], ["1.3.6.1.2.1.31.1.1.1.1.12", "Gi1/0/12"]] } });
S.events.sort((x, y) => (x.ts < y.ts ? 1 : -1));
S.events.forEach((e, i) => { e.id = 20000 - i; });
S.alerts.unshift(
  { id: 801, source: "event", count: 1, severity: "critical", status: "open", title: "Ổ cứng / RAID lỗi: NAS-Synology", message: "Volume 2 has been degraded. Please replace disk 3", asset_id: A("NAS-Synology").id, asset_name: "NAS-Synology", site_name: "Trụ sở chính", opened_at: new Date(Date.now() - 95 * 60e3).toISOString(), acked_by: "" },
  { id: 802, source: "event", count: 3, severity: "warning", status: "open", title: "Cổng switch down: SW-CORE (GigabitEthernet1/0/12)", message: "Interface GigabitEthernet1/0/12, changed state to down", asset_id: A("SW-CORE").id, asset_name: "SW-CORE", site_name: "Trụ sở chính", opened_at: new Date(Date.now() - 50 * 60e3).toISOString(), acked_by: "" },
);
S.rules = S.event_rules.map((r) => ({ ...r, hits: r.action === "drop" ? 18340 : Math.floor(Math.random() * 30), last_hit: new Date(Date.now() - Math.random() * 8e6).toISOString(), open_alerts: r.name.startsWith("Ổ cứng") || r.name === "Cổng switch down" ? 1 : 0 }));
S.receivers = { communities: ["__SECRET__"], communities_count: 1, v3_users: [], allowed_sources: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"], ports: { syslog_udp: 514, syslog_tcp: 514, snmp_trap: 162 } };
setInterval(() => {
  const src = SRC[Math.floor(Math.random() * SRC.length)];
  S.events.unshift({ ...mkEvent(src, src[2][Math.floor(Math.random() * src[2].length)], new Date().toISOString()), id: (S.events[0]?.id || 20000) + 1 });
}, 7000);

function eventStats() {
  const since = Date.now() - 24 * 3600e3;
  const evs = S.events.filter((e) => new Date(e.ts) >= since);
  const buckets = {};
  for (const e of evs) { const d = new Date(e.ts); d.setMinutes(Math.floor(d.getMinutes() / 15) * 15, 0, 0); const k = d.toISOString(); const b = (buckets[k] ||= { ts: k, error: 0, warning: 0, info: 0 }); b[e.severity <= 3 ? "error" : e.severity === 4 ? "warning" : "info"]++; }
  const unknown = {};
  evs.filter((e) => !e.asset_id).forEach((e) => { const u = (unknown[e.source_ip] ||= { source_ip: e.source_ip, count: 0, last: e.ts, host: e.host }); u.count++; if (e.ts > u.last) u.last = e.ts; });
  const top = {};
  evs.forEach((e) => { const k = e.asset_id || e.source_ip; (top[k] ||= { asset_id: e.asset_id, name: e.asset_name || e.source_ip, source_ip: e.source_ip, count: 0 }).count++; });
  return { bucket_min: 15, series: Object.values(buckets).sort((a, b) => (a.ts < b.ts ? -1 : 1)), total: evs.length, errors: evs.filter((e) => e.severity <= 3).length,
    warnings: evs.filter((e) => e.severity === 4).length, top_sources: Object.values(top).sort((a, b) => b.count - a.count).slice(0, 10), unknown_sources: Object.values(unknown),
    receiver: { listeners: { syslog_udp: { port: 514, ok: true }, syslog_tcp: { port: 514, ok: true }, snmp_trap: { port: 162, ok: true } }, received: 48210, stored: 29870, dropped_rate: 0, dropped_rule: 18340, dropped_queue: 0, dropped_acl: 37, blocked: [["113.161.4.20", 37]], last: { syslog: Math.floor(Date.now() / 1000) - 5, trap: Math.floor(Date.now() / 1000) - 3000 }, rate_limit: 200, retention_days: 30 } };
}
const pyRe = (p) => { try { return p ? new RegExp(p.replace(/\(\?P</g, "(?<"), "i") : null; } catch { return undefined; } };

function err(status, detail) { const e = new Error(detail); e.status = status; return e; }

// Máy ảo / container trên host – bản JS của backend/app/virt.py (chỉ dùng cho bản demo tĩnh)
const RUNNING = new Set(["poweredOn", "running", "Running"]);
const KIND_LABEL = { vm: "VM", qemu: "VM", lxc: "LXC", hyperv: "VM", docker: "Container" };
const PLATFORM_LABEL = { esxi: "VMware ESXi", proxmox: "Proxmox VE", hyperv: "Hyper-V", docker: "Docker" };
function guestRow(a) {
  const m = a.meta || {}, res = m.res || {};
  const running = m.power ? RUNNING.has(m.power) : a.status === "up";
  const kind = m.kind || (a.type === "container" ? "docker" : "vm");
  const vcpu = m.vcpu ?? null, memGb = m.mem_mb ? Math.round(m.mem_mb / 102.4) / 10 : res.mem_total_gb ?? null;
  const disks = res.disks || (res.disk != null ? [{ pct: res.disk, size_gb: res.disk_size_gb, used_gb: res.disk_used_gb }] : []);
  const dT = disks.reduce((t, d) => t + (d.size_gb || 0), 0) || null, dU = dT ? disks.reduce((t, d) => t + (d.used_gb || 0), 0) : null;
  const cp = running ? res.cpu ?? null : null, mp = running ? res.mem ?? null : null;
  const r1 = (x) => Math.round(x * 10) / 10;
  return { cpu_used: cp != null && vcpu ? Math.round(cp * vcpu) / 100 : null, cpu_total: vcpu, mem_used_gb: mp != null && memGb ? r1(mp * memGb / 100) : null,
    mem_total_gb: memGb, disk_used_gb: running && dU != null ? r1(dU) : null, disk_total_gb: dT ? r1(dT) : m.disk_alloc_gb ?? null, id: a.id, name: a.name, type: a.type, kind, kind_label: KIND_LABEL[kind] || kind, platform: m.platform || "", status: a.status, running,
    power: m.power, ip: a.ip, ips: m.ips || (a.ip ? [a.ip] : []), os: a.os, vcpu: m.vcpu ?? null, mem_gb: m.mem_mb ? Math.round(m.mem_mb / 102.4) / 10 : null,
    disk_alloc_gb: m.disk_alloc_gb ?? null, uptime_s: m.uptime_s ?? null, cpu: running ? res.cpu ?? null : null, mem: running ? res.mem ?? null : null,
    disk: running ? res.disk ?? null : null, disk_name: res.disk_name, snapshots: m.snapshots ?? null, oldest_snapshot_days: m.oldest_snapshot_days ?? null,
    tools: m.tools || "", missing: !!m.missing, via: m.via || "", backup: !!a.backup };
}
function guestsView(id) {
  const h = S.assets.find((x) => x.id === id) || {};
  const hm = h.meta || {}, hres = hm.res || {};
  const rows = S.assets.filter((x) => x.parent_id === id && ["vm", "container"].includes(x.type)).map(guestRow)
    .sort((a, b) => (a.running === b.running ? (b.cpu || 0) - (a.cpu || 0) : a.running ? -1 : 1));
  const cores = hm.cores || hres.cores || null, mem = hm.mem_gb || hres.mem_total_gb || null;
  const live = rows.filter((r) => r.running && r.kind !== "docker");
  const vcpu = live.reduce((t, r) => t + (r.vcpu || 0), 0), memA = live.reduce((t, r) => t + (r.mem_gb || 0), 0);
  const plats = [...new Set([...rows.map((r) => r.platform), hm.platform].filter(Boolean))].map((p) => PLATFORM_LABEL[p] || p);
  const vms = rows.filter((r) => r.type === "vm");
  return { host: { id, name: h.name, cores, cpu_unit: "luồng CPU", mem_gb: mem, cpu: hres.cpu ?? hm.cpu_pct, mem: hres.mem ?? hm.mem_pct }, platforms: plats,
    summary: { total: rows.length, running: rows.filter((r) => r.running).length, stopped: rows.filter((r) => !r.running).length, vms: vms.length,
      containers: rows.length - vms.length, missing: rows.filter((r) => r.missing).length, vcpu_alloc: vcpu, vcpu_ratio: cores ? Math.round(vcpu / cores * 100) / 100 : null,
      mem_alloc_gb: Math.round(memA * 10) / 10, mem_ratio: mem ? Math.round(memA / mem * 100) / 100 : null,
      old_snapshots: rows.filter((r) => (r.oldest_snapshot_days || 0) > 7).length,
      hot: rows.filter((r) => (r.cpu || 0) >= 90 || (r.mem || 0) >= 95 || (r.disk || 0) >= 90).length, no_backup: vms.filter((r) => !r.backup).length, allocation_only: rows.length > 0 && rows.every((r) => r.via === "snmp") },
    guests: rows };
}
const guestCount = (id) => { const g = S.assets.filter((x) => x.parent_id === id && ["vm", "container"].includes(x.type)); return g.length ? { total: g.length, running: g.map(guestRow).filter((r) => r.running).length } : null; };

const COLL = { sites: "sites", assets: "assets", critical: "critical", checks: "checks" };

function handle(method, url, body) {
  const u = new URL(url, "http://demo");
  const path = u.pathname.replace(/^\/api/, "");
  const q = Object.fromEntries(u.searchParams);
  const seg = path.split("/").filter(Boolean);
  const isAdmin = role === "admin";
  const needAdmin = () => { if (!isAdmin) throw err(403, "Chỉ admin mới được thay đổi"); };

  if (path === "/health") return { ok: true, version: "1.0.0-demo", app_name: "IT Ops Workspace · Demo" };
  if (path === "/auth/login") {
    const u2 = USERS.find((x) => x.username === (body.username || "").trim());
    if (!u2 || !body.password) throw err(401, "Sai tài khoản hoặc mật khẩu (demo: admin hoặc helpdesk, mật khẩu bất kỳ)");
    role = u2.role;
    return { token: "demo-" + u2.username, user: u2 };
  }
  if (path === "/auth/me") return me();
  if (path === "/auth/password") return { ok: true };
  if (path === "/auth/logout") return { ok: true };
  if (path === "/auth/sessions") return [{ id: "demo", username: me().username, created_at: new Date(Date.now() - 3600e3).toISOString(), last_seen: new Date().toISOString(), ip: "10.0.20.15", user_agent: navigator.userAgent, mfa: false, current: true }];
  if (path.startsWith("/auth/2fa/") || path.startsWith("/auth/sessions/")) throw err(400, "Bản demo không hỗ trợ 2FA / thu hồi phiên");
  if (path === "/dashboard") return dashboard();
  if (path === "/automation/catalog") return S.automation_catalog;
  if (path === "/automations" || path === "/automation/runs") return [];
  if (path === "/resources") return { ...S.resources, rows: S.resources.rows.map((r) => ({ ...r, ts: new Date(Date.now() - 20000).toISOString() })) };
  if (path === "/resources/history") return resHistory(Number(q.check_id), Number(q.hours || 24));
  if (path === "/topology") return S.topology;
  if (path === "/risks") return S.risks;
  if (path === "/audit") return S.audit;
  if (path === "/critical" && method === "GET") return liveCritical();
  if (path === "/search") {
    const s = (q.q || "").toLowerCase();
    return [
      ...S.assets.filter((a) => `${a.name} ${a.ip}`.toLowerCase().includes(s)).slice(0, 12).map((a) => ({ kind: "asset", id: a.id, title: a.name, sub: `${a.type} · ${a.ip}`, status: a.status })),
      ...S.checks.filter((c) => `${c.name} ${c.target}`.toLowerCase().includes(s)).slice(0, 6).map((c) => ({ kind: "check", id: c.id, title: c.name, sub: `${c.type} · ${c.target}`, status: c.status })),
    ];
  }
  if (path === "/users") { if (method === "GET") { needAdmin(); return USERS; } needAdmin(); const nu = { id: ++nextId, created_at: now(), role: "viewer", ...body }; delete nu.password; USERS.push(nu); return nu; }
  if (seg[0] === "users" && seg[1]) { needAdmin(); const i = USERS.findIndex((x) => x.id === +seg[1]); if (method === "DELETE") USERS.splice(i, 1); else Object.assign(USERS[i], { full_name: body.full_name ?? USERS[i].full_name, role: body.role || USERS[i].role }); return USERS[i] || { ok: true }; }
  if (path === "/settings/notify") { needAdmin(); if (method === "PUT") S.notify = Object.fromEntries(Object.entries(body).map(([k, v]) => [k, Object.fromEntries(Object.entries(v).map(([a, b]) => [a, ["bot_token", "password"].includes(a) && b ? "__SECRET__" : b]))])); return S.notify; }
  if (seg[0] === "settings" && seg[2] === "test") return { [seg[3]]: "ok" };
  if (path === "/checks-test") { needAdmin(); return simulateTest(body); }
  if (path === "/reset-data") { needAdmin(); S.sites = []; S.assets = []; S.checks = []; S.critical = []; S.alerts = []; S.topology = { tree: { id: "internet", name: "Internet", type: "internet", status: "up", children: [] }, flow: { nodes: [], edges: [] } }; S.risks = []; return { ok: true }; }
  if (path === "/import") return { imported: 0 };

  if (path === "/events/stats") return eventStats();
  if (path === "/events") {
    const re = (q.q || "").toLowerCase();
    let rows = S.events.filter((e) => (!re || `${e.message} ${e.app} ${e.host} ${e.source_ip}`.toLowerCase().includes(re))
      && (!q.kind || e.kind === q.kind) && e.severity <= +(q.max_severity ?? 7) && (!q.source_ip || e.source_ip === q.source_ip)
      && (!q.asset_id || e.asset_id === +q.asset_id) && (!q.unknown || !e.asset_id) && (!q.before_id || e.id < +q.before_id));
    return rows.slice(0, +(q.limit || 200));
  }
  if (path === "/event-rules" && method === "GET") return S.rules;
  if (path === "/event-rules/test") {
    const r = pyRe(body.pattern);
    if (r === undefined) throw err(400, "Biểu thức không hợp lệ");
    const out = {};
    if (body.sample) {
      const m = body.sample.match(/^<(\d+)>(?:.*?\s)?(%[A-Z0-9_]+-\d-[A-Z0-9_]+: )?(.*)$/s);
      const msg = (m ? m[3] : body.sample).replace(/^.*?(%[A-Z0-9_]+-\d-[A-Z0-9_]+: )/, "");
      const pri = m ? +m[1] : 13;
      const mm = r ? msg.match(r) : null;
      out.sample = { parsed: { severity: pri & 7, app: "", host: "" }, match: !!mm, key: mm ? (mm.groups?.key || mm[1] || "") : "", resolves: false };
    }
    const hits = r ? S.events.filter((e) => r.test(e.message)) : [];
    out.history = { scanned: S.events.length, matches: hits.length, examples: hits.slice(0, 5) };
    return out;
  }
  if (seg[0] === "event-rules" && seg[1]) {
    needAdmin();
    const i = S.rules.findIndex((x) => x.id === +seg[1]);
    if (method === "DELETE") { S.rules.splice(i, 1); return { ok: true }; }
    if (body.pattern !== undefined && pyRe(body.pattern) === undefined) throw err(400, "Biểu thức pattern không hợp lệ");
    Object.assign(S.rules[i], body); return S.rules[i];
  }
  if (path === "/event-rules" && method === "POST") {
    needAdmin();
    if (!String(body.name || "").trim()) throw err(400, "Thiếu tên");
    if (pyRe(body.pattern) === undefined) throw err(400, "Biểu thức pattern không hợp lệ");
    const o = { id: ++nextId, hits: 0, open_alerts: 0, builtin: false, ...body }; S.rules.unshift(o); return o;
  }
  if (path === "/settings/receivers") { needAdmin(); if (method === "PUT") Object.assign(S.receivers, body, { communities: body.communities.map((c) => (c ? "__SECRET__" : "")) }); return S.receivers; }

  if (path === "/alerts") {
    const st = q.status || "active";
    return S.alerts.filter((a) => (st === "all" ? true : st === "active" ? a.status !== "resolved" : a.status === st));
  }
  if (seg[0] === "alerts" && seg[2]) {
    const a = S.alerts.find((x) => x.id === +seg[1]);
    if (seg[2] === "ack") Object.assign(a, { status: "acknowledged", acked_by: me().username });
    if (seg[2] === "resolve") Object.assign(a, { status: "resolved", resolved_at: now() });
    return a;
  }
  if (seg[0] === "checks" && seg[2] === "history") return S.history[seg[1]]?.length > 20 ? S.history[seg[1]] : (S.history[seg[1]] = synthHistory(S.checks.find((c) => c.id === +seg[1]) || {}));
  if (seg[0] === "checks" && seg[2] === "run") {
    const c = S.checks.find((x) => x.id === +seg[1]);
    const r = c.config?.demo ? { status: c.status, message: c.last_message, latency: c.last_latency, data: c.last_data } : simulateTest(c);
    Object.assign(c, { last_checked: now(), status: r.status, last_message: r.message, last_data: r.data });
    return r;
  }

  const coll = COLL[seg[0]];
  if (coll) {
    const list = S[coll];
    if (method === "GET" && !seg[1]) {
      let rows = list;
      if (coll === "assets") {
        if (q.type) { const ts = q.type.split(","); rows = rows.filter((a) => ts.includes(a.type)); }
        rows = rows.map((a) => ({ ...a, guests: guestCount(a.id), checks: S.checks.filter((c) => c.asset_id === a.id).map((c) => ({ id: c.id, name: c.name, type: c.type, status: c.status, last_message: c.last_message })), critical: S.critical.filter((c) => c.asset_id === a.id).map((c) => ({ id: c.id, name: c.name, level: c.level })) }));
      }
      if (coll === "sites") rows = rows.map((s) => ({ ...s, assets: S.assets.filter((a) => a.site_id === s.id && !["vm", "container", "firewall", "device"].includes(a.type)).map((a) => ({ id: a.id, name: a.name, type: a.type, status: a.status })), checks_list: S.checks.filter((c) => c.site_id === s.id).map((c) => ({ id: c.id, name: c.name, type: c.type, status: c.status })) }));
      return rows;
    }
    if (method === "GET") {
      if (coll === "assets" && seg[2] === "guests") return guestsView(+seg[1]);
      if (coll === "assets") return assetDetail(+seg[1]);
      if (coll === "checks") return S.check_detail[seg[1]] ? { ...S.check_detail[seg[1]], ...S.checks.find((c) => c.id === +seg[1]) } : S.checks.find((c) => c.id === +seg[1]);
      return list.find((x) => x.id === +seg[1]);
    }
    needAdmin();
    if (method === "POST") {
      if (!String(body.name || "").trim()) throw err(400, "Thiếu tên");
      const o = { id: ++nextId, created_at: now(), ...body };
      if (coll === "assets") Object.assign(o, { status: o.status || "unknown", meta: {}, source: "manual", children_count: 0 });
      if (coll === "sites") Object.assign(o, { stats: { hosts: 0, vms: 0, vms_on: 0, devices: 0, checks: 0, checks_bad: 0, alerts: 0 }, firewalls: [], last_sync: null });
      if (coll === "critical") Object.assign(o, { depends_on: o.depends_on || [], check_ids: o.check_ids || [] });
      if (coll === "checks") {
        const r = simulateTest(body);
        const cfg = Object.fromEntries(Object.entries(body.config || {}).map(([k, v]) => [k, ["password", "community", "api_key", "private_key", "client_secret", "priv_key"].includes(k) && v ? "__SECRET__" : v]));
        Object.assign(o, { config: cfg, status: r.status, last_message: r.message, last_latency: r.latency, last_data: r.data, last_checked: now(), uptime_24h: 100, fail_count: 0 });
        const a = S.assets.find((x) => x.id === o.asset_id);
        if (a) { a.status = { ok: "up", warn: "warning", fail: "down" }[r.status]; if (!o.site_id) o.site_id = a.site_id; }
      }
      list.push(o);
      S.audit.unshift({ id: ++nextId, ts: now(), user: me().username, action: "create", entity: coll, entity_id: o.id, detail: `Tạo ${o.name}` });
      return o;
    }
    const i = list.findIndex((x) => x.id === +seg[1]);
    if (method === "PUT") {
      if (coll === "assets" && body.parent_id && +body.parent_id === +seg[1]) throw err(400, "Tài sản không thể là cha của chính nó");
      const b = { ...body };
      if (b.config) b.config = Object.fromEntries(Object.entries(b.config).map(([k, v]) => [k, ["password", "community", "api_key", "private_key", "client_secret", "priv_key"].includes(k) && v ? "__SECRET__" : v]));
      Object.assign(list[i], b);
      S.audit.unshift({ id: ++nextId, ts: now(), user: me().username, action: "update", entity: coll, entity_id: +seg[1], detail: `Sửa ${list[i].name}` });
      return list[i];
    }
    if (method === "DELETE") {
      const [o] = list.splice(i, 1);
      if (coll === "assets") S.assets.forEach((a) => { if (a.parent_id === o.id) a.parent_id = null; });
      if (coll === "checks") S.alerts.forEach((a) => { if (a.check_id === o.id && a.status !== "resolved") Object.assign(a, { status: "resolved", resolved_at: now() }); });
      S.audit.unshift({ id: ++nextId, ts: now(), user: me().username, action: "delete", entity: coll, entity_id: o.id, detail: `Xoá ${o.name}` });
      return { ok: true };
    }
  }
  throw err(404, "Không có trong bản demo");
}

export function installMock() {
  const real = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    if (!url.startsWith("/api")) return real(input, init);
    await new Promise((r) => setTimeout(r, 120 + Math.random() * 180));
    try {
      const body = init.body ? JSON.parse(init.body) : {};
      const data = handle((init.method || "GET").toUpperCase(), url, body);
      return new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ detail: e.message }), { status: e.status || 500, headers: { "Content-Type": "application/json" } });
    }
  };
}
