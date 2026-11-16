import React, { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";
import { Activity, ArrowDown, ArrowUp, Network, Settings as Cog, X, RefreshCw, Users, Shuffle, Gauge, Save, AlertTriangle } from "lucide-react";
import { useApp } from "../App";
import { api } from "../api";
import { useApi, PageHead, Stat, Table, Drawer, Field, Input, Toggle, Empty, timeAgo, useToast } from "../ui";
import { useUi, chartColors } from "../theme";

// Network traffic (2.10.0): NetFlow / IPFIX from pfSense (softflowd) → GoFlow2 → per-minute totals in PostgreSQL.
const RANGES = [[1, "1 hour"], [6, "6 hours"], [24, "24 hours"], [168, "7 days"], [720, "30 days"]];
const PROTO = { 0: "IP", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6" };
const PORTS = {
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
  123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 389: "LDAP", 443: "HTTPS",
  445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog", 587: "SMTP submit", 636: "LDAPS", 853: "DNS over TLS", 993: "IMAPS",
  995: "POP3S", 1194: "OpenVPN", 1433: "MS SQL", 1514: "Wazuh agent", 1515: "Wazuh enroll", 1723: "PPTP", 1883: "MQTT", 2055: "NetFlow",
  3268: "LDAP GC", 3306: "MySQL", 3389: "RDP", 3478: "STUN (Teams/Meet)", 4500: "IPsec NAT-T", 5060: "SIP", 5222: "XMPP",
  5228: "Google push", 5223: "Apple push", 5432: "PostgreSQL", 5938: "TeamViewer", 7680: "Windows Update P2P", 8080: "HTTP alt",
  8443: "HTTPS alt", 8883: "MQTT TLS", 9200: "Elasticsearch", 55000: "Wazuh API",
};
const svcName = (proto, port) => {
  const p = PROTO[proto] ?? String(proto);
  if (!port) return proto === 0 ? "IP (protocol 0 – softflowd ICMP)" : p;
  const n = proto === 17 && port === 443 ? "QUIC / HTTP3" : PORTS[port];
  return `${p}/${port}${n ? ` · ${n}` : ""}`;
};
export function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}
const mbps = (bytes, secs) => (secs ? (bytes * 8) / secs / 1e6 : 0);
const fmtMbps = (v) => (v >= 100 ? Math.round(v) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " Mbps";

function UpDown({ up, down, width = 120 }) {
  const t = up + down || 1;
  return <div className="row" style={{ gap: 6 }} title={`Upload ${fmtBytes(up)} · Download ${fmtBytes(down)}`}>
    <div style={{ display: "flex", width, height: 8, borderRadius: 4, overflow: "hidden", background: "var(--line)" }}>
      <i style={{ width: `${(100 * up) / t}%`, background: "#ea580c" }} /><i style={{ width: `${(100 * down) / t}%`, background: "#2563eb" }} />
    </div>
  </div>;
}

function Bar({ value, max, color = "var(--accent)" }) {
  return <div style={{ width: 110, height: 8, borderRadius: 4, background: "var(--line)", overflow: "hidden" }}>
    <i style={{ display: "block", height: "100%", width: `${max ? (100 * value) / max : 0}%`, background: color }} /></div>;
}

function NameCell({ ip, name, src, user }) {
  return <div>
    <div className="cell-title">{name || ip}</div>
    <div className="cell-sub">{name ? ip : ""}{src && <span className="badge" style={{ marginLeft: name ? 6 : 0 }} title="Where the name comes from">{src}</span>}
      {user && <span className="muted"> · {user}</span>}</div>
  </div>;
}

function TrafficChart({ data }) {
  const el = useRef();
  const { theme } = useUi();
  useEffect(() => {
    if (!el.current || !data?.series?.length) return;
    const c = echarts.init(el.current);
    const T = chartColors();
    const s = data.step;
    c.setOption({
      grid: { left: 52, right: 12, top: 30, bottom: 26 },
      tooltip: { ...T.tooltip, trigger: "axis", valueFormatter: (v) => (v == null ? "—" : fmtMbps(Math.abs(v))) },
      legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 3, textStyle: { color: T.text2, fontSize: 11 } },
      xAxis: { type: "time", min: Date.now() - data.hours * 3600e3, max: Date.now(), ...T.axis, axisLabel: { ...T.axis.axisLabel, hideOverlap: true } },
      yAxis: { type: "value", ...T.axis, axisLabel: { ...T.axis.axisLabel, formatter: (v) => `${Math.abs(v)}` }, name: "Mbps",
        nameTextStyle: { color: T.muted, fontSize: 10 }, splitLine: { lineStyle: { color: T.line } } },
      series: [
        { name: "Download", type: "line", areaStyle: { opacity: 0.15 }, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.6, color: "#2563eb" },
          itemStyle: { color: "#2563eb" }, data: data.series.map((p) => [p.t, +mbps(p.b_in, s).toFixed(3)]) },
        { name: "Upload", type: "line", areaStyle: { opacity: 0.15 }, showSymbol: false, smooth: 0.2, lineStyle: { width: 1.6, color: "#ea580c" },
          itemStyle: { color: "#ea580c" }, data: data.series.map((p) => [p.t, -mbps(p.b_out, s).toFixed(3)]) },
      ],
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [data, theme]);
  if (!data?.series?.length) return <div className="small faint" style={{ padding: 30, textAlign: "center" }}>No traffic in this period.</div>;
  return <div ref={el} style={{ height: 240 }} />;
}

function SetupState({ st, isAdmin, onSettings }) {
  const c = st.collector;
  if (!st.settings.enabled) return <div className="card card-pad" style={{ marginBottom: 16 }}>
    <h3 style={{ marginTop: 0 }}>Traffic collection is off</h3>
    <ol className="small" style={{ lineHeight: 1.8, margin: "6px 0 12px" }}>
      <li>Copy <b>goflow2-…-windows-amd64.exe</b> into <code>backend\tools\goflow2\</code> (Linux: put <code>goflow2</code> on the PATH).</li>
      <li>Allow UDP <b>{st.settings.port}</b> inbound on this machine (run <code>OPEN-FIREWALL.bat</code> again).</li>
      <li>Turn collection on here.</li>
      <li>pfSense: <i>Services → softflowd</i> → only the <b>LAN / VLAN</b> interfaces (not WAN, not the trunk), host = this server, port {st.settings.port}, version IPFIX.</li>
    </ol>
    {isAdmin ? <button className="btn primary" onClick={onSettings}><Cog size={15} />Open traffic settings</button>
      : <span className="small muted">Ask an administrator to turn it on.</span>}
  </div>;
  if (!c.running) return <div className="alert-box fail" style={{ marginBottom: 16 }}>
    <b>The collector (GoFlow2) is not running.</b> {c.last_error || "Starting…"}
    {isAdmin && <> <button className="btn sm" style={{ marginLeft: 8 }} onClick={onSettings}>Details</button></>}
  </div>;
  if (!st.exporters.length) return <div className="alert-box info" style={{ marginBottom: 16 }}>
    Collector running on UDP {st.settings.port}, waiting for the first flow records. On pfSense check <i>Services → softflowd</i> (host and port) –
    softflowd only sends a flow when it ends or after its timeout (set the timeouts to 60 s and Maximum Lifetime to 120 s).
  </div>;
  if (st.stats.transit_pct > 30) return <div className="alert-box warn" style={{ marginBottom: 16 }}>
    {st.stats.transit_pct}% of the flow records have no local address and are ignored – softflowd is probably also exporting the
    WAN / PPPoE interfaces (traffic after NAT, counted twice). Untick them in <i>Services → softflowd</i>, or add missing ranges under Settings → Local networks.
  </div>;
  return null;
}

function SettingsDrawer({ st, onClose, onSaved }) {
  const toast = useToast();
  const [s, setS] = useState({ ...st.settings, local_networks: st.settings.local_networks.join("\n") });
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try { onSaved(await api.put("/traffic/settings", s)); toast("Traffic settings saved"); } catch (e) { toast(e.message, true); }
    setBusy(false);
  };
  const c = st.collector;
  return <Drawer title={<><Cog size={18} />Traffic settings</>} onClose={onClose} wide
    actions={<button className="btn primary sm" disabled={busy} onClick={save}><Save size={14} />Save</button>}>
    <div className="stack" style={{ display: "grid", gap: 16, minWidth: 0 }}>
      <Toggle checked={s.enabled} onChange={(v) => setS({ ...s, enabled: v })} label="Collect traffic (start GoFlow2 with IT Ops)" />
      {st.disabled_by_env && <div className="alert-box warn">DISABLE_FLOW=1 is set – the collector will not start whatever this setting says.</div>}
      <div className="form-grid">
        <Field label="NetFlow / IPFIX port (UDP)"><Input type="number" value={s.port} onChange={(v) => setS({ ...s, port: v })} /></Field>
        <Field label="sFlow port (UDP)" hint="0 = off. 6343 for switches that send sFlow."><Input type="number" value={s.sflow_port} onChange={(v) => setS({ ...s, sflow_port: v })} /></Field>
        <Field label="Alert when an exporter is silent for (minutes)"><Input type="number" value={s.silent_minutes} onChange={(v) => setS({ ...s, silent_minutes: v })} /></Field>
        <Field label="Keep 1-minute detail (days)" hint="Hourly totals are kept longer."><Input type="number" value={s.keep_minute_days} onChange={(v) => setS({ ...s, keep_minute_days: v })} /></Field>
        <Field label="Keep hourly totals (days)"><Input type="number" value={s.keep_hour_days} onChange={(v) => setS({ ...s, keep_hour_days: v })} /></Field>
      </div>
      <Field full label="Local networks" hint="One per line. Traffic where neither side is in these ranges is ignored (WAN copies after NAT).">
        <textarea className="input" rows={5} value={s.local_networks} cols={20} onChange={(e) => setS({ ...s, local_networks: e.target.value })} style={{ fontFamily: "monospace" }} />
      </Field>
      <div className="card card-pad" style={{ minWidth: 0 }}>
        <div className="row" style={{ marginBottom: 6 }}><b>Collector</b>
          <span className={`badge ${c.running ? "ok" : st.settings.enabled ? "fail" : ""}`} style={{ marginLeft: 8 }}>{c.running ? `running · pid ${c.pid}` : "stopped"}</span></div>
        <div className="small muted" style={{ wordBreak: "break-all" }}>Program: <code>{c.binary || "not found – put GoFlow2 in backend\\tools\\goflow2\\"}</code></div>
        {c.command && <div className="small muted" style={{ wordBreak: "break-all" }}>Command: <code>{c.command}</code></div>}
        {c.last_error && <div className="small" style={{ color: "var(--fail)" }}>{c.last_error}</div>}
        {!!c.log.length && <pre className="small" style={{ maxHeight: 160, overflow: "auto", background: "var(--subtle)", padding: 8, borderRadius: 8, marginBottom: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{c.log.join("\n")}</pre>}
        <div className="small muted" style={{ marginTop: 6 }}>Records: {st.stats.lines.toLocaleString()} · ignored (no local address): {st.stats.transit_pct}% · local ↔ local seen twice: {st.stats.dup_local.toLocaleString()} · unreadable: {st.stats.bad}</div>
      </div>
      {st.exporters.map((e) => <ExporterNames key={e.ip} e={e} assets={st.assets} onSaved={onSaved} />)}
      {!st.exporters.length && <div className="card card-pad small muted">
        <b>Interface names</b> – the box to paste <code>ps aux | grep softflowd</code> appears here for each firewall once IT Ops has
        received its first flow records (the list is saved about once a minute). {c.running ? `Collector is listening on UDP ${st.settings.port}; ` +
        `records so far: ${st.stats.lines.toLocaleString()}.` : "Start the collector first (tick Collect traffic and Save)."}
      </div>}
    </div>
  </Drawer>;
}

function ExporterNames({ e, assets = [], onSaved }) {
  const toast = useToast();
  const [ps, setPs] = useState("");
  const [names, setNames] = useState(Object.fromEntries(e.interfaces.map((i) => [i.if_index, i.name || ""])));
  const save = async (body) => {
    try { const r = await api.put(`/traffic/exporters/${e.ip}`, body); onSaved(r); setPs("");
      const ne = r.exporters.find((x) => x.ip === e.ip); if (ne) setNames(Object.fromEntries(ne.interfaces.map((i) => [i.if_index, i.name || ""])));
      toast("Interface names saved"); } catch (err) { toast(err.message, true); }
  };
  return <div className="card card-pad" style={{ minWidth: 0 }}>
    <div className="row"><b>{e.name || e.ip}</b><span className="small muted" style={{ marginLeft: 8 }}>{e.ip} · last record {e.last_seen ? timeAgo(e.last_seen) : "—"}</span></div>
    <div className="row" style={{ gap: 8, margin: "8px 0" }}>
      <span className="small muted">Firewall asset</span>
      <select className="input" style={{ maxWidth: 320 }} value={e.asset_id || ""} onChange={(ev) => save({ asset_id: ev.target.value ? Number(ev.target.value) : null, name: ev.target.value ? assets.find((a) => a.id === Number(ev.target.value))?.name : e.name })}>
        <option value="">— not linked —</option>
        {assets.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.ip || "no IP"})</option>)}
      </select>
      {!e.asset_id && <span className="small" style={{ color: "var(--warn)" }}>link it so VLAN descriptions are filled in</span>}
    </div>
    <p className="small muted" style={{ margin: "6px 0" }}>softflowd numbers interfaces itself (not the SNMP ifIndex). Paste the output of
      <code> ps aux | grep softflowd </code> (pfSense → Diagnostics → Command Prompt) and IT Ops fills in the names, using the VLAN descriptions from the pfSense / SNMP check.</p>
    <textarea className="input" rows={3} placeholder="nobody 86371 … /usr/local/bin/softflowd -i 15:em0.15 -n 172.17.15.29:2055 …" value={ps} onChange={(ev) => setPs(ev.target.value)} style={{ fontFamily: "monospace", width: "100%", boxSizing: "border-box" }} />
    <div className="row" style={{ justifyContent: "flex-end", margin: "6px 0 10px" }}><button className="btn sm" disabled={!ps.trim()} onClick={() => save({ softflowd_ps: ps })}>Read names from ps output</button></div>
    {!!e.interfaces.length && <table className="tbl" style={{ fontSize: 13 }}><thead><tr><th>#</th><th>Name</th><th>Last seen</th><th style={{ textAlign: "right" }}>Volume</th></tr></thead>
      <tbody>{e.interfaces.map((i) => <tr key={i.if_index}><td>{i.if_index}</td>
        <td><input className="input" value={names[i.if_index] ?? ""} onChange={(ev) => setNames({ ...names, [i.if_index]: ev.target.value })} style={{ width: "100%" }} /></td>
        <td className="small muted">{i.last_seen ? timeAgo(i.last_seen) : "—"}</td><td style={{ textAlign: "right" }}>{fmtBytes(i.bytes)}</td></tr>)}</tbody></table>}
    {!!e.interfaces.length && <div className="row" style={{ justifyContent: "flex-end", marginTop: 8 }}><button className="btn sm primary" onClick={() => save({ if_names: names })}><Save size={13} />Save names</button></div>}
  </div>;
}

export default function Traffic() {
  const { isAdmin, route, nav } = useApp();
  const [hours, setHours] = useState(Number(route.params.hours) || 1);
  const [f, setF] = useState({ exporter: route.params.exporter || "", if_index: route.params.if_index || "", host: route.params.host || "", direction: route.params.direction || "" });
  const [showSet, setShowSet] = useState(false);
  const [allHosts, setAllHosts] = useState(false);
  const qs = useMemo(() => new URLSearchParams(Object.entries({ hours, ...f }).filter(([, v]) => v !== "" && v != null)).toString(), [hours, f]);
  const { data: st, setData: setSt, reload: reloadSt } = useApi("/traffic/status", { interval: 15000 });
  const { data, error, reload } = useApi(`/traffic/summary?${qs}`, { interval: 60000, deps: [qs] });
  useEffect(() => { nav && window.history.replaceState(null, "", `#/traffic?${qs}`); }, [qs, nav]);
  const ifName = (e, i) => data?.interfaces.find((x) => x.exporter === e && x.if_index === i)?.name || `Interface #${i}`;
  const secs = hours * 3600;
  const peak = useMemo(() => (data?.series || []).reduce((m, p) => Math.max(m, mbps(p.b_in, data.step), mbps(p.b_out, data.step)), 0), [data]);
  const setFilter = (patch) => setF({ ...f, ...patch });
  const chips = [
    f.if_index !== "" && { k: "if", label: `Interface: ${ifName(f.exporter, Number(f.if_index))}`, clear: { exporter: "", if_index: "" } },
    f.host && { k: "host", label: `Host: ${data?.hosts.find((h) => h.ip === f.host)?.name || f.host}`, clear: { host: "" } },
    f.direction === "l" && { k: "dir", label: "Local ↔ local only", clear: { direction: "" } },
  ].filter(Boolean);
  const maxHost = Math.max(1, ...(data?.hosts || []).map((h) => h.b_in + h.b_out));
  const maxSvc = Math.max(1, ...(data?.services || []).map((h) => h.b_in + h.b_out));
  const maxIf = Math.max(1, ...(data?.interfaces || []).map((h) => h.b_in + h.b_out));
  const maxRem = Math.max(1, ...(data?.remotes || []).map((h) => h.b_in + h.b_out));
  return <>
    <PageHead crumb="Operations" title="Network traffic" desc="Who uses the Internet connection, for what, through which VLAN – from pfSense flow records (NetFlow / IPFIX).">
      <div className="seg">{RANGES.map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}</div>
      <button className="btn" onClick={() => { reload(); reloadSt(); }}><RefreshCw size={15} /></button>
      {isAdmin && <button className="btn" onClick={() => setShowSet(true)}><Cog size={15} />Settings</button>}
    </PageHead>
    {st && <SetupState st={st} isAdmin={isAdmin} onSettings={() => setShowSet(true)} />}
    {!!chips.length && <div className="chips" style={{ marginBottom: 12 }}>{chips.map((c) => <span key={c.k} className="chip" onClick={() => setFilter(c.clear)}>{c.label}<X size={13} /></span>)}</div>}
    {error && <div className="alert-box fail" style={{ marginBottom: 12 }}>{error}</div>}
    {data && <>
      <div className="stats">
        <Stat icon={ArrowDown} label="Download" value={fmtBytes(data.totals.b_in)} sub={`avg ${fmtMbps(mbps(data.totals.b_in, secs))}`} />
        <Stat icon={ArrowUp} label="Upload" value={fmtBytes(data.totals.b_out)} sub={`avg ${fmtMbps(mbps(data.totals.b_out, secs))}`} />
        <Stat icon={Gauge} label="Peak" value={fmtMbps(peak)} sub={`highest ${data.step >= 3600 ? "hour" : data.step / 60 + "-minute"} average`} />
        <Stat icon={Users} label="Hosts on the Internet" value={data.totals.hosts} sub={st ? `${st.stats.rate} records/s now` : ""} />
      </div>
      <div className="card card-pad" style={{ marginBottom: 16 }}>
        <div className="row" style={{ marginBottom: 6 }}><Activity size={16} /><b style={{ marginLeft: 6 }}>{f.direction === "l" ? "Local ↔ local" : "Internet"} traffic</b>
          <span className="small muted grow" style={{ marginLeft: 8 }}>download up · upload down</span>
          {data.totals.local_bytes > 0 && f.direction !== "l" && <button className="btn sm ghost" onClick={() => setFilter({ direction: "l" })}><Shuffle size={13} />Local ↔ local: {fmtBytes(data.totals.local_bytes)}</button>}
        </div>
        <TrafficChart data={data} />
      </div>
      <div className="grid2" style={{ marginBottom: 16 }}>
        <div className="card">
          <div className="card-head"><Users size={17} /><h3>Top hosts</h3><span className="small muted" style={{ marginLeft: "auto" }}>click to filter</span></div>
          <Table rowKey="ip" onRow={(h) => setFilter({ host: f.host === h.ip ? "" : h.ip })} rows={allHosts ? data.hosts : data.hosts.slice(0, 10)} empty={<Empty title="No hosts" />} columns={[
            { key: "ip", label: "Host", render: (h) => <NameCell ip={h.ip} name={h.name} src={h.src} user={h.user} /> },
            { key: "bar", label: "Up / down", render: (h) => <UpDown up={h.b_out} down={h.b_in} width={90} /> },
            { key: "t", label: "Volume", sort: (h) => h.b_in + h.b_out, render: (h) => <div className="row" style={{ gap: 8 }}><Bar value={h.b_in + h.b_out} max={maxHost} /><span>{fmtBytes(h.b_in + h.b_out)}</span></div> },
          ]} />
          {data.hosts.length > 10 && <div className="card-pad" style={{ paddingTop: 8, paddingBottom: 10 }}><button className="btn sm ghost" onClick={() => setAllHosts(!allHosts)}>{allHosts ? "Show top 10" : `Show all ${data.hosts.length}`}</button></div>}
        </div>
        <div className="card">
          <div className="card-head"><Network size={17} /><h3>Services</h3><span className="small muted" style={{ marginLeft: "auto" }}>by port</span></div>
          <Table rowKey="k" rows={data.services.map((s) => ({ ...s, k: `${s.proto}/${s.port}` }))} empty={<Empty title="No traffic" />} columns={[
            { key: "k", label: "Service", render: (s) => svcName(s.proto, s.port) },
            { key: "flows", label: "Flows", render: (s) => s.flows.toLocaleString() },
            { key: "t", label: "Volume", sort: (s) => s.b_in + s.b_out, render: (s) => <div className="row" style={{ gap: 8 }}><Bar value={s.b_in + s.b_out} max={maxSvc} color="#7c3aed" /><span>{fmtBytes(s.b_in + s.b_out)}</span></div> },
          ]} />
        </div>
        <div className="card">
          <div className="card-head"><Network size={17} /><h3>Interfaces / VLANs</h3><span className="small muted" style={{ marginLeft: "auto" }}>click to filter</span></div>
          <Table rowKey="k" rows={data.interfaces.map((i) => ({ ...i, k: `${i.exporter}#${i.if_index}` }))}
            onRow={(i) => setFilter(String(f.if_index) === String(i.if_index) && f.exporter === i.exporter ? { exporter: "", if_index: "" } : { exporter: i.exporter, if_index: i.if_index })}
            empty={<Empty title="No interfaces" />} columns={[
              { key: "k", label: "Interface", render: (i) => <div><div className="cell-title">{i.name || `Interface #${i.if_index}`}</div><div className="cell-sub">#{i.if_index} · {i.exporter}{!i.name && isAdmin && " · name it in Settings"}</div></div> },
              { key: "bar", label: "Up / down", render: (i) => <UpDown up={i.b_out} down={i.b_in} width={90} /> },
              { key: "t", label: "Volume", sort: (i) => i.b_in + i.b_out, render: (i) => <div className="row" style={{ gap: 8 }}><Bar value={i.b_in + i.b_out} max={maxIf} color="#0891b2" /><span>{fmtBytes(i.b_in + i.b_out)}</span></div> },
            ]} />
        </div>
        <div className="card">
          <div className="card-head"><ArrowUp size={17} /><h3>Internet destinations</h3><span className="small muted" style={{ marginLeft: "auto" }}>IP only – names come later</span></div>
          <Table rowKey="ip" rows={data.remotes} empty={<Empty title="No destinations" />} columns={[
            { key: "ip", label: "Address", render: (r) => <div><div className="cell-title">{r.ip}</div><div className="cell-sub">{r.services.map(([p, n]) => svcName(p, n).split(" · ")[0]).join(", ")}</div></div> },
            { key: "hosts", label: "Hosts", render: (r) => r.hosts },
            { key: "t", label: "Volume", sort: (r) => r.b_in + r.b_out, render: (r) => <div className="row" style={{ gap: 8 }}><Bar value={r.b_in + r.b_out} max={maxRem} color="#16a34a" /><span>{fmtBytes(r.b_in + r.b_out)}</span></div> },
          ]} />
        </div>
      </div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-head"><Shuffle size={17} /><h3>Largest conversations</h3>
          <span className="small muted" style={{ marginLeft: "auto" }}>{hours > 24 ? "from the 1-minute detail (kept " + (st?.settings.keep_minute_days || 7) + " days)" : ""}</span></div>
        <Table rowKey="k" rows={data.conversations.map((c, i) => ({ ...c, k: i }))} empty={<Empty title="No conversations" />} columns={[
          { key: "local", label: "Local host", render: (c) => <NameCell ip={c.local} name={c.local_name} /> },
          { key: "remote", label: "Other side", render: (c) => <NameCell ip={c.remote} name={c.remote_name} src={c.direction === "l" ? "local" : ""} /> },
          { key: "svc", label: "Service", render: (c) => svcName(c.proto, c.port) },
          { key: "up", label: "Upload", sort: (c) => c.b_out, render: (c) => fmtBytes(c.b_out) },
          { key: "down", label: "Download", sort: (c) => c.b_in, render: (c) => fmtBytes(c.b_in) },
          { key: "last", label: "Last seen", sort: (c) => c.last, render: (c) => <span className="small muted">{timeAgo(c.last)}</span> },
        ]} />
      </div>
      <p className="small faint">Numbers come from pfSense flow records (softflowd), summed per minute. Encrypted traffic shows only addresses and ports – no web addresses.
        ICMP from softflowd appears as “protocol 0” (known softflowd bug).</p>
    </>}
    {!data && !error && <div className="card card-pad muted"><AlertTriangle size={15} /> Loading…</div>}
    {showSet && st && <SettingsDrawer st={st} onClose={() => setShowSet(false)} onSaved={(r) => { setSt(r); reload(); }} />}
  </>;
}
