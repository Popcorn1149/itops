import React, { useMemo, useState } from "react";
import { api } from "../api";
import { Boxes, Cpu, MemoryStick, Flame, Search, KeyRound, CheckCircle2, AlertTriangle } from "lucide-react";
import { useApi, Table, TypeIcon, Dot, Tabs, useToast } from "../ui";

// Virtual machines / containers running on a virtualization host (ESXi, Proxmox, Hyper-V, Docker)
const lvl = (v, warn, crit) => (v == null ? undefined : v >= crit ? "fail" : v >= warn ? "warn" : undefined);
const ratioLvl = (r) => (r == null ? "" : r > 4 ? "fail" : r > 2 ? "warn" : "");
const fmtUp = (s) => (!s ? "—" : s >= 86400 ? `${Math.floor(s / 86400)} days` : s >= 3600 ? `${Math.floor(s / 3600)} hours` : `${Math.floor(s / 60)} minutes`);

function Tile({ icon: Icon, label, value, unit, sub, sub2, tone, title }) {
  return (
    <div className="card card-pad" style={{ padding: "10px 12px", minWidth: 0 }} title={title}>
      <div className="small muted row" style={{ gap: 6 }}><Icon size={14} />{label}</div>
      <div style={{ fontSize: 20, fontWeight: 650 }}>{value}{unit && <span className="small muted" style={{ fontWeight: 400 }}> {unit}</span>}</div>
      {sub && <div className="small" style={{ color: tone ? `var(--${tone})` : "var(--ok)", fontWeight: 600 }}>{sub}</div>}
      {sub2 && <div className="small faint" style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{sub2}</div>}
    </div>
  );
}

// shows allocation, not actual usage
const cpuVerdict = (r) => (r == null ? null : r > 4 ? ["Overallocated", "critical"] : r > 2 ? ["Monitor", "trouble"] : ["Healthy", ""]);
const memVerdict = (r) => (r == null ? null : r > 1.2 ? ["Exceeds Host RAM", "critical"] : r > 1 ? ["Near Limit", "trouble"] : ["Healthy", ""]);
const pct = (v) => (v == null ? "—" : `${Math.round(v * 10) / 10}%`);
const num = (v, d = 1) => (v == null ? "—" : Number(v.toFixed(d)).toLocaleString("vi-VN"));

// "used / allocated" + small bar, e.g. 1 / 8 GB
function UseCell({ used, total, unit, pct: p, warn, crit, digits = 1 }) {
  if (total == null && used == null) return p != null ? <span className="small"><b>{pct(p)}</b></span> : <span className="faint">—</span>;
  const level = lvl(p, warn, crit);
  return (
    <div style={{ minWidth: 110 }}>
      <div className="small" style={{ whiteSpace: "nowrap" }}>
        <b style={{ color: level ? `var(--${level === "fail" ? "critical" : "trouble"})` : undefined }}>{used == null && p != null ? pct(p) : num(used, digits)}</b>
        {total != null && <span className="muted"> / {num(total, total % 1 ? 1 : 0)} {unit}</span>}
      </div>
      {p != null && <div style={{ height: 4, background: "var(--border)", borderRadius: 2, marginTop: 3, maxWidth: 110 }}>
        <div style={{ width: `${Math.min(100, p)}%`, height: "100%", borderRadius: 2,
          background: level === "fail" ? "var(--critical)" : level === "warn" ? "var(--trouble)" : "var(--ok)" }} /></div>}
    </div>
  );
}

// Enter a read-only ESXi account in the VM panel. It is saved to the existing SNMP check; run it again to retrieve per-VM CPU/RAM/disk metrics.
function EsxiPerf({ hostId, perf, need, canEdit, onDone }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [u, setU] = useState(perf.user || "");
  const [p, setP] = useState("");
  const [busy, setBusy] = useState(false);
  const show = need || open || perf.ok === false;
  const send = async (user, password) => {
    setBusy(true);
    try {
      const r = await api.post(`/assets/${hostId}/esxi-credentials`, { user, password });
      setP("");
      if (!user) { toast("ESXi credentials removed"); setU(""); }
      else if (r.perf?.ok) { toast(r.perf.note); setOpen(false); }
      else toast(r.perf?.note || r.result?.message || "Unable to retrieve metrics. Try again in a few minutes.", true);
      onDone?.();
    } catch (err) { toast(err.message, true); } finally { setBusy(false); }
  };
  const submit = (e) => { e?.preventDefault(); if (u) send(u, p); };
  if (!show) return (
    <div className="small faint row" style={{ marginBottom: 8, gap: 6 }}>
      <CheckCircle2 size={14} color="var(--ok)" />VM CPU/RAM/disk metrics retrieved through the ESXi API ({perf.user}).
      {canEdit && <button className="btn ghost sm" onClick={() => setOpen(true)}>Change Credentials</button>}
    </div>
  );
  return (
    <form className="card card-pad" style={{ marginBottom: 10, padding: "10px 12px" }} onSubmit={submit}>
      <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <KeyRound size={16} />
        <b className="small">Retrieve CPU/RAM/Disk for Each VM</b>
        {perf.ok === false && <span className="small row" style={{ color: "var(--fail)", gap: 4 }}><AlertTriangle size={13} />{perf.note}</span>}
      </div>
      {canEdit ? (
        <div className="row" style={{ gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <input className="input" style={{ width: 200 }} placeholder="User ESXi (Read-only)" value={u} onChange={(e) => setU(e.target.value)} autoComplete="off" />
          <input className="input" style={{ width: 200 }} type="password" placeholder={perf.has_credentials ? "Password (leave blank to keep current)" : "Password"} value={p}
            onChange={(e) => setP(e.target.value)} autoComplete="new-password" />
          <button className="btn primary sm" disabled={busy || !u}>{busy ? "Retrieving…" : "Retrieve Metrics"}</button>
          {perf.has_credentials && <button type="button" className="btn ghost sm" disabled={busy} onClick={() => send("", "")}>Remove Credentials</button>}
          <span className="small faint grow" style={{ minWidth: 220 }}>Use an account with the Read-only role on ESXi. Credentials are saved (encrypted) in check {perf.check_name}, ; no new check is created.</span>
        </div>
      ) : <div className="small muted" style={{ marginTop: 6 }}>An administrator must enter read-only ESXi credentials for this host.</div>}
    </form>
  );
}

export function GuestsPanel({ hostId, onOpen, tick, canEdit }) {
  const [bump, setBump] = useState(0);
  const { data } = useApi(`/assets/${hostId}/guests`, { deps: [hostId, tick, bump] });
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const rows = useMemo(() => (data?.guests || []).filter((r) => {
    if (tab === "on" && !r.running) return false;
    if (tab === "off" && r.running) return false;
    if (tab === "hot" && !((r.cpu || 0) >= 90 || (r.mem || 0) >= 95 || (r.disk || 0) >= 90)) return false;
    return !q || `${r.name} ${r.ip} ${r.os}`.toLowerCase().includes(q.toLowerCase());
  }), [data, tab, q]);
  if (!data || !data.summary.total) return null;
  const s = data.summary, h = data.host;
  return (
    <div style={{ marginBottom: 18 }}>
      <div className="row" style={{ marginBottom: 8 }}>
        <h4 className="grow" style={{ margin: 0 }}>Virtual Machines & Containers on Host</h4>
        {data.platforms.map((p) => <span key={p} className="badge outline">{p}</span>)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, marginBottom: 10 }}>
        <Tile icon={Boxes} label="VMs" value={`${s.running}/${s.total}`} unit="running"
          sub2={`${s.vms} VM${s.containers ? ` · ${s.containers} container` : ""}${s.stopped ? ` · ${s.stopped} stopped` : ""}`} />
        {(() => { const v = cpuVerdict(s.vcpu_ratio); return (
          <Tile icon={Cpu} label="CPU Allocated to VMs" value={`${s.vcpu_alloc} vCPU`} unit={h.cores ? `/ ${h.cores} ${h.cpu_unit || "CPU"}` : ""}
            sub={v ? `${v[0]} · ${s.vcpu_ratio} vCPU / ${h.cpu_unit || "CPU"}` : "Host CPU count unknown"} tone={v?.[1]}
            sub2={`Actual host usage: ${pct(h.cpu)}`}
            title={"Total vCPU allocated to Running VMs compared with the host CPU capacity. This is allocated capacity, not actual usage.\nCPU is time-shared, so overcommitment is normal: ≤ 2:1 is healthy, 2–4:1 should be monitored, > 4:1 may cause performance degradation."} />); })()}
        {(() => { const v = memVerdict(s.mem_ratio); return (
          <Tile icon={MemoryStick} label="RAM Allocated to VMs" value={`${s.mem_alloc_gb} GB`} unit={h.mem_gb ? `/ ${h.mem_gb} GB` : ""}
            sub={v ? `${v[0]} · ${Math.round((s.mem_ratio || 0) * 100)}% host RAM` : "Host RAM unknown"} tone={v?.[1]}
            sub2={`Actual host usage: ${pct(h.mem)}`}
            title={"Total RAM allocated to Running VMs compared with the host's physical RAM. Unlike CPU, RAM should not be overcommitted beyond 100%; memory pressure slows down all VMs."} />); })()}
        <Tile icon={Flame} label="Overloaded VMs" value={s.allocation_only ? "—" : s.hot}
          sub={s.allocation_only ? "No utilization data" : s.hot ? "See the Overloaded tab" : "None"} tone={s.allocation_only ? "trouble" : s.hot ? "critical" : ""}
          sub2="CPU ≥ 90%, RAM ≥ 95%, or disk ≥ 90% inside the VM"
          title="Number of VMs nearing resource limits, measured inside each VM." />
      </div>
      {data.perf && <EsxiPerf hostId={hostId} perf={data.perf} need={s.allocation_only} canEdit={canEdit} onDone={() => setBump((x) => x + 1)} />}
      <div className="card">
        <div className="toolbar" style={{ flexWrap: "wrap" }}>
          <Tabs value={tab} onChange={setTab} tabs={[
            { key: "all", label: "All", count: s.total }, { key: "on", label: "Running", count: s.running }, { key: "off", label: "Disabled", count: s.stopped },
            ...(s.allocation_only ? [] : [{ key: "hot", label: "Overloaded", count: s.hot }]),
          ]} />
          <div className="search" style={{ width: 200, marginLeft: "auto" }}><Search size={15} /><input placeholder="Search name or IP..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        </div>
        <Table rows={rows} onRow={(r) => onOpen?.(r.id)} empty={<div className="muted small" style={{ padding: 12 }}>No VMs found.</div>} columns={[
          { key: "name", label: "Name", render: (r) => <div><div className="cell-title"><Dot status={r.running ? r.status : "off"} /><TypeIcon type={r.type} />{r.name}
            <span className="badge outline" style={{ fontSize: 10.5 }}>{r.kind_label}</span>{r.missing && <span className="badge warn" style={{ fontSize: 10.5 }}>No longer detected</span>}</div>
            <div className="cell-sub">{[r.ips?.[0] || r.ip, r.os].filter(Boolean).join(" · ") || "—"}</div></div> },
          { key: "running", label: "Status", sort: (r) => (r.running ? 1 : 0), render: (r) => r.running
            ? <div className="small"><span className="badge ok">Running</span>{r.uptime_s ? <div className="faint">up {fmtUp(r.uptime_s)}</div> : null}</div>
            : <span className="badge">Disabled</span> },
          { key: "cpu", label: "CPU (used / allocated)", sort: (r) => r.cpu ?? -1, render: (r) => <UseCell used={r.cpu_used} total={r.cpu_total} unit="vCPU" pct={r.cpu} warn={80} crit={90} digits={2} /> },
          { key: "mem", label: "RAM (used / allocated)", sort: (r) => r.mem ?? -1, render: (r) => <UseCell used={r.mem_used_gb} total={r.mem_total_gb} unit="GB" pct={r.mem} warn={85} crit={95} /> },
          { key: "disk", label: "Disk (used / total)", sort: (r) => r.disk ?? -1, render: (r) => <UseCell used={r.disk_used_gb} total={r.disk_total_gb} unit="GB" pct={r.disk} warn={80} crit={90} /> },
        ]} />
      </div>
      <div className="small faint" style={{ marginTop: 6 }}>
        "Allocated to VMs" is allocated capacity, not actual usage: CPU overcommitment up to 4:1 is common, but RAM should not exceed 100%.
        CPU/RAM/disk columns show actual usage inside each VM (ESXi API: CPU/RAM are always available; disk and IP require VMware Tools. Proxmox requires the QEMU guest agent for disk and IP).
      </div>
    </div>
  );
}
