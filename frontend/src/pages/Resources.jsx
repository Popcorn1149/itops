import React, { useMemo, useState } from "react";
import { Cpu, MemoryStick, HardDrive, Search, Plus, Activity, Info, Gauge } from "lucide-react";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Table, Tabs, Drawer, Empty, UsageBar, TypeIcon, typeMeta, timeAgo, Select, Dot } from "../ui";
import { ResourcePanel, ResourceChart, fmtGb } from "../components/Resources";

const VIA = { snmp: "SNMP", ssh: "SSH", esxi: "ESXi", proxmox: "Proxmox", pfsense: "pfSense API" };
const SORTS = [["level", "Severity"], ["cpu", "Highest CPU"], ["mem", "Highest RAM"], ["disk", "Highest disk usage"], ["name", "Name A–Z"]];

// Suggested monitoring methods for devices without metrics
export function suggestCheck(a) {
  const win = /windows/i.test(a.os || "");
  if (a.type === "host") return a.meta?.platform === "proxmox" ? { type: "proxmox", hint: "Proxmox VE" } : { type: "esxi", hint: "ESXi/vCenter" };
  if (a.type === "server" || a.type === "vm") return { type: "ssh", hint: win ? "SSH (Windows)" : "SSH (Linux)", config: win ? { platform: "windows" } : {} };
  return { type: "snmp", hint: "SNMP" };
}

function ThresholdTable({ t }) {
  const f = (v) => (v == null ? <span className="faint">Disabled</span> : `${v}%`);
  return (
    <div className="card" style={{ marginBottom: 12, overflowX: "auto" }}>
      <table className="tbl small"><thead><tr><th style={{ padding: "6px 10px" }}>Threshold</th>
        <th style={{ padding: "6px 10px", color: "#a16207" }}>Attention</th><th style={{ padding: "6px 10px", color: "#c2410c" }}>Trouble</th>
        <th style={{ padding: "6px 10px", color: "#b91c1c" }}>Critical</th><th style={{ padding: "6px 10px", color: "#15803d" }}>Rearm (resolve when &lt;)</th></tr></thead>
        <tbody>{[["cpu", "CPU"], ["mem", "RAM"], ["disk", "Disk"]].map(([k, l]) => <tr key={k}><td style={{ padding: "5px 10px" }}><b>{l}</b></td>
          {["attention", "trouble", "critical", "rearm"].map((x) => <td key={x} style={{ padding: "5px 10px" }}>{f(t[`${k}_${x}`])}</td>)}</tr>)}</tbody></table>
      <div className="small faint" style={{ padding: "6px 10px" }}>Edit in the checks ("Open checks & edit thresholds"). Exceeding a threshold is not considered DOWN and does not reduce uptime.</div>
    </div>
  );
}

function Detail({ row, onClose }) {
  const { openCheck, openAsset } = useApp();
  return (
    <Drawer title={<><TypeIcon type={row.type} />{row.name}</>} onClose={onClose}>
      <div className="small muted" style={{ marginBottom: 14 }}>
        {[typeMeta(row.type).label, row.site_name, row.ip].filter(Boolean).join(" · ")}
        {row.via && <> · via <b>{VIA[row.via] || row.via}</b>{row.check_name ? ` (${row.check_name})` : ""}</>}
        {row.ts && <> · Updated {timeAgo(row.ts)}</>}
      </div>
      {row.stale && <div className="alert-box warn" style={{ marginBottom: 12 }}>Metrics are stale – the checks may not be running or may have failed. Open the checks to investigate.</div>}
      <div className="card card-pad" style={{ marginBottom: 14 }}><ResourcePanel res={row} thresholds={row.thresholds} /></div>
      {row.has_history
        ? <div className="card card-pad" style={{ marginBottom: 14 }}><ResourceChart checkId={row.check_id} thresholds={row.thresholds} current={row} /></div>
        : <div className="alert-box info" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> Metrics for this virtual machine are collected from ESXi (VMware Tools required), so only current values are available. To view VM-specific history and alerts, add an SSH/SNMP check directly to the VM.</div>}
      <ThresholdTable t={row.thresholds} />
      <div className="row wrap" style={{ gap: 8 }}>
        {row.check_id && <button className="btn" onClick={() => { onClose(); openCheck(row.check_id); }}><Activity size={14} />Open checks & edit thresholds</button>}
        {row.asset_id && <button className="btn" onClick={() => { onClose(); openAsset(row.asset_id); }}>View asset</button>}
      </div>
    </Drawer>
  );
}

export default function Resources() {
  const { tick, newCheck, isAdmin } = useApp();
  const { data } = useApi("/resources", { interval: 20000, deps: [tick] });
  const sites = useApi("/sites");
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const [site, setSite] = useState("");
  const [sort, setSort] = useState("level");
  const [sel, setSel] = useState(null);

  const rows = useMemo(() => {
    let r = (data?.rows || []).filter((x) =>
      (tab === "all" || (tab === "problems" ? x.level !== "ok" : tab === "stale" ? x.stale : x.levels[tab] && x.levels[tab] !== "ok"))
      && (!site || String(x.site_id) === String(site))
      && (!q || `${x.name} ${x.ip || ""} ${x.disk_name || ""} ${x.type}`.toLowerCase().includes(q.toLowerCase())));
    const o = { fail: 2, warn: 1, ok: 0 };
    const top = (x) => Math.max(x.cpu || 0, x.mem || 0, x.disk || 0);
    const by = {
      level: (a, b) => o[b.level] - o[a.level] || top(b) - top(a),
      name: (a, b) => a.name.localeCompare(b.name, "vi"),
      cpu: (a, b) => (b.cpu ?? -1) - (a.cpu ?? -1), mem: (a, b) => (b.mem ?? -1) - (a.mem ?? -1), disk: (a, b) => (b.disk ?? -1) - (a.disk ?? -1),
    }[sort];
    return [...r].sort(by).map((x) => ({ ...x, _k: x.asset_id ? `a${x.asset_id}` : `c${x.check_id}` }));
  }, [data, tab, q, site, sort]);

  if (!data) return null;
  const sm = data.summary;
  const n = (k) => sm[k].attention + sm[k].trouble + sm[k].critical;
  const sub = (k) => (n(k) ? [["critical", "Critical"], ["trouble", "Trouble"], ["attention", "Attention"]].filter(([x]) => sm[k][x]).map(([x, l]) => `${sm[k][x]} ${l}`).join(" · ") : "trong threshold");
  const add = (a) => {
    const s = suggestCheck(a);
    newCheck({ type: s.type, name: a.name, target: a.ip || "", asset_id: a.id, site_id: a.site_id, ...(s.config ? { _config: s.config } : {}) });
  };

  return (
    <>
      <PageHead crumb="Operations › Resources" title="CPU / RAM / Disk Resources"
        desc="Collect metrics from SNMP, SSH (Linux/Windows/pfSense), ESXi, and the pfSense API. Threshold breaches trigger Attention / Trouble / Critical alerts, which resolve automatically when values fall below the rearm threshold. Missing metrics are not treated as DOWN." />
      <div className="stats">
        <Stat icon={Gauge} label="Devices with metrics" value={data.total} sub={data.uncovered.length ? `${data.uncovered.length} devices without metrics` : "All devices covered"} tone={data.uncovered.length ? "" : "good"} onClick={() => document.getElementById("res-uncovered")?.scrollIntoView({ behavior: "smooth" })} />
        <Stat icon={Cpu} label="High CPU" value={n("cpu")} sub={sub("cpu")} tone={n("cpu") ? "bad" : "good"} onClick={() => setTab("cpu")} />
        <Stat icon={MemoryStick} label="High RAM" value={n("mem")} sub={sub("mem")} tone={n("mem") ? "bad" : "good"} onClick={() => setTab("mem")} />
        <Stat icon={HardDrive} label="Disk nearly full" value={n("disk")} sub={sub("disk")} tone={n("disk") ? "bad" : "good"} onClick={() => setTab("disk")} />
      </div>

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "All", count: data.total },
        { key: "problems", label: "Issues", count: data.problems },
        { key: "cpu", label: "CPU", count: n("cpu") },
        { key: "mem", label: "RAM", count: n("mem") },
        { key: "disk", label: "Disk", count: n("disk") },
        ...(data.stale ? [{ key: "stale", label: "Stale data", count: data.stale }] : []),
      ]} />
      <div className="card">
        <div className="toolbar row wrap" style={{ gap: 10 }}>
          <div className="search" style={{ width: 260, maxWidth: "100%" }}><Search size={16} /><input placeholder="Search devices, IPs, disks..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div style={{ width: 190 }}><Select value={site} onChange={setSite} placeholder="All site" options={(sites.data || []).map((s) => [s.id, s.name])} /></div>
          <div style={{ width: 200 }}><Select value={sort} onChange={setSort} options={SORTS} /></div>
        </div>
        <Table rows={rows} rowKey="_k" onRow={setSel}
          empty={<Empty icon={Gauge} title={data.total ? "No devices match the current filters" : "No resource data available"}>
            {data.total ? "Try removing some filters." : "Add SNMP / SSH / ESXi / pfSense checks for devices to display CPU/RAM/disk metrics here."}</Empty>}
          columns={[
            { key: "level", label: "", width: 30, render: (r) => <Dot status={r.stale ? "unknown" : r.level === "ok" ? "ok" : r.level} /> },
            { key: "name", label: "Device", render: (r) => (
              <div className="res-row-name"><TypeIcon type={r.type} size={15} />
                <div style={{ minWidth: 0 }}>
                  <div className="cell-title">{r.name}{r.stale && <span className="res-stale" style={{ marginLeft: 6 }}>Stale</span>}</div>
                  <div className="cell-sub">{[r.site_name, VIA[r.via] || r.via].filter(Boolean).join(" · ")}</div>
                </div>
              </div>) },
            { key: "cpu", label: "CPU", sort: (r) => r.cpu ?? -1, render: (r) => <UsageBar pct={r.cpu} level={r.levels.cpu} width={90} /> },
            { key: "mem", label: "RAM", sort: (r) => r.mem ?? -1, render: (r) => <UsageBar pct={r.mem} level={r.levels.mem} width={90} sub={r.mem_total_gb ? fmtGb(r.mem_total_gb) : null} /> },
            { key: "disk", label: "Disk", sort: (r) => r.disk ?? -1, render: (r) => <UsageBar pct={r.disk} level={r.levels.disk} width={90} sub={r.disks?.length > 1 ? r.disk_name : null} /> },
            { key: "ts", label: "Updated", sort: (r) => r.age_s ?? 1e9, render: (r) => <span className="small muted">{timeAgo(r.ts)}</span> },
          ]} />
      </div>

      <div className="card" id="res-uncovered" style={{ marginTop: 16 }}>
        <div className="card-head"><Info size={17} /><h3>No data available CPU/RAM/Disk</h3><span className="muted small" style={{ marginLeft: "auto" }}>{data.uncovered.length} devices</span></div>
        {data.uncovered.length === 0
          ? <div className="card-pad small muted">All active firewalls, switches, hosts, servers, NAS devices, and VMs have metrics. 👍</div>
          : <>
            <div className="card-pad small muted" style={{ paddingBottom: 6 }}>
              Switches/firewalls/NAS/UPS: enable SNMP on the devices and add an SNMP check <b>SNMP</b>. Linux/Windows machines: add an SSH checks <b>SSH</b> (Windows requires OpenSSH Server). ESXi: add a check <b>ESXi</b> – VM metrics are available when VMware Tools is installed.
              Devices monitored only with ping/HTTP will not report CPU/RAM/disk metrics.
            </div>
            {data.uncovered.map((a) => {
              const s = suggestCheck(a);
              return (
                <div key={a.id} className="risk-item" style={{ cursor: "default" }}>
                  <TypeIcon type={a.type} size={15} />
                  <div className="grow"><div style={{ fontWeight: 600 }}>{a.name}</div><div className="small muted">{[typeMeta(a.type).label, a.site_name, a.ip].filter(Boolean).join(" · ")}</div></div>
                  {isAdmin && <button className="btn sm" onClick={() => add(a)}><Plus size={13} />Add {s.hint}</button>}
                </div>
              );
            })}
          </>}
      </div>
      {sel && <Detail row={sel} onClose={() => setSel(null)} />}
    </>
  );
}
