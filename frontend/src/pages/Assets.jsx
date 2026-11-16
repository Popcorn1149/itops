import React, { useMemo, useState } from "react";
import { Plus, Pencil, Trash2, Archive, ChevronRight, Search } from "lucide-react";
import { api } from "../api";
import { useApp, go } from "../App";
import {
  useApi, PageHead, Table, Tabs, StatusBadge, TypeIcon, typeMeta, TYPES, Modal, Drawer, Field, Input, Select, Toggle,
  useToast, timeAgo, Dot, LevelBadge, UsageBar, fmtTime, confirmDelete, Empty, SevBadge,
} from "../ui";
import { ResourcePanel, ResourceChart } from "../components/Resources";
import { GuestsPanel } from "../components/Guests";

const TYPE_OPTIONS = Object.entries(TYPES).map(([k, v]) => [k, v.label]);

export function AssetForm({ asset, preset, onClose, onSaved }) {
  const [f, setF] = useState(asset || { type: "server", status: "unknown", backup: false, ...preset });
  const sites = useApi("/sites");
  const assets = useApi("/assets");
  const toast = useToast();
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const save = async () => {
    const body = { ...f, site_id: f.site_id ? Number(f.site_id) : null, parent_id: f.parent_id ? Number(f.parent_id) : null };
    delete body.checks; delete body.critical; delete body.children; delete body.alerts; delete body.path;
    try {
      const r = asset?.id ? await api.put(`/assets/${asset.id}`, body) : await api.post("/assets", body);
      toast("Asset saved"); onSaved(r);
    } catch (e) { toast(e.message, true); }
  };
  const parents = (assets.data || []).filter((a) => a.id !== asset?.id && !["container"].includes(a.type));
  return (
    <Modal title={asset?.id ? `Edit ${asset.name}` : "Add Asset"} onClose={onClose} width={760}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={save}>Save</button></>}>
      <div className="form-grid">
        <Field label="Name *"><Input value={f.name} onChange={set("name")} placeholder="VD: SW-CORE, DC01" /></Field>
        <Field label="Type"><Select value={f.type} onChange={set("type")} options={TYPE_OPTIONS} /></Field>
        <Field label="Site"><Select value={f.site_id} onChange={set("site_id")} placeholder="— Unassigned —" options={(sites.data || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Depends on / Hosted on" hint="VM → host; host → switch; switch → firewall. Used to build the topology map.">
          <Select value={f.parent_id} onChange={set("parent_id")} placeholder="— None —" options={parents.map((a) => [a.id, `${a.name} (${typeMeta(a.type).label})`])} />
        </Field>
        <Field label="IP / hostname"><Input value={f.ip} onChange={set("ip")} placeholder="10.0.0.1" /></Field>
        <Field label="Manual Status" hint="Automatically updated when a checks is linked"><Select value={f.status} onChange={set("status")} options={[["unknown", "Unknown"], ["up", "Operational"], ["warning", "Warning"], ["down", "Error"], ["off", "Disabled"]]} /></Field>
        <Field label="Vendor"><Input value={f.vendor} onChange={set("vendor")} /></Field>
        <Field label="Model"><Input value={f.model} onChange={set("model")} /></Field>
        <Field label="Operating System / Firmware"><Input value={f.os} onChange={set("os")} /></Field>
        <Field label="Serial / Service tag"><Input value={f.serial} onChange={set("serial")} /></Field>
        <Field label="Owner"><Input value={f.owner} onChange={set("owner")} /></Field>
        <Field label="Location (rack, room, etc.)"><Input value={f.location} onChange={set("location")} /></Field>
        <div className="section-title">Backup</div>
        <Field><Toggle checked={f.backup} onChange={set("backup")} label="Backup available" /></Field>
        <Field><Input value={f.backup_note} onChange={set("backup_note")} placeholder="e.g. Nightly Veeam job, Active Backup..." /></Field>
        <Field label="Notes" full><textarea className="input" value={f.notes || ""} onChange={(e) => set("notes")(e.target.value)} /></Field>
      </div>
    </Modal>
  );
}

function LiveMetrics({ a }) {
  const m = { ...(a.meta || {}), ...((a.meta || {}).live || {}) };
  const res = (a.meta || {}).res;
  const rows = res ? [] : [
    ["CPU", m.cpu_pct ?? m.cpu], ["RAM", m.mem_pct ?? m.mem], ["Disk", m.disk],
  ].filter((r) => r[1] != null);
  const info = [
    ["Uptime", m.uptime], ["Version", m.version], ["vCPU", m.vcpu], ["Allocated RAM", m.mem_mb ? `${m.mem_mb} MB` : null],
    ["Cores", m.cores], ["RAM", m.mem_gb ? `${m.mem_gb} GB` : null], ["VMware Tools", m.tools], ["Snapshot", m.snapshots ? `${m.snapshots} (oldest ${m.oldest_snapshot_days} days)` : null],
    ["Port", m.ports_total ? `${m.ports_up}/${m.ports_total} up` : null], ["Temperature", m.temp ? `${m.temp}°C` : null],
    ["Description SNMP", m.sys_descr], ["MAC", m.mac], ["Notes VM", m.annotation],
  ].filter((r) => r[1] != null && r[1] !== "");
  if (!rows.length && !info.length && !res) return null;
  return (
    <div className="card card-pad" style={{ marginBottom: 16 }}>
      {res && <div style={{ marginBottom: info.length ? 14 : 0 }}>
        <ResourcePanel res={res} />
        {res.check_id && <div style={{ marginTop: 12 }}><ResourceChart checkId={res.check_id} height={150} current={res} /></div>}
      </div>}
      {rows.length > 0 && <div className="row wrap" style={{ gap: 22, marginBottom: info.length ? 10 : 0 }}>{rows.map(([k, v]) => <div key={k}><div className="small muted">{k}</div><UsageBar pct={v} /></div>)}</div>}
      {info.length > 0 && <div className="kv">{info.map(([k, v]) => <React.Fragment key={k}><div>{k}</div><div>{String(v)}</div></React.Fragment>)}</div>}
      {m.missing && <div className="alert-box warn" style={{ marginTop: 10 }}>This asset is no longer present in the sync source — it may have been deleted or moved.</div>}
    </div>
  );
}

export function AssetDrawer({ id, onClose }) {
  const { isAdmin, newCheck, openCheck, refresh, tick } = useApp();
  const { data: a, reload } = useApi(`/assets/${id}`, { deps: [tick, id] });
  const [edit, setEdit] = useState(false);
  const [childId, setChildId] = useState(null);
  const toast = useToast();
  if (childId) return <AssetDrawer id={childId} onClose={() => setChildId(null)} />;
  if (!a) return <Drawer title="Loading..." onClose={onClose} />;
  const guestKids = a.children.filter((c) => ["vm", "container"].includes(c.type));
  const otherKids = a.children.filter((c) => !["vm", "container"].includes(c.type));
  const remove = async () => {
    if (!(await confirmDelete(a.name))) return;
    await api.del(`/assets/${a.id}`); toast("Deleted"); refresh(); onClose();
  };
  return (
    <Drawer wide={guestKids.length > 0} onClose={onClose} title={<><TypeIcon type={a.type} size={18} />{a.name}</>}
      actions={isAdmin && <><button className="btn sm" onClick={() => setEdit(true)}><Pencil size={14} />Edit</button><button className="btn sm danger" onClick={remove}><Trash2 size={14} /></button></>}>
      <div className="row wrap" style={{ marginBottom: 14 }}>
        <StatusBadge status={a.status} />
        <span className="badge outline">{typeMeta(a.type).label}</span>
        {a.backup ? <span className="badge ok"><Archive size={12} />Backup available</span> : ["vm", "host", "server", "nas"].includes(a.type) && <span className="badge warn"><Archive size={12} />No backup</span>}
        {a.source !== "manual" && <span className="badge info">Synced automatically</span>}
      </div>
      {a.path?.length > 0 && (
        <div className="row wrap small muted" style={{ marginBottom: 14, gap: 4 }}>
          {a.path.map((p) => <React.Fragment key={p.id}><a style={{ cursor: "pointer", textDecoration: "underline" }} onClick={() => setChildId(p.id)}>{p.name}</a><ChevronRight size={13} /></React.Fragment>)}
          <b style={{ color: "var(--text)" }}>{a.name}</b>
        </div>
      )}
      <LiveMetrics a={a} />
      <div className="kv" style={{ marginBottom: 18 }}>
        <div>IP</div><div className="mono">{a.ip || "—"}</div>
        <div>Vendor / Model</div><div>{[a.vendor, a.model].filter(Boolean).join(" ") || "—"}</div>
        <div>OS / firmware</div><div>{a.os || "—"}</div>
        {a.serial && <><div>Serial</div><div className="mono">{a.serial}</div></>}
        {a.owner && <><div>Owner</div><div>{a.owner}</div></>}
        {a.location && <><div>Location</div><div>{a.location}</div></>}
        {a.backup_note && <><div>Backup</div><div>{a.backup_note}</div></>}
        <div>Last seen</div><div>{a.last_seen ? timeAgo(a.last_seen) : "—"}</div>
      </div>
      {a.notes && <div className="alert-box info" style={{ marginBottom: 18, whiteSpace: "pre-wrap" }}>{a.notes}</div>}

      {a.critical.length > 0 && <>
        <h4>Critical systems hosted here</h4>
        <div className="chips" style={{ marginBottom: 18 }}>{a.critical.map((c) => <span key={c.id} className="chip"><LevelBadge level={c.level} />{c.name}</span>)}</div>
      </>}

      <div className="row"><h4 className="grow">Monitoring ({a.checks.length})</h4>
        {isAdmin && <button className="btn sm" onClick={() => newCheck({ asset_id: a.id, site_id: a.site_id, target: a.ip, name: a.name, type: a.type === "firewall" ? "pfsense" : a.type === "host" ? (a.meta?.platform === "proxmox" ? "proxmox" : "esxi") : ["switch", "router", "ap", "ups", "nas"].includes(a.type) ? "snmp" : "ping" })}><Plus size={14} />Add checks</button>}
      </div>
      {a.checks.length === 0 ? <div className="muted small" style={{ marginBottom: 18 }}>No checks configured. Add Ping/SNMP/SSH checks to update the status automatically.</div> : (
        <div className="card" style={{ marginBottom: 18 }}>
          {a.checks.map((c) => (
            <div key={c.id} className="risk-item" onClick={() => openCheck(c.id)}>
              <Dot status={c.status} pulse />
              <div className="grow"><b>{c.name}</b> <span className="faint small">{c.type}</span><div className="small muted">{c.last_message || "Not running"}</div></div>
              <span className="small faint">{timeAgo(c.last_checked)}</span>
            </div>
          ))}
        </div>
      )}

      {guestKids.length > 0 && <GuestsPanel hostId={a.id} tick={tick} onOpen={setChildId} canEdit={isAdmin} />}

      {otherKids.length > 0 && <>
        <h4>Child devices ({otherKids.length})</h4>
        <div className="card" style={{ marginBottom: 18 }}>
          {otherKids.map((c) => (
            <div key={c.id} className="risk-item" onClick={() => setChildId(c.id)}>
              <TypeIcon type={c.type} />
              <div className="grow"><b>{c.name}</b><div className="small muted">{[c.ip, c.os].filter(Boolean).join(" · ")}</div></div>
              {!c.backup && c.type === "vm" && <span className="badge warn small">Never backup</span>}
              <Dot status={c.status} />
            </div>
          ))}
        </div>
      </>}

      {a.events?.length > 0 && <>
        <div className="row"><h4 className="grow">Recent logs</h4><button className="btn sm" onClick={() => { onClose(); go(`logs?asset_id=${a.id}`); }}>View all</button></div>
        <div className="card" style={{ marginBottom: 18 }}>
          {a.events.map((e) => (
            <div key={e.id} className="risk-item" style={{ cursor: "default" }}>
              <div className={`sev ${e.severity <= 3 ? "high" : e.severity === 4 ? "medium" : "low"}`} />
              <div className="grow small"><span className="mono muted">{new Date(e.ts).toLocaleString("vi-VN", { hour12: false })}</span> <b>{e.app}</b><div className="mono" style={{ wordBreak: "break-word" }}>{e.message.slice(0, 220)}</div></div>
            </div>
          ))}
        </div>
      </>}

      {a.alerts.length > 0 && <>
        <h4>Recent alerts</h4>
        {a.alerts.map((al) => (
          <div key={al.id} className="row small" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
            {al.status === "resolved" ? <span className="badge ok">Resolved</span> : <SevBadge sev={al.severity} />}
            <span className="grow">{al.title}</span><span className="faint">{fmtTime(al.opened_at)}</span>
          </div>
        ))}
      </>}
      {edit && <AssetForm asset={a} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); reload(); refresh(); }} />}
    </Drawer>
  );
}

export default function Assets() {
  const { route, openAsset, isAdmin, tick } = useApp();
  const type = route.params.type || "";
  const { data, reload } = useApi(`/assets${type ? `?type=${type}` : ""}`, { interval: 30000, deps: [tick] });
  const sites = useApi("/sites");
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const [siteF, setSiteF] = useState("");
  const [adding, setAdding] = useState(false);
  const siteName = Object.fromEntries((sites.data || []).map((s) => [s.id, s.name]));
  const all = data || [];
  const byId = Object.fromEntries(all.map((a) => [a.id, a]));
  const rows = useMemo(() => all.filter((a) => {
    if (tab === "down" && a.status !== "down") return false;
    if (tab === "warn" && a.status !== "warning") return false;
    if (tab === "nobackup" && (a.backup || !["vm", "host", "server", "nas"].includes(a.type))) return false;
    if (tab === "nocheck" && a.checks.length) return false;
    if (siteF && String(a.site_id) !== siteF) return false;
    if (q && !`${a.name} ${a.ip} ${a.model} ${a.os} ${a.vendor}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  }), [all, tab, q, siteF]);
  const types = type.split(",").filter(Boolean);
  const title = types.length === 1 ? typeMeta(types[0]).label : { "switch,router,ap": "Network devices", "host,server": "Physical Hosts", "vm,container": "Virtual machines & containers" }[type] || (type ? "Other Devices" : "All assets");

  return (
    <>
      <PageHead crumb={`Infrastructure › ${title}`} title={title} desc={types.includes("host") ? "Physical hosts and virtualisation hosts (ESXi, Proxmox, Hyper-V, Docker). Add ESXi / Proxmox / SSH checks to discover virtual devices; select a host to view the count, resource allocation and performance for each virtual machine." : "Asset inventory. Add assets manually or let ESXi / Proxmox / pfSense checks sync them automatically. Select a row to view its details."}>
        {isAdmin && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={15} />Add Asset</button>}
      </PageHead>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "All", count: all.length },
        { key: "down", label: "Failing", count: all.filter((a) => a.status === "down").length },
        { key: "warn", label: "Warning", count: all.filter((a) => a.status === "warning").length },
        { key: "nobackup", label: "No backup", count: all.filter((a) => !a.backup && ["vm", "host", "server", "nas"].includes(a.type)).length },
        { key: "nocheck", label: "Not monitored", count: all.filter((a) => !a.checks.length).length },
      ]} />
      <div className="card">
        <div className="toolbar">
          <div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Search name, IP, model..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div style={{ width: 220 }}><Select value={siteF} onChange={setSiteF} placeholder="All site" options={(sites.data || []).map((s) => [String(s.id), s.name])} /></div>
          <span className="muted small" style={{ marginLeft: "auto" }}>{rows.length} items</span>
        </div>
        <Table rows={rows} onRow={(a) => openAsset(a.id)} empty={<Empty title="No assets found" />} columns={[
          { key: "idx", label: "STT", width: 50, sortable: false, render: (_, i) => <span className="muted">{i + 1}</span> },
          { key: "name", label: "Name", render: (a) => <div><div className="cell-title"><TypeIcon type={a.type} />{a.name}{a.critical.length > 0 && <span className="badge fail" style={{ fontSize: 11 }}>★ {a.critical[0].level}</span>}</div><div className="cell-sub">{typeMeta(a.type).label}{a.source !== "manual" ? " · Auto-synced" : ""}</div></div> },
          { key: "site_id", label: "Site", sort: (a) => siteName[a.site_id] || "", render: (a) => siteName[a.site_id] || <span className="faint">—</span> },
          { key: "ip", label: "IP", render: (a) => <span className="mono">{a.ip || "—"}</span> },
          { key: "model", label: "Model / OS", render: (a) => <div className="small">{[a.vendor, a.model].filter(Boolean).join(" ")}<div className="muted">{a.os}</div></div> },
          { key: "parent_id", label: "Hosted on", sort: (a) => byId[a.parent_id]?.name || a.parent_name || "", render: (a) => a.parent_id ? <span className="small">{byId[a.parent_id]?.name || a.parent_name || `#${a.parent_id}`}</span> : <span className="faint">—</span> },
          ...(types.some((t) => ["host", "server", "vm"].includes(t)) || !type ? [{ key: "guests", label: "Virtual machines / containers", sort: (a) => a.guests?.total || 0,
            render: (a) => a.guests ? <span className="small"><b>{a.guests.running}</b>/{a.guests.total} <span className="muted">running</span></span>
              : ["host", "server"].includes(a.type) && !a.checks.some((c) => ["esxi", "proxmox"].includes(c.type) || (c.type === "ssh"))
                ? <span className="small faint" title="Add ESXi / Proxmox checks (or SSH + Hyper-V / Docker) to discover virtual devices">No virtual devices discovered</span>
                : <span className="faint">—</span> }] : []),
          { key: "status", label: "Status", render: (a) => <StatusBadge status={a.status} /> },
          { key: "backup", label: "Backup", render: (a) => a.backup ? <span className="badge ok">Yes</span> : ["vm", "host", "server", "nas"].includes(a.type) ? <span className="badge warn">No</span> : <span className="faint">—</span> },
          { key: "checks", label: "Check", sort: (a) => a.checks.length, render: (a) => a.checks.length ? <span className="row" style={{ gap: 4 }}>{a.checks.map((c) => <Dot key={c.id} status={c.status} />)}</span> : <span className="faint small">Never canh</span> },
        ]} />
      </div>
      {adding && <AssetForm preset={types.length === 1 ? { type: types[0] } : {}} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}
    </>
  );
}
