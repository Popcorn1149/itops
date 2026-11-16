import React, { useState } from "react";
import { Plus, LayoutGrid, Flame, Archive, Bell, XCircle, EyeOff, Unlink, Map, Search, Pencil, Trash2, ExternalLink, CheckCircle2 } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Tabs, Table, LevelBadge, Modal, Field, Input, Select, Toggle, useToast, TypeIcon, typeMeta, Empty, confirmDelete } from "../ui";
import { ShieldCheck } from "lucide-react";

const LAYERS = ["Entry & Authentication", "Infrastructure", "Data", "Applications", "Communications", "Security"];

function MultiPick({ items, value, onChange }) {
  const v = new Set(value || []);
  return (
    <div className="card" style={{ maxHeight: 170, overflowY: "auto", padding: "6px 10px" }}>
      {items.length === 0 && <div className="small muted">No items</div>}
      {items.map(([id, label]) => (
        <label key={id} className="check-row" style={{ padding: "3px 0" }}>
          <input type="checkbox" checked={v.has(id)} onChange={(e) => { const n = new Set(v); e.target.checked ? n.add(id) : n.delete(id); onChange([...n]); }} />{label}
        </label>
      ))}
    </div>
  );
}

function CriticalForm({ item, all, onClose, onSaved }) {
  const [f, setF] = useState(item || { level: "High", layer: "Applications", depends_on: [], check_ids: [] });
  const assets = useApi("/assets");
  const checks = useApi("/checks");
  const toast = useToast();
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const save = async () => {
    const body = { ...f, asset_id: f.asset_id ? Number(f.asset_id) : null };
    try {
      item?.id ? await api.put(`/critical/${item.id}`, body) : await api.post("/critical", body);
      toast("Saved"); onSaved();
    } catch (e) { toast(e.message, true); }
  };
  return (
    <Modal title={item?.id ? `Edit ${item.name}` : "Create Critical System"} onClose={onClose} width={780}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={save}>Save</button></>}>
      <div className="form-grid">
        <Field label="System Name *"><Input value={f.name} onChange={set("name")} placeholder="VD: ERP, Active Directory, Email" /></Field>
        <Field label="Short Description"><Input value={f.description} onChange={set("description")} placeholder="Who would be affected if this system went down?" /></Field>
        <Field label="Layer"><Select value={f.layer} onChange={set("layer")} options={LAYERS} /></Field>
        <Field label="Severity"><Select value={f.level} onChange={set("level")} options={[["High", "High — company-wide impact"], ["Medium", "Medium — department-level impact"], ["Low", "Low"]]} /></Field>
        <div className="section-title">Hosting Location</div>
        <Field full><Toggle checked={f.hosted_externally} onChange={set("hosted_externally")} label="Third-party / cloud service (Microsoft 365, Google, Cloudflare...)" /></Field>
        {f.hosted_externally
          ? <Field label="Provider" full><Input value={f.external_note} onChange={set("external_note")} placeholder="Microsoft 365" /></Field>
          : <Field label="Hosted on machine / VM" full hint="Leave blank if unknown — it will appear under “Unmapped hosts”.">
              <Select value={f.asset_id} onChange={set("asset_id")} placeholder="— Unknown —" options={(assets.data || []).map((a) => [a.id, `${a.name} · ${typeMeta(a.type).label}${a.ip ? " · " + a.ip : ""}`])} />
            </Field>}
        <div className="section-title">Backup</div>
        <Field><Toggle checked={f.backup} onChange={set("backup")} label="Backup available (data/configuration)" /></Field>
        <Field><Input value={f.backup_note} onChange={set("backup_note")} placeholder="Location, frequency, and whether restore has been tested" /></Field>
        <div className="section-title">Dependencies</div>
        <Field label="Depends on systems"><MultiPick items={all.filter((x) => x.id !== item?.id).map((x) => [x.id, x.name])} value={f.depends_on} onChange={set("depends_on")} /></Field>
        <Field label="Monitoring checks" hint="Checks attached to the host above are included automatically."><MultiPick items={(checks.data || []).map((c) => [c.id, `${c.name} (${c.type})`])} value={f.check_ids} onChange={set("check_ids")} /></Field>
        <Field label="Owner"><Input value={f.owner} onChange={set("owner")} /></Field>
        <Field label="Access URL"><Input value={f.url} onChange={set("url")} placeholder="https://" /></Field>
        <Field label="Runbook — incident response steps" full><textarea className="input" style={{ minHeight: 110 }} value={f.runbook || ""} onChange={(e) => set("runbook")(e.target.value)} placeholder={"1. Check that the VM is running on ESXi\n2. Check the SQL service\n3. Contact the service provider"} /></Field>
      </div>
    </Modal>
  );
}

function CriticalDetail({ c, onClose, onEdit }) {
  const { openAsset, openCheck } = useApp();
  return (
    <Modal title={c.name} onClose={onClose} width={720} footer={<button className="btn" onClick={onEdit}><Pencil size={14} />Edit</button>}>
      <div className="row wrap" style={{ marginBottom: 14 }}><LevelBadge level={c.level} /><span className="badge outline">{c.layer}</span>{c.owner && <span className="badge">{c.owner}</span>}
        {c.url && <a className="badge info" href={c.url} target="_blank" rel="noreferrer"><ExternalLink size={12} />Open</a>}</div>
      {c.description && <p className="muted">{c.description}</p>}
      <div className="kv" style={{ marginBottom: 16 }}>
        <div>Hosted on</div><div>{c.hosted_externally ? `Externally hosted · ${c.external_note}` : c.asset ? <a style={{ cursor: "pointer", textDecoration: "underline" }} onClick={() => openAsset(c.asset.id)}>{c.asset.name}</a> : <span className="badge warn">Unmapped</span>}{c.host && <span className="muted"> on {c.host.name}</span>}</div>
        <div>Backup</div><div>{c.backup_ok ? <span className="badge ok">Yes</span> : <span className="badge fail">No</span>} {c.backup_note}</div>
        <div>Dependencies</div><div>{c.depends_names?.join(", ") || "—"}</div>
      </div>
      <h4>Check ({c.checks.length})</h4>
      {c.checks.map((k) => <div key={k.id} className="risk-item" style={{ padding: "8px 0" }} onClick={() => openCheck(k.id)}><span className={`dot ${k.status}`} /><div className="grow"><b>{k.name}</b><div className="small muted">{k.last_message}</div></div></div>)}
      {c.runbook && <><h4>Runbook</h4><pre className="json" style={{ whiteSpace: "pre-wrap", fontFamily: "inherit", fontSize: 13.5 }}>{c.runbook}</pre></>}
    </Modal>
  );
}

export default function Critical() {
  const { route, nav, isAdmin, tick, refresh } = useApp();
  const { data, reload } = useApi("/critical", { interval: 30000, deps: [tick] });
  const [tab, setTab] = useState(route.params.tab || "all");
  const [q, setQ] = useState("");
  const [edit, setEdit] = useState(null);
  const [view, setView] = useState(null);
  const toast = useToast();
  const all = (data || []).map((c) => ({ ...c, depends_names: c.depends_on.map((d) => (data || []).find((x) => x.id === d)?.name).filter(Boolean) }));
  const F = {
    all: () => true, high: (c) => c.level === "High", nobackup: (c) => !c.backup_ok, alerting: (c) => c.alerts > 0,
    failing: (c) => c.status === "fail", unmonitored: (c) => !c.checks.length, unmapped: (c) => !c.asset_id && !c.hosted_externally,
  };
  const rows = all.filter(F[tab] || F.all).filter((c) => !q || `${c.name} ${c.description} ${c.asset?.name || ""}`.toLowerCase().includes(q.toLowerCase()));
  const n = (k) => all.filter(F[k]).length;
  const remove = async (c) => { if (!(await confirmDelete(c.name))) return; await api.del(`/critical/${c.id}`); toast("Deleted"); reload(); };

  return (
    <>
      <PageHead crumb="Infrastructure › Critical systems" title="Critical systems"
        desc="Systems whose failure would affect the entire company. Status is calculated automatically from checks, VMs (backup and power state), hosts, and related alerts.">
        <button className="btn" onClick={() => nav("map")}><Map size={15} />View system map</button>
        {isAdmin && <button className="btn primary" onClick={() => setEdit({})}><Plus size={15} />Add critical system</button>}
      </PageHead>
      <div className="stats">
        <Stat icon={ShieldCheck} label="Critical systems" value={all.length} sub={`${n("high")} High severity · ${all.length - n("high")} other levels`} tone="bad" onClick={() => setTab("all")} />
        <Stat icon={Archive} label="No backup" value={n("nobackup")} sub="Not marked as backed up" tone={n("nobackup") ? "bad" : "good"} onClick={() => setTab("nobackup")} />
        <Stat icon={Bell} label="Has alerts" value={n("alerting")} sub="Related open alerts" tone={n("alerting") ? "bad" : "good"} onClick={() => setTab("alerting")} />
        <Stat icon={Unlink} label="Unmapped Server" value={n("unmapped")} sub="Host/VM not identified" tone={n("unmapped") ? "bad" : "good"} onClick={() => setTab("unmapped")} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "System", icon: LayoutGrid, count: all.length },
        { key: "high", label: "High severity", icon: Flame, count: n("high") },
        { key: "nobackup", label: "No backup", icon: Archive, count: n("nobackup") },
        { key: "alerting", label: "Has alerts", icon: Bell, count: n("alerting") },
        { key: "failing", label: "Failing", icon: XCircle, count: n("failing") },
        { key: "unmonitored", label: "Not monitored", icon: EyeOff, count: n("unmonitored") },
        { key: "unmapped", label: "Unmapped", icon: Unlink, count: n("unmapped") },
      ]} />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 280, marginLeft: "auto" }}><Search size={16} /><input placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} onRow={setView} empty={<Empty icon={ShieldCheck} title={all.length ? "No items match this filter" : "No critical systems defined"}>{!all.length && "List your most important systems: AD, ERP, file server, email, firewall..."}</Empty>} columns={[
          { key: "i", label: "STT", width: 50, sortable: false, render: (_, i) => <span className="muted">{i + 1}</span> },
          { key: "name", label: "System", render: (c) => <div><div className="cell-title"><TypeIcon type={c.asset?.type || "service"} />{c.name}</div><div className="cell-sub">{c.description}</div></div> },
          { key: "layer", label: "Layer", render: (c) => <span className="badge">{c.layer}</span> },
          { key: "level", label: "Level", sort: (c) => ({ High: 0, Medium: 1, Low: 2 }[c.level]), render: (c) => <LevelBadge level={c.level} /> },
          { key: "status", label: "Status", render: (c) => (
            <div className="stack" style={{ gap: 4 }}>
              {c.checks.length === 0 ? <span className="badge"><EyeOff size={12} />Not monitored</span>
                : <span className={`badge ${c.status === "ok" ? "ok" : c.status === "fail" ? "fail" : c.status === "warn" ? "warn" : ""}`}><CheckCircle2 size={12} />{c.checks.filter((k) => k.status === "ok").length}/{c.checks.length} checks OK</span>}
              {c.alerts > 0 && <span className="badge fail"><Bell size={12} />{c.alerts} alerts</span>}
            </div>) },
          { key: "backup_ok", label: "Backup", render: (c) => c.hosted_externally ? <span className="faint">—</span> : c.backup_ok ? <span className="badge ok">Yes</span> : <span className="badge fail">No</span> },
          { key: "asset", label: "Device / host", sort: (c) => c.asset?.name || "", render: (c) => c.hosted_externally ? <div className="small"><span className="faint">—</span><div className="muted">Cloud ({c.external_note || "externally hosted"})</div></div>
            : c.asset ? <div className="small"><span className="mono">{c.asset.ip || c.asset.name}</span><div className="muted">{c.asset.name}{c.host ? ` · ${c.host.name}` : ""}</div></div>
            : <span className="badge warn">Unmapped</span> },
          ...(isAdmin ? [{ key: "act", label: "", sortable: false, render: (c) => <div className="row" onClick={(e) => e.stopPropagation()}><button className="btn ghost sm" onClick={() => setEdit(c)}><Pencil size={14} /></button><button className="btn ghost sm danger" onClick={() => remove(c)}><Trash2 size={14} /></button></div> }] : []),
        ]} />
      </div>
      {view && <CriticalDetail c={view} onClose={() => setView(null)} onEdit={() => { setEdit(view); setView(null); }} />}
      {edit && <CriticalForm item={edit.id ? edit : null} all={all} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); refresh(); }} />}
    </>
  );
}
