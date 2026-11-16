import React, { useState } from "react";
import { Building2, Plus, Pencil, Trash2, Shield, Network } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Modal, Field, Input, Select, Dot, TypeIcon, timeAgo, useToast, Empty, confirmDelete, SiteHealth, InternetLine } from "../ui";

const KINDS = [["datacenter", "Datacenter / Head Office"], ["branch", "Branch"], ["office", "Office"], ["vps", "VPS"], ["cloud", "Cloud"]];
const STATUS_CHIP = { ok: "green", warn: "amber", fail: "red" };

export function SiteForm({ site, onClose, onSaved }) {
  const [f, setF] = useState(site || { kind: "branch", sort: 0 });
  const toast = useToast();
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const save = async () => {
    try {
      const r = site?.id ? await api.put(`/sites/${site.id}`, f) : await api.post("/sites", f);
      toast("Site saved"); onSaved(r);
    } catch (e) { toast(e.message, true); }
  };
  return (
    <Modal title={site?.id ? `Edit site ${site.name}` : "Add site"} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={save}>Save</button></>}>
      <div className="form-grid">
        <Field label="Site Name *"><Input value={f.name} onChange={set("name")} placeholder="VD: Head Office HCM" /></Field>
        <Field label="Type"><Select value={f.kind} onChange={set("kind")} options={KINDS} /></Field>
        <Field label="Location" full><Input value={f.location} onChange={set("location")} /></Field>
        <Field label="WAN"><Input value={f.wan} onChange={set("wan")} placeholder="Static IP, dynamic IP..." /></Field>
        <Field label="VPN"><Input value={f.vpn} onChange={set("vpn")} placeholder="IPsec to HQ, OpenVPN..." /></Field>
        <Field label="Display Order"><Input type="number" value={f.sort} onChange={(v) => set("sort")(Number(v))} /></Field>
        <Field label="Notes" full><textarea className="input" value={f.description || ""} onChange={(e) => set("description")(e.target.value)} /></Field>
      </div>
    </Modal>
  );
}

export default function Sites() {
  const { openAsset, openCheck, isAdmin, tick } = useApp();
  const { data, reload } = useApi("/sites", { interval: 30000, deps: [tick] });
  const [edit, setEdit] = useState(null);
  const toast = useToast();
  const remove = async (s) => {
    if (!(await confirmDelete(s.name))) return;
    await api.del(`/sites/${s.id}`); toast("Site deleted"); reload();
  };
  return (
    <>
      <PageHead crumb="Infrastructure › Sites" title="Sites" desc="Each site groups resources that share the same Site: firewalls, hosts, virtual machines, devices, and monitoring checks.">
        {isAdmin && <button className="btn primary" onClick={() => setEdit({})}><Plus size={15} />Add site</button>}
      </PageHead>
      {data && data.length === 0 && <div className="card"><Empty icon={Building2} title="No sites yet">Create your first site (headquarters, branch, VPS, etc.), then assign devices to it.</Empty></div>}
      <div className="grid2">
        {data?.map((s) => (
          <div className="card site-card" key={s.id}>
            <div className="card-head" style={{ alignItems: "flex-start" }}>
              <Building2 size={18} color="#ea7a0c" style={{ marginTop: 2 }} />
              <div className="grow">
                <div className="row"><h3>{s.name}</h3><SiteHealth s={s} /></div>
                <div className="site-meta">{KINDS.find((k) => k[0] === s.kind)?.[1]}{s.location ? ` · ${s.location}` : ""}</div>
              </div>
              {isAdmin && <>
                <button className="btn ghost sm" onClick={() => setEdit(s)}><Pencil size={15} /></button>
                <button className="btn ghost sm danger" onClick={() => remove(s)}><Trash2 size={15} /></button>
              </>}
            </div>
            <div className="card-pad">
              <div className="kv">
                <div>Internet</div><div><InternetLine items={s.internet} onOpen={openCheck} /></div>
                <div>WAN</div><div>{s.wan || "—"}</div>
                <div>VPN</div><div>{s.vpn || "—"}</div>
                <div>Infrastructure</div><div>{s.stats.hosts} hosts · {s.stats.vms_on}/{s.stats.vms} Running VMs · {s.stats.devices} devices · {s.stats.checks} checks</div>
                <div>Updated Last seen</div><div>{timeAgo(s.last_sync)}</div>
              </div>
              {s.firewalls.map((fw) => (
                <div className="fw-box" key={fw.id} style={{ cursor: "pointer" }} onClick={() => openAsset(fw.id)}>
                  <Shield size={16} color="#ea7a0c" /><b>{fw.name}</b>
                  <span className="muted small">{[fw.vendor, fw.model].filter(Boolean).join(" ")}</span>
                  {fw.live?.cpu != null && <span className="muted small">CPU {fw.live.cpu}%</span>}
                  {fw.live?.version && <span className="muted small">v{fw.live.version}</span>}
                  <span style={{ marginLeft: "auto" }}><Dot status={fw.status} /></span>
                </div>
              ))}
              {s.assets.length > 0 && (
                <div className="row wrap" style={{ gap: 7, marginBottom: 12, marginTop: s.firewalls.length ? 0 : 14 }}>
                  <Network size={15} className="muted" />
                  {s.assets.map((a) => (
                    <span key={a.id} className={`chip ${a.status === "down" ? "red" : ""}`} onClick={() => openAsset(a.id)}><TypeIcon type={a.type} size={13} />{a.name}</span>
                  ))}
                </div>
              )}
              <div className="chips">
                {s.checks_list.map((c) => (
                  <span key={c.id} className={`chip ${STATUS_CHIP[c.status] || ""}`} onClick={() => openCheck(c.id)}><Dot status={c.status} />{c.name} <span className="faint">{c.type}</span></span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      {edit && <SiteForm site={edit.id ? edit : null} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </>
  );
}
