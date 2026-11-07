import React, { useState } from "react";
import { Building2, Plus, Pencil, Trash2, Shield, Network } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Modal, Field, Input, Select, Dot, TypeIcon, timeAgo, useToast, Empty, confirmDelete, SiteHealth, InternetLine } from "../ui";

const KINDS = [["datacenter", "Datacenter / Trụ sở"], ["branch", "Chi nhánh"], ["office", "Văn phòng"], ["vps", "VPS"], ["cloud", "Cloud"]];
const STATUS_CHIP = { ok: "green", warn: "amber", fail: "red" };

export function SiteForm({ site, onClose, onSaved }) {
  const [f, setF] = useState(site || { kind: "branch", sort: 0 });
  const toast = useToast();
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const save = async () => {
    try {
      const r = site?.id ? await api.put(`/sites/${site.id}`, f) : await api.post("/sites", f);
      toast("Đã lưu site"); onSaved(r);
    } catch (e) { toast(e.message, true); }
  };
  return (
    <Modal title={site?.id ? `Sửa site ${site.name}` : "Thêm site"} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Huỷ</button><button className="btn primary" onClick={save}>Lưu</button></>}>
      <div className="form-grid">
        <Field label="Tên site *"><Input value={f.name} onChange={set("name")} placeholder="VD: Trụ sở HCM" /></Field>
        <Field label="Loại"><Select value={f.kind} onChange={set("kind")} options={KINDS} /></Field>
        <Field label="Địa điểm" full><Input value={f.location} onChange={set("location")} /></Field>
        <Field label="WAN"><Input value={f.wan} onChange={set("wan")} placeholder="IP tĩnh FPT, IP động..." /></Field>
        <Field label="VPN"><Input value={f.vpn} onChange={set("vpn")} placeholder="IPsec về HQ, OpenVPN..." /></Field>
        <Field label="Thứ tự hiển thị"><Input type="number" value={f.sort} onChange={(v) => set("sort")(Number(v))} /></Field>
        <Field label="Ghi chú" full><textarea className="input" value={f.description || ""} onChange={(e) => set("description")(e.target.value)} /></Field>
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
    await api.del(`/sites/${s.id}`); toast("Đã xoá site"); reload();
  };
  return (
    <>
      <PageHead crumb="Hạ tầng › Sites" title="Sites" desc="Mỗi site gom các nguồn có cùng trường “Site”: firewall, host, máy ảo, thiết bị, check giám sát.">
        {isAdmin && <button className="btn primary" onClick={() => setEdit({})}><Plus size={15} />Thêm site</button>}
      </PageHead>
      {data && data.length === 0 && <div className="card"><Empty icon={Building2} title="Chưa có site nào">Tạo site đầu tiên (trụ sở, chi nhánh, VPS...) rồi gắn thiết bị vào.</Empty></div>}
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
                <div>Hạ tầng</div><div>{s.stats.hosts} host · {s.stats.vms_on}/{s.stats.vms} VM đang chạy · {s.stats.devices} thiết bị · {s.stats.checks} check</div>
                <div>Cập nhật lần cuối</div><div>{timeAgo(s.last_sync)}</div>
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
