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
      toast("Đã lưu tài sản"); onSaved(r);
    } catch (e) { toast(e.message, true); }
  };
  const parents = (assets.data || []).filter((a) => a.id !== asset?.id && !["container"].includes(a.type));
  return (
    <Modal title={asset?.id ? `Sửa ${asset.name}` : "Thêm tài sản"} onClose={onClose} width={760}
      footer={<><button className="btn" onClick={onClose}>Huỷ</button><button className="btn primary" onClick={save}>Lưu</button></>}>
      <div className="form-grid">
        <Field label="Tên *"><Input value={f.name} onChange={set("name")} placeholder="VD: SW-CORE, DC01" /></Field>
        <Field label="Loại"><Select value={f.type} onChange={set("type")} options={TYPE_OPTIONS} /></Field>
        <Field label="Site"><Select value={f.site_id} onChange={set("site_id")} placeholder="— Chưa gán —" options={(sites.data || []).map((s) => [s.id, s.name])} /></Field>
        <Field label="Nằm sau / chạy trên" hint="VM → host; host → switch; switch → firewall. Dùng để vẽ bản đồ.">
          <Select value={f.parent_id} onChange={set("parent_id")} placeholder="— Không —" options={parents.map((a) => [a.id, `${a.name} (${typeMeta(a.type).label})`])} />
        </Field>
        <Field label="IP / hostname"><Input value={f.ip} onChange={set("ip")} placeholder="10.0.0.1" /></Field>
        <Field label="Status thủ công" hint="Tự cập nhật nếu có check gắn vào"><Select value={f.status} onChange={set("status")} options={[["unknown", "Chưa rõ"], ["up", "Hoạt động"], ["warning", "Cảnh báo"], ["down", "Lỗi"], ["off", "Đã tắt"]]} /></Field>
        <Field label="Hãng"><Input value={f.vendor} onChange={set("vendor")} /></Field>
        <Field label="Model"><Input value={f.model} onChange={set("model")} /></Field>
        <Field label="Hệ điều hành / firmware"><Input value={f.os} onChange={set("os")} /></Field>
        <Field label="Serial / Service tag"><Input value={f.serial} onChange={set("serial")} /></Field>
        <Field label="Người phụ trách"><Input value={f.owner} onChange={set("owner")} /></Field>
        <Field label="Vị trí (rack, phòng...)"><Input value={f.location} onChange={set("location")} /></Field>
        <div className="section-title">Backup</div>
        <Field><Toggle checked={f.backup} onChange={set("backup")} label="Đã có backup" /></Field>
        <Field><Input value={f.backup_note} onChange={set("backup_note")} placeholder="Veeam job hằng đêm, Active Backup..." /></Field>
        <Field label="Ghi chú" full><textarea className="input" value={f.notes || ""} onChange={(e) => set("notes")(e.target.value)} /></Field>
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
    ["Uptime", m.uptime], ["Phiên bản", m.version], ["vCPU", m.vcpu], ["RAM cấp", m.mem_mb ? `${m.mem_mb} MB` : null],
    ["Cores", m.cores], ["RAM", m.mem_gb ? `${m.mem_gb} GB` : null], ["VMware Tools", m.tools], ["Snapshot", m.snapshots ? `${m.snapshots} (cũ nhất ${m.oldest_snapshot_days} ngày)` : null],
    ["Cổng", m.ports_total ? `${m.ports_up}/${m.ports_total} up` : null], ["Nhiệt độ", m.temp ? `${m.temp}°C` : null],
    ["Mô tả SNMP", m.sys_descr], ["MAC", m.mac], ["Ghi chú VM", m.annotation],
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
      {m.missing && <div className="alert-box warn" style={{ marginTop: 10 }}>Không còn thấy tài sản này ở nguồn đồng bộ — có thể đã bị xoá hoặc di chuyển.</div>}
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
  if (!a) return <Drawer title="Đang tải..." onClose={onClose} />;
  const guestKids = a.children.filter((c) => ["vm", "container"].includes(c.type));
  const otherKids = a.children.filter((c) => !["vm", "container"].includes(c.type));
  const remove = async () => {
    if (!(await confirmDelete(a.name))) return;
    await api.del(`/assets/${a.id}`); toast("Đã xoá"); refresh(); onClose();
  };
  return (
    <Drawer wide={guestKids.length > 0} onClose={onClose} title={<><TypeIcon type={a.type} size={18} />{a.name}</>}
      actions={isAdmin && <><button className="btn sm" onClick={() => setEdit(true)}><Pencil size={14} />Sửa</button><button className="btn sm danger" onClick={remove}><Trash2 size={14} /></button></>}>
      <div className="row wrap" style={{ marginBottom: 14 }}>
        <StatusBadge status={a.status} />
        <span className="badge outline">{typeMeta(a.type).label}</span>
        {a.backup ? <span className="badge ok"><Archive size={12} />Có backup</span> : ["vm", "host", "server", "nas"].includes(a.type) && <span className="badge warn"><Archive size={12} />Chưa backup</span>}
        {a.source !== "manual" && <span className="badge info">Tự đồng bộ</span>}
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
        <div>Hãng / Model</div><div>{[a.vendor, a.model].filter(Boolean).join(" ") || "—"}</div>
        <div>HĐH / firmware</div><div>{a.os || "—"}</div>
        {a.serial && <><div>Serial</div><div className="mono">{a.serial}</div></>}
        {a.owner && <><div>Phụ trách</div><div>{a.owner}</div></>}
        {a.location && <><div>Vị trí</div><div>{a.location}</div></>}
        {a.backup_note && <><div>Backup</div><div>{a.backup_note}</div></>}
        <div>Thấy lần cuối</div><div>{a.last_seen ? timeAgo(a.last_seen) : "—"}</div>
      </div>
      {a.notes && <div className="alert-box info" style={{ marginBottom: 18, whiteSpace: "pre-wrap" }}>{a.notes}</div>}

      {a.critical.length > 0 && <>
        <h4>Hệ thống trọng yếu chạy ở đây</h4>
        <div className="chips" style={{ marginBottom: 18 }}>{a.critical.map((c) => <span key={c.id} className="chip"><LevelBadge level={c.level} />{c.name}</span>)}</div>
      </>}

      <div className="row"><h4 className="grow">Giám sát ({a.checks.length})</h4>
        {isAdmin && <button className="btn sm" onClick={() => newCheck({ asset_id: a.id, site_id: a.site_id, target: a.ip, name: a.name, type: a.type === "firewall" ? "pfsense" : a.type === "host" ? (a.meta?.platform === "proxmox" ? "proxmox" : "esxi") : ["switch", "router", "ap", "ups", "nas"].includes(a.type) ? "snmp" : "ping" })}><Plus size={14} />Thêm check</button>}
      </div>
      {a.checks.length === 0 ? <div className="muted small" style={{ marginBottom: 18 }}>Chưa có check nào. Thêm Ping/SNMP/SSH để tự cập nhật status.</div> : (
        <div className="card" style={{ marginBottom: 18 }}>
          {a.checks.map((c) => (
            <div key={c.id} className="risk-item" onClick={() => openCheck(c.id)}>
              <Dot status={c.status} pulse />
              <div className="grow"><b>{c.name}</b> <span className="faint small">{c.type}</span><div className="small muted">{c.last_message || "Chưa chạy"}</div></div>
              <span className="small faint">{timeAgo(c.last_checked)}</span>
            </div>
          ))}
        </div>
      )}

      {guestKids.length > 0 && <GuestsPanel hostId={a.id} tick={tick} onOpen={setChildId} canEdit={isAdmin} />}

      {otherKids.length > 0 && <>
        <h4>Bên dưới ({otherKids.length})</h4>
        <div className="card" style={{ marginBottom: 18 }}>
          {otherKids.map((c) => (
            <div key={c.id} className="risk-item" onClick={() => setChildId(c.id)}>
              <TypeIcon type={c.type} />
              <div className="grow"><b>{c.name}</b><div className="small muted">{[c.ip, c.os].filter(Boolean).join(" · ")}</div></div>
              {!c.backup && c.type === "vm" && <span className="badge warn small">chưa backup</span>}
              <Dot status={c.status} />
            </div>
          ))}
        </div>
      </>}

      {a.events?.length > 0 && <>
        <div className="row"><h4 className="grow">Log gần đây</h4><button className="btn sm" onClick={() => { onClose(); go(`logs?asset_id=${a.id}`); }}>Xem tất cả</button></div>
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
        <h4>Cảnh báo gần đây</h4>
        {a.alerts.map((al) => (
          <div key={al.id} className="row small" style={{ padding: "6px 0", borderBottom: "1px solid #f1efec" }}>
            {al.status === "resolved" ? <span className="badge ok">Đã xử lý</span> : <SevBadge sev={al.severity} />}
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
  const title = types.length === 1 ? typeMeta(types[0]).label : { "switch,router,ap": "Thiết bị mạng", "host,server": "Host vật lý", "vm,container": "Máy ảo & container" }[type] || (type ? "Thiết bị khác" : "Tất cả tài sản");

  return (
    <>
      <PageHead crumb={`Hạ tầng › ${title}`} title={title} desc={types.includes("host") ? "Host vật lý và host ảo hoá (ESXi, Proxmox, Hyper-V, Docker). Thêm check ESXi / Proxmox / SSH để máy ảo tự hiện; bấm vào host để xem số lượng, cấp phát và hiệu năng từng máy ảo." : "Danh sách tài sản. Thêm thủ công hoặc để check ESXi / Proxmox / pfSense tự đồng bộ. Bấm vào một dòng để xem chi tiết."}>
        {isAdmin && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={15} />Thêm tài sản</button>}
      </PageHead>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "Tất cả", count: all.length },
        { key: "down", label: "Đang lỗi", count: all.filter((a) => a.status === "down").length },
        { key: "warn", label: "Cảnh báo", count: all.filter((a) => a.status === "warning").length },
        { key: "nobackup", label: "Chưa backup", count: all.filter((a) => !a.backup && ["vm", "host", "server", "nas"].includes(a.type)).length },
        { key: "nocheck", label: "Chưa giám sát", count: all.filter((a) => !a.checks.length).length },
      ]} />
      <div className="card">
        <div className="toolbar">
          <div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm tên, IP, model..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div style={{ width: 220 }}><Select value={siteF} onChange={setSiteF} placeholder="Tất cả site" options={(sites.data || []).map((s) => [String(s.id), s.name])} /></div>
          <span className="muted small" style={{ marginLeft: "auto" }}>{rows.length} mục</span>
        </div>
        <Table rows={rows} onRow={(a) => openAsset(a.id)} empty={<Empty title="Không có tài sản nào" />} columns={[
          { key: "idx", label: "STT", width: 50, sortable: false, render: (_, i) => <span className="muted">{i + 1}</span> },
          { key: "name", label: "Tên", render: (a) => <div><div className="cell-title"><TypeIcon type={a.type} />{a.name}{a.critical.length > 0 && <span className="badge fail" style={{ fontSize: 11 }}>★ {a.critical[0].level}</span>}</div><div className="cell-sub">{typeMeta(a.type).label}{a.source !== "manual" ? " · tự đồng bộ" : ""}</div></div> },
          { key: "site_id", label: "Site", sort: (a) => siteName[a.site_id] || "", render: (a) => siteName[a.site_id] || <span className="faint">—</span> },
          { key: "ip", label: "IP", render: (a) => <span className="mono">{a.ip || "—"}</span> },
          { key: "model", label: "Model / HĐH", render: (a) => <div className="small">{[a.vendor, a.model].filter(Boolean).join(" ")}<div className="muted">{a.os}</div></div> },
          { key: "parent_id", label: "Chạy trên", sort: (a) => byId[a.parent_id]?.name || a.parent_name || "", render: (a) => a.parent_id ? <span className="small">{byId[a.parent_id]?.name || a.parent_name || `#${a.parent_id}`}</span> : <span className="faint">—</span> },
          ...(types.some((t) => ["host", "server", "vm"].includes(t)) || !type ? [{ key: "guests", label: "Máy ảo / container", sort: (a) => a.guests?.total || 0,
            render: (a) => a.guests ? <span className="small"><b>{a.guests.running}</b>/{a.guests.total} <span className="muted">đang chạy</span></span>
              : ["host", "server"].includes(a.type) && !a.checks.some((c) => ["esxi", "proxmox"].includes(c.type) || (c.type === "ssh"))
                ? <span className="small faint" title="Thêm check ESXi / Proxmox (hoặc SSH + Hyper-V / Docker) để thấy máy ảo">chưa đọc máy ảo</span>
                : <span className="faint">—</span> }] : []),
          { key: "status", label: "Status", render: (a) => <StatusBadge status={a.status} /> },
          { key: "backup", label: "Backup", render: (a) => a.backup ? <span className="badge ok">Có</span> : ["vm", "host", "server", "nas"].includes(a.type) ? <span className="badge warn">Chưa</span> : <span className="faint">—</span> },
          { key: "checks", label: "Check", sort: (a) => a.checks.length, render: (a) => a.checks.length ? <span className="row" style={{ gap: 4 }}>{a.checks.map((c) => <Dot key={c.id} status={c.status} />)}</span> : <span className="faint small">chưa canh</span> },
        ]} />
      </div>
      {adding && <AssetForm preset={types.length === 1 ? { type: types[0] } : {}} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}
    </>
  );
}
