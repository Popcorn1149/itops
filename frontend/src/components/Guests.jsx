import React, { useMemo, useState } from "react";
import { api } from "../api";
import { Boxes, Cpu, MemoryStick, Flame, Search, KeyRound, CheckCircle2, AlertTriangle } from "lucide-react";
import { useApi, Table, TypeIcon, Dot, Tabs, useToast } from "../ui";

// Máy ảo / container chạy trên một host ảo hoá (ESXi, Proxmox, Hyper-V, Docker)
const lvl = (v, warn, crit) => (v == null ? undefined : v >= crit ? "fail" : v >= warn ? "warn" : undefined);
const ratioLvl = (r) => (r == null ? "" : r > 4 ? "fail" : r > 2 ? "warn" : "");
const fmtUp = (s) => (!s ? "—" : s >= 86400 ? `${Math.floor(s / 86400)} ngày` : s >= 3600 ? `${Math.floor(s / 3600)} giờ` : `${Math.floor(s / 60)} phút`);

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

// đánh giá mức chia (cấp phát) – không phải mức đang dùng
const cpuVerdict = (r) => (r == null ? null : r > 4 ? ["Chia quá nhiều", "critical"] : r > 2 ? ["Nên theo dõi", "trouble"] : ["An toàn", ""]);
const memVerdict = (r) => (r == null ? null : r > 1.2 ? ["Vượt RAM host", "critical"] : r > 1 ? ["Sát giới hạn", "trouble"] : ["An toàn", ""]);
const pct = (v) => (v == null ? "—" : `${Math.round(v * 10) / 10}%`);
const num = (v, d = 1) => (v == null ? "—" : Number(v.toFixed(d)).toLocaleString("vi-VN"));

// "đang dùng / được cấp" + thanh nhỏ, ví dụ 1 / 8 GB
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

// Ô nhập tài khoản ESXi chỉ đọc ngay trong khối máy ảo: lưu vào check SNMP hiện có rồi chạy lại → có CPU/RAM/Disk từng VM
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
      if (!user) { toast("Đã bỏ tài khoản ESXi"); setU(""); }
      else if (r.perf?.ok) { toast(r.perf.note); setOpen(false); }
      else toast(r.perf?.note || r.result?.message || "Chưa lấy được số liệu, thử lại sau ít phút", true);
      onDone?.();
    } catch (err) { toast(err.message, true); } finally { setBusy(false); }
  };
  const submit = (e) => { e?.preventDefault(); if (u) send(u, p); };
  if (!show) return (
    <div className="small faint row" style={{ marginBottom: 8, gap: 6 }}>
      <CheckCircle2 size={14} color="var(--ok)" />CPU/RAM/Disk VM đọc qua API ESXi ({perf.user}).
      {canEdit && <button className="btn ghost sm" onClick={() => setOpen(true)}>Đổi tài khoản</button>}
    </div>
  );
  return (
    <form className="card card-pad" style={{ marginBottom: 10, padding: "10px 12px" }} onSubmit={submit}>
      <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <KeyRound size={16} />
        <b className="small">Lấy CPU/RAM/Disk từng VM</b>
        {perf.ok === false && <span className="small row" style={{ color: "var(--fail)", gap: 4 }}><AlertTriangle size={13} />{perf.note}</span>}
      </div>
      {canEdit ? (
        <div className="row" style={{ gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <input className="input" style={{ width: 200 }} placeholder="User ESXi (Read-only)" value={u} onChange={(e) => setU(e.target.value)} autoComplete="off" />
          <input className="input" style={{ width: 200 }} type="password" placeholder={perf.has_credentials ? "Mật khẩu (để trống = giữ)" : "Mật khẩu"} value={p}
            onChange={(e) => setP(e.target.value)} autoComplete="new-password" />
          <button className="btn primary sm" disabled={busy || !u}>{busy ? "Đang đọc…" : "Lấy số liệu"}</button>
          {perf.has_credentials && <button type="button" className="btn ghost sm" disabled={busy} onClick={() => send("", "")}>Bỏ tài khoản</button>}
          <span className="small faint grow" style={{ minWidth: 220 }}>Dùng user có role Read-only trên ESXi. Lưu (mã hoá) vào check {perf.check_name}, không tạo check mới.</span>
        </div>
      ) : <div className="small muted" style={{ marginTop: 6 }}>Cần quản trị viên nhập tài khoản ESXi chỉ đọc cho host này.</div>}
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
        <h4 className="grow" style={{ margin: 0 }}>Máy ảo & container trên host</h4>
        {data.platforms.map((p) => <span key={p} className="badge outline">{p}</span>)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, marginBottom: 10 }}>
        <Tile icon={Boxes} label="Số máy" value={`${s.running}/${s.total}`} unit="đang chạy"
          sub2={`${s.vms} VM${s.containers ? ` · ${s.containers} container` : ""}${s.stopped ? ` · ${s.stopped} đã tắt` : ""}`} />
        {(() => { const v = cpuVerdict(s.vcpu_ratio); return (
          <Tile icon={Cpu} label="CPU đã chia cho VM" value={`${s.vcpu_alloc} vCPU`} unit={h.cores ? `/ ${h.cores} ${h.cpu_unit || "CPU"}` : ""}
            sub={v ? `${v[0]} · ${s.vcpu_ratio} vCPU / ${h.cpu_unit || "CPU"}` : "chưa biết số CPU của host"} tone={v?.[1]}
            sub2={`Host đang dùng thật: ${pct(h.cpu)}`}
            title={"Tổng vCPU cấp cho các máy đang chạy, so với CPU của host. Đây là mức ĐÃ CHIA, không phải mức đang dùng.\nCPU được chia chung theo thời gian nên chia vượt là bình thường: ≤ 2:1 an toàn, 2–4:1 nên theo dõi, > 4:1 dễ chậm."} />); })()}
        {(() => { const v = memVerdict(s.mem_ratio); return (
          <Tile icon={MemoryStick} label="RAM đã chia cho VM" value={`${s.mem_alloc_gb} GB`} unit={h.mem_gb ? `/ ${h.mem_gb} GB` : ""}
            sub={v ? `${v[0]} · ${Math.round((s.mem_ratio || 0) * 100)}% RAM host` : "chưa biết RAM của host"} tone={v?.[1]}
            sub2={`Host đang dùng thật: ${pct(h.mem)}`}
            title={"Tổng RAM cấp cho các máy đang chạy, so với RAM thật của host. Khác CPU, RAM không nên chia vượt 100%: thiếu RAM làm mọi VM chậm."} />); })()}
        <Tile icon={Flame} label="VM quá tải" value={s.allocation_only ? "—" : s.hot}
          sub={s.allocation_only ? "Chưa có số liệu sử dụng" : s.hot ? "Xem tab Quá tải" : "Không có"} tone={s.allocation_only ? "trouble" : s.hot ? "critical" : ""}
          sub2="CPU ≥ 90%, RAM ≥ 95% hoặc disk ≥ 90% bên trong VM"
          title="Số máy đang dùng gần hết tài nguyên – đo bên trong từng VM." />
      </div>
      {data.perf && <EsxiPerf hostId={hostId} perf={data.perf} need={s.allocation_only} canEdit={canEdit} onDone={() => setBump((x) => x + 1)} />}
      <div className="card">
        <div className="toolbar" style={{ flexWrap: "wrap" }}>
          <Tabs value={tab} onChange={setTab} tabs={[
            { key: "all", label: "Tất cả", count: s.total }, { key: "on", label: "Đang chạy", count: s.running }, { key: "off", label: "Đã tắt", count: s.stopped },
            ...(s.allocation_only ? [] : [{ key: "hot", label: "Quá tải", count: s.hot }]),
          ]} />
          <div className="search" style={{ width: 200, marginLeft: "auto" }}><Search size={15} /><input placeholder="Tìm tên, IP..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
        </div>
        <Table rows={rows} onRow={(r) => onOpen?.(r.id)} empty={<div className="muted small" style={{ padding: 12 }}>Không có máy nào.</div>} columns={[
          { key: "name", label: "Tên", render: (r) => <div><div className="cell-title"><Dot status={r.running ? r.status : "off"} /><TypeIcon type={r.type} />{r.name}
            <span className="badge outline" style={{ fontSize: 10.5 }}>{r.kind_label}</span>{r.missing && <span className="badge warn" style={{ fontSize: 10.5 }}>không còn thấy</span>}</div>
            <div className="cell-sub">{[r.ips?.[0] || r.ip, r.os].filter(Boolean).join(" · ") || "—"}</div></div> },
          { key: "running", label: "Status", sort: (r) => (r.running ? 1 : 0), render: (r) => r.running
            ? <div className="small"><span className="badge ok">Đang chạy</span>{r.uptime_s ? <div className="faint">up {fmtUp(r.uptime_s)}</div> : null}</div>
            : <span className="badge">Đã tắt</span> },
          { key: "cpu", label: "CPU (dùng / cấp)", sort: (r) => r.cpu ?? -1, render: (r) => <UseCell used={r.cpu_used} total={r.cpu_total} unit="vCPU" pct={r.cpu} warn={80} crit={90} digits={2} /> },
          { key: "mem", label: "RAM (dùng / cấp)", sort: (r) => r.mem ?? -1, render: (r) => <UseCell used={r.mem_used_gb} total={r.mem_total_gb} unit="GB" pct={r.mem} warn={85} crit={95} /> },
          { key: "disk", label: "Disk (dùng / tổng)", sort: (r) => r.disk ?? -1, render: (r) => <UseCell used={r.disk_used_gb} total={r.disk_total_gb} unit="GB" pct={r.disk} warn={80} crit={90} /> },
        ]} />
      </div>
      <div className="small faint" style={{ marginTop: 6 }}>
        "Đã chia cho VM" là phần tài nguyên cấp phát, không phải đang dùng: chia CPU vượt số CPU host là bình thường (tới 4:1), RAM thì không nên vượt 100%.
        Cột CPU/RAM/Disk là mức dùng thật bên trong từng máy (ESXi API: CPU/RAM luôn có, disk và IP cần VMware Tools; Proxmox cần QEMU guest agent cho disk và IP).
      </div>
    </div>
  );
}
