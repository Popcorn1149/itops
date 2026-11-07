import React, { useMemo, useState } from "react";
import { Cpu, MemoryStick, HardDrive, Search, Plus, Activity, Info, Gauge } from "lucide-react";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Table, Tabs, Drawer, Empty, UsageBar, TypeIcon, typeMeta, timeAgo, Select, Dot } from "../ui";
import { ResourcePanel, ResourceChart, fmtGb } from "../components/Resources";

const VIA = { snmp: "SNMP", ssh: "SSH", esxi: "ESXi", proxmox: "Proxmox", pfsense: "pfSense API" };
const SORTS = [["level", "Mức độ nghiêm trọng"], ["cpu", "CPU cao nhất"], ["mem", "RAM cao nhất"], ["disk", "Disk đầy nhất"], ["name", "Tên A→Z"]];

// cách giám sát gợi ý cho thiết bị chưa có số liệu
export function suggestCheck(a) {
  const win = /windows/i.test(a.os || "");
  if (a.type === "host") return a.meta?.platform === "proxmox" ? { type: "proxmox", hint: "Proxmox VE" } : { type: "esxi", hint: "ESXi/vCenter" };
  if (a.type === "server" || a.type === "vm") return { type: "ssh", hint: win ? "SSH (Windows)" : "SSH (Linux)", config: win ? { platform: "windows" } : {} };
  return { type: "snmp", hint: "SNMP" };
}

function ThresholdTable({ t }) {
  const f = (v) => (v == null ? <span className="faint">tắt</span> : `${v}%`);
  return (
    <div className="card" style={{ marginBottom: 12, overflowX: "auto" }}>
      <table className="tbl small"><thead><tr><th style={{ padding: "6px 10px" }}>Threshold</th>
        <th style={{ padding: "6px 10px", color: "#a16207" }}>Attention</th><th style={{ padding: "6px 10px", color: "#c2410c" }}>Trouble</th>
        <th style={{ padding: "6px 10px", color: "#b91c1c" }}>Critical</th><th style={{ padding: "6px 10px", color: "#15803d" }}>Rearm (đóng khi &lt;)</th></tr></thead>
        <tbody>{[["cpu", "CPU"], ["mem", "RAM"], ["disk", "Disk"]].map(([k, l]) => <tr key={k}><td style={{ padding: "5px 10px" }}><b>{l}</b></td>
          {["attention", "trouble", "critical", "rearm"].map((x) => <td key={x} style={{ padding: "5px 10px" }}>{f(t[`${k}_${x}`])}</td>)}</tr>)}</tbody></table>
      <div className="small faint" style={{ padding: "6px 10px" }}>Sửa trong check (“Mở check & sửa threshold”). Vượt threshold không tính là DOWN và không trừ uptime.</div>
    </div>
  );
}

function Detail({ row, onClose }) {
  const { openCheck, openAsset } = useApp();
  return (
    <Drawer title={<><TypeIcon type={row.type} />{row.name}</>} onClose={onClose}>
      <div className="small muted" style={{ marginBottom: 14 }}>
        {[typeMeta(row.type).label, row.site_name, row.ip].filter(Boolean).join(" · ")}
        {row.via && <> · lấy qua <b>{VIA[row.via] || row.via}</b>{row.check_name ? ` (${row.check_name})` : ""}</>}
        {row.ts && <> · cập nhật {timeAgo(row.ts)}</>}
      </div>
      {row.stale && <div className="alert-box warn" style={{ marginBottom: 12 }}>Số liệu đã cũ – check không chạy được hoặc đang lỗi. Mở check để kiểm tra.</div>}
      <div className="card card-pad" style={{ marginBottom: 14 }}><ResourcePanel res={row} thresholds={row.thresholds} /></div>
      {row.has_history
        ? <div className="card card-pad" style={{ marginBottom: 14 }}><ResourceChart checkId={row.check_id} thresholds={row.thresholds} current={row} /></div>
        : <div className="alert-box info" style={{ marginBottom: 14 }}><Info size={14} style={{ verticalAlign: -2 }} /> Số liệu của máy ảo này lấy từ ESXi (cần VMware Tools) nên chỉ có giá trị hiện tại. Muốn xem lịch sử và cảnh báo riêng cho VM, thêm check SSH/SNMP vào chính VM.</div>}
      <ThresholdTable t={row.thresholds} />
      <div className="row wrap" style={{ gap: 8 }}>
        {row.check_id && <button className="btn" onClick={() => { onClose(); openCheck(row.check_id); }}><Activity size={14} />Mở check & sửa threshold</button>}
        {row.asset_id && <button className="btn" onClick={() => { onClose(); openAsset(row.asset_id); }}>Xem tài sản</button>}
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
      <PageHead crumb="Vận hành › Tài nguyên" title="Tài nguyên CPU / RAM / Disk"
        desc="Gom số liệu từ SNMP, SSH (Linux/Windows/pfSense), ESXi, pfSense API. Vượt threshold → cảnh báo Attention / Trouble / Critical, tự đóng khi xuống dưới Rearm. Không tính là DOWN." />
      <div className="stats">
        <Stat icon={Gauge} label="Thiết bị có số liệu" value={data.total} sub={data.uncovered.length ? `${data.uncovered.length} thiết bị chưa có số liệu` : "đã phủ toàn bộ"} tone={data.uncovered.length ? "" : "good"} onClick={() => document.getElementById("res-uncovered")?.scrollIntoView({ behavior: "smooth" })} />
        <Stat icon={Cpu} label="CPU cao" value={n("cpu")} sub={sub("cpu")} tone={n("cpu") ? "bad" : "good"} onClick={() => setTab("cpu")} />
        <Stat icon={MemoryStick} label="RAM cao" value={n("mem")} sub={sub("mem")} tone={n("mem") ? "bad" : "good"} onClick={() => setTab("mem")} />
        <Stat icon={HardDrive} label="Disk gần đầy" value={n("disk")} sub={sub("disk")} tone={n("disk") ? "bad" : "good"} onClick={() => setTab("disk")} />
      </div>

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "all", label: "Tất cả", count: data.total },
        { key: "problems", label: "Có vấn đề", count: data.problems },
        { key: "cpu", label: "CPU", count: n("cpu") },
        { key: "mem", label: "RAM", count: n("mem") },
        { key: "disk", label: "Disk", count: n("disk") },
        ...(data.stale ? [{ key: "stale", label: "Số liệu cũ", count: data.stale }] : []),
      ]} />
      <div className="card">
        <div className="toolbar row wrap" style={{ gap: 10 }}>
          <div className="search" style={{ width: 260, maxWidth: "100%" }}><Search size={16} /><input placeholder="Tìm thiết bị, IP, ổ đĩa..." value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div style={{ width: 190 }}><Select value={site} onChange={setSite} placeholder="Tất cả site" options={(sites.data || []).map((s) => [s.id, s.name])} /></div>
          <div style={{ width: 200 }}><Select value={sort} onChange={setSort} options={SORTS} /></div>
        </div>
        <Table rows={rows} rowKey="_k" onRow={setSel}
          empty={<Empty icon={Gauge} title={data.total ? "Không có thiết bị nào khớp bộ lọc" : "Chưa có số liệu tài nguyên"}>
            {data.total ? "Thử bỏ bộ lọc." : "Thêm check SNMP / SSH / ESXi / pfSense cho thiết bị – số liệu CPU/RAM/Disk sẽ tự hiện ở đây."}</Empty>}
          columns={[
            { key: "level", label: "", width: 30, render: (r) => <Dot status={r.stale ? "unknown" : r.level === "ok" ? "ok" : r.level} /> },
            { key: "name", label: "Thiết bị", render: (r) => (
              <div className="res-row-name"><TypeIcon type={r.type} size={15} />
                <div style={{ minWidth: 0 }}>
                  <div className="cell-title">{r.name}{r.stale && <span className="res-stale" style={{ marginLeft: 6 }}>cũ</span>}</div>
                  <div className="cell-sub">{[r.site_name, VIA[r.via] || r.via].filter(Boolean).join(" · ")}</div>
                </div>
              </div>) },
            { key: "cpu", label: "CPU", sort: (r) => r.cpu ?? -1, render: (r) => <UsageBar pct={r.cpu} level={r.levels.cpu} width={90} /> },
            { key: "mem", label: "RAM", sort: (r) => r.mem ?? -1, render: (r) => <UsageBar pct={r.mem} level={r.levels.mem} width={90} sub={r.mem_total_gb ? fmtGb(r.mem_total_gb) : null} /> },
            { key: "disk", label: "Disk", sort: (r) => r.disk ?? -1, render: (r) => <UsageBar pct={r.disk} level={r.levels.disk} width={90} sub={r.disks?.length > 1 ? r.disk_name : null} /> },
            { key: "ts", label: "Cập nhật", sort: (r) => r.age_s ?? 1e9, render: (r) => <span className="small muted">{timeAgo(r.ts)}</span> },
          ]} />
      </div>

      <div className="card" id="res-uncovered" style={{ marginTop: 16 }}>
        <div className="card-head"><Info size={17} /><h3>Chưa có số liệu CPU/RAM/Disk</h3><span className="muted small" style={{ marginLeft: "auto" }}>{data.uncovered.length} thiết bị</span></div>
        {data.uncovered.length === 0
          ? <div className="card-pad small muted">Mọi firewall, switch, host, server, NAS và VM đang chạy đều đã có số liệu. 👍</div>
          : <>
            <div className="card-pad small muted" style={{ paddingBottom: 6 }}>
              Switch/firewall/NAS/UPS: bật SNMP trên thiết bị rồi thêm check <b>SNMP</b>. Máy Linux/Windows: thêm check <b>SSH</b> (Windows cần OpenSSH Server). ESXi: thêm check <b>ESXi</b> – VM sẽ có số liệu nếu cài VMware Tools.
              Thiết bị chỉ có ping/HTTP sẽ không có CPU/RAM/Disk.
            </div>
            {data.uncovered.map((a) => {
              const s = suggestCheck(a);
              return (
                <div key={a.id} className="risk-item" style={{ cursor: "default" }}>
                  <TypeIcon type={a.type} size={15} />
                  <div className="grow"><div style={{ fontWeight: 600 }}>{a.name}</div><div className="small muted">{[typeMeta(a.type).label, a.site_name, a.ip].filter(Boolean).join(" · ")}</div></div>
                  {isAdmin && <button className="btn sm" onClick={() => add(a)}><Plus size={13} />Thêm {s.hint}</button>}
                </div>
              );
            })}
          </>}
      </div>
      {sel && <Detail row={sel} onClose={() => setSel(null)} />}
    </>
  );
}
