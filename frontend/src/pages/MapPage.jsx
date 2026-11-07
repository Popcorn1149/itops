import React, { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";
import { useUi, chartColors } from "../theme";
import {
  RefreshCw, List, Orbit, GitBranch, Workflow, AlertTriangle, Maximize2, Minimize2, Download, ChevronsUpDown,
  ChevronsDownUp, Monitor, Container, Crosshair,
} from "lucide-react";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Tabs, Empty, typeMeta, useToast, useIsMobile, DEMO } from "../ui";
import { SourcesStrip } from "./Dashboard";
import { ShieldCheck, Archive, Bell, Unlink } from "lucide-react";

// Escape mọi dữ liệu đưa vào tooltip (ECharts render tooltip bằng innerHTML) – tên VM/hostname DHCP có thể do người khác đặt
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STATUS_COLOR = { up: "#16a34a", ok: "#16a34a", warning: "#d97706", warn: "#d97706", down: "#dc2626", fail: "#dc2626", off: "#d6d3d1", unknown: "#a8a29e" };
const SIZE = { internet: 26, site: 20, firewall: 17, host: 15, switch: 14, router: 14, server: 14, nas: 12, vm: 10, container: 8 };

function toTree(n, opts, depth = 0, radial = false, T = chartColors()) {
  const color = STATUS_COLOR[n.status] || STATUS_COLOR.unknown;
  const meta = typeMeta(n.type);
  const isHub = n.type === "internet" || n.type === "site";
  let collapsed = false;
  if (opts.collapseVM && n.type === "host") collapsed = true;
  if (opts.collapseCtr && ["vm", "server"].includes(n.type) && n.children.some((c) => c.type === "container")) collapsed = true;
  if (opts.collapseAll && depth >= 2) collapsed = true;
  const badge = n.critical ? ` ★` : "";
  return {
    name: n.name + badge,
    value: n.sub || "",
    raw: n,
    collapsed,
    symbolSize: SIZE[n.type] || 11,
    symbol: n.type === "site" ? "roundRect" : n.type === "internet" ? "circle" : n.type === "firewall" ? "diamond" : "circle",
    itemStyle: {
      color: isHub ? T.panel : color,
      borderColor: isHub ? (n.worst === "fail" ? "#dc2626" : n.worst === "warn" ? "#d97706" : T.accent) : n.critical === "High" ? T.text : T.panel,
      borderWidth: isHub ? 3 : n.critical ? 2.5 : 1.5,
      shadowBlur: n.status === "down" ? 10 : 0, shadowColor: "#dc2626",
    },
    label: {
      formatter: (p) => `{n|${p.name}}${p.value ? `\n{s|${p.value}}` : ""}`,
      rich: {
        n: { fontSize: isHub ? 13 : 11.5, fontWeight: isHub || n.type === "firewall" ? 700 : 500, color: n.status === "down" ? T.failInk : T.text },
        s: { fontSize: 10, color: T.muted, lineHeight: 14 },
      },
      ...(radial && isHub ? { rotate: 0, position: "bottom", distance: 4, backgroundColor: T.dark ? "rgba(34,34,38,.92)" : "rgba(255,255,255,.92)", padding: [2, 6], borderRadius: 4 } : {}),
    },
    tooltipType: meta.label,
    children: n.children.map((c) => toTree(c, opts, depth + 1, radial, T)),
  };
}

function TreeChart({ tree, layout, opts, onPick, chartRef, mobile }) {
  const { theme } = useUi();
  const el = useRef();
  useEffect(() => {
    const c = echarts.init(el.current, null, { renderer: "canvas" });
    chartRef.current = c;
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(el.current);
    c.on("click", (p) => { if (p.data?.raw?.asset_id && p.event?.event?.altKey !== true) onPick(p.data.raw); });
    return () => { ro.disconnect(); c.dispose(); };
  }, []);
  useEffect(() => {
    const radial = layout === "radial";
    const T = chartColors();
    const data = toTree(tree, opts, 0, radial, T);
    chartRef.current.setOption({
      tooltip: {
        ...T.tooltip, trigger: "item", confine: true,
        formatter: (p) => {
          const r = p.data.raw || {};
          return `<b>${esc(r.name)}</b><br/>${esc(p.data.tooltipType)}${r.model ? " · " + esc(r.model) : ""}${r.ip ? "<br/>" + esc(r.ip) : ""}` +
            `<br/>Status: <b style="color:${STATUS_COLOR[r.status] || T.muted}">${esc(r.status)}</b>${r.critical ? `<br/>Trọng yếu: ${esc(r.critical)}` : ""}` +
            (r.count > 1 ? `<br/><span style="color:${T.muted}">${r.count - 1} mục bên dưới</span>` : "");
        },
      },
      series: [{
        type: "tree", data: [data], layout: radial ? "radial" : "orthogonal", orient: "LR",
        top: radial ? "6%" : "3%", bottom: radial ? "6%" : "3%", left: radial ? "6%" : mobile ? "20%" : "8%", right: radial ? "6%" : mobile ? "24%" : "16%",
        roam: true, scaleLimit: { min: 0.3, max: 4 }, initialTreeDepth: -1, expandAndCollapse: true,
        animationDuration: 400, animationDurationUpdate: 500,
        lineStyle: { color: T.edge, width: 1.2, curveness: radial ? 0.5 : 0.5 },
        label: radial ? { position: "right", distance: 6 } : { position: "left", verticalAlign: "middle", align: "right", distance: 8 },
        leaves: { label: radial ? { position: "right" } : { position: "right", verticalAlign: "middle", align: "left" } },
        emphasis: { focus: "descendant" },
      }],
    }, true);
  }, [tree, layout, opts, mobile, theme]);
  return <div ref={el} style={{ position: "absolute", inset: 0 }} />;
}

function FlowChart({ flow, onPick, chartRef }) {
  const { theme } = useUi();
  const el = useRef();
  useEffect(() => {
    const c = echarts.init(el.current);
    chartRef.current = c;
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(el.current);
    c.on("click", (p) => p.dataType === "node" && p.data.asset_id && onPick({ asset_id: p.data.asset_id }));
    return () => { ro.disconnect(); c.dispose(); };
  }, []);
  useEffect(() => {
    const T = chartColors();
    const nodes = flow.nodes.map((n) => {
      const color = STATUS_COLOR[n.status] || "#a8a29e";
      const crit = n.kind === "critical";
      return {
        id: n.id, name: n.name, asset_id: n.asset_id, category: crit ? 0 : 1,
        symbol: crit ? "roundRect" : "circle", symbolSize: crit ? [Math.max(70, n.name.length * 7.5), 26] : (SIZE[n.type] || 12) + 6,
        itemStyle: crit ? { color: T.panel, borderColor: n.level === "High" ? "#dc2626" : n.level === "Medium" ? "#d97706" : "#a8a29e", borderWidth: 2 } : { color },
        label: crit ? { show: true, position: "inside", color: T.text, fontWeight: 600, fontSize: 11 } : { show: true, position: "right", fontSize: 11, color: T.text2 },
        tip: crit ? `Hệ thống trọng yếu · ${esc(n.level)}<br/>${esc(n.layer)}` : esc(typeMeta(n.type).label),
      };
    });
    const edges = flow.edges.map((e) => ({
      source: e.source, target: e.target, label: { show: true, formatter: e.label, fontSize: 9.5, color: T.faint },
      lineStyle: { color: e.label === "phụ thuộc" ? T.accent : T.edge, type: e.label === "phụ thuộc" ? "dashed" : "solid", width: 1.4, curveness: 0.1 },
    }));
    chartRef.current.setOption({
      tooltip: { ...T.tooltip, formatter: (p) => (p.dataType === "node" ? `<b>${esc(p.data.name)}</b><br/>${p.data.tip}` : esc(p.data.label?.formatter)) },
      series: [{
        type: "graph", layout: "force", roam: true, zoom: 0.85, draggable: true, data: nodes, links: edges,
        categories: [{ name: "Hệ thống trọng yếu" }, { name: "Hạ tầng" }],
        force: { repulsion: 420, edgeLength: [70, 140], gravity: 0.08 },
        edgeSymbol: ["none", "arrow"], edgeSymbolSize: 7, emphasis: { focus: "adjacency" },
      }],
    }, true);
  }, [flow, theme]);
  return <div ref={el} style={{ position: "absolute", inset: 0 }} />;
}

export function RiskList({ risks }) {
  const { nav, openAsset, openCheck } = useApp();
  if (!risks.length) return <Empty icon={ShieldCheck} title="Không phát hiện điểm rủi ro nào" />;
  const go = (l) => { if (!l) return; if (l.page === "asset") openAsset(l.id); else if (l.page === "check") openCheck(l.id); else nav(l.page); };
  return risks.map((r, i) => (
    <div key={i} className="risk-item" onClick={() => go(r.link)}>
      <div className={`sev ${r.severity}`} />
      <div className="grow">
        <div className="row"><span className={`badge ${r.severity === "high" ? "fail" : r.severity === "medium" ? "warn" : ""}`}>{r.kind}</span><b>{r.title}</b></div>
        <div className="small muted" style={{ marginTop: 4 }}>{r.detail}</div>
      </div>
    </div>
  ));
}

export default function MapPage() {
  const { openAsset, nav, tick } = useApp();
  const toast = useToast();
  const topo = useApi("/topology", { interval: 60000, deps: [tick] });
  const dash = useApi("/dashboard", { interval: 60000, deps: [tick] });
  const risks = useApi("/risks", { interval: 60000, deps: [tick] });
  const mobile = useIsMobile();
  const [view, setView] = useState(mobile ? "tree" : "radial");
  const [opts, setOpts] = useState({ collapseVM: false, collapseCtr: true, collapseAll: false });
  const [full, setFull] = useState(false);
  const chartRef = useRef();

  const reloadAll = () => { topo.reload(); dash.reload(); risks.reload(); toast("Đã làm mới bản đồ"); };
  const exportImg = () => {
    if (!chartRef.current) return;
    const url = chartRef.current.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: chartColors().panel });
    const a = document.createElement("a"); a.href = url; a.download = `ban-do-he-thong-${new Date().toISOString().slice(0, 10)}.png`; a.click();
  };
  const fit = () => chartRef.current?.dispatchAction({ type: "restore" });
  const d = dash.data;
  const pick = (raw) => raw.asset_id && openAsset(raw.asset_id);
  const treeOpts = useMemo(() => opts, [opts]);

  return (
    <>
      <PageHead crumb="Hạ tầng › Bản đồ hệ thống" title="Bản đồ hệ thống"
        desc={<>Theo site: Internet → từng site → cửa ngõ (firewall) → mạng → máy chủ → VM → dịch vụ / container.<br />Theo luồng: các hệ thống trọng yếu nối với nhau ra sao.</>}>
        <button className="btn" onClick={reloadAll}><RefreshCw size={15} />Làm mới</button>
        <button className="btn" onClick={() => nav("assets")}><List size={15} />Danh sách</button>
      </PageHead>
      {d && (
        <div className="stats">
          <Stat icon={ShieldCheck} label="Hệ thống trọng yếu" value={d.critical_total} sub={`${d.critical_high} mức High · ${d.critical_total - d.critical_high} mức khác`} tone="bad" onClick={() => nav("critical")} />
          <Stat icon={Archive} label="Chưa backup" value={d.critical_no_backup} sub="chưa đánh dấu có backup" tone={d.critical_no_backup ? "bad" : "good"} onClick={() => nav("critical", null, { tab: "nobackup" })} />
          <Stat icon={Bell} label="Có cảnh báo" value={d.critical_alerting} sub="hệ thống trọng yếu đang có cảnh báo" tone={d.critical_alerting ? "bad" : "good"} onClick={() => nav("critical", null, { tab: "alerting" })} />
          <Stat icon={Unlink} label="Chưa ghép máy chủ" value={d.critical_unmapped} sub="chưa biết chạy trên VM nào" tone={d.critical_unmapped ? "bad" : "good"} onClick={() => nav("critical", null, { tab: "unmapped" })} />
        </div>
      )}
      {d && <SourcesStrip data={d} />}

      <div className="card">
        <div className="toolbar" style={{ flexWrap: "wrap" }}>
          <span className="live"><span className="dot fail pulse" />LIVE</span>
          <Tabs value={view} onChange={setView} tabs={[
            { key: "radial", label: mobile ? "Tỏa tròn" : "Mindmap tỏa tròn", icon: Orbit },
            { key: "tree", label: "Dạng cây", icon: GitBranch },
            { key: "flow", label: mobile ? "Theo luồng" : "Theo luồng hệ thống", icon: Workflow },
            { key: "risks", label: "Điểm rủi ro", icon: AlertTriangle, count: risks.data?.length ?? 0 },
          ]} />
          <span className="muted small hide-mobile" style={{ marginLeft: "auto" }}>tự tải lại mỗi phút</span>
          {!DEMO && <button className="btn sm" onClick={exportImg} disabled={view === "risks"}><Download size={14} /><span className="hide-mobile">Xuất ảnh</span></button>}
        </div>
        {(view === "radial" || view === "tree") && (
          <div className="toolbar" style={{ flexWrap: "wrap", gap: 8 }}>
            <button className={`btn sm`} onClick={() => setOpts({ collapseVM: false, collapseCtr: false, collapseAll: false })}><ChevronsUpDown size={14} />Mở hết</button>
            <button className={`btn sm hide-mobile ${opts.collapseAll ? "primary" : ""}`} onClick={() => setOpts({ ...opts, collapseAll: !opts.collapseAll })}><ChevronsDownUp size={14} />Chỉ tới site</button>
            <button className={`btn sm ${opts.collapseVM ? "primary" : ""}`} onClick={() => setOpts({ ...opts, collapseVM: !opts.collapseVM })}><Monitor size={14} />{mobile ? "Gọn VM" : "Thu gọn VM"}</button>
            <button className={`btn sm ${opts.collapseCtr ? "primary" : ""}`} onClick={() => setOpts({ ...opts, collapseCtr: !opts.collapseCtr })}><Container size={14} />{mobile ? "Gọn container" : "Thu gọn container"}</button>
            <div className="legend hide-mobile" style={{ marginLeft: 12 }}>
              <span><span className="dot ok" />Hoạt động</span><span><span className="dot warn" />Cảnh báo</span>
              <span><span className="dot fail" />Lỗi</span><span><span className="dot off" />Tắt / chưa rõ</span><span>★ Trọng yếu</span>
            </div>
            <button className="btn sm" style={{ marginLeft: "auto" }} onClick={fit}><Crosshair size={14} /><span className="hide-mobile">Vừa khung</span></button>
            <button className="icon-btn" onClick={() => setFull(true)} title="Toàn màn hình"><Maximize2 size={15} /></button>
          </div>
        )}
        {view === "risks" ? (
          <div>{risks.data && <RiskList risks={risks.data} />}</div>
        ) : (
          <div className={`map-wrap ${full ? "full" : ""}`}>
            {full && <button className="btn" style={{ position: "absolute", top: 14, right: 14, zIndex: 2 }} onClick={() => setFull(false)}><Minimize2 size={15} />Thoát</button>}
            {topo.data && (topo.data.tree.children.length === 0
              ? <Empty title="Bản đồ trống">Thêm site, tài sản hoặc check ESXi để tự vẽ bản đồ.</Empty>
              : view === "flow"
                ? (topo.data.flow.nodes.length ? <FlowChart key="flow" flow={topo.data.flow} onPick={pick} chartRef={chartRef} /> : <Empty title="Chưa có hệ thống trọng yếu">Khai báo ở mục Hệ thống trọng yếu để xem luồng phụ thuộc.</Empty>)
                : <TreeChart key={view + full} tree={topo.data.tree} layout={view} opts={treeOpts} onPick={pick} chartRef={chartRef} mobile={mobile} />)}
          </div>
        )}
      </div>
    </>
  );
}
