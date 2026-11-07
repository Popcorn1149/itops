// Thành phần dùng chung cho giám sát CPU / RAM / Disk
import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { useApi, UsageBar } from "../ui";

export const RES_COLORS = { cpu: "#2563eb", mem: "#7c3aed", disk: "#0d9488" };
export const RES_NAMES = { cpu: "CPU", mem: "RAM", disk: "Disk" };
const DEF = {
  cpu_attention: 80, cpu_trouble: 90, cpu_critical: 95, cpu_rearm: 75,
  mem_attention: 85, mem_trouble: 92, mem_critical: 97, mem_rearm: 80,
  disk_attention: 80, disk_trouble: 90, disk_critical: 95, disk_rearm: 75,
};

/** Mức theo threshold: critical / trouble / attention / ok (để trống = tắt mức đó). */
export function levelOf(v, t, key) {
  if (v == null) return null;
  for (const lv of ["critical", "trouble", "attention"]) {
    const x = t[`${key}_${lv}`];
    if (x != null && x !== "" && Number(x) > 0 && v >= Number(x)) return lv;
  }
  return "ok";
}

const gb = (v) => (v == null ? "" : v >= 1024 ? `${(v / 1024).toFixed(1)} TB` : `${v} GB`);
export const fmtGb = gb;

/** Khối CPU / RAM / Disk cho một thiết bị (data.res từ collector, hoặc dòng của /api/resources). */
export function ResourcePanel({ res, thresholds = {}, compact }) {
  if (!res) return null;
  const t = { ...DEF, ...thresholds };
  const lv = res.levels || {};
  const L = (k, v) => lv[k] || levelOf(v, t, k);
  const disks = res.disks || [];
  return (
    <div className="res-panel">
      <div className="res-grid">
        <div className="res-cell">
          <div className="res-label">CPU{res.cores ? <span className="faint"> · {res.cores} core</span> : null}</div>
          <UsageBar pct={res.cpu} level={L("cpu", res.cpu)} width={compact ? 70 : 110} />
        </div>
        <div className="res-cell">
          <div className="res-label">RAM{res.mem_total_gb ? <span className="faint"> · {gb(res.mem_total_gb)}</span> : null}</div>
          <UsageBar pct={res.mem} level={L("mem", res.mem)} width={compact ? 70 : 110} />
          {res.mem_note && <div className="small faint" title={res.mem_note} style={{ cursor: "help" }}>ước tính ⓘ</div>}
          {res.swap != null && res.swap > 0 && <div className="small faint">swap {Math.round(res.swap)}%</div>}
        </div>
        <div className="res-cell">
          <div className="res-label">Disk{disks.length > 1 ? <span className="faint"> · {disks.length} ổ</span> : null}</div>
          <UsageBar pct={res.disk} level={L("disk", res.disk)} width={compact ? 70 : 110} sub={res.disk_name && disks.length > 1 ? res.disk_name : null} />
        </div>
      </div>
      {!compact && res.source && <div className="small faint" style={{ marginTop: 8 }}>Nguồn: {res.source}</div>}
      {!compact && disks.length > 0 && (
        <div className="res-disks">
          {disks.map((d, i) => (
            <div key={i} className="res-disk">
              <span className="mono small res-disk-name" title={d.name}>{d.name}</span>
              <UsageBar pct={d.pct} level={d.level || levelOf(d.pct, t, "disk")} width={120} />
              <span className="small faint res-disk-size">{d.size_gb != null ? `${gb(d.used_gb)} / ${gb(d.size_gb)}` : ""}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Biểu đồ lịch sử CPU / RAM / Disk của một check. */
// Dòng "Current" – giá trị hiện tại: CPU %, RAM đã dùng / tổng (GB), Disk đã dùng / tổng (GB)
function currentLine(cur) {
  if (!cur) return null;
  const parts = [];
  if (cur.cpu != null) parts.push(["cpu", `${Math.round(cur.cpu * 10) / 10}%`]);
  if (cur.mem != null) parts.push(["mem", cur.mem_total_gb ? `${gb(Math.round(cur.mem * cur.mem_total_gb / 10) / 10)} / ${gb(cur.mem_total_gb)}` : `${cur.mem}%`]);
  const ds = (cur.disks || []).filter((d) => d.size_gb != null);
  if (ds.length) {
    const used = Math.round(ds.reduce((a, d) => a + (d.used_gb || 0), 0) * 10) / 10, size = Math.round(ds.reduce((a, d) => a + d.size_gb, 0) * 10) / 10;
    parts.push(["disk", `${gb(used)} / ${gb(size)}`]);
  } else if (cur.disk != null) parts.push(["disk", `${cur.disk}%`]);
  return parts;
}

export function ResourceChart({ checkId, thresholds = {}, height = 200, current }) {
  const [hours, setHours] = useState(24);
  const [showSum, setShowSum] = useState(false);
  const { data } = useApi(checkId ? `/resources/history?check_id=${checkId}&hours=${hours}` : null, { deps: [hours] });
  const el = useRef();
  const pts = data?.points || [];
  const keys = ["cpu", "mem", "disk"].filter((k) => pts.some((p) => p[k] != null));
  useEffect(() => {
    if (!el.current || !pts.length) return;
    const c = echarts.init(el.current);
    const t = { ...DEF, ...thresholds };
    c.setOption({
      grid: { left: 36, right: 12, top: 30, bottom: 24 },
      tooltip: { trigger: "axis", valueFormatter: (v) => (v == null ? "—" : `${v}%`) },
      legend: { top: 0, left: 0, itemWidth: 14, itemHeight: 3, textStyle: { fontSize: 11 } },
      xAxis: { type: "time", min: Date.now() - hours * 3600e3, max: Date.now(), axisLabel: { fontSize: 10, hideOverlap: true } },
      yAxis: { type: "value", min: 0, max: 100, interval: 25, axisLabel: { fontSize: 10, formatter: "{value}%" }, splitLine: { lineStyle: { color: "#f1efec" } } },
      series: keys.map((k) => ({
        name: RES_NAMES[k], type: "line", showSymbol: pts.length < 40, symbolSize: 4, smooth: 0.2, connectNulls: true,
        lineStyle: { width: 1.8, color: RES_COLORS[k] }, itemStyle: { color: RES_COLORS[k] },
        data: pts.map((p) => [p.ts, p[k] ?? null]),
        markLine: (t[`${k}_attention`] || t[`${k}_trouble`]) ? { silent: true, symbol: "none", label: { show: false },
          lineStyle: { color: RES_COLORS[k], type: "dashed", opacity: 0.45, width: 1 }, data: [{ yAxis: Number(t[`${k}_attention`] || t[`${k}_trouble`]) }] } : undefined,
      })),
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [data]);
  if (!checkId) return null;
  return (
    <div>
      <div className="row wrap" style={{ marginBottom: 6, gap: 8 }}>
        <div className="small muted grow">
          {currentLine(current)?.length ? <>Current: {currentLine(current).map(([k, v]) => <span key={k} style={{ marginRight: 10 }}>
            <b style={{ color: RES_COLORS[k] }}>{RES_NAMES[k]}</b> {v}</span>)}</> : "Resource history"}
        </div>
        {data?.stats && Object.keys(data.stats).length > 0 && <button className={`btn sm ${showSum ? "on" : ""}`} onClick={() => setShowSum(!showSum)}>Summarize</button>}
        <div className="seg">
          {[[6, "6 giờ"], [24, "24 giờ"], [168, "7 ngày"]].map(([h, l]) => <button key={h} className={hours === h ? "on" : ""} onClick={() => setHours(h)}>{l}</button>)}
        </div>
      </div>
      {showSum && data?.stats && <div className="res-sum">
        <table className="tbl small"><thead><tr><th>{{ 6: "Last 6h", 24: "Last 24h", 168: "Last 7 days" }[hours]}</th><th>Avg</th><th>Min</th><th>Max</th></tr></thead>
          <tbody>{Object.entries(data.stats).map(([k, s]) => <tr key={k}><td><b style={{ color: RES_COLORS[k] }}>{RES_NAMES[k]}</b></td>
            <td>{s.avg}%</td><td>{s.min}%</td><td>{s.max}%</td></tr>)}</tbody></table>
      </div>}
      {data && !pts.length ? <div className="small muted">Chưa có lịch sử – số liệu sẽ được ghi lại từ lần chạy tới.</div> : <div ref={el} style={{ height }} />}
      <div className="small faint" style={{ marginTop: 2 }}>Đường nét đứt = threshold Attention (mức thấp nhất).</div>
    </div>
  );
}
