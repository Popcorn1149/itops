import React, { useEffect, useRef, useState } from "react";
import { Printer, ArrowLeft, AlertTriangle, ChevronDown, Search } from "lucide-react";
import { useApp, go } from "../App";
import { useApi, fmtTime, Select } from "../ui";

// Monitoring uptime report (1 / 7 / 14 / 30 days) – a page made for printing / "Save as PDF".
const PERIODS = [[1, "1 day"], [7, "7 days"], [14, "14 days"], [30, "30 days"]];

export function fmtDur(s) {
  if (!s) return "0m";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.round((s % 3600) / 60);
  return [d && `${d}d`, (d || h) && `${h}h`, `${String(m).padStart(d || h ? 2 : 1, "0")}m`].filter(Boolean).join(" ");
}
// 2 decimals, normal rounding (99.567 → 99.57%), like Uptime Kuma. Never rounded UP to 100%:
// a check that was down at all shows at most 99.99%; only a clean run shows "100%".
const pct = (v) => (v == null ? "—" : v >= 100 ? "100%" : `${Math.min(99.99, Math.round(v * 100) / 100).toFixed(2)}%`);
const ms = (v) => (v == null ? "—" : v < 1 ? "<1 ms" : `${v} ms`);   // Windows ping reports "<1ms" as 0
const tone = (v) => (v == null ? "" : v >= 99.9 ? "ok" : v >= 99 ? "warn" : "fail");


// Pick any set of checks (some Internet lines, a few servers…). Grouped by type; clicking a group name toggles the whole group.
const TYPE_NAME = { internet: "Internet lines", ping: "Ping", tcp: "TCP port", http: "Web / HTTP", snmp: "SNMP", ssh: "Servers (SSH)",
  winrm: "Windows servers", esxi: "ESXi", proxmox: "Proxmox", pfsense: "Firewall (pfSense)" };
function CheckPicker({ checks, picked, onChange }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const box = useRef(null);
  useEffect(() => {
    if (!open) return;
    const away = (e) => { if (!box.current?.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  const set = new Set(picked);
  const shown = checks.filter((c) => !q || `${c.name} ${c.target} ${c.type}`.toLowerCase().includes(q.toLowerCase()));
  const groups = {};
  shown.forEach((c) => { (groups[c.type] = groups[c.type] || []).push(c); });
  const toggle = (ids, on) => { const n = new Set(set); ids.forEach((i) => (on ? n.add(i) : n.delete(i))); onChange([...n]); };
  const label = !picked.length ? "All checks" : picked.length === 1 ? (checks.find((c) => String(c.id) === picked[0])?.name || "1 check") : `${picked.length} checks selected`;
  return <div ref={box} style={{ position: "relative" }}>
    <button type="button" className="btn" onClick={() => setOpen(!open)} aria-haspopup="listbox" aria-expanded={open} aria-label="Checks">
      {label} <ChevronDown size={14} />
    </button>
    {open && <div style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, zIndex: 40, width: 340, maxHeight: 440, display: "flex", flexDirection: "column",
      background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--pop-shadow)" }}>
      <div style={{ padding: 8, borderBottom: "1px solid var(--border)" }}>
        <div className="search"><Search size={15} /><input autoFocus placeholder="Search checks…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      </div>
      <div style={{ overflowY: "auto", padding: "4px 0" }}>
        {!shown.length && <div className="small muted" style={{ padding: "8px 14px" }}>No check matches.</div>}
        {Object.keys(groups).sort((a, b) => (TYPE_NAME[a] || a).localeCompare(TYPE_NAME[b] || b)).map((t) => {
          const ids = groups[t].map((c) => String(c.id));
          const all = ids.every((i) => set.has(i));
          return <div key={t}>
            <label className="row small" style={{ gap: 8, padding: "6px 14px", fontWeight: 600, cursor: "pointer", background: "var(--bg)" }}>
              <input type="checkbox" checked={all} ref={(el) => { if (el) el.indeterminate = !all && ids.some((i) => set.has(i)); }}
                onChange={() => toggle(ids, !all)} />
              {TYPE_NAME[t] || t} <span className="muted" style={{ fontWeight: 400 }}>({ids.length})</span>
            </label>
            {groups[t].map((c) => <label key={c.id} className="row small" style={{ gap: 8, padding: "5px 14px 5px 34px", cursor: "pointer" }}>
              <input type="checkbox" checked={set.has(String(c.id))} onChange={(e) => toggle([String(c.id)], e.target.checked)} />
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</span>
              <span className="muted mono" style={{ fontSize: 11 }}>{c.target?.slice(0, 22)}</span>
            </label>)}
          </div>;
        })}
      </div>
      <div className="row small" style={{ justifyContent: "space-between", padding: 8, borderTop: "1px solid var(--border)" }}>
        <button type="button" className="btn" onClick={() => onChange([])} disabled={!picked.length}>Clear (all checks)</button>
        <button type="button" className="btn primary" onClick={() => setOpen(false)}>Done</button>
      </div>
    </div>}
  </div>;
}

export default function Report() {
  const { appName, route } = useApp();
  const qs = route.params || {};
  const [days, setDays] = useState([1, 7, 14, 30].includes(+qs.days) ? +qs.days : 7);
  const [site, setSite] = useState(qs.site_id || "");
  const [picked, setPicked] = useState(() => (qs.check_ids || qs.check_id || "").split(",").filter(Boolean));
  const sites = useApi("/sites").data || [];
  const checks = (useApi("/checks").data || []).filter((c) => !site || String(c.site_id) === site).sort((a, b) => a.name.localeCompare(b.name));
  const sel = picked.join(",");
  const { data: r, error } = useApi(`/reports/monitoring?days=${days}${site ? `&site_id=${site}` : ""}${sel ? `&check_ids=${sel}` : ""}`, { deps: [days, site, sel] });
  const partial = r?.data_since && r.data_since > r.from;
  const measured = (r?.checks || []).filter((c) => c.runs);
  const idle = (r?.checks || []).filter((c) => !c.runs);

  return (
    <div className="report">
      <div className="no-print row" style={{ gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        <button className="btn" onClick={() => go("checks")}><ArrowLeft size={15} /> Monitoring</button>
        <div className="seg">{PERIODS.map(([d, l]) => <button key={d} className={days === d ? "on" : ""} onClick={() => setDays(d)}>{l}</button>)}</div>
        <Select value={site} onChange={(v) => { setSite(v); setPicked([]); }} options={[["", "All sites"], ...sites.map((s) => [String(s.id), s.name])]} style={{ width: "auto" }} />
        <CheckPicker checks={checks} picked={picked} onChange={setPicked} />
        <button className="btn primary" style={{ marginLeft: "auto" }} onClick={() => window.print()} disabled={!r}><Printer size={15} /> Print / Save as PDF</button>
      </div>

      {error && <div className="alert-box fail">{String(error.message || error)}</div>}
      {!r ? <div className="muted">Loading…</div> : <div className="card card-pad report-sheet">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
          <div>
            <div className="small muted">{appName}</div>
            <h1 style={{ margin: "2px 0 4px" }}>Monitoring report – last {PERIODS.find(([d]) => d === r.days)?.[1]}</h1>
            <div className="small">{fmtTime(r.from)} → {fmtTime(r.to)}{r.site && <> · Site: <b>{r.site}</b></>}{r.check && <> · {picked.length > 1 ? "Checks" : "Check"}: <b>{r.check}</b></>}</div>
          </div>
          <div className="small muted" style={{ textAlign: "right" }}>Generated {fmtTime(r.generated)}</div>
        </div>

        {partial && <div className="alert-box warn" style={{ marginTop: 12 }}><AlertTriangle size={15} /> ITOps has data only since {fmtTime(r.data_since)}; earlier time in this period is not counted.</div>}

        <div className="report-kpis">
          <div><span className="muted small">Overall uptime</span><b className={`t-${tone(r.summary.uptime)}`}>{pct(r.summary.uptime)}</b></div>
          <div><span className="muted small">Checks at 100%</span><b>{r.summary.at_100} / {r.summary.measured}</b></div>
          <div><span className="muted small">Outages</span><b>{r.summary.outages}</b></div>
          <div><span className="muted small">Total downtime</span><b>{fmtDur(r.summary.downtime_s)}</b></div>
        </div>

        <h3>Uptime per check</h3>
        <table className="tbl report-tbl">
          <thead><tr><th>Check</th><th>Site</th><th>Target</th><th className="num">Uptime</th><th className="num">Outages</th>
            <th className="num">Downtime</th><th className="num">Ping min</th><th className="num">avg</th><th className="num">max</th></tr></thead>
          <tbody>{measured.map((c) => <tr key={c.id}>
            <td><b>{c.name}</b> <span className="small muted">{c.type}</span></td><td className="small">{c.site || "—"}</td>
            <td className="small mono">{c.target}</td>
            <td className="num"><span className={`badge ${tone(c.uptime)}`}>{pct(c.uptime)}</span></td>
            <td className="num">{c.outages || "—"}</td><td className="num">{c.downtime_s ? fmtDur(c.downtime_s) : "—"}</td>
            <td className="num small">{ms(c.lat_min)}</td><td className="num small">{ms(c.lat_avg)}</td><td className="num small">{ms(c.lat_max)}</td>
          </tr>)}</tbody>
        </table>
        {idle.length > 0 && <div className="small muted" style={{ marginTop: 6 }}>No results in this period (disabled or new): {idle.map((c) => c.name).join(", ")}</div>}

        <h3>Outages</h3>
        {!r.outage_list.length ? <div className="small muted">No outage in this period.</div> : <table className="tbl report-tbl">
          <thead><tr><th>Check</th><th>Down from</th><th>Back up</th><th className="num">Duration</th><th>Reason</th></tr></thead>
          <tbody>{r.outage_list.map((o, i) => <tr key={i}>
            <td><b>{o.check}</b></td><td className="small">{fmtTime(o.start)}</td>
            <td className="small">{o.end ? fmtTime(o.end) : <span className="badge fail">still down</span>}</td>
            <td className="num">{fmtDur(o.seconds)}</td><td className="small muted report-msg">{o.message || "—"}</td>
          </tr>)}</tbody>
        </table>}

        <div className="small muted" style={{ marginTop: 14 }}>
          Uptime = share of check runs that were not DOWN (no connection). Threshold warnings (CPU / RAM / disk, service errors) do not reduce uptime.
          Ping min / avg / max only from successful runs. Durations of outages that started before the period are counted from its start.
        </div>
      </div>}
    </div>
  );
}
