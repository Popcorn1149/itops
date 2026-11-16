import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  Shield, Server, Monitor, Router, Network, Wifi, HardDrive, BatteryCharging, Printer, Camera, Box, Globe, Cloud,
  Cpu, Container, CircleHelp, X, Inbox, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Check, Smartphone, Laptop,
} from "lucide-react";
import { api, setAuditReason } from "./api";

export const DEMO = import.meta.env.VITE_DEMO === "1";

export const TYPES = {
  firewall: { label: "Firewall", icon: Shield, color: "#ea7a0c" },
  router: { label: "Router", icon: Router, color: "#0891b2" },
  switch: { label: "Switch", icon: Network, color: "#2563eb" },
  ap: { label: "Access Point", icon: Wifi, color: "#7c3aed" },
  host: { label: "Physical Hosts", icon: Server, color: "#0f766e" },
  server: { label: "Server", icon: Server, color: "#0f766e" },
  vm: { label: "Virtual Machine (VM)", icon: Monitor, color: "#4f46e5" },
  workstation: { label: "Workstation", icon: Laptop, color: "#0369a1" },
  container: { label: "Container", icon: Container, color: "#0284c7" },
  service: { label: "Service", icon: Box, color: "#9333ea" },
  website: { label: "Website", icon: Globe, color: "#0d9488" },
  nas: { label: "NAS / Storage", icon: HardDrive, color: "#a16207" },
  ups: { label: "UPS", icon: BatteryCharging, color: "#65a30d" },
  printer: { label: "Printer", icon: Printer, color: "var(--text-3)" },
  camera: { label: "Camera", icon: Camera, color: "var(--text-3)" },
  device: { label: "Other Devices", icon: Smartphone, color: "var(--muted)" },
  cloud: { label: "Cloud", icon: Cloud, color: "#0ea5e9" },
  other: { label: "Other", icon: Cpu, color: "var(--muted)" },
};
export const typeMeta = (t) => TYPES[t] || { label: t, icon: CircleHelp, color: "var(--muted)" };
export function TypeIcon({ type, size = 16, style }) {
  const M = typeMeta(type);
  const I = M.icon;
  // CSS variable colors (gray icons adapt to Light/Dark) use currentColor because SVG attributes do not reliably resolve var()
  const v = M.color.startsWith("var(");
  return <I size={size} color={v ? "currentColor" : M.color} style={{ flexShrink: 0, ...(v ? { color: M.color } : {}), ...style }} />;
}

export const CHECK_TYPES = {
  ping: "Ping (ICMP)", tcp: "TCP Port", http: "Website / HTTP(S)", snmp: "SNMP (switch, AP, UPS, NAS...)",
  ssh: "SSH (Linux / Windows)", esxi: "VMware ESXi / vCenter", proxmox: "Proxmox VE", pfsense: "pfSense / OPNsense",
  internet: "Line Internet (ping/DNS/HTTP)",
};

const NORM = { up: "ok", ok: "ok", warning: "warn", warn: "warn", down: "fail", fail: "fail", off: "off", unknown: "unknown" };
const LABEL = { ok: "Operational", warn: "Warning", fail: "Error", off: "Disabled", unknown: "Unknown" };
export const norm = (s) => NORM[s] || "unknown";
export const statusLabel = (s) => LABEL[norm(s)];

export function Dot({ status, pulse }) {
  if (SEV[status]) return <span className={`dot sev-${SEV[status].cls} ${pulse && status === "down" ? "pulse" : ""}`} />;
  const n = norm(status);
  return <span className={`dot ${n} ${pulse && n === "fail" ? "pulse" : ""}`} />;
}
// OpManager-style incident levels. DOWN is reserved for actual connectivity loss.
export const SEV = {
  attention: { label: "Attention", cls: "attention", vi: "Needs attention" },
  trouble: { label: "Trouble", cls: "trouble", vi: "Issues" },
  warning: { label: "Trouble", cls: "trouble", vi: "Issues" },
  critical: { label: "Critical", cls: "critical", vi: "Critical" },
  down: { label: "DOWN", cls: "down", vi: "Disconnected" },
};
export const SEV_RANK = { attention: 1, trouble: 2, warning: 2, critical: 3, down: 4 };
export function SevBadge({ sev, children, title }) {
  const m = SEV[sev];
  if (!m) return null;
  return <span className={`badge sev-${m.cls}`} title={title || m.vi}>{children || m.label}</span>;
}
export function StatusBadge({ status, children }) {
  const n = norm(status);
  const cls = n === "off" || n === "unknown" ? "" : n;
  return <span className={`badge ${cls}`}><Dot status={status} />{children || statusLabel(status)}</span>;
}
// Site status based on actual checks: Not monitored / Not running / healthy / alerts / error
export function SiteHealth({ s }) {
  const h = s.health || (s.stats?.alerts ? "warn" : "unknown");
  if (h === "unmonitored") return <span className="badge" title="Site has no enabled monitoring checks">Not monitored</span>;
  if (h === "unknown") return <span className="badge"><Dot status="unknown" />Not running</span>;
  if (h === "fail") return <span className="badge fail"><Dot status="fail" />{s.stats?.alerts ? `${s.stats.alerts} alerts` : "Error"}</span>;
  if (h === "warn") return <span className="badge warn"><Dot status="warn" />{s.stats?.alerts ? `${s.stats.alerts} alerts` : "Warning"}</span>;
  return <span className="badge ok"><Dot status="ok" />Operational</span>;
}
export function InternetLine({ items, onOpen }) {
  if (!items?.length) return <span className="faint">Not assigned – Monitoring › Add checks › Line Internet</span>;
  const down = items.filter((i) => i.down).length, known = items.filter((i) => i.status !== "unknown").length;
  const up = known - down;
  return <span className="row wrap" style={{ gap: 6 }}>
    <b style={{ color: down === known && known ? "var(--fail)" : down ? "var(--warn)" : undefined }}>{up}/{items.length} line{down ? ` · ${down} down` : ""}</b>
    {items.map((i, n) => {
      const txt = i.down ? `${i.name}: DOWN` : [i.name, i.latency_ms != null ? `${i.latency_ms} ms` : null, i.loss ? `${i.loss}% packet loss` : null].filter(Boolean).join(" · ");
      return <span key={n} className={`chip ${i.down ? "red" : ""}`} onClick={() => onOpen && i.id && onOpen(i.id)} title={i.message || ""}>
        <Dot status={i.down ? "down" : i.status} pulse />{txt}{i.public_ip && <span className="faint mono">{i.public_ip}</span>}
      </span>;
    })}</span>;
}
export function LevelBadge({ level }) {
  const cls = level === "High" ? "fail" : level === "Medium" ? "warn" : "";
  return <span className={`badge ${cls}`}>{level}</span>;
}

export function timeAgo(iso) {
  if (!iso) return "Not running";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)} seconds ago`;
  if (s < 3600) return `${Math.floor(s / 60)} minutes ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} hours ago`;
  return `${Math.floor(s / 86400)} days ago`;
}
export const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString("vi-VN", { hour12: false }) : "—");

// ---------- toast ----------
const ToastCtx = createContext(() => {});
export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((msg, err = false) => {
    const id = Math.random();
    setItems((x) => [...x, { id, msg, err }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), err ? 6000 : 3000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-wrap">{items.map((t) => <div key={t.id} className={`toast ${t.err ? "err" : ""}`}>{t.msg}</div>)}</div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);

// ---------- data hook ----------
export function useApi(path, { interval = 0, deps = [] } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async (bg) => {
    if (!path) return;
    try {
      const d = await api.get(path, bg === true ? { background: true } : undefined);
      setData(d);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    load();
    if (interval) {
      const t = setInterval(() => load(true), interval);   // auto-refresh runs as a background request
      return () => clearInterval(t);
    }
  }, [load, interval, ...deps]);
  return { data, error, loading, reload: load, setData };
}

// ---------- layout bits ----------
export function PageHead({ crumb, title, desc, children }) {
  return (
    <>
      {crumb && <div className="crumb">{crumb}</div>}
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          {desc && <p>{desc}</p>}
        </div>
        {children && <div className="page-actions">{children}</div>}
      </div>
    </>
  );
}

export function Stat({ icon: I, label, value, sub, tone, onClick }) {
  return (
    <div className="card stat" onClick={onClick}>
      <div className="stat-label">{I && <I size={17} />}{label}</div>
      <div className="stat-value">{value ?? "–"}</div>
      <div className={`stat-sub ${tone || ""}`}>{sub}</div>
    </div>
  );
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.key} className={`tab ${value === t.key ? "active" : ""}`} onClick={() => onChange(t.key)}>
          {t.icon && <t.icon size={15} />}{t.label}{t.count !== undefined && <span className="n">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Empty({ icon: I = Inbox, title, children }) {
  return (
    <div className="empty">
      <I size={34} />
      <div style={{ fontWeight: 600, color: "var(--text-2)" }}>{title}</div>
      {children && <div style={{ marginTop: 6 }}>{children}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, footer, width }) {
  useEffect(() => {
    const k = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={width ? { maxWidth: width } : null}>
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={onClose}><X size={18} /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children, actions, wide }) {
  useEffect(() => {
    const k = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className={`drawer${wide ? " wide" : ""}`}>
        <div className="modal-head">
          <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>{title}</h3>
          <div className="row" style={{ marginLeft: "auto" }}>
            {actions}
            <button className="btn ghost sm" onClick={onClose}><X size={18} /></button>
          </div>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </>
  );
}

export function Field({ label, hint, full, children }) {
  return (
    <div className={`field ${full ? "full" : ""}`}>
      {label && <label>{label}</label>}
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Input({ value, onChange, ...p }) {
  return <input className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value)} {...p} />;
}
export function Select({ value, onChange, options, placeholder, ...p }) {
  return (
    <select className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value)} {...p}>
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => (Array.isArray(o) ? <option key={o[0]} value={o[0]}>{o[1]}</option> : <option key={o} value={o}>{o}</option>))}
    </select>
  );
}
export function Toggle({ checked, onChange, label }) {
  return (
    <label className="check-row">
      <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} /> {label}
    </label>
  );
}

// ---------- responsive helpers ----------
export function useIsMobile(bp = 760) {
  const q = `(max-width: ${bp}px)`;
  const [m, setM] = useState(() => typeof window !== "undefined" && window.matchMedia(q).matches);
  useEffect(() => {
    const mq = window.matchMedia(q);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [q]);
  return m;
}

// ---------- sortable table (card layout on mobile) ----------
// sortBy/onSort: server-side sorting. The table then only shows the arrow; the server orders ALL rows
// (sorting just the visible page would mix up paged results).
export function Table({ columns, rows, onRow, empty, rowKey = "id", sortBy, onSort }) {
  const [localSort, setSort] = useState(null);
  const sort = onSort ? sortBy : localSort;
  const mobile = useIsMobile();
  const sorted = useMemo(() => {
    if (!sort || onSort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    const get = col.sort || ((r) => r[col.key]);
    return [...rows].sort((a, b) => {
      const x = get(a), y = get(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""), "vi", { numeric: true, sensitivity: "base" });
      return sort.dir * r;
    });
  }, [rows, sort, columns, onSort]);
  if (!rows.length) return empty || <Empty title="No data available" />;
  if (mobile) {
    const cols = columns.filter((c) => !["idx", "i"].includes(c.key));
    const lead = cols.filter((c) => !c.label && c.key !== "act");
    const titleCol = cols.find((c) => c.label);
    const body = cols.filter((c) => c.label && c !== titleCol);
    const act = cols.find((c) => c.key === "act" || c.key === "a");
    return (
      <div className="mcards">
        {sorted.map((r, i) => (
          <div key={r[rowKey] ?? i} className={`mcard ${onRow ? "clickable" : ""}`} onClick={() => onRow && onRow(r)}>
            <div className="mcard-head">
              {lead.map((c) => <span key={c.key}>{c.render ? c.render(r, i) : r[c.key]}</span>)}
              <div className="grow">{titleCol && (titleCol.render ? titleCol.render(r, i) : r[titleCol.key])}</div>
            </div>
            <div className="mcard-body">
              {body.filter((c) => c !== act).map((c) => (
                <React.Fragment key={c.key}><div className="mlabel">{c.label}</div><div className="mval">{c.render ? c.render(r, i) : r[c.key]}</div></React.Fragment>
              ))}
            </div>
            {act && <div className="mcard-act">{act.render(r, i)}</div>}
          </div>
        ))}
      </div>
    );
  }
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.sortable !== false && c.label ? "sortable" : ""} style={{ width: c.width }}
                onClick={() => c.sortable !== false && c.label && (onSort ? onSort(c.key) : setSort((s) => ({ key: c.key, dir: s?.key === c.key ? -s.dir : 1 })))}>
                <span className="row" style={{ gap: 4 }}>{c.label}
                  {sort?.key === c.key && (sort.dir > 0 ? <ChevronUp size={13} /> : <ChevronDown size={13} />)}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <tr key={r[rowKey] ?? i} className={onRow ? "clickable" : ""} onClick={() => onRow && onRow(r)}>
              {columns.map((c) => <td key={c.key}>{c.render ? c.render(r, i) : r[c.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Spark({ points, width = 120, height = 28, color = "#16a34a" }) {
  const vals = points.filter((v) => v !== null && v !== undefined);
  if (vals.length < 2) return <span className="faint small">—</span>;
  const max = Math.max(...vals), min = Math.min(...vals);
  const span = max - min || 1;
  const step = width / (points.length - 1);
  const d = points.map((v, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)},${v == null ? height : (height - 2 - ((v - min) / span) * (height - 4)).toFixed(1)}`).join(" ");
  return <svg className="spark" width={width} height={height}><path d={d} fill="none" stroke={color} strokeWidth="1.6" /></svg>;
}

export function UsageBar({ pct, level, width = 80, sub }) {
  if (pct == null) return <span className="faint">—</span>;
  const cls = level ? (level === "ok" ? "" : level === "warn" ? "trouble" : level === "fail" ? "critical" : level) : "";
  const n = Math.round(pct * 10) / 10;
  return (
    <div className="row" style={{ gap: 8, minWidth: 0 }}>
      <div className={`bar ${cls}`} style={{ width, flexShrink: 0 }}><div style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} /></div>
      <span className="small" style={{ fontWeight: cls ? 600 : 400, color: cls ? `var(--${cls})` : undefined, whiteSpace: "nowrap" }}>{n}%</span>
      {sub && <span className="small faint" style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{sub}</span>}
    </div>
  );
}

export function useClickOutside(onOut) {
  const ref = useRef();
  useEffect(() => {
    const h = (e) => ref.current && !ref.current.contains(e.target) && onOut();
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [onOut]);
  return ref;
}

// ---------- in-app confirmation dialog (replaces window.confirm/prompt) ----------
let _openConfirm = null;
export function askConfirm(opts) {
  return new Promise((resolve) => (_openConfirm ? _openConfirm({ ...opts, resolve }) : resolve(false)));
}
export function confirmDelete(name) {
  return askConfirm({ title: `Delete "${name}"?`, message: "This action cannot be undone.", okText: "Delete", danger: true });
}
export function ConfirmHost() {
  const [o, setO] = useState(null);
  const [txt, setTxt] = useState("");
  const [why, setWhy] = useState("");
  useEffect(() => { _openConfirm = (x) => { setTxt(""); setWhy(""); setO(x); }; return () => { _openConfirm = null; }; }, []);
  if (!o) return null;
  const done = (v) => { if (v && o.danger) setAuditReason(why); o.resolve(v); setO(null); };
  const blocked = o.requireText && txt !== o.requireText;
  return (
    <div className="overlay confirm-overlay" onMouseDown={(e) => e.target === e.currentTarget && done(false)}>
      <div className="modal confirm-box" role="alertdialog">
        <div className="modal-body">
          <h3 style={{ margin: "0 0 8px" }}>{o.title}</h3>
          {o.message && <div className="muted" style={{ lineHeight: 1.5 }}>{o.message}</div>}
          {o.requireText && <div style={{ marginTop: 12 }}><div className="small" style={{ marginBottom: 6 }}>Type <b>{o.requireText}</b> to confirm</div>
            <input className="input" autoFocus value={txt} onChange={(e) => setTxt(e.target.value)} /></div>}
          {o.danger && <div style={{ marginTop: 12 }}><div className="small muted" style={{ marginBottom: 6 }}>Reason (optional; recorded in the audit log)</div>
            <input className="input" placeholder="e.g. decommissioned device, change request CR-12" value={why} onChange={(e) => setWhy(e.target.value)} maxLength={300} /></div>}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={() => done(false)}>Cancel</button>
          <button className={`btn ${o.danger ? "danger-solid" : "primary"}`} disabled={blocked} onClick={() => done(true)}>{o.okText || "Confirm"}</button>
        </div>
      </div>
    </div>
  );
}

// ---------- pager for server-paged tables ----------
// Footer pager: "Rows per page: N ⌄" on the left, ‹ 1 2 … › on the right.
function pageList(cur, last) {
  const set = new Set([0, last, cur - 1, cur, cur + 1].filter((i) => i >= 0 && i <= last));
  const out = [];
  [...set].sort((x, y) => x - y).forEach((i, k, arr) => { if (k && i - arr[k - 1] > 1) out.push("…" + i); out.push(i); });
  return out;
}
// "Rows per page: N ⌄" that opens a small menu upwards (the pager sits at the bottom of the table).
export function PerMenu({ per, onPer }) {
  const [open, setOpen] = useState(false);
  const box = useRef(null);
  useEffect(() => {
    if (!open) return;
    const away = (e) => { if (!box.current?.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return <div ref={box} style={{ position: "relative" }}>
    <button type="button" onClick={() => setOpen(!open)} aria-haspopup="listbox" aria-expanded={open} aria-label="Rows per page"
      style={{ background: "none", border: 0, padding: "2px 0", cursor: "pointer", color: "inherit", font: "inherit", display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{ textDecoration: "underline", textUnderlineOffset: 3 }}>Rows per page: {per}</span><ChevronDown size={14} />
    </button>
    {open && <div role="listbox" style={{ position: "absolute", bottom: "calc(100% + 8px)", left: 0, minWidth: 150, zIndex: 30, background: "var(--panel)",
      border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--pop-shadow)", padding: "6px 0" }}>
      {[25, 50, 100, 500].map((n) => <button key={n} type="button" role="option" aria-selected={n === per} onClick={() => { onPer(String(n)); setOpen(false); }}
        style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", background: "none", border: 0, padding: "9px 16px", cursor: "pointer", color: "inherit", font: "inherit", fontSize: 14, textAlign: "left" }}
        onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg)"; }} onMouseLeave={(e) => { e.currentTarget.style.background = "none"; }}>
        <span style={{ width: 16, display: "inline-flex" }}>{n === per && <Check size={15} />}</span>{n} rows
      </button>)}
    </div>}
  </div>;
}
export function Pager({ total, per, page, onPer, onPage, label }) {
  const last = Math.max(0, Math.ceil(total / per) - 1);
  const link = { background: "none", border: 0, padding: "2px 6px", cursor: "pointer", color: "inherit", font: "inherit" };
  return <div className="row small" style={{ justifyContent: "space-between", alignItems: "center", padding: "8px 16px", background: "var(--bg)", borderTop: "1px solid var(--border)" }}>
    <div className="row" style={{ gap: 14, alignItems: "center" }}><PerMenu per={per} onPer={onPer} />{label && <span className="muted">{label}</span>}</div>
    <div className="row" style={{ gap: 2, alignItems: "center" }}>
      <button style={{ ...link, opacity: page === 0 ? 0.35 : 1 }} disabled={page === 0} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft size={16} /></button>
      {pageList(page, last).map((i) => typeof i === "string"
        ? <span key={i} className="muted" style={{ padding: "0 4px" }}>…</span>
        : <button key={i} style={{ ...link, color: i === page ? "var(--accent)" : "inherit", textDecoration: i === page ? "underline" : "none", textUnderlineOffset: 3, fontWeight: i === page ? 600 : 400 }}
            onClick={() => onPage(i)} aria-current={i === page ? "page" : undefined}>{i + 1}</button>)}
      <button style={{ ...link, opacity: page >= last ? 0.35 : 1 }} disabled={page >= last} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight size={16} /></button>
    </div>
  </div>;
}


// Shown under a list that the server cut at `limit` rows: say so instead of silently hiding the rest.
export function CapNote({ shown, limit, what = "items", hint = "Narrow the filters or search to see the rest." }) {
  if (!shown || shown < limit) return null;
  return <div className="small muted" style={{ padding: "8px 16px", borderTop: "1px solid var(--border)", background: "var(--bg)" }}>
    Showing the newest {limit.toLocaleString()} {what} only. {hint}
  </div>;
}

// Rows-per-page choice remembered per list.
export function usePerPage(key, def = 50) {
  const [per, setPer] = useState(() => { try { const v = +localStorage.getItem(key); return [25, 50, 100, 500].includes(v) ? v : def; } catch { return def; } });
  const change = (v) => { setPer(+v); try { localStorage.setItem(key, String(v)); } catch { /* ignore */ } };
  return [per, change];
}
