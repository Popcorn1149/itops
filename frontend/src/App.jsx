import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  LayoutDashboard, Map, Globe2, Shield, Server, Monitor, Network, HardDrive, ShieldCheck, Activity, Bell,
  ScrollText, Settings, Search, PanelLeft, Laptop, Clock, Boxes, LogOut, KeyRound, Menu, FileText, Gauge, Zap,
} from "lucide-react";
import { useUi, setPinned } from "./theme";
import ThemeSwitch from "./components/ThemeSwitch";
import { api } from "./api";
import { ForcedTwoFactor } from "./components/AccountSecurity";
import { Dot, TypeIcon, useClickOutside, useApi, DEMO } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import MapPage from "./pages/MapPage";
import Sites from "./pages/Sites";
import Assets, { AssetDrawer } from "./pages/Assets";
import Critical from "./pages/Critical";
import Checks, { CheckForm } from "./pages/Checks";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";
import Agents from "./pages/Agents";
import SettingsPage from "./pages/Settings";
import Logs from "./pages/Logs";
import Resources from "./pages/Resources";
import Automation from "./pages/Automation";

const AppCtx = createContext(null);
export const useApp = () => useContext(AppCtx);

// Router: dùng hash (#/trang?x=y). Bản demo chạy trong khung artifact nên giữ route trong bộ nhớ.
let _demoRoute = "dashboard";
const _listeners = new Set();
export function go(path) {
  path = path.replace(/^#?\/?/, "");
  if (DEMO) { _demoRoute = path; _listeners.forEach((f) => f()); window.scrollTo(0, 0); }
  else window.location.hash = "/" + path;
}
function parseHash() {
  const h = DEMO ? _demoRoute : window.location.hash.replace(/^#\/?/, "");
  const [path, qs] = h.split("?");
  const [page = "dashboard", id] = path.split("/");
  return { page, id, params: Object.fromEntries(new URLSearchParams(qs || "")) };
}

const NAV = [
  { key: "dashboard", label: "Bảng điều khiển", icon: LayoutDashboard },
  { group: "Hạ tầng" },
  { key: "map", label: "Bản đồ hệ thống", icon: Map },
  { key: "sites", label: "Sites", icon: Globe2 },
  { key: "assets", q: "type=firewall", label: "Firewall", icon: Shield, types: ["firewall"] },
  { key: "assets", q: "type=switch,router,ap", label: "Thiết bị mạng", icon: Network, types: ["switch", "router", "ap"] },
  { key: "assets", q: "type=host,server", label: "Host vật lý", icon: Server, types: ["host", "server"] },
  { key: "assets", q: "type=vm,container", label: "Máy ảo & container", icon: Monitor, types: ["vm", "container"] },
  { key: "assets", q: "type=nas,ups,printer,camera,device,other,service,website,cloud", label: "Thiết bị khác", icon: HardDrive, types: ["nas", "ups", "printer", "camera", "device", "other", "service", "website", "cloud"] },
  { key: "assets", q: "", label: "Tất cả tài sản", icon: Boxes },
  { group: "Vận hành" },
  { key: "critical", label: "Hệ thống trọng yếu", icon: ShieldCheck },
  { key: "checks", label: "Giám sát", icon: Activity },
  { key: "resources", label: "Tài nguyên", icon: Gauge },
  { key: "automation", label: "Tự động hoá", icon: Zap },
  { key: "agents", label: "Máy trạm", icon: Laptop },
  { key: "alerts", label: "Cảnh báo", icon: Bell, badge: true },
  { key: "logs", label: "Log thiết bị", icon: FileText },
  { key: "audit", label: "Audit log", icon: ScrollText },
  { key: "settings", label: "Cài đặt", icon: Settings },
];

// Status backend thật: hỏi /api/health mỗi 30 giây. Bản demo (không có backend) thì ẩn.
function ApiStatus() {
  const [st, setSt] = useState(null);
  useEffect(() => {
    if (DEMO) return;
    let alive = true;
    const probe = async () => {
      const t0 = performance.now();
      try {
        const ctl = new AbortController(); const to = setTimeout(() => ctl.abort(), 8000);
        const r = await fetch("/api/health", { cache: "no-store", signal: ctl.signal }); clearTimeout(to);
        const d = await r.json();
        const ms = Math.round(performance.now() - t0);
        if (!alive) return;
        if (!r.ok || !d.db) setSt({ s: "fail", t: "Lỗi cơ sở dữ liệu", ms });
        else if (d.scheduler === "stalled") setSt({ s: "warn", t: "Bộ giám sát ngừng chạy", ms });
        else if (d.receivers_ok === false) setSt({ s: "warn", t: "API ổn · bộ nhận log lỗi", ms });
        else setSt({ s: "ok", t: d.scheduler === "off" ? "API hoạt động (tắt lập lịch)" : "API hoạt động", ms });
      } catch { if (alive) setSt({ s: "fail", t: "Mất kết nối API" }); }
    };
    probe(); const i = setInterval(probe, 30000);
    return () => { alive = false; clearInterval(i); };
  }, []);
  if (DEMO || !st) return null;
  return <div className="row" title={st.ms != null ? `Phản hồi ${st.ms} ms · kiểm tra mỗi 30 giây` : "Không gọi được /api/health"}>
    <Dot status={st.s} pulse={st.s !== "ok"} /><span style={{ color: st.s === "ok" ? undefined : `var(--${st.s})` }}>{st.t}</span>
    {st.ms != null && st.s === "ok" && <span className="faint">· {st.ms} ms</span>}
  </div>;
}

function ClockBox() {
  const [t, setT] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setT(new Date()), 1000); return () => clearInterval(i); }, []);
  return <div className="clock"><Clock size={14} /><b>{t.toLocaleTimeString("vi-VN", { hour12: false })}</b>{t.toLocaleDateString("vi-VN")}</div>;
}

function GlobalSearch() {
  const { openAsset, nav, openCheck } = useApp();
  const [q, setQ] = useState("");
  const [res, setRes] = useState([]);
  const [open, setOpen] = useState(false);
  const ref = useClickOutside(() => setOpen(false));
  useEffect(() => {
    if (!q.trim()) { setRes([]); return; }
    const t = setTimeout(() => api.get(`/search?q=${encodeURIComponent(q)}`).then(setRes).catch(() => {}), 200);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    const k = (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); ref.current?.querySelector("input")?.focus(); } };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [ref]);
  const pick = (r) => {
    setOpen(false); setQ("");
    if (r.kind === "asset") openAsset(r.id);
    else if (r.kind === "site") nav("sites");
    else if (r.kind === "critical") nav("critical");
    else if (r.kind === "check") openCheck(r.id);
  };
  return (
    <div className="search" ref={ref}>
      <Search size={16} />
      <input placeholder="Tìm máy chủ, IP, check...  (Ctrl K)" value={q} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} />
      {open && res.length > 0 && (
        <div className="search-results">
          {res.map((r) => (
            <div key={r.kind + r.id} className="search-item" onClick={() => pick(r)}>
              {r.status && <Dot status={r.status} />}
              <div><div style={{ fontWeight: 600 }}>{r.title}</div><div className="small muted">{r.sub}</div></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function UserMenu({ me, onLogout }) {
  const [open, setOpen] = useState(false);
  const ref = useClickOutside(() => setOpen(false));
  const { nav } = useApp();
  return (
    <div style={{ position: "relative" }} ref={ref}>
      <button className="avatar" onClick={() => setOpen(!open)}>{(me.full_name || me.username)[0].toUpperCase()}</button>
      {open && (
        <div className="search-results" style={{ right: 0, left: "auto", width: 220 }}>
          <div style={{ padding: "8px 10px" }}><b>{me.full_name || me.username}</b><div className="small muted">{me.username} · {me.role}</div></div>
          <div className="search-item" onClick={() => { setOpen(false); nav("settings", null, { tab: "account" }); }}><KeyRound size={15} />Mật khẩu · 2FA · Phiên</div>
          <div style={{ padding: "6px 10px 8px", display: "flex", alignItems: "center", gap: 8 }}><span className="small muted grow">Giao diện</span><ThemeSwitch /></div>
          <div className="search-item" onClick={onLogout}><LogOut size={15} />Đăng xuất</div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [route, setRoute] = useState(parseHash());
  const [me, setMe] = useState(null);
  const [checked, setChecked] = useState(false);
  const { pinned, theme } = useUi();
  const collapsed = !pinned;
  const [peek, setPeek] = useState(false);          // bỏ ghim + rê chuột → mở tạm đè lên nội dung
  const peekTimer = useRef();
  const peekOn = () => { if (!collapsed) return; clearTimeout(peekTimer.current); peekTimer.current = setTimeout(() => setPeek(true), 120); };
  const peekOff = () => { clearTimeout(peekTimer.current); peekTimer.current = setTimeout(() => setPeek(false), 200); };
  const [mobileNav, setMobileNav] = useState(false);
  const [assetId, setAssetId] = useState(null);
  const [checkEdit, setCheckEdit] = useState(null); // {id} | {new:true, preset}
  const [tick, setTick] = useState(0);
  const [appName, setAppName] = useState("IT Ops Workspace");
  const [version, setVersion] = useState("");
  const [notice, setNotice] = useState(() => { try { return sessionStorage.getItem("itops_logout_reason") || ""; } catch { return ""; } });   // lý do bị đăng xuất

  useEffect(() => {
    const h = () => { setRoute(parseHash()); setMobileNav(false); };
    window.addEventListener("hashchange", h);
    _listeners.add(h);
    const out = (e) => { if (e && e.detail) setNotice(e.detail); setMe(null); };   // e.detail: lý do (hết phiên, không thao tác…)
    const need2fa = () => api.get("/auth/me").then(setMe).catch(() => {});
    window.addEventListener("itops:logout", out);
    window.addEventListener("itops:need2fa", need2fa);
    fetch("/api/health").then((r) => r.json()).then((d) => { setAppName(d.app_name); setVersion(d.version); document.title = d.app_name; }).catch(() => {});
    return () => { _listeners.delete(h); window.removeEventListener("hashchange", h); window.removeEventListener("itops:logout", out); window.removeEventListener("itops:need2fa", need2fa); };
  }, []);
  useEffect(() => {
    // phiên nằm trong cookie HttpOnly (JS không đọc được); cookie gợi ý itops_auth=1 cho biết có nên hỏi server
    if (!/(^|;\s*)itops_auth=1/.test(document.cookie)) { setChecked(true); return; }
    api.get("/auth/me").then(setMe).catch(() => {}).finally(() => setChecked(true));
  }, []);
  const logout = useCallback(async () => {
    try { await api.post("/auth/logout"); } catch { /* phiên đã hết hạn thì thôi */ }
    try { sessionStorage.removeItem("itops_logout_reason"); } catch { /* bỏ qua */ }
    setNotice(""); setMe(null); go("dashboard");
  }, []);

  const nav = useCallback((page, id, params) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    go(`${page}${id ? "/" + id : ""}${qs}`);
  }, []);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  const ctx = {
    me, setMe, logout, route, nav, tick, refresh, theme, isAdmin: me?.role === "admin",
    openAsset: (id) => setAssetId(id),
    openCheck: (id) => setCheckEdit({ id }),
    newCheck: (preset) => setCheckEdit({ isNew: true, preset }),
  };

  const alertsCount = useApi(me && !me.need_2fa_setup ? "/alerts?status=active&limit=500" : null, { interval: 30000, deps: [tick] });

  if (!checked) return null;
  if (!me) return <Login appName={appName} notice={notice} onLogin={(u) => { setNotice(""); try { sessionStorage.removeItem("itops_logout_reason"); } catch { /* bỏ qua */ } setMe(u); }} />;
  if (me.need_2fa_setup) return <ForcedTwoFactor me={me} onDone={(u) => setMe(u)} onLogout={logout} />;

  const curQ = new URLSearchParams(route.params).toString().replace(/%2C/g, ",");
  const isActive = (n) => n.key === route.page && (n.key !== "assets" || (n.q ?? "") === curQ);
  const Page = { dashboard: Dashboard, map: MapPage, sites: Sites, assets: Assets, critical: Critical, checks: Checks, resources: Resources, automation: Automation, alerts: Alerts, agents: Agents, logs: Logs, audit: Audit, settings: SettingsPage }[route.page] || Dashboard;
  const openAlerts = alertsCount.data?.length || 0;

  return (
    <AppCtx.Provider value={ctx}>
      <div className={`app ${collapsed ? "collapsed" : ""} ${mobileNav ? "mobile-nav" : ""}`}>
        <header className="topbar">
          <button className="icon-btn" title={collapsed ? "Ghim thanh bên" : "Bỏ ghim thanh bên"}
            onClick={() => (window.innerWidth < 760 ? setMobileNav(!mobileNav) : (setPinned(collapsed), setPeek(false)))}>
            {window.innerWidth < 760 ? <Menu size={17} /> : <PanelLeft size={17} />}
          </button>
          <div className="brand"><div className="brand-logo">IT</div><span>{appName}</span></div>
          <nav className="top-links">
            <button className="top-link" onClick={() => nav("alerts")}>Cảnh báo {openAlerts > 0 && <span className="pill-count">{openAlerts}</span>}</button>
            <button className="top-link" onClick={() => nav("checks")}>Giám sát</button>
            <button className="top-link" onClick={() => nav("resources")}>Tài nguyên</button>
            <button className="top-link" onClick={() => nav("logs")}>Log thiết bị</button>
            <button className="top-link" onClick={() => nav("audit")}>Audit log</button>
          </nav>
          <div className="top-right">
            <ClockBox />
            <div className="hide-mobile"><ThemeSwitch /></div>
            <GlobalSearch />
            <UserMenu me={me} onLogout={logout} />
          </div>
        </header>
        {mobileNav && <div className="nav-backdrop" onClick={() => setMobileNav(false)} />}
        <aside className={`sidebar ${collapsed && peek ? "peek" : ""}`} onMouseEnter={peekOn} onMouseLeave={peekOff}>
          {NAV.map((n, i) => n.group ? <div key={i} className="nav-group">{n.group}</div> : (
            <button key={i} className={`nav-item ${isActive(n) ? "active" : ""}`} title={n.label}
              onClick={() => (n.key === "assets" ? go(`assets${n.q ? "?" + n.q : ""}`) : nav(n.key))}>
              <n.icon size={18} /><span>{n.label}</span>
              {n.badge && openAlerts > 0 && <span className="count" style={{ color: "var(--fail)", fontWeight: 700 }}>{openAlerts}</span>}
            </button>
          ))}
          <div className="side-foot">
            <ApiStatus />
            <div className="row faint"><span>Phiên bản {version}</span></div>
          </div>
        </aside>
        <main className="main">
          <Page key={route.page + curQ} />
        </main>
      </div>
      {assetId && <AssetDrawer id={assetId} onClose={() => setAssetId(null)} />}
      {checkEdit && <CheckForm edit={checkEdit} onClose={() => setCheckEdit(null)} onSaved={() => { setCheckEdit(null); refresh(); }} />}
    </AppCtx.Provider>
  );
}

export { TypeIcon };
