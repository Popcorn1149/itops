import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  LayoutDashboard, Map, Globe2, Shield, ShieldAlert, Bug, Server, Monitor, Network, HardDrive, ShieldCheck, Activity, Bell,
  ScrollText, Settings, Search, PanelLeft, Laptop, Clock, Boxes, LogOut, KeyRound, Menu, FileText, Gauge, Zap, ArrowDownUp,
} from "lucide-react";
import { getInitialLanguage, saveLanguage, translate, getDateLocale } from "./i18n";
import { useUi, setPinned } from "./theme";
import ThemeSwitch from "./components/ThemeSwitch";
import { api } from "./api";
import { ForcedTwoFactor } from "./components/AccountSecurity";
import { Dot, TypeIcon, useClickOutside, useApi, DEMO } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import MapPage from "./pages/MapPage";
import Cves from "./pages/Cves";
import Vulnerabilities from "./pages/Vulnerabilities";
import Report from "./pages/Report";
import Sites from "./pages/Sites";
import Assets, { AssetDrawer } from "./pages/Assets";
import Critical from "./pages/Critical";
import Checks, { CheckForm } from "./pages/Checks";
import Alerts from "./pages/Alerts";
import Audit from "./pages/Audit";
import Agents from "./pages/Agents";
import SettingsPage from "./pages/Settings";
import Logs from "./pages/Logs";
import Traffic from "./pages/Traffic";
import Resources from "./pages/Resources";
import Automation from "./pages/Automation";

const AppCtx = createContext(null);
export const useApp = () => useContext(AppCtx);

// Router uses hashes (#/page?x=y). The demo runs in an embedded artifact, so routes are kept in memory.
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

// Language switcher is hidden for now: the UI ships English-only until terminology is stable.
// Keep the i18n code; set to true to re-enable VN/EN switching (the saved choice is honoured again).
const SHOW_LANG_SWITCH = false;

const NAV = [
  { key: "dashboard", label: "Dashboard", tk: "dashboard", icon: LayoutDashboard },
  { group: "Infrastructure", tk: "infrastructure" },
  { key: "map", label: "System map", tk: "map", icon: Map },
  { key: "sites", label: "Sites", tk: "sites", icon: Globe2 },
  { key: "assets", q: "type=firewall", label: "Firewall", tk: "firewall", icon: Shield, types: ["firewall"] },
  { key: "assets", q: "type=switch,router,ap", label: "Network devices", tk: "networkDevices", icon: Network, types: ["switch", "router", "ap"] },
  { key: "assets", q: "type=host,server", label: "Physical Hosts", tk: "physicalHosts", icon: Server, types: ["host", "server"] },
  { key: "assets", q: "type=vm,container", label: "Virtual machines & containers", tk: "virtualMachines", icon: Monitor, types: ["vm", "container"] },
  { key: "assets", q: "type=nas,ups,printer,camera,device,other,service,website,cloud", label: "Other Devices", tk: "otherDevices", icon: HardDrive, types: ["nas", "ups", "printer", "camera", "device", "other", "service", "website", "cloud"] },
  { key: "assets", q: "", label: "All assets", tk: "allAssets", icon: Boxes },
  { group: "Operations", tk: "operations" },
  { key: "critical", label: "Critical systems", tk: "criticalSystems", icon: ShieldCheck },
  { key: "checks", label: "Monitoring", tk: "monitoring", icon: Activity },
  { key: "resources", label: "Resources", tk: "resources", icon: Gauge },
  { key: "traffic", label: "Network traffic", tk: "traffic", icon: ArrowDownUp },
  { key: "automation", label: "Automation", tk: "automation", icon: Zap },
  { key: "agents", label: "Workstation", tk: "endpoints", icon: Laptop },
  { key: "cves", label: "CVEs", tk: "cves", icon: ShieldAlert },
  { key: "vulns", label: "Vulnerabilities", tk: "vulns", icon: Bug },
  { key: "alerts", label: "Warning", tk: "alerts", icon: Bell, badge: true },
  { key: "logs", label: "Device Logs", tk: "deviceLogs", icon: FileText },
  { key: "audit", label: "Audit log", tk: "auditLog", icon: ScrollText },
  { key: "settings", label: "Settings", tk: "settings", icon: Settings },
];

// Live backend status: query /api/health every 30 seconds. Hidden in the demo when no backend is available.
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
        if (!r.ok || !d.db) setSt({ s: "fail", t: "Database error", ms });
        else if (d.scheduler === "stalled") setSt({ s: "warn", t: "Monitoring scheduler stopped", ms });
        else if (d.receivers_ok === false) setSt({ s: "warn", t: "API online · log receiver error", ms });
        else setSt({ s: "ok", t: d.scheduler === "off" ? "API online (scheduler disabled)" : "API online", ms });
      } catch { if (alive) setSt({ s: "fail", t: "Disconnected API" }); }
    };
    probe(); const i = setInterval(probe, 30000);
    return () => { alive = false; clearInterval(i); };
  }, []);
  if (DEMO || !st) return null;
  return <div className="row" title={st.ms != null ? `Response time: ${st.ms} ms · checked every 30 seconds` : "Unable to reach /api/health"}>
    <Dot status={st.s} pulse={st.s !== "ok"} /><span style={{ color: st.s === "ok" ? undefined : `var(--${st.s})` }}>{st.t}</span>
    {st.ms != null && st.s === "ok" && <span className="faint">· {st.ms} ms</span>}
  </div>;
}

function ClockBox({ locale = "vi-VN" }) {
  const [t, setT] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setT(new Date()), 1000); return () => clearInterval(i); }, []);
  return <div className="clock"><Clock size={14} /><b>{t.toLocaleTimeString(locale, { hour12: false })}</b>{t.toLocaleDateString(locale)}</div>;
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
      <input placeholder="Search servers, IPs, checks... (Ctrl+K)" value={q} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} />
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
          <div className="search-item" onClick={() => { setOpen(false); nav("settings", null, { tab: "account" }); }}><KeyRound size={15} />Password · 2FA · Sessions</div>
          <div style={{ padding: "6px 10px 8px", display: "flex", alignItems: "center", gap: 8 }}><span className="small muted grow">Appearance</span><ThemeSwitch /></div>
          <div className="search-item" onClick={onLogout}><LogOut size={15} />Sign out</div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [lang, setLangState] = useState(() => (SHOW_LANG_SWITCH ? getInitialLanguage() : "en"));
  const setLanguage = (next) => setLangState(saveLanguage(next));
  const [route, setRoute] = useState(parseHash());
  const [me, setMe] = useState(null);
  const [checked, setChecked] = useState(false);
  const { pinned, theme } = useUi();
  const collapsed = !pinned;
  const [peek, setPeek] = useState(false);          // when unpinned, hovering temporarily opens the sidebar over the content
  const peekTimer = useRef();
  const peekOn = () => { if (!collapsed) return; clearTimeout(peekTimer.current); peekTimer.current = setTimeout(() => setPeek(true), 120); };
  const peekOff = () => { clearTimeout(peekTimer.current); peekTimer.current = setTimeout(() => setPeek(false), 200); };
  const [mobileNav, setMobileNav] = useState(false);
  const [assetId, setAssetId] = useState(null);
  const [checkEdit, setCheckEdit] = useState(null); // {id} | {new:true, preset}
  const [tick, setTick] = useState(0);
  const [appName, setAppName] = useState("IT Ops Workspace");
  const [version, setVersion] = useState("");
  const [notice, setNotice] = useState(() => { try { return sessionStorage.getItem("itops_logout_reason") || ""; } catch { return ""; } });   // sign-out reason

  useEffect(() => {
    const h = () => { setRoute(parseHash()); setMobileNav(false); };
    window.addEventListener("hashchange", h);
    _listeners.add(h);
    const out = (e) => { if (e && e.detail) setNotice(e.detail); setMe(null); };   // e.detail: reason (session expired, inactivity, etc.)
    const need2fa = () => api.get("/auth/me").then(setMe).catch(() => {});
    window.addEventListener("itops:logout", out);
    window.addEventListener("itops:need2fa", need2fa);
    fetch("/api/health").then((r) => r.json()).then((d) => { setAppName(d.app_name); setVersion(d.version); document.title = d.app_name; }).catch(() => {});
    return () => { _listeners.delete(h); window.removeEventListener("hashchange", h); window.removeEventListener("itops:logout", out); window.removeEventListener("itops:need2fa", need2fa); };
  }, []);
  useEffect(() => {
    // session is stored in an HttpOnly cookie (not readable by JavaScript); the itops_auth=1 cookie hint indicates whether the server should be queried
    if (!/(^|;\s*)itops_auth=1/.test(document.cookie)) { setChecked(true); return; }
    api.get("/auth/me").then(setMe).catch(() => {}).finally(() => setChecked(true));
  }, []);
  const logout = useCallback(async () => {
    try { await api.post("/auth/logout"); } catch { /* ignore if the session has already expired */ }
    try { sessionStorage.removeItem("itops_logout_reason"); } catch { /* ignore */ }
    setNotice(""); setMe(null); go("dashboard");
  }, []);

  const nav = useCallback((page, id, params) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    go(`${page}${id ? "/" + id : ""}${qs}`);
  }, []);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  const t = (key, params) => translate(lang, key, params);
  const ctx = {
    appName,
    lang, setLanguage, t, dateLocale: getDateLocale(lang),
    me, setMe, logout, route, nav, tick, refresh, theme, isAdmin: me?.role === "admin",
    openAsset: (id) => setAssetId(id),
    openCheck: (id) => setCheckEdit({ id }),
    newCheck: (preset) => setCheckEdit({ isNew: true, preset }),
  };

  const alertsCount = useApi(me && !me.need_2fa_setup ? "/alerts?status=active&limit=500" : null, { interval: 30000, deps: [tick] });

  if (!checked) return null;
  if (!me) return <Login appName={appName} notice={notice} onLogin={(u) => { setNotice(""); try { sessionStorage.removeItem("itops_logout_reason"); } catch { /* ignore */ } setMe(u); }} />;
  if (me.need_2fa_setup) return <ForcedTwoFactor me={me} onDone={(u) => setMe(u)} onLogout={logout} />;

  const curQ = new URLSearchParams(route.params).toString().replace(/%2C/g, ",");
  const isActive = (n) => n.key === route.page && (n.key !== "assets" || (n.q ?? "") === curQ);
  const Page = { dashboard: Dashboard, map: MapPage, sites: Sites, assets: Assets, critical: Critical, checks: Checks, resources: Resources, automation: Automation, alerts: Alerts, agents: Agents, cves: Cves, vulns: Vulnerabilities, report: Report, logs: Logs, traffic: Traffic, audit: Audit, settings: SettingsPage }[route.page] || Dashboard;
  const openAlerts = alertsCount.data?.length || 0;

  return (
    <AppCtx.Provider value={ctx}>
      <div className={`app ${collapsed ? "collapsed" : ""} ${mobileNav ? "mobile-nav" : ""}`}>
        <header className="topbar">
          <button className="icon-btn" title={collapsed ? "Pin sidebar" : "Unpin sidebar"}
            onClick={() => (window.innerWidth < 760 ? setMobileNav(!mobileNav) : (setPinned(collapsed), setPeek(false)))}>
            {window.innerWidth < 760 ? <Menu size={17} /> : <PanelLeft size={17} />}
          </button>
          <div className="brand"><div className="brand-logo">IT</div><span>{appName}</span></div>
          <nav className="top-links">
            <button className="top-link" onClick={() => nav("alerts")}>{t("nav.alerts")} {openAlerts > 0 && <span className="pill-count">{openAlerts}</span>}</button>
            <button className="top-link" onClick={() => nav("checks")}>{t("nav.monitoring")}</button>
            <button className="top-link" onClick={() => nav("resources")}>{t("nav.resources")}</button>
            <button className="top-link" onClick={() => nav("logs")}>{t("nav.deviceLogs")}</button>
            <button className="top-link" onClick={() => nav("audit")}>{t("nav.auditLog")}</button>
          </nav>
          <div className="top-right">
            <ClockBox locale={getDateLocale(lang)} />
            {SHOW_LANG_SWITCH && <button className="btn sm" title="Vietnamese / English" onClick={() => setLanguage(lang === "vi" ? "en" : "vi")}
              style={{ fontWeight: 600, minWidth: 44 }}>{lang === "vi" ? "VN" : "EN"}</button>}
            <div className="hide-mobile"><ThemeSwitch /></div>
            <GlobalSearch />
            <UserMenu me={me} onLogout={logout} />
          </div>
        </header>
        {mobileNav && <div className="nav-backdrop" onClick={() => setMobileNav(false)} />}
        <aside className={`sidebar ${collapsed && peek ? "peek" : ""}`} onMouseEnter={peekOn} onMouseLeave={peekOff}>
          {NAV.map((n, i) => n.group ? <div key={i} className="nav-group">{t(`nav.${n.tk}`)}</div> : (
            <button key={i} className={`nav-item ${isActive(n) ? "active" : ""}`} title={t(`nav.${n.tk}`)}
              onClick={() => (n.key === "assets" ? go(`assets${n.q ? "?" + n.q : ""}`) : nav(n.key))}>
              <n.icon size={18} /><span>{t(`nav.${n.tk}`)}</span>
              {n.badge && openAlerts > 0 && <span className="count" style={{ color: "var(--fail)", fontWeight: 700 }}>{openAlerts}</span>}
            </button>
          ))}
          <div className="side-foot">
            <ApiStatus />
            <div className="row faint"><span>Version {version}</span></div>
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
