import React, { useEffect, useState } from "react";
import { ShieldAlert, Flame, Sparkles, RefreshCw, Search, ExternalLink, Skull } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Table, Drawer, Empty, Select, useToast, timeAgo, fmtTime, Pager, usePerPage } from "../ui";
import { ATTACK_OPTS, AttackTags } from "./Vulnerabilities";

// CVE module – part 2: catalogue of recent CVEs (NVD) enriched with CISA KEV and FIRST EPSS.
// Matching CVEs to our own assets comes in part 3.

const SEV = { critical: ["Critical", "fail"], high: ["High", "warn"], medium: ["Medium", "info"], low: ["Low", ""], none: ["None", ""] };
const PERIODS = [["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["0", "All loaded"]];
const SEL = { width: "auto", flex: "0 0 auto" };
const SORTS = [["published", "Newest"], ["cvss", "Highest CVSS"], ["epss", "Highest EPSS"], ["kev", "Recently added to KEV"], ["cve", "CVE ID"], ["product", "Product"]];
const SORT_DIR = { published: "desc", cvss: "desc", epss: "desc", kev: "desc", cve: "asc", product: "asc" };
const COL_SORT = { cve_id: "cve", cvss_score: "cvss", products: "product" };   // table column → server sort key

// part 5: which of our machines have this CVE (from Operations › Vulnerabilities)
function Affected({ id }) {
  const { data } = useApi(`/vuln/findings?cve=${encodeURIComponent(id)}&status=open&triage=all&limit=200`);
  const items = data?.items || [];
  return <>
    <h4>Our machines {data && <span className="muted small">({data.total})</span>}</h4>
    {!data ? <div className="small muted">Loading…</div> : !items.length ? <div className="small faint">None of our machines is reported with this CVE.</div>
      : <div className="stack" style={{ gap: 4 }}>{items.map((f) => <div key={f.id} className="small">
          <span className={`badge ${{ P1: "fail", P2: "warn", P3: "info" }[f.band] || ""}`}>{f.band} {f.priority}</span> <b>{f.target_name}</b>
          <span className="muted"> {f.target_ip}{f.packages?.[0] && ` · ${f.packages[0]}`}{f.due_at && ` · due ${f.due_at.slice(0, 10)}`}{f.triage && ` · ${f.triage.replace("_", " ")}`}</span>
        </div>)}</div>}
    {data && data.total > items.length && <div className="small muted" style={{ marginTop: 6 }}>Showing {items.length} of {data.total}. See all in Operations › Vulnerabilities (filter by this CVE).</div>}
  </>;
}

export function SevBadge({ c }) {
  const [label, tone] = SEV[c.cvss_severity] || ["Not scored", ""];
  return <span className={`badge ${tone}`} style={{ whiteSpace: "nowrap" }} title={c.cvss_version ? `CVSS ${c.cvss_version}` : "NVD has not scored this CVE yet"}>
    {label}{c.cvss_score != null && ` · ${c.cvss_score}`}</span>;
}

export function Epss({ c }) {
  if (c.epss == null) return <span className="faint">—</span>;
  const pct = c.epss * 100;
  return <span title={`Probability of exploitation in the next 30 days. Higher than ${Math.round((c.epss_percentile || 0) * 100)}% of all CVEs.`}
    style={{ whiteSpace: "nowrap", color: pct >= 10 ? "var(--fail)" : pct >= 1 ? "var(--warn)" : undefined, fontWeight: pct >= 10 ? 600 : undefined }}>
    {pct >= 1 ? pct.toFixed(0) : pct.toFixed(2)}%</span>;
}

export function Kev({ c }) {
  if (!c.kev) return <span className="faint">—</span>;
  return <span style={{ whiteSpace: "nowrap" }} title={`Known exploited (CISA KEV) since ${c.kev_added?.slice(0, 10) || "?"}${c.kev_due ? ` · federal due date ${c.kev_due.slice(0, 10)}` : ""}`}>
    <span className="badge fail">Exploited</span>{c.kev_ransomware && <span className="badge fail" style={{ marginLeft: 4 }} title="Used in ransomware campaigns"><Skull size={12} /></span>}
  </span>;
}

function SyncStatus({ s, isAdmin, onSync, busy }) {
  const feeds = [["nvd", "NVD"], ["kev", "CISA KEV"], ["epss", "EPSS"]];
  return (
    <div className="card card-pad" style={{ marginBottom: 14 }}>
      <div className="row" style={{ gap: 14, flexWrap: "wrap", alignItems: "center" }}>
        <b>Feeds</b>
        {feeds.map(([k, label]) => {
          const f = s?.[k];
          return <span key={k} className="small" title={f?.error || ""}>
            <span className={`badge ${!f ? "" : f.ok ? "ok" : "fail"}`}>{label}</span>{" "}
            <span className="muted">{!f ? "never synced" : f.ok ? `updated ${timeAgo(f.at)}` : "failed – hover for details"}</span>
          </span>;
        })}
        {s?.running && <span className="small muted"><RefreshCw size={13} className="spin" /> Sync in progress…</span>}
        {isAdmin && <button className="btn sm" style={{ marginLeft: "auto" }} onClick={onSync} disabled={busy || s?.running}>
          <RefreshCw size={14} /> Sync now</button>}
      </div>
    </div>
  );
}

function CveDrawer({ id, onClose }) {
  const { data: c, error } = useApi(`/cves/${id}`);
  if (error) return <Drawer title={id} onClose={onClose} wide><div className="small" style={{ color: "var(--fail)" }}>{error}</div></Drawer>;
  if (!c) return <Drawer title={id} onClose={onClose} wide><div className="small muted">Loading…</div></Drawer>;
  return (
    <Drawer title={<>{c.cve_id} <SevBadge c={c} /></>} onClose={onClose} wide
      actions={<a className="btn sm" href={c.nvd_url} target="_blank" rel="noreferrer"><ExternalLink size={14} /> Open on NVD</a>}>
      <p style={{ marginTop: 0 }}>{c.description || <span className="faint">No description yet.</span>}</p>
      <div className="kv">
        <div>Published</div><div>{fmtTime(c.published)} <span className="small muted">· NVD status: {c.status || "—"}</span></div>
        <div>CVSS</div><div>{c.cvss_score ?? "—"} {c.cvss_vector && <span className="small mono muted">{c.cvss_vector}</span>}</div>
        <div>EPSS</div><div><Epss c={c} />{c.epss_percentile != null && <span className="small muted"> · percentile {Math.round(c.epss_percentile * 100)}</span>}</div>
        <div>Known exploited</div><div>{c.kev
          ? <><Kev c={c} /> <span className="small">since {c.kev_added?.slice(0, 10)}{c.kev_due && ` · due ${c.kev_due.slice(0, 10)}`}</span>
            {c.kev_action && <div className="small muted" style={{ marginTop: 4 }}>{c.kev_action}</div>}</>
          : <span className="faint">Not in CISA KEV</span>}</div>
        <div>Weakness</div><div className="small">{c.cwe?.length ? c.cwe.join(", ") : "—"}</div>
        <div>Affected products</div><div className="small">{c.products?.length ? c.products.join(", ") : <span className="faint">Not analysed yet</span>}</div>
      </div>
      <Affected id={c.cve_id} />
      {c.references?.length > 0 && <>
        <h4>References</h4>
        <div className="stack" style={{ gap: 4 }}>
          {c.references.map((r) => <div key={r.url} className="small" style={{ wordBreak: "break-all" }}>
            <a href={r.url} target="_blank" rel="noreferrer">{r.url}</a>{r.tags?.length > 0 && <span className="muted"> · {r.tags.join(", ")}</span>}</div>)}
        </div>
      </>}
    </Drawer>
  );
}

export default function Cves() {
  const { isAdmin } = useApp();
  const toast = useToast();
  const [q, setQ] = useState("");
  const [days, setDays] = useState("30");
  const [sev, setSev] = useState("");
  const [kev, setKev] = useState(false);
  const [sort, setSort] = useState("published");
  const [dir, setDir] = useState("desc");
  const [attack, setAttack] = useState("");
  const [per, setPer] = usePerPage("itops_cve_per");
  const [page, setPage] = useState(0);
  const pickSort = (k) => { setSort(k); setDir(SORT_DIR[k] || "asc"); };
  const headSort = (col) => { const k = COL_SORT[col] || col; if (k === sort) setDir(dir === "asc" ? "desc" : "asc"); else pickSort(k); };
  useEffect(() => { setPage(0); }, [q, days, sev, kev, sort, dir, per, attack]);
  const [open, setOpen] = useState(null);
  const [busy, setBusy] = useState(false);
  const params = new URLSearchParams({ q, days, severity: sev, kev: kev ? "true" : "false", sort, dir, attack, limit: String(per), offset: String(page * per) }).toString();
  const sum = useApi("/cves/summary", { interval: 15000 });
  const list = useApi(`/cves?${params}`, { deps: [params] });
  const s = sum.data;

  const sync = async () => {
    setBusy(true);
    try {
      const r = await api.post("/cves/sync");
      toast(r.message);
      setTimeout(() => { sum.reload(); list.reload(); }, 3000);
    } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };

  const items = (list.data?.items || []).map((c) => ({ ...c, id: c.cve_id }));
  return (
    <>
      <PageHead crumb="Operations › CVEs" title="CVEs"
        desc="Newly published vulnerabilities (NVD) with real-world exploitation (CISA KEV) and exploit probability (EPSS). Which of your machines are affected: Operations › Vulnerabilities." />
      <div className="stats" style={{ marginBottom: 14 }}>
        <Stat icon={Sparkles} label="New in 7 days" value={s?.new_7d} sub={`${s?.critical_7d ?? 0} critical`} tone={s?.critical_7d ? "fail" : ""}
          onClick={() => { setDays("7"); setKev(false); setSev(""); }} />
        <Stat icon={Flame} label="Added to KEV in 30 days" value={s?.kev_30d} sub="exploited in the wild" tone={s?.kev_30d ? "fail" : ""}
          onClick={() => { setDays("30"); setKev(true); setSev(""); pickSort("kev"); }} />
        <Stat icon={ShieldAlert} label="Known exploited (KEV)" value={s?.kev_total} sub="in the catalogue"
          onClick={() => { setDays("0"); setKev(true); setSev(""); pickSort("kev"); }} />
        <Stat icon={Search} label="CVEs loaded" value={s?.total} sub={s?.sync?.last_run ? `synced ${timeAgo(s.sync.last_run)}` : "not synced yet"} />
      </div>
      <SyncStatus s={s?.sync} isAdmin={isAdmin} onSync={sync} busy={busy} />
      <div className="card">
        <div className="card-pad" style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <div className="search" style={{ flex: "1 1 260px" }}>
            <Search size={16} />
            <input placeholder="Search CVE ID, product (e.g. fortinet, exchange, esxi) or text…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <Select value={days} onChange={setDays} options={PERIODS} style={SEL} />
          <Select value={sev} onChange={setSev} options={[["", "All severities"], ["critical", "Critical"], ["critical,high", "Critical + High"], ["medium", "Medium"], ["low", "Low"]]} style={SEL} />
          <Select value={attack} onChange={setAttack} options={[["", "All attack types"], ...ATTACK_OPTS]} style={SEL} title="Kind of attack (from the CWE weakness type)" />
            <Select value={sort} onChange={pickSort} options={SORTS} style={SEL} title="Sort order (or click a column header; click again to reverse)" />
          <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={kev} onChange={(e) => setKev(e.target.checked)} /> Known exploited only</label>
          <span className="small muted">{list.data ? `${list.data.total} CVEs` : ""}</span>
        </div>
        <Table rows={items} onRow={(c) => setOpen(c.cve_id)} onSort={headSort}
          sortBy={{ key: Object.keys(COL_SORT).find((c) => COL_SORT[c] === sort) || sort, dir: dir === "asc" ? 1 : -1 }}
          empty={<Empty icon={ShieldAlert} title={s?.total ? "No CVE matches the filters" : "The catalogue is empty"}>
            {s?.total ? "Widen the period or clear the filters." : isAdmin ? "Press “Sync now” – the first sync downloads the last 120 days and can take a few minutes." : "Ask an administrator to run the first sync."}
          </Empty>}
          columns={[
            { key: "cve_id", label: "CVE", render: (c) => <span className="mono small" style={{ whiteSpace: "nowrap" }}>{c.cve_id}</span> },
            { key: "published", label: "Published", sort: (c) => c.published || "", render: (c) => <span className="small" style={{ whiteSpace: "nowrap" }}>{c.published?.slice(0, 10) || "—"}</span> },
            { key: "cvss_score", label: "Severity", sort: (c) => c.cvss_score ?? -1, render: (c) => <SevBadge c={c} /> },
            { key: "kev", label: "KEV", sort: (c) => (c.kev ? 1 : 0), render: (c) => <Kev c={c} /> },
            { key: "epss", label: "EPSS", sort: (c) => c.epss ?? -1, render: (c) => <Epss c={c} /> },
            { key: "products", label: "Product", sort: (c) => c.products?.[0] || "", render: (c) => <span className="small">{c.products?.length
              ? <>{c.products.slice(0, 2).join(", ")}{c.products.length > 2 && <span className="muted"> +{c.products.length - 2}</span>}</> : <span className="faint">not analysed</span>}</span> },
            { key: "description", label: "Description", sortable: false, render: (c) => <><span className="small muted" style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{c.description}</span><AttackTags list={c.attack} /></> },
          ]} />
        {list.data && list.data.total > 0 && <Pager total={list.data.total} per={per} page={page} onPer={setPer} onPage={setPage} label={`${list.data.total.toLocaleString()} CVEs`} />}
      </div>
      <div className="small muted" style={{ marginTop: 10 }}>
        Severity = CVSS base score (3.x preferred). KEV = listed by CISA as exploited in the wild. EPSS = probability of exploitation in the next 30 days.
        Prioritise: <b>KEV</b> first, then <b>high EPSS</b>, then CVSS.
      </div>
      {open && <CveDrawer id={open} onClose={() => setOpen(null)} />}
    </>
  );
}
