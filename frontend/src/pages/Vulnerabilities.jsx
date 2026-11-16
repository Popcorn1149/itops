import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Bug, ShieldAlert, Flame, Monitor, HelpCircle, Search, RefreshCw, Plus, Upload, Plug, Pencil, Link2, GitCompare, ExternalLink, AlertTriangle,
  LayoutDashboard, List, Server, Database, SlidersHorizontal, Download, Clock, CheckCircle2, X, Send, Wrench, Package } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Stat, Table, Drawer, Modal, Empty, Select, Field, Input, Toggle, Tabs, useToast, timeAgo, fmtTime, Pager } from "../ui";
import { SevBadge, Epss, Kev } from "./Cves";

// CVE module – part 3: which CVE is on which machine.
// IT Ops is the core (machines, findings, history, triage); sources are replaceable adapters (Wazuh, file import, CPE matching).
// Severity / priority always come from the IT Ops CVE catalogue – never from a source.

const SEL = { width: "auto", flex: "0 0 auto" };
const CONF = { high: ["High", "ok"], medium: ["Medium", "warn"], low: ["Low", "fail"] };
const STATUS = { open: ["Open", "fail"], fixed: ["Fixed", "ok"], source_off: ["Source off", ""] };
const TRIAGE = { false_positive: "False positive", accepted: "Risk accepted" };
const BAND_TONE = { P1: "fail", P2: "warn", P3: "info", P4: "" };
const SLA = { overdue: ["Overdue", "fail"], due_soon: ["Due soon", "warn"], on_track: ["On track", "ok"], awaiting_verification: ["Not started", ""] };

function Prio({ band, value }) {
  return <span className={`badge ${BAND_TONE[band] || ""}`} style={{ whiteSpace: "nowrap" }}
    title="Priority 0–100 computed by IT Ops: CVSS, exploited (KEV), EPSS and how important the machine is">{band}{value != null && ` · ${value}`}</span>;
}

function Due({ f }) {
  if (f.sla_state === "none" || !f.sla_state) return <span className="faint small">—</span>;
  const [label, tone] = SLA[f.sla_state] || [f.sla_state, ""];
  return <span style={{ whiteSpace: "nowrap" }} title={f.sla_state === "awaiting_verification" ? "The deadline starts when the finding is confirmed (verified, high confidence or two sources)" : ""}>
    <span className={`badge ${tone}`}>{f.sla_state === "overdue" ? `${f.overdue_days} d overdue` : label}</span>
    {f.due_at && f.sla_state !== "overdue" && <span className="small muted"> {f.due_at.slice(0, 10)}</span>}
  </span>;
}

function ConfBadge({ f }) {
  const [label, tone] = CONF[f.confidence] || [f.confidence, ""];
  return <span style={{ whiteSpace: "nowrap" }}>
    <span className={`badge ${tone}`} title="How sure the source is that this CVE is really on the machine (not how dangerous it is)">{label}</span>
    {f.needs_verification && <span className="badge outline" style={{ marginLeft: 4 }} title="Medium / low confidence and seen by one source only – confirm before patching">verify</span>}
    {f.verified && <span className="badge ok" style={{ marginLeft: 4 }}>verified</span>}
  </span>;
}

function StatusBadge({ f }) {
  const [label, tone] = STATUS[f.status] || [f.status, ""];
  return <span style={{ whiteSpace: "nowrap" }}>
    <span className={`badge ${tone}`} title={f.status === "source_off" ? "Only disabled sources reported it – unknown, not fixed" : ""}>{label}</span>
    {f.triage && <span className="badge info" style={{ marginLeft: 4 }}>{TRIAGE[f.triage]}</span>}
    {f.stale && <span className="badge warn" style={{ marginLeft: 4 }} title="The source has not synced successfully for a while – data may be old">stale</span>}
  </span>;
}

function Sev({ f }) {
  return <span title={f.score_source === "source" ? "Not in the IT Ops catalogue yet – showing the source's score until NVD is synced" : ""}>
    <SevBadge c={f} />{f.score_source === "source" && <span className="faint small"> *</span>}</span>;
}

// ------------------------------------------------------------------ sources
function SourceCard({ s, isAdmin, onEdit, onChanged, onUnmatched, onImport }) {
  const toast = useToast();
  const [busy, setBusy] = useState("");
  const st = s.state || {};
  const act = async (what) => {
    setBusy(what);
    try {
      if (what === "test") {
        const r = await api.post(`/vuln/sources/${s.id}/test`);
        if (r.ok) toast(`Connected${r.version ? ` · Wazuh ${r.version}${r.tested ? "" : " (not the tested version 4.14 – check results)"}` : ""}${r.agents != null ? ` · ${r.agents} agents` : ""}${r.vulnerability_documents != null ? ` · ${r.vulnerability_documents} vulnerability records` : ""}`);
        else toast(r.error, true);
      } else if (what === "sync") {
        await api.post(`/vuln/sources/${s.id}/sync`);
        toast("Sync started");
        setTimeout(onChanged, 2500);
      } else if (what === "toggle") {
        await api.put(`/vuln/sources/${s.id}`, { enabled: !s.enabled });
        toast(s.enabled ? "Source disabled – its findings show as “source off”, never as fixed" : "Source enabled");
        onChanged();
      }
    } catch (e) { toast(e.message, true); } finally { setBusy(""); }
  };
  const statusText = st.running ? "syncing…" : !st.at ? "never synced" : st.ok ? `synced ${timeAgo(st.at)}` : `failed ${timeAgo(st.at)}`;
  return (
    <div className="card card-pad" style={{ flex: "1 1 300px", minWidth: 280, opacity: s.enabled ? 1 : 0.65 }}>
      <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <b>{s.name}</b>
        {!s.builtin && <span className="badge outline">{s.kind_label}</span>}
        {!s.enabled && <span className="badge">disabled</span>}
      </div>
      <div className="small" style={{ marginTop: 6, display: "flex", gap: 10, flexWrap: "wrap" }}>
        <span><span className={`badge ${st.running ? "info" : !st.at ? "" : st.ok ? "ok" : "fail"}`}>{statusText}</span></span>
        {s.stale && <span className="badge warn" title={`No successful sync in the last ${s.stale_hours} hours`}><AlertTriangle size={12} /> stale</span>}
        <span className="muted">confidence: <b>{s.confidence}</b></span>
        {st.findings != null && <span className="muted">{st.findings} CVE×machine</span>}
        {st.info?.version && <span className="muted" title={st.info.tested ? "Tested version" : "Not the tested version (4.14) – see README → Wazuh upgrade checklist"}>
          Wazuh {st.info.version}{!st.info.tested && " ⚠"}</span>}
        {st.info?.file && <span className="muted">{st.info.file}</span>}
      </div>
      {st.ok === false && st.error && <div className="small" style={{ color: "var(--fail)", marginTop: 6 }}>{st.error}</div>}
      {s.config?.verify_tls === false && <div className="small" style={{ color: "var(--warn)", marginTop: 6 }}>TLS certificate check is OFF – paste Wazuh's root CA instead.</div>}
      <div className="row" style={{ gap: 6, marginTop: 10, flexWrap: "wrap" }}>
        {st.unmatched_count > 0 && <button className="btn sm" onClick={() => onUnmatched(s)}><Link2 size={14} /> {st.unmatched_count} unmatched hosts</button>}
        {isAdmin && <>
          {s.kind === "wazuh" && <button className="btn sm" disabled={!!busy} onClick={() => act("test")}><Plug size={14} /> Test</button>}
          {s.scheduled && <button className="btn sm" disabled={!!busy || !s.enabled || st.running} onClick={() => act("sync")}><RefreshCw size={14} /> Sync now</button>}
          {s.kind === "file" && <button className="btn sm" disabled={!s.enabled} onClick={() => onImport(s)}><Upload size={14} /> Import file</button>}
          <button className="btn sm ghost" onClick={() => onEdit(s)}><Pencil size={14} /> Edit</button>
          <button className="btn sm ghost" disabled={!!busy} onClick={() => act("toggle")}>{s.enabled ? "Disable" : "Enable"}</button>
        </>}
      </div>
    </div>
  );
}

const WAZUH_FIELDS = [
  ["api_url", "Wazuh API URL", "https://<wazuh-ip>:55000"], ["username", "API user (read-only)"], ["password", "API password", "", "password"],
  ["indexer_url", "Wazuh indexer URL", "https://<wazuh-ip>:9200"], ["indexer_username", "Indexer user (read-only)"],
  ["indexer_password", "Indexer password", "", "password"], ["index", "Vulnerability index", "wazuh-states-vulnerabilities-*"],
  ["interval_hours", "Sync every (hours)", "6", "number"],
];

function SourceModal({ init, kinds, onClose, onSaved }) {
  const toast = useToast();
  const isNew = !init.id;
  const kind = init.kind;
  const def = kinds.find((k) => k.kind === kind);
  const [f, setF] = useState({ name: init.name || (kind === "wazuh" ? "Wazuh" : "Scanner export"), confidence: init.confidence || def?.confidence || "high",
    config: { ...(def?.defaults || {}), ...(init.config || {}) } });
  const set = (k, v) => setF({ ...f, config: { ...f.config, [k]: v } });
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      const cfg = { ...f.config };
      if (cfg.interval_hours !== undefined) cfg.interval_hours = Number(cfg.interval_hours) || 6;
      if (cfg.stale_days !== undefined) cfg.stale_days = Number(cfg.stale_days) || 30;
      if (isNew) await api.post("/vuln/sources", { kind, name: f.name, confidence: f.confidence, config: cfg });
      else await api.put(`/vuln/sources/${init.id}`, { name: f.name, confidence: f.confidence, config: cfg });
      toast("Saved");
      onSaved();
    } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };
  return (
    <Modal title={isNew ? `Add source – ${def?.label || kind}` : `Edit – ${init.name}`} onClose={onClose} width={720}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <Field label="Name"><Input value={f.name} onChange={(v) => setF({ ...f, name: v })} disabled={init.builtin} /></Field>
        <Field label="Confidence of its results" hint="High = exact package/version match. Medium / low results are flagged “verify” until confirmed. This never changes severity or priority.">
          <Select value={f.confidence} onChange={(v) => setF({ ...f, confidence: v })} options={[["high", "High"], ["medium", "Medium"], ["low", "Low"]]} /></Field>
        {kind === "wazuh" && WAZUH_FIELDS.map(([k, label, ph, type]) => (
          <Field key={k} label={label} hint={type === "password" && f.config[k] === "__SECRET__" ? "Saved (encrypted). Type to replace." : undefined}>
            <Input value={f.config[k]} onChange={(v) => set(k, v)} placeholder={ph} type={type === "password" ? "password" : type === "number" ? "number" : "text"} autoComplete="off" />
          </Field>))}
        {kind === "wazuh" && <>
          <Field full label="Wazuh root CA certificate (root-ca.pem)" hint="Paste the PEM text so IT Ops can verify Wazuh's certificate. On the Wazuh server it is usually /etc/wazuh-indexer/certs/root-ca.pem.">
            <textarea className="input mono small" rows={4} value={f.config.ca_cert || ""} onChange={(e) => set("ca_cert", e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
          <Field full><Toggle checked={f.config.verify_tls !== false} onChange={(v) => set("verify_tls", v)} label="Verify TLS certificate (keep on – turning it off allows man-in-the-middle)" /></Field>
        </>}
        {kind === "file" && <Field label="Mark stale after (days)" hint="Imported results older than this are labelled stale.">
          <Input type="number" value={f.config.stale_days} onChange={(v) => set("stale_days", v)} /></Field>}
        {kind === "cpe" && <Field label="Run every (hours)"><Input type="number" value={f.config.interval_hours} onChange={(v) => set("interval_hours", v)} /></Field>}
      </div>
      {kind === "wazuh" && <div className="small muted" style={{ marginTop: 10 }}>
        IT Ops only reads from Wazuh. Use dedicated read-only users: API (agent list) and indexer (index <span className="mono">wazuh-states-vulnerabilities-*</span>, read).
        Tested with Wazuh 4.14.</div>}
    </Modal>
  );
}

function ImportModal({ s, onClose, onDone }) {
  const toast = useToast();
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const go = async () => {
    if (!file) return toast("Choose a file first", true);
    setBusy(true);
    try {
      const content = await file.text();
      const r = await api.post(`/vuln/sources/${s.id}/import`, { filename: file.name, content });
      toast(`Imported ${r.records} rows · ${r.findings} CVE×machine · ${r.new_findings} new · ${r.no_longer_seen} no longer listed${r.unmatched_count ? ` · ${r.unmatched_count} hosts unmatched` : ""}`);
      onDone();
    } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };
  return (
    <Modal title={`Import into “${s.name}”`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !file} onClick={go}><Upload size={14} /> Import</button></>}>
      <input type="file" accept=".csv,.json,.txt" onChange={(e) => setFile(e.target.files?.[0] || null)} />
      <div className="small muted" style={{ marginTop: 10 }}>
        CSV or JSON with at least a <b>host</b> (or IP) column and a <b>CVE</b> column. Optional: package, version, fixed_version, severity, score.
        A CSV exported from Wazuh Discover (<span className="mono">agent.name, vulnerability.id, package.name…</span>) works as-is.
        Every host in the file counts as fully scanned: its CVEs missing from the new file become “fixed”.
      </div>
    </Modal>
  );
}

function UnmatchedModal({ s, isAdmin, onClose, onChanged }) {
  const toast = useToast();
  const [q, setQ] = useState("");
  const [pick, setPick] = useState({});
  const targets = useApi(`/vuln/targets?q=${encodeURIComponent(q)}`, { deps: [q] });
  const save = async (ref, target) => {
    try {
      await api.put(`/vuln/sources/${s.id}/mapping`, { ref, target });
      toast(target === "ignore" ? "Host ignored" : "Mapped – applied on the next sync");
      onChanged();
    } catch (e) { toast(e.message, true); }
  };
  const opts = (targets.data || []).map((t) => [t.target, `${t.name}${t.ip ? ` (${t.ip})` : ""} · ${t.kind}`]);
  return (
    <Modal title={`Unmatched hosts – ${s.name}`} onClose={onClose} width={860}>
      <div className="small muted" style={{ marginBottom: 10 }}>
        These hosts could not be linked to an IT Ops machine safely (no unique serial, name or IP). IT Ops never guesses – pick the machine, or ignore the host.
      </div>
      {isAdmin && <div className="search" style={{ marginBottom: 10 }}><Search size={16} /><input placeholder="Find a machine by name or IP…" value={q} onChange={(e) => setQ(e.target.value)} /></div>}
      <Table rowKey="ref" rows={s.state?.unmatched || []} columns={[
        { key: "name", label: "Host in source", render: (h) => <><b>{h.name || h.ref}</b> <span className="small muted">#{h.ref}</span></> },
        { key: "ip", label: "IP", render: (h) => <span className="small mono">{h.ip || "—"}</span> },
        { key: "reason", label: "Why", render: (h) => <span className="small muted">{h.reason}</span> },
        ...(isAdmin ? [{ key: "map", label: "Map to", render: (h) => <div className="row" style={{ gap: 6 }}>
          <Select value={pick[h.ref] || ""} onChange={(v) => setPick({ ...pick, [h.ref]: v })} options={opts} placeholder="— machine —" style={{ minWidth: 200 }} />
          <button className="btn sm" disabled={!pick[h.ref]} onClick={() => save(h.ref, pick[h.ref])}>Map</button>
          <button className="btn sm ghost" onClick={() => save(h.ref, "ignore")}>Ignore</button></div> }] : []),
      ]} />
    </Modal>
  );
}

function CompareModal({ sources, onClose }) {
  const [a, setA] = useState(String(sources[0]?.id || ""));
  const [b, setB] = useState(String(sources[1]?.id || ""));
  const r = useApi(a && b && a !== b ? `/vuln/compare?a=${a}&b=${b}` : null, { deps: [a, b] });
  const d = r.data;
  const opts = sources.map((s) => [String(s.id), s.name]);
  return (
    <Modal title="Compare two sources (parallel run)" onClose={onClose} width={860}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <Select value={a} onChange={setA} options={opts} style={SEL} /> <span className="muted">vs</span> <Select value={b} onChange={setB} options={opts} style={SEL} />
      </div>
      {a === b ? <div className="small muted">Pick two different sources.</div> : !d ? <div className="small muted">Loading…</div> : <>
        <div className="stats" style={{ marginBottom: 12 }}>
          <Stat label="Machines in common" value={d.machines_in_common} />
          <Stat label="Seen by both" value={d.both} sub={d.agreement != null ? `${d.agreement}% agreement` : ""} tone="ok" />
          <Stat label={`Only ${d.a.name}`} value={d.only_a} tone={d.only_a ? "warn" : ""} />
          <Stat label={`Only ${d.b.name}`} value={d.only_b} tone={d.only_b ? "warn" : ""} />
        </div>
        <div className="small muted" style={{ marginBottom: 8 }}>Only machines both sources cover are compared. Switch off the old source once agreement is good enough for you.</div>
        {[["only_a_items", d.a.name], ["only_b_items", d.b.name]].map(([k, n]) => d[k].length > 0 && <div key={k} style={{ marginBottom: 10 }}>
          <b className="small">Only {n}</b>
          <div className="small mono" style={{ maxHeight: 160, overflow: "auto" }}>{d[k].map((x) => <div key={x.target + x.cve_id}>{x.target_name} · {x.cve_id}</div>)}</div>
        </div>)}
      </>}
    </Modal>
  );
}

// ------------------------------------------------------------------ finding detail
// ---------------------------------------------------------------- Remediation Mapping: playbook for one finding
const REM_STATUS = { fix_available: ["Fix available", "ok"], no_fix_yet: ["No fixed version yet", "warn"], mitigation_only: ["No fixed version yet", "warn"], check_version: ["Check installed version", "info"] };
const PHASE = [["fix", "Fix"], ["next", "Next"], ["mitigate", "Reduce risk now"], ["watch", "Watch"], ["remind", "Reminders"]];

function Step({ s }) {
  const color = s.kind === "check" ? (s.detail === "ok" ? "var(--ok)" : "var(--warn)") : undefined;
  return (
    <li style={{ marginBottom: 4, color }}>
      {s.text}
      {s.url && <> <a href={s.url} target="_blank" rel="noreferrer" title="Open"><ExternalLink size={12} /></a></>}
    </li>
  );
}

function RemediationPlaybook({ fid, isAdmin }) {
  const toast = useToast();
  const [refresh, setRefresh] = useState(0);
  const { data: p, error, reload } = useApi(`/vuln/findings/${fid}/remediation${refresh ? `?refresh=1&n=${refresh}` : ""}`, { deps: [refresh] });
  const loading = !!p?.advisory?.loading;
  useEffect(() => {                       // Microsoft data is fetched in the background → ask again until it is there
    if (!loading) return undefined;
    let n = 0;
    const t = setInterval(() => { n += 1; if (n > 30) clearInterval(t); else reload(); }, 3000);
    return () => clearInterval(t);
  }, [loading, reload]);
  if (error) return <div className="small" style={{ color: "var(--fail)" }}>{error}</div>;
  if (!p) return <div className="small muted">Loading…</div>;
  const [sl, sc] = REM_STATUS[p.status] || [p.status, ""];
  const copy = async () => {
    try { await navigator.clipboard.writeText(p.text); toast("Copied – paste it into the change request / ticket"); }
    catch { toast("Copy failed – select the text manually", true); }
  };
  const refs = p.references;
  const T = { fontSize: 13.5, lineHeight: 1.55 };            // one text size and weight for the whole tab
  const H = { fontSize: 13.5, fontWeight: 600, margin: "14px 0 4px" };
  return (
    <div data-testid="remediation" style={T}>
      <div className="row wrap" style={{ gap: 8 }}>
        <span className={`badge ${sc}`}>{sl}</span>
        {p.exploited && <span className="badge fail">Exploited in the wild</span>}
        <span className="grow">{p.title}</span>
        <button className="btn sm" onClick={copy} title="Plain text for a ticket or change request"><Download size={14} />Copy as text</button>
        {isAdmin && !loading && <button className="btn sm ghost" onClick={() => setRefresh((n) => n + 1)} title="Ask the vendor sources again now"><RefreshCw size={14} />Refresh</button>}
      </div>
      {loading && <div className="muted" style={{ marginTop: 8 }}><RefreshCw size={13} className="spin" /> Getting the fix details for this machine…</div>}
      {!loading && p.advisory.microsoft && p.advisory.error && (
        <div className="alert-box warn" style={{ marginTop: 8 }}>Microsoft could not be reached{p.advisory.found ? " – showing the last saved copy." : "."}</div>
      )}
      {p.facts.length > 0 && (
        <div className="kv" style={{ marginTop: 10 }}>
          {p.facts.map((x, i) => <React.Fragment key={i}><div>{x.label}</div><div>{x.value}</div></React.Fragment>)}
        </div>
      )}
      {PHASE.map(([key, label]) => {
        const items = p.steps.filter((x) => x.phase === key);
        if (!items.length) return null;
        return (
          <div key={key}>
            <div style={H}>{label}</div>
            <ul style={{ margin: 0, paddingLeft: 18 }}>{items.map((x, i) => <Step key={i} s={x} />)}</ul>
          </div>
        );
      })}
      <div style={H}>References</div>
      {[["Official", refs.official], ["Catalogues", refs.catalog], ["Other", refs.other]].map(([t, list]) => list.length > 0 && (
        <div key={t} style={{ marginBottom: 2 }}>
          {t}: {list.map((r, i) => <span key={r.url}>{i > 0 && " · "}<a href={r.url} target="_blank" rel="noreferrer">{r.title}</a></span>)}
        </div>
      ))}
      {refs.hidden_exploit_links > 0 && <div className="muted">Exploit / proof-of-concept links hidden: {refs.hidden_exploit_links}</div>}
    </div>
  );
}

function FindingDrawer({ id, isAdmin, onClose, onChanged }) {
  const toast = useToast();
  const { data: f, error, reload } = useApi(`/vuln/findings/${id}`);
  const [mode, setMode] = useState("");
  const [view, setView] = useState("remediation");
  const [note, setNote] = useState("");
  const [until, setUntil] = useState("");
  const act = async (action) => {
    try {
      await api.post(`/vuln/findings/${id}/triage`, { action, note, until: until || null });
      setMode(""); setNote(""); setUntil("");
      reload(); onChanged();
    } catch (e) { toast(e.message, true); }
  };
  if (error) return <Drawer title="Finding" onClose={onClose} wide><div className="small" style={{ color: "var(--fail)" }}>{error}</div></Drawer>;
  if (!f) return <Drawer title="Finding" onClose={onClose} wide><div className="small muted">Loading…</div></Drawer>;
  const c = f.cve;
  return (
    <Drawer title={<>{f.cve_id} <Sev f={f} /></>} onClose={onClose} wide
      actions={<a className="btn sm" href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer"><ExternalLink size={14} /> NVD</a>}>
      <div className="kv" style={{ marginBottom: 12 }}>
        <div>Machine</div><div><b>{f.target_name}</b> <span className="small muted">{f.target_ip} · {f.target_kind}</span></div>
        <div>Priority</div><div><Prio band={f.band} value={f.priority} /> <span className="small muted">· patch deadline</span> <Due f={f} /></div>
      </div>
      <Tabs value={view} onChange={setView} tabs={[{ key: "remediation", label: "Remediation", icon: Wrench }, { key: "details", label: "Details", icon: List }]} />
      <div style={{ marginTop: 12 }}>
      {view === "remediation" && <RemediationPlaybook fid={id} isAdmin={isAdmin} />}
      {view === "details" && <>
      <div className="kv">
        <div>Status</div><div><StatusBadge f={f} />{f.fixed_at && <span className="small muted"> · fixed {fmtTime(f.fixed_at)}</span>}{f.reopened > 0 && <span className="small muted"> · reopened {f.reopened}×</span>}</div>
        <div>SLA class</div><div className="small">{f.sla_category || "—"}</div>
        <div>Confidence</div><div><ConfBadge f={f} /> <span className="small muted">· {f.sources_active} active source(s)</span></div>
        <div>First seen</div><div>{fmtTime(f.first_seen)} <span className="small muted">· last seen {timeAgo(f.last_seen)}</span></div>
        <div>Exploitation</div><div><Kev c={f} /> <span className="small muted">EPSS</span> <Epss c={f} /></div>
        <div>Attack type</div><div>{f.attack?.length ? <AttackTags list={f.attack} /> : <span className="small muted">not classified (no known weakness type)</span>}</div>
        <div>Packages</div><div className="small mono">{f.packages?.length ? f.packages.join(", ") : "—"}</div>
        {f.triage && <><div>Triage</div><div className="small">{TRIAGE[f.triage]}{f.triage_until && ` until ${f.triage_until.slice(0, 10)}`} · {f.triage_note} <span className="muted">({f.triage_by}, {timeAgo(f.triage_at)})</span></div></>}
      </div>
      <p className="small" style={{ marginTop: 12 }}>{c?.description || f.description || <span className="faint">Not in the IT Ops catalogue yet – queued for the next NVD sync.</span>}</p>
      <h4>What each source reports</h4>
      <Table rowKey="package" rows={f.detections.map((d, i) => ({ ...d, package: `${d.source}-${d.package}-${i}`, pkg: d.package }))} columns={[
        { key: "source", label: "Source", render: (d) => <>{d.source}{!d.source_enabled && <span className="badge" style={{ marginLeft: 4 }}>disabled</span>}</> },
        { key: "pkg", label: "Package", render: (d) => <span className="small mono">{d.pkg || "—"} {d.version}</span> },
        { key: "fixed_version", label: "Fixed in", render: (d) => <span className="small mono">{d.fixed_version || "—"}</span> },
        { key: "score", label: "Source score", render: (d) => <span className="small muted" title="Reference only – IT Ops does not use it for priority">{d.severity || "—"}{d.score != null && ` · ${d.score}`}</span> },
        { key: "active", label: "Now", render: (d) => d.active ? <span className="badge fail">listed</span> : <span className="badge ok">gone</span> },
        { key: "last_seen", label: "Last seen", render: (d) => <span className="small">{timeAgo(d.last_seen)}</span> },
      ]} />
      {isAdmin && <div style={{ marginTop: 14 }}>
        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
          {f.verified ? <button className="btn sm" onClick={() => act("unverify")}>Remove verification</button>
            : <button className="btn sm" onClick={() => act("verify")}>Mark verified</button>}
          <button className="btn sm" onClick={() => setMode("false_positive")}>False positive…</button>
          <button className="btn sm" onClick={() => setMode("accepted")}>Accept risk…</button>
          {f.raw_triage && <button className="btn sm ghost" onClick={() => act("clear")}>Clear triage</button>}
        </div>
        {mode && <div className="card card-pad" style={{ marginTop: 10 }}>
          <div className="form-grid">
            <Field full label={mode === "accepted" ? "Why is the risk accepted?" : "Why is it a false positive?"}><Input value={note} onChange={setNote} /></Field>
            {mode === "accepted" && <Field label="Review date"><Input type="date" value={until} onChange={setUntil} /></Field>}
          </div>
          <div className="row" style={{ gap: 6, marginTop: 8 }}>
            <button className="btn primary sm" onClick={() => act(mode)}>Save</button><button className="btn sm ghost" onClick={() => setMode("")}>Cancel</button>
          </div>
          <div className="small muted" style={{ marginTop: 6 }}>Kept on this machine + CVE even if the source changes. Recorded in the audit log.</div>
        </div>}
      </div>}
      </>}
      </div>
    </Drawer>
  );
}

// ------------------------------------------------------------------ part 5: overview
function TrendChart({ trend }) {
  const max = Math.max(1, ...trend.map((d) => Math.max(d.new, d.fixed)));
  const W = 600, H = 110, bw = W / trend.length;
  return <svg viewBox={`0 0 ${W} ${H + 16}`} style={{ width: "100%", height: 140 }} role="img" aria-label="New and fixed findings per day, last 30 days">
    {trend.map((d, i) => <g key={d.day}>
      <rect x={i * bw + 1} y={H - (d.new / max) * H} width={bw / 2 - 1} height={(d.new / max) * H} fill="var(--fail)" opacity="0.75"><title>{d.day}: {d.new} new</title></rect>
      <rect x={i * bw + bw / 2} y={H - (d.fixed / max) * H} width={bw / 2 - 1} height={(d.fixed / max) * H} fill="var(--ok)" opacity="0.8"><title>{d.day}: {d.fixed} fixed</title></rect>
    </g>)}
    <line x1="0" x2={W} y1={H} y2={H} stroke="var(--border)" />
    <text x="0" y={H + 13} fontSize="11" fill="var(--muted)">{trend[0]?.day.slice(5)}</text>
    <text x={W} y={H + 13} fontSize="11" fill="var(--muted)" textAnchor="end">{trend[trend.length - 1]?.day.slice(5)}</text>
  </svg>;
}

function Overview({ go }) {
  const { data: o } = useApi("/vuln/overview", { interval: 30000 });
  if (!o) return <div className="small muted">Loading…</div>;
  const total = Math.max(1, o.open);
  return <>
    <div className="stats" style={{ gridTemplateColumns: "repeat(6, 1fr)", marginBottom: 14 }}>
      <Stat icon={Bug} label="Open" value={o.open} sub={`${o.machines} machines`} onClick={() => go({})} />
      <Stat icon={AlertTriangle} label="Overdue" value={o.overdue} sub="past the patch deadline" tone={o.overdue ? "fail" : ""} onClick={() => go({ sla: "overdue" })} />
      <Stat icon={Clock} label={`Due in ${o.due_soon_days} days`} value={o.due_soon} tone={o.due_soon ? "warn" : ""} onClick={() => go({ sla: "due_soon" })} />
      <Stat icon={Flame} label="Exploited (KEV)" value={o.kev} sub="CISA KEV" tone={o.kev ? "fail" : ""} onClick={() => go({ kev: true })} />
      <Stat icon={HelpCircle} label="Awaiting verification" value={o.awaiting_verification} sub="deadline not started" onClick={() => go({ sla: "awaiting_verification" })} />
      <Stat icon={CheckCircle2} label="Fixed in 30 days" value={o.fixed_30d} sub={o.on_time_pct != null ? `${o.on_time_pct}% on time` : ""} tone="ok" />
    </div>
    <div className="grid2" style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1.4fr)", gap: 14, marginBottom: 14 }}>
      <div className="card card-pad">
        <b>Open by priority</b>
        <div className="stack" style={{ gap: 10, marginTop: 12 }}>
          {["P1", "P2", "P3", "P4"].map((b) => <div key={b} style={{ cursor: "pointer" }} onClick={() => go({ band: b })}>
            <div className="row small" style={{ justifyContent: "space-between" }}>
              <span><Prio band={b} /> <span className="muted">{{ P1: "80–100", P2: "60–79", P3: "40–59", P4: "0–39" }[b]}</span></span>
              <span><b>{o.by_band[b]}</b>{o.overdue_by_band[b] > 0 && <span style={{ color: "var(--fail)" }}> · {o.overdue_by_band[b]} overdue</span>}</span>
            </div>
            <div className={`bar ${BAND_TONE[b]}`} style={{ marginTop: 4 }}><div style={{ width: `${(o.by_band[b] / total) * 100}%` }} /></div>
          </div>)}
        </div>
        <div className="small muted" style={{ marginTop: 14 }}>
          {o.sources.map((s) => <div key={s.id}>{s.name}: {!s.enabled ? "disabled" : !s.at ? "never synced" : s.ok === false ? <span style={{ color: "var(--fail)" }}>last sync failed</span>
            : s.stale ? <span style={{ color: "var(--warn)" }}>stale</span> : `synced ${timeAgo(s.at)}`}</div>)}
        </div>
      </div>
      <div className="card card-pad">
        <div className="row" style={{ justifyContent: "space-between" }}><b>Last 30 days</b>
          <span className="small muted"><span style={{ color: "var(--fail)" }}>■</span> new · <span style={{ color: "var(--ok)" }}>■</span> fixed</span></div>
        <TrendChart trend={o.trend} />
      </div>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 14 }}>
      <div className="card"><div className="card-pad"><b>Machines needing attention</b></div>
        <Table rowKey="target" rows={o.top_machines} onRow={(m) => go({ target: m.target, targetName: m.name })}
          empty={<Empty icon={Monitor} title="Nothing open" />} columns={[
            { key: "name", label: "Machine", render: (m) => <b>{m.name}</b> },
            { key: "band", label: "Top", render: (m) => <Prio band={m.band} value={m.max_priority} /> },
            { key: "open", label: "Open" },
            { key: "overdue", label: "Overdue", render: (m) => m.overdue ? <span className="badge fail">{m.overdue}</span> : "—" },
          ]} /></div>
      <div className="card"><div className="card-pad"><b>Most urgent CVEs</b></div>
        <Table rowKey="cve_id" rows={o.top_cves} onRow={(c) => go({ cve: c.cve_id })}
          empty={<Empty icon={ShieldAlert} title="Nothing open" />} columns={[
            { key: "cve_id", label: "CVE", render: (c) => <span className="mono small">{c.cve_id}</span> },
            { key: "band", label: "Top", render: (c) => <>{<Prio band={c.band} value={c.max_priority} />} {c.kev && <span className="badge fail">KEV</span>}</> },
            { key: "machines", label: "Machines" },
            { key: "overdue", label: "Overdue", render: (c) => c.overdue ? <span className="badge fail">{c.overdue}</span> : "—" },
          ]} /></div>
    </div>
  </>;
}

function ByMachine({ go }) {
  const [q, setQ] = useState("");
  const { data } = useApi(`/vuln/by-machine?q=${encodeURIComponent(q)}`, { deps: [q] });
  return <div className="card">
    <div className="card-pad"><div className="search" style={{ maxWidth: 360 }}><Search size={16} /><input placeholder="Machine name or IP…" value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
    <Table rowKey="target" rows={data || []} onRow={(m) => go({ target: m.target, targetName: m.name })}
      empty={<Empty icon={Monitor} title="No machine has open findings" />} columns={[
        { key: "name", label: "Machine", sort: (m) => m.name, render: (m) => <><b>{m.name}</b> <span className="small muted">{m.ip}</span></> },
        { key: "kind", label: "Type", render: (m) => <span className="small muted">{m.kind}</span> },
        { key: "importance", label: "Importance", render: (m) => m.importance ? <span className="badge outline" title="From Critical systems">{m.importance}</span> : <span className="faint small">normal</span> },
        { key: "max_priority", label: "Top priority", sort: (m) => m.max_priority, render: (m) => <Prio band={m.band} value={m.max_priority} /> },
        { key: "open", label: "Open", sort: (m) => m.open, render: (m) => <span className="small">{m.open} <span className="muted">({["P1", "P2", "P3", "P4"].filter((b) => m[b]).map((b) => `${m[b]} ${b}`).join(" · ")})</span></span> },
        { key: "kev", label: "KEV", sort: (m) => m.kev, render: (m) => m.kev ? <span className="badge fail">{m.kev}</span> : "—" },
        { key: "overdue", label: "Overdue", sort: (m) => m.overdue, render: (m) => m.overdue ? <span className="badge fail">{m.overdue}</span> : "—" },
        { key: "next_due", label: "Next deadline", sort: (m) => m.next_due || "9", render: (m) => <span className="small">{m.next_due?.slice(0, 10) || "—"}</span> },
      ]} />
  </div>;
}

function ByCve({ go }) {
  const [q, setQ] = useState("");
  const [attack, setAttack] = useState("");
  const { data } = useApi(`/vuln/by-cve?q=${encodeURIComponent(q)}&attack=${attack}`, { deps: [q, attack] });
  return <div className="card">
    <div className="card-pad row" style={{ gap: 8 }}><div className="search" style={{ maxWidth: 360, flex: 1 }}><Search size={16} /><input placeholder="CVE id…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <FSel value={attack} onChange={setAttack} title="Kind of attack (from the CWE weakness type)" options={[["", "Attack: All"], ...ATTACK_OPTS.map(([k, l]) => [k, `Attack: ${l}`])]} /></div>
    <Table rowKey="cve_id" rows={data || []} onRow={(c) => go({ cve: c.cve_id })}
      empty={<Empty icon={ShieldAlert} title="No open CVE on our machines" />} columns={[
        { key: "cve_id", label: "CVE", render: (c) => <span className="mono small" style={{ whiteSpace: "nowrap" }}>{c.cve_id}</span> },
        { key: "max_priority", label: "Top priority", sort: (c) => c.max_priority, render: (c) => <Prio band={c.band} value={c.max_priority} /> },
        { key: "cvss_score", label: "Severity", sort: (c) => c.cvss_score ?? -1, render: (c) => <SevBadge c={c} /> },
        { key: "kev", label: "KEV", sort: (c) => (c.kev ? 1 : 0), render: (c) => <Kev c={c} /> },
        { key: "epss", label: "EPSS", sort: (c) => c.epss ?? -1, render: (c) => <Epss c={c} /> },
        { key: "machines", label: "Machines", sort: (c) => c.machines },
        { key: "overdue", label: "Overdue", sort: (c) => c.overdue, render: (c) => c.overdue ? <span className="badge fail">{c.overdue}</span> : "—" },
        { key: "attack", label: "Attack type", sortable: false, render: (c) => c.attack?.length ? <AttackTags list={c.attack} /> : <span className="faint small">—</span> },
        { key: "description", label: "Description", render: (c) => <span className="small muted">{c.description?.slice(0, 110) || <span className="faint">not in catalogue yet</span>}</span> },
      ]} />
  </div>;
}

// One row = one job: update this software on N machines. Fix version = highest fix a source REPORTED (never guessed).
function BySoftware({ go }) {
  const [q, setQ] = useState("");
  const [attack, setAttack] = useState("");
  const [open, setOpen] = useState(null);
  const { data } = useApi(`/vuln/by-software?q=${encodeURIComponent(q)}&attack=${attack}`, { deps: [q, attack] });
  const rows = data || [];
  return <div className="card">
    <div className="card-pad row" style={{ gap: 8, alignItems: "center" }}>
      <div className="search" style={{ maxWidth: 360, flex: 1 }}><Search size={16} /><input placeholder="Software name…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <FSel value={attack} onChange={setAttack} title="Only software with CVEs of this attack type" options={[["", "Attack: All"], ...ATTACK_OPTS.map(([k, l]) => [k, `Attack: ${l}`])]} />
      <span className="small muted" style={{ marginLeft: "auto" }}>{data ? `${rows.length} software to update` : ""}</span>
    </div>
    <Table rowKey="key" rows={rows} onRow={(r) => setOpen(r)}
      empty={<Empty icon={Package} title="No software with open findings" />} columns={[
        { key: "name", label: "Software", sort: (r) => r.name.toLowerCase(), render: (r) => <b>{r.name}</b> },
        { key: "max_priority", label: "Top priority", sort: (r) => r.max_priority, render: (r) => <Prio band={r.band} value={r.max_priority} /> },
        { key: "cves", label: "CVEs", sort: (r) => r.cves },
        { key: "machines", label: "Machines", sort: (r) => r.machines },
        { key: "kev", label: "KEV", sort: (r) => r.kev, render: (r) => r.kev ? <span className="badge fail">{r.kev}</span> : "—" },
        { key: "overdue", label: "Overdue", sort: (r) => r.overdue, render: (r) => r.overdue ? <span className="badge fail">{r.overdue}</span> : "—" },
        { key: "fix_version", label: "What to do", sortable: false, render: (r) => <FixText r={r} /> },
        { key: "attack", label: "Attack types", sortable: false, render: (r) => <AttackTags list={r.attack.slice(0, 3).map((a) => `${a.label} ×${a.cves}`)} /> },
      ]} />
    {open && <SoftwareDrawer row={open} onClose={() => setOpen(null)} go={go} />}
  </div>;
}

function FixText({ r }) {
  const parts = [];
  if (r.fix_version) parts.push(<>Update to <b className="mono">{r.fix_version}</b> or later</>);
  else if (r.newer_than) parts.push(<>Update to a version newer than <b className="mono">{r.newer_than}</b></>);
  if (r.kbs?.length) parts.push(<>Install <b className="mono">{r.kbs.join(", ")}</b>{r.kbs_more ? ` +${r.kbs_more} more` : ""}</>);
  if (!parts.length) return <span className="small muted">No fixed version found in the available data – see Remediation of each CVE</span>;
  return <span className="small">{parts.map((x, i) => <span key={i}>{i > 0 && " · "}{x}</span>)}
    {r.cves_with_fix < r.cves && <span className="muted"> · fix known for {r.cves_with_fix} of {r.cves} CVEs</span>}</span>;
}

function SoftwareDrawer({ row, onClose, go }) {
  const { data: d } = useApi(`/vuln/by-software/detail?key=${encodeURIComponent(row.key)}`, { deps: [row.key] });
  return <Drawer title={row.name} onClose={onClose}>
    <div style={{ marginBottom: 12 }}><FixText r={d ? { ...d, cves: d.cves.length } : row} /></div>
    {!d ? <div className="small muted">Loading…</div> : <>
      <h4>Machines ({d.machines.length})</h4>
      <Table rowKey="target" rows={d.machines} onRow={(m) => go({ target: m.target, targetName: m.name, q: row.name })} columns={[
        { key: "name", label: "Machine", render: (m) => <><b>{m.name}</b> <span className="small muted">{m.ip}</span></> },
        { key: "versions", label: "Installed", render: (m) => <span className="small mono">{m.versions.join(", ") || "—"}</span> },
        { key: "cves", label: "CVEs" },
        { key: "max_priority", label: "Top", render: (m) => <Prio band={m.band} value={m.max_priority} /> },
      ]} />
      <h4>CVEs ({d.cves.length})</h4>
      <Table rowKey="cve_id" rows={d.cves} onRow={(c) => go({ cve: c.cve_id })} columns={[
        { key: "cve_id", label: "CVE", render: (c) => <span className="mono small" style={{ whiteSpace: "nowrap" }}>{c.cve_id}</span> },
        { key: "max_priority", label: "Top", render: (c) => <>{<Prio band={c.band} value={c.max_priority} />} {c.kev && <span className="badge fail">KEV</span>}</> },
        { key: "cvss_score", label: "CVSS", render: (c) => <SevBadge c={c} /> },
        { key: "fixed_versions", label: "Fix", render: (c) => <span className="small mono">{c.fixed_versions.length ? `≥ ${c.fixed_versions.join(", ")}`
          : c.newer_than ? `> ${c.newer_than}` : c.kbs?.length ? c.kbs.join(", ") : "—"}</span> },
        { key: "attack", label: "Attack type", render: (c) => <AttackTags list={c.attack} /> },
      ]} />
      <div className="small muted" style={{ marginTop: 8 }}>Click a machine or a CVE to open its findings. Fixes come only from published data (scanner, official CVE record, NVD, Microsoft) – never guessed.</div>
    </>}
  </Drawer>;
}

function Policy({ isAdmin }) {
  const toast = useToast();
  const { data, reload } = useApi("/vuln/policy");
  const [p, setP] = useState(null);
  const cur = p || data;
  if (!cur) return <div className="small muted">Loading…</div>;
  const setSla = (k, v) => setP({ ...cur, sla_days: { ...cur.sla_days, [k]: v } });
  const save = async () => {
    try { await api.put("/vuln/policy", cur); toast("Saved – priorities and deadlines recalculated"); setP(null); reload(); }
    catch (e) { toast(e.message, true); }
  };
  const digest = async () => {
    try { const r = await api.post("/vuln/digest/test"); toast(r.sent ? "Digest sent to the enabled channels" : r.reason, !r.sent); }
    catch (e) { toast(e.message, true); }
  };
  const ro = !isAdmin;
  return <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 14 }}>
    <div className="card card-pad">
      <b>Patch deadlines (SLA)</b>
      <div className="small muted" style={{ margin: "4px 0 12px" }}>Days from the moment a finding is confirmed. Exploited (KEV) wins over severity.</div>
      <div className="form-grid">
        {[["kev", "Exploited in the wild (KEV)"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["unscored", "Not scored yet"]].map(([k, l]) =>
          <Field key={k} label={l}><Input type="number" value={cur.sla_days[k]} disabled={ro} onChange={(v) => setSla(k, v)} /></Field>)}
        <Field label="“Due soon” window (days)"><Input type="number" value={cur.due_soon_days} disabled={ro} onChange={(v) => setP({ ...cur, due_soon_days: v })} /></Field>
      </div>
    </div>
    <div className="card card-pad">
      <b>Alerts</b>
      <div className="small muted" style={{ margin: "4px 0 12px" }}>Sent through Settings › Notifications (Telegram, e-mail, webhook). One message per sync, each finding only once.</div>
      <div className="stack" style={{ gap: 10 }}>
        <Toggle checked={cur.alerts.enabled} onChange={(v) => !ro && setP({ ...cur, alerts: { ...cur.alerts, enabled: v } })} label="Alert on new urgent findings" />
        <Toggle checked={cur.alerts.kev} onChange={(v) => !ro && setP({ ...cur, alerts: { ...cur.alerts, kev: v } })} label="Always alert when exploited in the wild (KEV)" />
        <Field label="…and when priority is at least"><Input type="number" value={cur.alerts.min_priority} disabled={ro} onChange={(v) => setP({ ...cur, alerts: { ...cur.alerts, min_priority: v } })} /></Field>
        <Toggle checked={cur.digest.enabled} onChange={(v) => !ro && setP({ ...cur, digest: { ...cur.digest, enabled: v } })} label="Morning digest: overdue, due soon, new, KEV" />
        <Field label="Digest hour (local time, 0–23)"><Input type="number" value={cur.digest.hour} disabled={ro} onChange={(v) => setP({ ...cur, digest: { ...cur.digest, hour: v } })} /></Field>
      </div>
    </div>
    <div className="card card-pad" style={{ gridColumn: "1 / -1" }}>
      <b>How priority is calculated</b>
      <div className="small" style={{ marginTop: 8, lineHeight: 1.7 }}>
        CVSS × 6 (0–60, not scored yet counts as 5.0) · + 25 if exploited in the wild (CISA KEV) · + 5 if used by ransomware · + EPSS percentile × 10 ·
        + machine importance from <i>Critical systems</i>: High + 10, Medium + 5, Low − 5. Capped 0–100. <b>P1</b> ≥ 80 · <b>P2</b> ≥ 60 · <b>P3</b> ≥ 40 · <b>P4</b> below.
        <div className="muted">Only the IT Ops CVE catalogue and your own data are used – never a source's score – so switching tools does not change priorities.
          Confidence does not lower priority; unconfirmed findings simply have no deadline yet.</div>
      </div>
      {isAdmin && <div className="row" style={{ gap: 8, marginTop: 12 }}>
        <button className="btn primary" disabled={!p} onClick={save}>Save policy</button>
        {p && <button className="btn ghost" onClick={() => setP(null)}>Discard</button>}
        <button className="btn" onClick={digest}><Send size={14} /> Send digest now</button>
      </div>}
    </div>
  </div>;
}


// Filter dropdown sized to the chosen label (a native select is otherwise as wide as its longest option).
function FSel({ value, options, ...p }) {
  const label = (options.find((o) => o[0] === value) || options[0])[1];
  const box = useRef(null);
  const [w, setW] = useState(null);
  useLayoutEffect(() => {
    const el = box.current?.querySelector("select");
    if (!el) return;
    const cs = getComputedStyle(el), ctx = document.createElement("canvas").getContext("2d");
    ctx.font = cs.font;
    setW(Math.ceil(ctx.measureText(label).width + parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight) + parseFloat(cs.borderLeftWidth) * 2 + 22));
  }, [label]);
  return <span ref={box} style={{ flex: "0 0 auto", display: "inline-flex" }}><Select value={value} options={options} {...p} style={{ width: w ? `${w}px` : "auto", maxWidth: 260, paddingLeft: 10 }} /></span>;
}


// Attack type from the CVE's CWE ids (server: app/vuln_groups.py ATTACK_TYPES).
export const ATTACK_OPTS = [["rce", "Code execution"], ["memory", "Memory corruption"], ["privesc", "Privilege escalation"],
  ["auth", "Authentication bypass"], ["info", "Information disclosure"], ["traversal", "Path traversal"], ["injection", "Injection / XSS"],
  ["dos", "Denial of service"], ["none", "Not classified"]];
export function AttackTags({ list }) {
  if (!list?.length) return null;
  return <span className="row" style={{ gap: 4, flexWrap: "wrap", display: "inline-flex" }}>
    {list.map((a) => <span key={a} className="badge outline" style={{ fontSize: 11 }}>{a}</span>)}</span>;
}

// Findings sort keys (server-side, over ALL matching findings – not just the page on screen).
const SORT_DIR = { priority: "desc", due: "asc", cvss: "desc", epss: "desc", first_seen: "desc", machine: "asc", ip: "asc", cve: "asc",
  kev: "desc", package: "asc", confidence: "desc", status: "asc" };
const COL_SORT = { target_name: "machine", target_ip: "ip", cve_id: "cve", cvss_score: "cvss", packages: "package", due_at: "due" };
const SORT_OPTS = [["priority", "Sort: Priority"], ["due", "Sort: Deadline"], ["cvss", "Sort: CVSS"], ["epss", "Sort: EPSS"], ["first_seen", "Sort: Newest"],
  ["machine", "Sort: Machine"], ["ip", "Sort: IP"], ["cve", "Sort: CVE"], ["kev", "Sort: KEV"], ["package", "Sort: Package"], ["confidence", "Sort: Confidence"], ["status", "Sort: Status"]];

// ------------------------------------------------------------------ page
export default function Vulnerabilities() {
  const { isAdmin } = useApp();
  const [tab, setTab] = useState("overview");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("open");
  const [sev, setSev] = useState("");
  const [band, setBand] = useState("");
  const [sla, setSla] = useState("");
  const [kev, setKev] = useState(false);
  const [verify, setVerify] = useState(false);
  const [triage, setTriage] = useState("none");
  const [src, setSrc] = useState("");
  const [sort, setSort] = useState("priority");
  const [dir, setDir] = useState("desc");
  const [attack, setAttack] = useState("");
  const pickSort = (k) => { setSort(k); setDir(SORT_DIR[k] || "asc"); };                    // dropdown: each key's natural direction
  const headSort = (col) => { const k = COL_SORT[col] || col;                                  // header click: same column flips direction
    if (k === sort) setDir(dir === "asc" ? "desc" : "asc"); else pickSort(k); };
  const [target, setTarget] = useState(null);
  const [cve, setCve] = useState("");
  const [open, setOpen] = useState(null);
  const [edit, setEdit] = useState(null);
  const [unmatched, setUnmatched] = useState(null);
  const [imp, setImp] = useState(null);
  const [cmp, setCmp] = useState(false);
  const [per, setPer] = useState(() => { try { return [25, 50, 100, 500].includes(+localStorage.getItem("itops_vuln_per")) ? +localStorage.getItem("itops_vuln_per") : 50; } catch { return 50; } });
  const [page, setPage] = useState(0);
  const filterKey = [q, status, sev, band, sla, kev, verify, triage, src, sort, dir, target?.target, cve, attack].join("|");
  useEffect(() => { setPage(0); }, [filterKey, per]);
  const changePer = (v) => { setPer(+v); try { localStorage.setItem("itops_vuln_per", v); } catch { /* ignore */ } };
  const params = new URLSearchParams({ q, status, severity: sev, band, sla, kev: kev ? "true" : "false", needs_verification: verify ? "true" : "false",
    triage, source_id: src || "0", sort, dir, attack, target: target?.target || "", cve, limit: String(per), offset: String(page * per) }).toString();
  const sum = useApi("/vuln/summary", { interval: 15000 });
  const list = useApi(tab === "findings" ? `/vuln/findings?${params}` : null, { deps: [params, tab] });
  const s = sum.data;
  const refresh = () => { sum.reload(); list.reload(); };
  const reset = () => { setStatus("open"); setSev(""); setBand(""); setSla(""); setKev(false); setVerify(false); setTriage("none"); setTarget(null); setCve(""); setQ(""); setAttack(""); };
  const go = (f) => { reset(); if (f.sla) setSla(f.sla); if (f.band) setBand(f.band); if (f.kev) setKev(true); if (f.cve) setCve(f.cve); if (f.q) setQ(f.q); if (f.attack) setAttack(f.attack);
    if (f.target) setTarget({ target: f.target, name: f.targetName }); setTab("findings"); };
  const items = list.data?.items || [];
  const sources = s?.sources || [];
  const exportUrl = `/api/vuln/export.csv?${new URLSearchParams({ q, status, severity: sev, band, sla, kev: kev ? "true" : "false",
    needs_verification: verify ? "true" : "false", triage, source_id: src || "0", sort, dir, attack, target: target?.target || "", cve })}`;   // same filters + order as the list, all pages
  return (
    <>
      <PageHead crumb="Operations › Vulnerabilities" title="Vulnerabilities"
        desc="Which CVE is on which machine, how urgent it is and when it must be patched. Results come from replaceable sources; priority is always computed by IT Ops.">
        {tab === "sources" && sources.length > 1 && <button className="btn" onClick={() => setCmp(true)}><GitCompare size={15} /> Compare sources</button>}
        {tab === "sources" && isAdmin && <>
          <button className="btn" onClick={() => setEdit({ kind: "file" })}><Upload size={15} /> Add file source</button>
          <button className="btn primary" onClick={() => setEdit({ kind: "wazuh" })}><Plus size={15} /> Add Wazuh</button>
        </>}
        {tab === "findings" && <a className="btn" href={exportUrl}><Download size={15} /> Export CSV</a>}
      </PageHead>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "overview", label: "Overview", icon: LayoutDashboard },
        { key: "findings", label: "Findings", icon: List, count: s?.open },
        { key: "machines", label: "By machine", icon: Server },
        { key: "software", label: "By software", icon: Package },
        { key: "cves", label: "By CVE", icon: ShieldAlert },
        { key: "sources", label: "Sources", icon: Database, count: sources.filter((x) => x.enabled && (x.stale || x.state?.ok === false)).length || undefined },
        { key: "policy", label: "Policy", icon: SlidersHorizontal },
      ]} />
      {tab === "overview" && <Overview go={go} />}
      {tab === "machines" && <ByMachine go={go} />}
      {tab === "cves" && <ByCve go={go} />}
      {tab === "software" && <BySoftware go={go} />}
      {tab === "policy" && <Policy isAdmin={isAdmin} />}
      {tab === "sources" && <>
        <div className="row" style={{ gap: 12, flexWrap: "wrap", marginBottom: 14, alignItems: "stretch" }}>
          {sources.map((x) => <SourceCard key={x.id} s={x} isAdmin={isAdmin} onChanged={refresh} onEdit={setEdit} onUnmatched={setUnmatched} onImport={setImp} />)}
        </div>
        <div className="small muted">A source only says which CVE it sees on which host. Disabling one never marks its findings fixed (they become “source off”).
          Before switching tools, run both and use <b>Compare sources</b>.</div>
      </>}
      {tab === "findings" && <>
        <div className="card">
          <div className="card-pad" style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <div className="search" style={{ flex: "1 1 170px", minWidth: 130 }}>
              <Search size={16} />
              <input placeholder="Search machine, IP, CVE, package…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            {target && <span className="badge info">machine: {target.name || target.target} <X size={12} style={{ cursor: "pointer" }} onClick={() => setTarget(null)} /></span>}
            {cve && <span className="badge info">{cve} <X size={12} style={{ cursor: "pointer" }} onClick={() => setCve("")} /></span>}
            <FSel value={band} onChange={setBand} title="Priority computed by IT Ops: P1 urgent · P2 high · P3 medium · P4 low" options={[["", "Priority: All"], ["P1", "Priority: P1"], ["P1,P2", "Priority: P1 + P2"], ["P2", "Priority: P2"], ["P3", "Priority: P3"], ["P4", "Priority: P4"]]} />
            <FSel value={sla} onChange={setSla} title="Patch deadline" options={[["", "Deadline: Any"], ["overdue", "Deadline: Overdue"], ["due_soon", "Deadline: Due soon"], ["awaiting_verification", "Deadline: Not started"]]} />
            <FSel value={status} onChange={setStatus} title="Open = still detected · Fixed = a source rescanned and no longer sees it · Source off = its source is disabled" options={[["open", "Status: Open"], ["fixed", "Status: Fixed"], ["source_off", "Status: Source off"], ["all", "Status: All"]]} />
            <FSel value={sev} onChange={setSev} title="Severity from CVSS score" options={[["", "Severity: All"], ["critical", "Severity: Critical"], ["critical,high", "Severity: Crit + High"], ["medium", "Severity: Medium"], ["low", "Severity: Low"], ["unscored", "Severity: Not scored"]]} />
            <FSel value={attack} onChange={setAttack} title="Kind of attack the CVE allows (from its CWE weakness type)" options={[["", "Attack: All"], ...ATTACK_OPTS.map(([k, l]) => [k, `Attack: ${l}`])]} />
            <FSel value={triage} onChange={setTriage} title="IT review of the finding" options={[["none", "Review: Not reviewed"], ["false_positive", "Review: False positive"], ["accepted", "Review: Risk accepted"], ["all", "Review: All"]]} />
            <FSel value={src} onChange={setSrc} title="Which tool reported it" options={[["", "Source: All"], ...sources.map((x) => [String(x.id), `Source: ${x.name}`])]} />
            <FSel value={sort} onChange={pickSort} title="Sort order (or click a column header; click again to reverse)" options={SORT_OPTS} />
            <label className="row small" style={{ gap: 6, whiteSpace: "nowrap" }} title="Only CVEs on the CISA KEV list: known to be exploited in real attacks"><input type="checkbox" checked={kev} onChange={(e) => setKev(e.target.checked)} /> KEV only</label>
            <label className="row small" style={{ gap: 6, whiteSpace: "nowrap" }} title="Findings IT still has to confirm"><input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} /> Needs verification</label>
          </div>
          <Table rows={items} onRow={(f) => setOpen(f.id)} onSort={headSort}
            sortBy={{ key: Object.keys(COL_SORT).find((c) => COL_SORT[c] === sort) || sort, dir: dir === "asc" ? 1 : -1 }}
            empty={<Empty icon={Bug} title={s?.open ? "No finding matches the filters" : "No findings yet"}>
              {s?.open ? "Clear the filters." : isAdmin ? "Connect a source on the Sources tab (Wazuh or a scanner file). Devices without an agent are matched automatically once the CVE catalogue has synced." : "Ask an administrator to connect a source."}
            </Empty>}
            columns={[
              { key: "priority", label: "Priority", sort: (f) => f.priority, render: (f) => <Prio band={f.band} value={f.priority} /> },
              { key: "target_name", label: "Machine", sort: (f) => f.target_name, render: (f) => <b style={{ whiteSpace: "nowrap" }}>{f.target_name}</b> },
              { key: "target_ip", label: "IP", sort: (f) => (f.target_ip || "").split(".").map((n) => n.padStart(3, "0")).join("."), render: (f) => <span className="small mono" style={{ whiteSpace: "nowrap" }}>{f.target_ip || "—"}</span> },
              { key: "cve_id", label: "CVE", render: (f) => <span className="mono small" style={{ whiteSpace: "nowrap" }}>{f.cve_id}</span> },
              { key: "cvss_score", label: "Severity", sort: (f) => f.cvss_score ?? -1, render: (f) => <Sev f={f} /> },
              { key: "kev", label: "KEV", sort: (f) => (f.kev ? 1 : 0), render: (f) => <Kev c={f} /> },
              { key: "epss", label: "EPSS", sort: (f) => f.epss ?? -1, render: (f) => <Epss c={f} /> },
              { key: "packages", label: "Package", sort: (f) => f.packages?.[0] || "", render: (f) => <span className="small mono">{f.packages?.[0] || "—"}{f.packages?.length > 1 && <span className="muted"> +{f.packages.length - 1}</span>}</span> },
              { key: "due_at", label: "Deadline", sort: (f) => f.due_at || "9", render: (f) => <Due f={f} /> },
              { key: "confidence", label: "Confidence", sort: (f) => ({ high: 3, medium: 2, low: 1 }[f.confidence] || 0), render: (f) => <ConfBadge f={f} /> },
              { key: "status", label: "Status", render: (f) => <StatusBadge f={f} /> },
            ]} />
          {list.data && list.data.total > 0 && <Pager total={list.data.total} per={per} page={page} onPer={changePer} onPage={setPage} label={`${list.data.total.toLocaleString()} findings`} />}
        </div>
        <div className="small muted" style={{ marginTop: 10 }}>
          Severity, KEV and EPSS come from the IT Ops catalogue (<span className="faint">*</span> = source score shown until NVD is synced). Confidence says how sure a result is,
          not how dangerous it is. A finding is closed only when an enabled source looks again and no longer lists it.
        </div>
      </>}
      {open && <FindingDrawer id={open} isAdmin={isAdmin} onClose={() => setOpen(null)} onChanged={refresh} />}
      {edit && <SourceModal init={edit} kinds={[...(s?.kinds || []), { kind: "cpe", defaults: { interval_hours: 24 }, confidence: "medium" }]}
        onClose={() => setEdit(null)} onSaved={() => { setEdit(null); refresh(); }} />}
      {unmatched && <UnmatchedModal s={sources.find((x) => x.id === unmatched.id) || unmatched} isAdmin={isAdmin} onClose={() => setUnmatched(null)} onChanged={refresh} />}
      {imp && <ImportModal s={imp} onClose={() => setImp(null)} onDone={() => { setImp(null); refresh(); }} />}
      {cmp && <CompareModal sources={sources} onClose={() => setCmp(false)} />}
    </>
  );
}
