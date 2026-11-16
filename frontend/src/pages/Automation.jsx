import React, { useMemo, useState } from "react";
import { Zap, Plus, Play, FlaskConical, Pencil, Trash2, History, BookOpen, Code2, ListChecks, X, Ban } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Tabs, Table, Modal, Field, Input, Select, Toggle, useToast, timeAgo, fmtTime, Empty, confirmDelete, Stat, DEMO, CapNote } from "../ui";

const GROUPS = [
  ["RPT", "Reports", "How is the infrastructure performing this week, and who needs to know?"],
  ["INC", "Alerts & Incidents", "What failed, who should be notified, and how should it be handled?"],
  ["PRE", "Prevention & Forecasting", "What is likely to fail next?"],
  ["LCM", "Maintenance & Lifecycle", "What needs replacement, renewal, or review?"],
];
const LEVELS = [["L0", "L0 · notify only"], ["L1", "L1 · notify with recommendation"], ["L2", "L2 · execute after approval"], ["L3", "L3 · automatic (reversible)"]];
const CRON_PRESETS = [
  ["30 7 * * *", "07:30 Daily"], ["0 8 * * 1-5", "08:00 Monday–Friday"], ["0 8 * * 1", "08:00 Every Monday"],
  ["0 16 * * 5", "16:00 Every Friday"], ["0 8 1 * *", "08:00 On the first day of each month"], ["0 9 1 1,4,7,10 *", "09:00 At the start of each quarter"],
];
const EVENTS = [["alert_opened", "Alert opened"], ["alert_resolved", "Alert resolved"], ["alert_escalated", "Alert escalated"]];
const TARGET_TYPES = [["default", "Default channel (Settings)"], ["telegram", "Telegram (chat ID)"], ["email", "Email"], ["webhook", "Webhook"]];
const STATUS = { ok: ["ok", "Success"], skipped: ["", "Nothing to send"], error: ["fail", "Error"] };
const TRIG = { schedule: "Scheduled", interval: "Recurring", event: "Event", hook: "On alert", manual: "Manual", test: "Test run", tick: "Recurring" };

// ------------------------------------------------------------------ recipients
function Targets({ value, onChange, allowEmpty }) {
  const list = value?.length ? value : allowEmpty ? [] : [{ type: "default" }];
  const set = (i, patch) => onChange(list.map((t, j) => (j === i ? { ...t, ...patch } : t)));
  const key = { telegram: "chat", email: "to", webhook: "url" };
  const ph = { telegram: "-1001234567890", email: "truong-it@congty.vn, quan-ly@congty.vn", webhook: "https://chat.googleapis.com/..." };
  return (
    <div className="auto-targets">
      {list.map((t, i) => (
        <div key={i} className="auto-target">
          <Select value={t.type} onChange={(v) => set(i, { type: v })} options={TARGET_TYPES} />
          {t.type !== "default" ? <Input value={t[key[t.type]]} onChange={(v) => set(i, { [key[t.type]]: v })} placeholder={ph[t.type]} />
            : <span className="small faint">Telegram / Email / Webhook enabled in Settings</span>}
          <button className="btn icon sm" title="Dropped" onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button>
        </div>
      ))}
      <button className="btn sm" onClick={() => onChange([...list, { type: "telegram", chat: "" }])}><Plus size={13} />Add recipient</button>
      {allowEmpty && !list.length && <span className="small faint" style={{ marginLeft: 8 }}>Leave empty to use the default channel</span>}
    </div>
  );
}

function MultiCheck({ options, value, onChange }) {
  const v = value || [];
  return <div className="row wrap" style={{ gap: 10 }}>{options.map(([k, l]) => (
    <label key={k} className="check-row small"><input type="checkbox" checked={v.includes(k)}
      onChange={(e) => onChange(e.target.checked ? [...v, k] : v.filter((x) => x !== k))} />{l}</label>))}</div>;
}

// ------------------------------------------------------------------ special parameters
function Steps({ value, onChange }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((s, i) => (
    <div key={i} className="auto-subcard">
      <div className="row wrap" style={{ gap: 8 }}>
        <b className="small">Step {i + 1}</b>
        <Input value={s.label} onChange={(v) => set(i, { label: v })} placeholder="Step name (e.g. Team Lead)" style={{ maxWidth: 200 }} />
        <span className="small">sau</span><Input type="number" value={s.after_min} onChange={(v) => set(i, { after_min: Number(v) })} style={{ width: 80 }} />
        <span className="small">minutes without acknowledgment · severity</span>
        <MultiCheck options={[["High", "High"], ["Medium", "Medium"], ["Low", "Low"]]} value={s.severities} onChange={(v) => set(i, { severities: v })} />
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button>
      </div>
      <div className="small muted" style={{ margin: "6px 0 4px" }}>Notify:</div>
      <Targets value={s.targets} onChange={(v) => set(i, { targets: v })} allowEmpty />
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { label: "", after_min: 30, severities: ["High"], targets: [] }])}><Plus size={13} />Add step</button>
  </div>;
}

function Rules({ value, onChange }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((r, i) => (
    <div key={i} className="auto-subcard">
      <div className="row" style={{ gap: 8 }}><span className="small">When the title/check name contains</span>
        <Input value={r.contains} onChange={(v) => set(i, { contains: v })} placeholder="VD VNPT" style={{ maxWidth: 200 }} />
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button></div>
      <textarea className="input" rows={3} style={{ marginTop: 6 }} placeholder={"One step per line\nCall the service desk\nRead the contract reference ..."}
        value={(r.steps || []).join("\n")} onChange={(e) => set(i, { steps: e.target.value.split("\n") })} />
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { contains: "", steps: [] }])}><Plus size={13} />Add custom runbook</button>
    <div className="small faint">If no rule matches, use the critical system runbook (if available), then the default runbook for the check type.</div>
  </div>;
}

function Windows({ value, onChange, assets, sites }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((w, i) => (
    <div key={i} className="auto-subcard">
      <div className="form-grid">
        <Field label="Name"><Input value={w.name} onChange={(v) => set(i, { name: v })} placeholder="e.g. Switch firmware upgrade" /></Field>
        <Field label="Start time (cron, Vietnam time)" hint="e.g. 0 22 * * 6 = every Saturday at 22:00"><Input value={w.cron} onChange={(v) => set(i, { cron: v })} placeholder="0 22 * * 6" /></Field>
        <Field label="Duration (minutes)"><Input type="number" value={w.duration_min} onChange={(v) => set(i, { duration_min: Number(v) })} /></Field>
        <Field label="Site"><select className="input" multiple value={(w.sites || []).map(String)} style={{ height: 70 }}
          onChange={(e) => set(i, { sites: [...e.target.selectedOptions].map((o) => Number(o.value)) })}>{sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
        <Field label="Device (including downstream devices)" full><select className="input" multiple value={(w.assets || []).map(String)} style={{ height: 90 }}
          onChange={(e) => set(i, { assets: [...e.target.selectedOptions].map((o) => Number(o.value)) })}>{assets.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.type}</option>)}</select></Field>
      </div>
      <button className="btn sm danger-text" onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={13} />Remove this window</button>
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { name: "", cron: "0 22 * * 6", duration_min: 120, assets: [], sites: [] }])}><Plus size={13} />Add maintenance window</button>
  </div>;
}

function ParamField({ f, value, onChange, ctx }) {
  if (f.type === "bool") return <Toggle checked={value} onChange={onChange} label={f.label} />;
  if (f.type === "textarea") return <Field label={f.label} full><textarea className="input" rows={2} value={value || ""} onChange={(e) => onChange(e.target.value)} /></Field>;
  if (f.type === "multi") return <Field label={f.label}><MultiCheck options={f.options.map((o) => [o, o])} value={value} onChange={onChange} /></Field>;
  if (f.type === "list") return <Field label={f.label} hint="Comma-separated values"><Input value={(value || []).join(", ")}
    onChange={(v) => onChange(v.split(",").map((x) => Number(x.trim())).filter((x) => x > 0))} /></Field>;
  if (f.type === "steps") return <Field label={f.label} full><Steps value={value} onChange={onChange} /></Field>;
  if (f.type === "rules") return <Field label={f.label} full><Rules value={value} onChange={onChange} /></Field>;
  if (f.type === "windows") return <Field label={f.label} full><Windows value={value} onChange={onChange} assets={ctx.assets} sites={ctx.sites} /></Field>;
  return <Field label={f.label}><Input type="number" step={f.step || 1} value={value} onChange={(v) => onChange(v === "" ? "" : Number(v))} /></Field>;
}

// ------------------------------------------------------------------ editor
export function AutomationEditor({ edit, catalog, onClose, onSaved }) {
  const toast = useToast();
  const sites = useApi("/sites").data || [];
  const assets = useApi("/assets").data || [];
  const code = edit.code;
  const tpl = catalog.templates.find((t) => t.code === code);
  const base = edit.id ? edit.effective : tpl.spec;
  const [f, setF] = useState({ name: edit.name || (code === "CUSTOM" ? "" : tpl.name), enabled: edit.id ? edit.enabled : true, spec: JSON.parse(JSON.stringify(base)) });
  const [mode, setMode] = useState("form");
  const [yaml, setYaml] = useState("");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const sp = f.spec;
  const setSpec = (k, v) => setF({ ...f, spec: { ...sp, [k]: v } });
  const setP = (k) => (v) => setSpec("params", { ...(sp.params || {}), [k]: v });
  const trg = sp.trigger || {};
  const setT = (p) => setSpec("trigger", { ...trg, ...p });
  const scope = sp.scope || { sites: "all" };
  const setScope = (p) => setSpec("scope", { ...scope, ...p });
  const content = sp.content || {};
  const setContent = (p) => setSpec("content", { ...content, ...p });

  const toYaml = async () => {
    try { setYaml((await api.post("/automation/to-yaml", { code, spec: sp, name: f.name, enabled: f.enabled })).yaml); setMode("yaml"); } catch (e) { toast(e.message, true); }
  };
  const fromYaml = async () => {
    try {
      const r = await api.post("/automation/from-yaml", { code, yaml });
      setF({ name: r.name ?? f.name, enabled: r.enabled ?? f.enabled, spec: r.spec }); setMode("form");
    } catch (e) { toast(e.message, true); }
  };
  const body = () => (mode === "yaml" ? { code, yaml, name: f.name } : { code, spec: sp, name: f.name, enabled: f.enabled });
  const save = async () => {
    if (!f.name.trim()) return toast("Enter a scenario name", true);
    setBusy(true);
    try {
      const r = edit.id ? await api.put(`/automations/${edit.id}`, body()) : await api.post("/automations", body());
      toast(edit.id ? "Scenario saved" : "Scenario added"); onSaved(r);
    } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true);
    try { setPreview(await api.post("/automations/preview", body())); } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };

  return (
    <Modal title={<span className="row"><Zap size={17} />{edit.id ? "Edit" : "Add"} scenario <span className="badge">{code}</span></span>} onClose={onClose} width={820}
      footer={<>
        <button className="btn" onClick={test} disabled={busy}><FlaskConical size={15} />Test run (no notifications sent)</button>
        <div className="grow" />
        <button className="btn" onClick={onClose}>Close</button>
        <button className="btn primary" onClick={save} disabled={busy}>Save</button>
      </>}>
      {tpl && code !== "CUSTOM" && <div className="alert-box info" style={{ marginBottom: 12 }}><b>{tpl.name}</b> – {tpl.desc}<div className="small muted" style={{ marginTop: 4 }}>KPI: {tpl.kpi} · Data: {tpl.data}</div></div>}
      <div className="row" style={{ marginBottom: 12, gap: 8 }}>
        <div className="seg">
          <button className={mode === "form" ? "on" : ""} onClick={() => (mode === "yaml" ? fromYaml() : null)}><ListChecks size={13} /> Form</button>
          <button className={mode === "yaml" ? "on" : ""} onClick={() => (mode === "form" ? toYaml() : null)}><Code2 size={13} /> YAML</button>
        </div>
        <span className="small faint">YAML must match the documented template format (paste the complete id/name/trigger/... block here)</span>
      </div>

      {mode === "yaml" ? <textarea className="input mono" rows={22} value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} style={{ fontSize: 12.5 }} /> : (
        <div className="form-grid">
          <Field label="Name scenario *"><Input value={f.name} onChange={(v) => setF({ ...f, name: v })} placeholder="e.g. End-of-day summary" /></Field>
          <Field label="Automation level" hint={tpl.reversible ? "L2–L3 are limited to reversible actions" : "This template only sends notifications → L0/L1"}>
            <Select value={sp.level || "L0"} onChange={(v) => setSpec("level", v)} options={LEVELS.filter(([k]) => tpl.reversible || k === "L0" || k === "L1")} />
          </Field>
          <Toggle checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Enabled" />

          <div className="section-title">When to run</div>
          {trg.type === "hook" ? <div className="full small muted">Runs whenever an alert is opened or resolved (before notifications are sent). No schedule required.</div> : <>
            <Field label="Type trigger"><Select value={trg.type} onChange={(v) => setT({ type: v, ...(v === "schedule" ? { cron: trg.cron || "0 8 * * 1-5" } : v === "interval" ? { minutes: trg.minutes || 15 } : { on: trg.on || ["alert_opened"] }) })}
              options={[["schedule", "Scheduled (hours VN)"], ["interval", "Recurring every N minutes"], ["event", "When alert events occur"]].filter(([k]) => tpl.triggers.includes(k))} /></Field>
            {trg.type === "schedule" && <Field label="Schedule (cron: minute hour day month weekday)" hint={<span>Quick select: <select className="input" style={{ display: "inline", width: "auto", padding: "1px 4px", fontSize: 12 }}
              value="" onChange={(e) => e.target.value && setT({ cron: e.target.value })}><option value="">…</option>{CRON_PRESETS.map(([c, l]) => <option key={c} value={c}>{l}</option>)}</select></span>}>
              <Input value={trg.cron} onChange={(v) => setT({ cron: v })} className="input mono" /></Field>}
            {trg.type === "interval" && <Field label="Every (minutes)"><Input type="number" value={trg.minutes} onChange={(v) => setT({ minutes: Number(v) })} /></Field>}
            {trg.type === "event" && <Field label="Event"><MultiCheck options={EVENTS} value={trg.on} onChange={(v) => setT({ on: v })} /></Field>}
          </>}

          <div className="section-title">Scope</div>
          <Field label="Site" hint="No selection = all sites"><select className="input" multiple value={scope.sites === "all" ? [] : (scope.sites || []).map(String)} style={{ height: 70 }}
            onChange={(e) => { const v = [...e.target.selectedOptions].map((o) => Number(o.value)); setScope({ sites: v.length ? v : "all" }); }}>
            {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
          <Field label="Alert severity" hint="None select = all severities · High = DOWN/Critical · Medium = Trouble · Low = Attention">
            <MultiCheck options={[["High", "High"], ["Medium", "Medium"], ["Low", "Low"]]} value={scope.severities} onChange={(v) => setScope({ severities: v })} /></Field>

          {tpl.fields.length > 0 && <div className="section-title">Parameters</div>}
          {tpl.fields.map((x) => <ParamField key={x.key} f={x} value={(sp.params || {})[x.key]} onChange={setP(x.key)} ctx={{ sites, assets }} />)}

          {code === "CUSTOM" && <>
            <div className="section-title">Content</div>
            <Field label="Notification title" hint={`Variables: ${catalog.placeholders.map((p) => `{${p}}`).join(" ")}`} full>
              <Input value={content.title} onChange={(v) => setContent({ title: v })} placeholder={trg.type === "event" ? "[HQ] {title}" : "Infrastructure status {time}"} /></Field>
            {trg.type === "event" ? <Field label="Content tin" full><textarea className="input" rows={3} value={content.message || ""} onChange={(e) => setContent({ message: e.target.value })}
              placeholder="{asset} at {site} — {severity} at {time}\n{message}" /></Field> : <>
              <Field label="Content blocks" full><MultiCheck options={catalog.blocks.map((b) => [b.key, b.label])} value={content.blocks} onChange={(v) => setContent({ blocks: v })} /></Field>
              <Field label="Send when"><Select value={sp.send_when || "always"} onChange={(v) => setSpec("send_when", v)} options={[["always", "Always send"], ["has_items", "Only when there are items to report"]]} /></Field>
              <Field label="Intro message (optional)"><Input value={content.message} onChange={(v) => setContent({ message: v })} /></Field>
            </>}
          </>}

          {trg.type !== "hook" && <><div className="section-title">Send to</div>
            <Field full><Targets value={sp.actions} onChange={(v) => setSpec("actions", v)} /></Field></>}
        </div>
      )}
      {preview && <PreviewBox r={preview} onClose={() => setPreview(null)} />}
    </Modal>
  );
}

function PreviewBox({ r, onClose }) {
  return (
    <div className="card card-pad" style={{ marginTop: 14, background: "var(--subtle)" }}>
      <div className="row" style={{ marginBottom: 6 }}><FlaskConical size={15} /><b>Test result</b>
        <span className={`badge ${STATUS[r.status]?.[0] || ""}`}>{STATUS[r.status]?.[1] || r.status}</span>
        <span className="small muted">{r.summary}</span>
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={onClose}><X size={14} /></button></div>
      {r.output ? <pre className="auto-out">{r.output}</pre> : <div className="small muted">No notifications were generated with the current data.</div>}
      <div className="small faint" style={{ marginTop: 6 }}>The test run does not send notifications or make changes.</div>
    </div>
  );
}

// ------------------------------------------------------------------ trang
export default function Automation() {
  const { isAdmin } = useApp();
  const toast = useToast();
  const [tab, setTab] = useState("library");
  const [tick, setTick] = useState(0);
  const catalog = useApi("/automation/catalog").data;
  const autos = useApi("/automations", { interval: 30000, deps: [tick] }).data;
  const runs = useApi("/automation/runs?limit=200", { interval: 30000, deps: [tick, tab] }).data;
  const [edit, setEdit] = useState(null);
  const [out, setOut] = useState(null);
  const refresh = () => setTick((x) => x + 1);
  const byCode = useMemo(() => Object.fromEntries((autos || []).filter((a) => a.code !== "CUSTOM").map((a) => [a.code, a])), [autos]);
  if (!catalog || !autos) return null;
  const toggle = async (a, v) => { try { await api.put(`/automations/${a.id}`, { enabled: v }); refresh(); toast(v ? `Enabled ${a.code}` : `Disabled ${a.code}`); } catch (e) { toast(e.message, true); } };
  const runNow = async (a, dry) => {
    try { const r = await api.post(`/automations/${a.id}/run?dry=${dry}`); setOut({ ...r, title: `${a.code} · ${a.name}`, dry }); refresh(); } catch (e) { toast(e.message, true); }
  };
  const del = async (a) => { if (await confirmDelete(a.name)) { await api.del(`/automations/${a.id}`); refresh(); } };
  const on = autos.filter((a) => a.enabled).length;
  const errors = autos.filter((a) => a.last_status === "error").length;

  return (
    <>
      <PageHead crumb="Operations › Automation" title="Automation"
        desc="Scenario configuration: When to run → Scope → Content → Send to. The template library includes only templates supported by the currently available data.">
        {isAdmin && <button className="btn primary" onClick={() => setEdit({ code: "CUSTOM" })}><Plus size={16} />Create custom scenario</button>}
      </PageHead>
      <div className="stats">
        <Stat icon={Zap} label="Enabled" value={on} sub={`${autos.length} scenarios added`} tone={on ? "good" : ""} />
        <Stat icon={BookOpen} label="Available templates" value={catalog.templates.length - 1} sub={`${catalog.unsupported.length} types requiring further integration`} />
        <Stat icon={History} label="Recent runs" value={(runs || []).filter((r) => !r.dry_run).length} sub="Latest 200 runs" />
        <Stat icon={Ban} label="Error" value={errors} sub={errors ? "See History tab" : "Not available"} tone={errors ? "bad" : "good"} />
      </div>
      {DEMO && <div className="alert-box info" style={{ marginBottom: 12 }}>Demo mode: test runs display sample data and do not send notifications.</div>}
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "library", label: "Template library", icon: BookOpen, count: catalog.templates.length - 1 },
        { key: "mine", label: "My automations", icon: Zap, count: autos.length },
        { key: "runs", label: "Run history", icon: History },
      ]} />

      {tab === "library" && <>
        {GROUPS.map(([g, label, q]) => (
          <div key={g} style={{ marginBottom: 18 }}>
            <div className="auto-group"><b>{label}</b> <span className="badge">{g}</span> <span className="small muted">{q}</span></div>
            <div className="auto-grid">
              {catalog.templates.filter((t) => t.group === g).map((t) => {
                const a = byCode[t.code];
                return (
                  <div key={t.code} className={`card card-pad auto-card ${a?.enabled ? "on" : ""}`}>
                    <div className="row" style={{ gap: 6 }}><span className="badge mono">{t.code}</span><b className="grow">{t.name}</b>
                      {a && <span className={`badge ${a.enabled ? "ok" : ""}`}>{a.enabled ? "Enabled" : "Added · Disabled"}</span>}</div>
                    <div className="small" style={{ margin: "8px 0" }}>{t.desc}</div>
                    <div className="small muted">⏱ {t.when} · {t.data}</div>
                    <div className="small faint" style={{ marginTop: 2 }}>KPI: {t.kpi}</div>
                    {isAdmin && <div className="row" style={{ gap: 6, marginTop: 10 }}>
                      {a ? <>
                        <Toggle checked={a.enabled} onChange={(v) => toggle(a, v)} label="" />
                        <button className="btn sm" onClick={() => setEdit(a)}><Pencil size={13} />Edit</button>
                        <button className="btn sm" onClick={() => runNow(a, true)}><FlaskConical size={13} />Test run</button>
                      </> : <button className="btn sm primary" onClick={() => setEdit({ code: t.code })}><Plus size={13} />Use this template</button>}
                    </div>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        <details className="card card-pad">
          <summary style={{ cursor: "pointer" }}><b>Not supported ({catalog.unsupported.length})</b> <span className="small muted">– requires an integration or additional data; do not use these templates because they may run incorrectly</span></summary>
          <div style={{ marginTop: 10 }}>{catalog.unsupported.map((u) => <div key={u.code} className="small" style={{ padding: "4px 0" }}><span className="badge mono">{u.code}</span> <b>{u.name}</b> <span className="muted">– {u.reason}</span></div>)}</div>
        </details>
      </>}

      {tab === "mine" && <div className="card">
        <Table rows={autos} rowKey="id" onRow={isAdmin ? setEdit : undefined}
          empty={<Empty icon={Zap} title="No scenarios yet">Choose a template from the “Template library” or click “Create custom scenario”.</Empty>}
          columns={[
            { key: "enabled", label: "", width: 60, render: (a) => <span onClick={(e) => e.stopPropagation()}><Toggle checked={a.enabled} onChange={(v) => toggle(a, v)} label="" /></span> },
            { key: "name", label: "Automation", render: (a) => <div><div className="cell-title"><span className="badge mono">{a.code}</span> {a.name}</div><div className="cell-sub">{a.when} · {a.effective.level}</div></div> },
            { key: "next_run", label: "Next run", render: (a) => <span className="small">{a.next_run ? fmtTime(a.next_run) : a.enabled ? a.when : "—"}</span> },
            { key: "last_run_at", label: "Last run", render: (a) => a.last_run_at ? <div className="small"><span className={`badge ${STATUS[a.last_status]?.[0] || ""}`}>{STATUS[a.last_status]?.[1] || a.last_status}</span> {timeAgo(a.last_run_at)}<div className="faint" style={{ maxWidth: 320 }}>{a.last_summary}</div></div> : <span className="faint small">Not running</span> },
            ...(isAdmin ? [{ key: "act", label: "", render: (a) => <div className="row" style={{ gap: 4 }} onClick={(e) => e.stopPropagation()}>
              <button className="btn sm" title="Test run – preview only, no notifications sent" onClick={() => runNow(a, true)}><FlaskConical size={13} /></button>
              <button className="btn sm" title="Run now and send notifications" onClick={() => runNow(a, false)}><Play size={13} /></button>
              <button className="btn sm" title="Delete" onClick={() => del(a)}><Trash2 size={13} /></button></div> }] : []),
          ]} />
      </div>}

      {tab === "runs" && <div className="card">
        <Table rows={runs || []} rowKey="id" onRow={(r) => setOut({ ...r, title: `${r.code} · ${r.name}` })}
          empty={<Empty icon={History} title="No runs yet" />}
          columns={[
            { key: "ts", label: "Time", render: (r) => <span className="small">{fmtTime(r.ts)}</span> },
            { key: "name", label: "Automation", render: (r) => <span className="small"><span className="badge mono">{r.code}</span> {r.name}</span> },
            { key: "trigger", label: "Trigger", render: (r) => <span className="small">{TRIG[r.trigger] || r.trigger}{r.dry_run && " · test"}</span> },
            { key: "status", label: "Result", render: (r) => <span className={`badge ${STATUS[r.status]?.[0] || ""}`}>{STATUS[r.status]?.[1] || r.status}</span> },
            { key: "summary", label: "Summary", render: (r) => <span className="small">{r.summary}</span> },
            { key: "sent", label: "Sent", render: (r) => <span className="small faint">{Object.entries(r.sent || {}).map(([k, v]) => `${k}: ${v}`).join(" · ") || (r.dry_run ? "Not sent" : "—")}</span> },
          ]} />
        <CapNote shown={(runs || []).length} limit={200} what="runs" hint="Older runs are not listed here." />
      </div>}

      {edit && <AutomationEditor edit={edit} catalog={catalog} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); refresh(); setTab("mine"); }} />}
      {out && <Modal title={out.title} onClose={() => setOut(null)} width={720} footer={<button className="btn" onClick={() => setOut(null)}>Close</button>}>
        <div className="row" style={{ marginBottom: 8, gap: 8 }}><span className={`badge ${STATUS[out.status]?.[0] || ""}`}>{STATUS[out.status]?.[1] || out.status}</span>
          <span className="small muted">{out.summary}</span>{out.dry && <span className="badge">Test run – no notifications sent</span>}</div>
        {out.output ? <pre className="auto-out">{out.output}</pre> : <div className="small muted">No notifications were generated.</div>}
        {out.sent && Object.keys(out.sent).length > 0 && <div className="small" style={{ marginTop: 8 }}><b>Sent:</b> {Object.entries(out.sent).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>}
      </Modal>}
    </>
  );
}
