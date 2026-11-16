import React, { useEffect, useState } from "react";
import { Save, ShieldCheck, Archive, RefreshCw, CheckCircle2, XCircle, Radio } from "lucide-react";
import { api } from "../api";
import { Field, Input, Select, Toggle, useToast, Table, fmtTime } from "../ui";

const DAYS = [["0", "T2"], ["1", "T3"], ["2", "T4"], ["3", "T5"], ["4", "T6"], ["5", "T7"], ["6", "CN"]];
const SEV = [["critical", "Critical"], ["trouble", "Trouble"], ["attention", "Attention"]];

// targets [{type:'default'|'email'|'telegram', to|chat}] <-> {useDefault, emails, chat}
const fromTargets = (t = []) => ({
  useDefault: t.some((x) => x.type === "default"),
  emails: t.filter((x) => x.type === "email").map((x) => x.to).join(", "),
  chat: (t.find((x) => x.type === "telegram") || {}).chat || "",
});
const toTargets = ({ useDefault, emails, chat }) => [
  ...(useDefault ? [{ type: "default" }] : []),
  ...String(emails || "").split(",").map((x) => x.trim()).filter(Boolean).map((to) => ({ type: "email", to })),
  ...(chat ? [{ type: "telegram", chat: String(chat).trim() }] : []),
];

function Targets({ value, onChange, allowDefault = true }) {
  const v = fromTargets(value);
  const set = (k) => (x) => onChange(toTargets({ ...v, [k]: x }));
  return (
    <div className="form-grid">
      {allowDefault && <Field label="Default channel" hint="Channels enabled on the Alert channels tab"><Toggle checked={v.useDefault} onChange={set("useDefault")} label="Send to all default channels" /></Field>}
      <Field label="Dedicated email recipients" hint="Comma-separated values"><Input value={v.emails} onChange={set("emails")} placeholder="truong.it@congty.vn" /></Field>
      <Field label="Dedicated Telegram chat" hint="Group/recipient chat ID (use the bot configured under Alert channels)"><Input value={v.chat} onChange={set("chat")} placeholder="-1001234567890" /></Field>
    </div>
  );
}

export function SecuritySettings() {
  const toast = useToast();
  const [s, setS] = useState(null);
  const [arc, setArc] = useState(null);
  const loadArc = () => api.get("/secmon/archive").then(setArc).catch(() => {});
  useEffect(() => { api.get("/secmon").then(setS).catch((e) => toast(e.message, true)); loadArc(); }, []);
  if (!s) return null;
  const up = (sec, k) => (v) => setS({ ...s, [sec]: { ...s[sec], [k]: v } });
  const upSla = (lvl, k) => (v) => setS({ ...s, sla: { ...s.sla, [lvl]: { ...s.sla[lvl], [k]: k === "mode" ? v : Number(v) } } });
  const num = (sec, k) => (v) => up(sec, k)(Number(v));
  const save = async () => {
    try { const { production, archive_path, ...body } = s; setS({ ...(await api.put("/secmon", body)), production, archive_path }); toast("Security monitoring configuration saved"); }
    catch (e) { toast(e.message, true); }
  };
  const runArc = async () => {
    try { const r = await api.post("/secmon/archive/run"); toast(r.made.length ? `Archived ${r.made.length} days` : "No additional days to archive"); loadArc(); }
    catch (e) { toast(e.message, true); }
  };
  const days = new Set((s.business.days || []).map(String));
  return (
    <div className="stack" style={{ maxWidth: 900 }}>
      {s.production
        ? <div className="alert-box ok"><ShieldCheck size={14} style={{ verticalAlign: -2 }} /> Running in <b>production</b> mode: deleting all data is disabled.</div>
        : <div className="alert-box info">Production mode is not enabled. For production deployment, set <span className="mono">ITOPS_ENV=production</span> in .env to disable the delete-all-data feature.</div>}

      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Business Hours and SLA</h3>
        <p className="muted small" style={{ marginTop: 0 }}>The acknowledgment deadline starts when an alert is opened. Critical alerts are measured 24/7 (with a separate after-hours deadline); Trouble/Attention alerts are measured only during business hours. Overdue alerts are flagged and a reminder is sent once.</p>
        <div className="form-grid">
          <Field label="Working Days">
            <div className="row wrap">{DAYS.map(([d, l]) => <label key={d} className="row small" style={{ gap: 4 }}><input type="checkbox" checked={days.has(d)}
              onChange={(e) => { const n = new Set(days); e.target.checked ? n.add(d) : n.delete(d); up("business", "days")([...n].map(Number).sort()); }} />{l}</label>)}</div>
          </Field>
          <Field label="Start – End Time"><div className="row"><Input value={s.business.start} onChange={up("business", "start")} /><span>–</span><Input value={s.business.end} onChange={up("business", "end")} /></div></Field>
        </div>
        <table className="tbl" style={{ marginTop: 10 }}>
          <thead><tr><th>Severity</th><th>Calculation</th><th>Ack Deadline (minutes)</th><th>After-hours Ack Deadline (minutes)</th></tr></thead>
          <tbody>{SEV.map(([k, l]) => (
            <tr key={k}><td><b>{l}</b></td>
              <td><Select value={s.sla[k].mode} onChange={upSla(k, "mode")} options={[["24x7", "24/7"], ["business", "Business hours"]]} /></td>
              <td><Input type="number" value={s.sla[k].ack_min} onChange={upSla(k, "ack_min")} /></td>
              <td>{s.sla[k].mode === "24x7" ? <Input type="number" value={s.sla[k].ack_min_off ?? s.sla[k].ack_min} onChange={upSla(k, "ack_min_off")} /> : <span className="faint">—</span>}</td></tr>))}
          </tbody>
        </table>
        <div style={{ marginTop: 8 }}><Toggle checked={s.sla.notify !== false} onChange={(v) => setS({ ...s, sla: { ...s.sla, notify: v } })} label="Send a reminder when the ack deadline is missed" /></div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Administrator Activity Alerts (UC-14)</h3>
          <Toggle checked={s.audit_alert.enabled} onChange={up("audit_alert", "enabled")} label="Enable" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Trigger on repeated failed IT Ops logins, account creation/deletion, role changes, disabling/deleting checks, log rules or automation scenarios, notification channel changes, data imports/deletions, and changes to this page.
          The actor <b>cannot acknowledge or resolve</b> alerts about their own activity. Send these alerts to the IT lead / ISMS owner rather than the general administrator group.</p>
        <Targets value={s.audit_alert.targets} onChange={up("audit_alert", "targets")} />
        <div className="form-grid" style={{ marginTop: 8 }}>
          <Field label="Failed Sign-ins: Count"><Input type="number" value={s.audit_alert.login_fail_threshold} onChange={num("audit_alert", "login_fail_threshold")} /></Field>
          <Field label="within (minutes)"><Input type="number" value={s.audit_alert.window_min} onChange={num("audit_alert", "window_min")} /></Field>
        </div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Silent Log Source (UC-13)</h3>
          <Toggle checked={s.silence.enabled} onChange={up("silence", "enabled")} label="Enable" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Applies only to devices that have previously sent logs. No alert is generated when a device is DOWN (the monitoring checks already reports this). For switches with an SNMP checks, alert only while SNMP remains responsive.
          Linux servers should send periodic heartbeats, for example cron <span className="mono">*/10 * * * * logger -t itops-heartbeat alive</span>, to support short thresholds.</p>
        <div className="form-grid">
          <Field label="Firewall / Router (minutes)"><Input type="number" value={s.silence.firewall} onChange={num("silence", "firewall")} /></Field>
          <Field label="Server / VM (minutes)"><Input type="number" value={s.silence.server} onChange={num("silence", "server")} /></Field>
          <Field label="Switch / AP (minutes)"><Input type="number" value={s.silence.switch} onChange={num("silence", "switch")} /></Field>
          <Field label="Other Devices (minutes)"><Input type="number" value={s.silence.other} onChange={num("silence", "other")} /></Field>
        </div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Log Archive and Hash Chain</h3>
          <Toggle checked={s.archive.enabled} onChange={up("archive", "enabled")} label="Enable" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Every day at {s.archive.run_at}, logs, audit records, and alerts from the previous day are compressed into <span className="mono">itops-YYYY-MM-DD.jsonl.gz</span>,
          calculate SHA-256 and append it to <span className="mono">hash-chain.csv</span>. Any file modification or deletion is detected. The directory should be on a NAS volume with read-only snapshots.</p>
        <div className="form-grid">
          <Field label="Archive Directory" hint={`Current: ${s.archive_path}`} full><Input value={s.archive.dir} onChange={up("archive", "dir")} placeholder="\\\\NAS01\\itops-archive or /mnt/nas/itops" /></Field>
          <Field label="Database Retention (days)"><Input type="number" value={s.archive.db_days} onChange={num("archive", "db_days")} /></Field>
          <Field label="Archive File Retention (days)"><Input type="number" value={s.archive.keep_days} onChange={num("archive", "keep_days")} /></Field>
          <Field label="Run Time"><Input value={s.archive.run_at} onChange={up("archive", "run_at")} /></Field>
        </div>
        <h4 style={{ marginBottom: 6 }}>Send Daily Hash To</h4>
        <Targets value={s.archive.hash_targets} onChange={up("archive", "hash_targets")} allowDefault={false} />
      </div>
      <div className="row"><button className="btn primary" onClick={save}><Save size={15} />Save Configuration</button></div>

      <div className="card">
        <div className="row card-pad" style={{ paddingBottom: 0 }}>
          <h3 style={{ margin: 0 }} className="grow"><Archive size={16} style={{ verticalAlign: -3 }} /> Verify Archive Integrity</h3>
          {arc && (arc.ok ? <span className="badge ok">Hash chain is valid</span> : <span className="badge fail">Integrity mismatch detected</span>)}
          <button className="btn" onClick={loadArc}><RefreshCw size={14} />Verify Again</button>
          <button className="btn" onClick={runArc}><Archive size={14} />Archive Missing Days Now</button>
        </div>
        <Table rowKey="day" empty="No archived days found." rows={(arc?.days || []).slice(0, 60)} columns={[
          { key: "day", label: "Date", render: (r) => <span className="mono">{r.day}</span> },
          { key: "rows", label: "Records" },
          { key: "size", label: "Size", render: (r) => r.exists ? `${(r.size / 1024).toFixed(1)} KB` : <span className="faint">deleted by retention policy</span> },
          { key: "sha256", label: "SHA-256", render: (r) => <span className="mono small">{r.sha256.slice(0, 16)}…</span> },
          { key: "ok", label: "Integrity", render: (r) => (r.chain_ok && (r.file_ok || !r.exists))
            ? <CheckCircle2 size={16} color="var(--ok)" /> : <span className="row small" style={{ color: "var(--fail)" }}><XCircle size={16} />{!r.chain_ok ? "invalid chain" : "file modified"}</span> },
        ]} />
      </div>
    </div>
  );
}

// D: source currently sending logs to IT Ops — answer the question: “Are the device logs arriving?”
export function SourcesCard() {
  const [d, setD] = useState(null);
  const load = () => api.get("/receivers/sources").then(setD).catch(() => {});
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  const ago = (s) => s < 60 ? `${s} seconds` : s < 3600 ? `${Math.floor(s / 60)} minutes` : `${Math.floor(s / 3600)} hours`;
  return (
    <div className="card">
      <div className="row card-pad" style={{ paddingBottom: 0 }}>
        <h3 style={{ margin: 0 }} className="grow"><Radio size={16} style={{ verticalAlign: -3 }} /> Sources Currently Sending to IT Ops</h3>
        <span className="small muted">Auto-refresh every 5 seconds · since IT Ops started</span>
      </div>
      <p className="muted small card-pad" style={{ margin: 0, paddingTop: 6 }}>A device missing from this table means no packets have reached IT Ops (check the device configuration, capture traffic on port 514, and review Windows Firewall).
        If a device appears but is <b>blocked</b>, add its IP address to the allowlist above.</p>
      <Table rowKey="ip" empty="No packets received since startup." rows={d?.sources || []} columns={[
        { key: "ip", label: "IP source", render: (r) => <span className="mono">{r.ip}</span> },
        { key: "asset", label: "Asset", render: (r) => r.asset || <span className="faint">Not configured</span> },
        { key: "kind", label: "Type" },
        { key: "count", label: "Packet Count" },
        { key: "last", label: "Last Seen", render: (r) => `${ago(r.ago_s)} ago` },
        { key: "blocked", label: "Status", render: (r) => r.blocked ? <span className="badge fail">Blocked (IP not allowlisted)</span> : <span className="badge ok">Received</span> },
      ]} />
    </div>
  );
}
