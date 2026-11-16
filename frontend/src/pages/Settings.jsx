import React, { useEffect, useRef, useState } from "react";
import { Send, Save, Download, Upload, Trash2, Plus, KeyRound, Users, BellRing, Database, Radio, ShieldCheck } from "lucide-react";
import { api, SECRET } from "../api";
import { useApp } from "../App";
import { SecuritySettings, SourcesCard } from "../components/SecuritySettings";
import { TwoFactorCard, SessionsCard } from "../components/AccountSecurity";
import { useApi, PageHead, Tabs, Field, Input, Select, Toggle, useToast, Table, Modal, fmtTime, confirmDelete, askConfirm, DEMO } from "../ui";

function Secret({ value, onChange, placeholder }) {
  return <input className="input" type="password" autoComplete="new-password" value={value === SECRET ? "" : value || ""}
    placeholder={value === SECRET ? "•••••• (saved)" : placeholder} onChange={(e) => onChange(e.target.value || (value === SECRET ? SECRET : ""))} />;
}

function NotifySettings() {
  const toast = useToast();
  const [s, setS] = useState(null);
  useEffect(() => { api.get("/settings/notify").then(setS); }, []);
  if (!s) return null;
  const set = (ch, k) => (v) => setS({ ...s, [ch]: { ...s[ch], [k]: v } });
  const save = async () => { try { setS(await api.put("/settings/notify", s)); toast("Alert configuration saved"); } catch (e) { toast(e.message, true); } };
  const test = async (ch) => {
    await save();
    const r = await api.post(`/settings/notify/test/${ch}`);
    r[ch] === "ok" ? toast("Test message sent ✓") : toast(`Send failed: ${r[ch]}`, true);
  };
  const t = s.telegram, e = s.email, w = s.webhook;
  return (
    <div className="stack">
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Telegram</h3><Toggle checked={t.enabled} onChange={set("telegram", "enabled")} label="Enable" /></div>
        <div className="form-grid">
          <Field label="Bot Token" hint="Create a bot with @BotFather"><Secret value={t.bot_token} onChange={set("telegram", "bot_token")} placeholder="123456:ABC..." /></Field>
          <Field label="Chat ID" hint="IT group ID (add the bot to the group, then use @userinfobot / getUpdates to retrieve it)"><Input value={t.chat_id} onChange={set("telegram", "chat_id")} placeholder="-100123456789" /></Field>
          <Field><Toggle checked={t.include_warnings ?? true} onChange={set("telegram", "include_warnings")} label="Include warnings (not only errors)" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("telegram")}><Send size={14} />Send Test</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Email (SMTP)</h3><Toggle checked={e.enabled} onChange={set("email", "enabled")} label="Enable" /></div>
        <div className="form-grid">
          <Field label="SMTP server"><Input value={e.host} onChange={set("email", "host")} placeholder="smtp.office365.com" /></Field>
          <Field label="Port"><Input type="number" value={e.port ?? 587} onChange={(v) => set("email", "port")(Number(v))} /></Field>
          <Field label="Security"><Select value={e.security || "starttls"} onChange={set("email", "security")} options={[["starttls", "STARTTLS (587)"], ["ssl", "SSL/TLS (465)"], ["none", "None"]]} /></Field>
          <Field label="Sender (From)"><Input value={e.from} onChange={set("email", "from")} placeholder="itops@congty.vn" /></Field>
          <Field label="Username"><Input value={e.username} onChange={set("email", "username")} /></Field>
          <Field label="Password"><Secret value={e.password} onChange={set("email", "password")} /></Field>
          <Field label="Send to" full hint="Comma-separated email addresses"><Input value={e.to} onChange={set("email", "to")} placeholder="it@congty.vn" /></Field>
          <Field><Toggle checked={e.include_warnings ?? true} onChange={set("email", "include_warnings")} label="Include warning-level alerts" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("email")}><Send size={14} />Send Test</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Webhook (Slack, Teams, Google Chat, Discord...)</h3><Toggle checked={w.enabled} onChange={set("webhook", "enabled")} label="Enable" /></div>
        <div className="form-grid">
          <Field label="URL" full><Input value={w.url} onChange={set("webhook", "url")} placeholder="https://hooks.slack.com/..." /></Field>
          <Field><Toggle checked={w.include_warnings ?? true} onChange={set("webhook", "include_warnings")} label="Include warning-level alerts" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("webhook")}><Send size={14} />Send Test</button></div>
        </div>
      </div>
      <div><button className="btn primary" onClick={save}><Save size={15} />Save configuration</button></div>
    </div>
  );
}

function ReceiverSettings() {
  const toast = useToast();
  const [s, setS] = useState(null);
  useEffect(() => { api.get("/settings/receivers").then(setS).catch((e) => toast(e.message, true)); }, []);
  if (!s) return null;
  const save = async () => { try { setS(await api.put("/settings/receivers", { ...s, allowed_sources: (s.allowed_sources || []).map((x) => x.trim()).filter(Boolean) })); toast("Receiver configuration saved"); } catch (e) { toast(e.message, true); } };
  const setU = (i, k, v) => setS({ ...s, v3_users: s.v3_users.map((u, j) => (j === i ? { ...u, [k]: v } : u)) });
  return (
    <div className="stack" style={{ maxWidth: 820 }}>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Port Listening</h3>
        <div className="kv"><div>Syslog UDP</div><div className="mono">{s.ports.syslog_udp}</div><div>Syslog TCP</div><div className="mono">{s.ports.syslog_tcp}</div><div>SNMP Trap UDP</div><div className="mono">{s.ports.snmp_trap}</div></div>
        <p className="muted small">Change ports using the environment variables SYSLOG_UDP_PORT / SYSLOG_TCP_PORT / TRAP_PORT in .env and the port mappings in docker-compose.yml.</p>
      </div>
      <SourcesCard />
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Allowed log / trap sender IPs</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Enter one IP address or subnet per line. Logs/traps from other IPs will be dropped (counted on the Device Logs page). Leave empty to accept from any source (not recommended).</p>
        <textarea className="input mono" style={{ minHeight: 110 }} value={(s.allowed_sources || []).join("\n")}
          onChange={(e) => setS({ ...s, allowed_sources: e.target.value.split("\n") })} placeholder={"10.0.0.0/8\n192.168.1.0/24"} />
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Community received trap (v1/v2c)</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Only traps with the matching community are accepted. Use a dedicated string different from the read community.</p>
        <div className="stack" style={{ gap: 8 }}>
          {s.communities.map((c, i) => (
            <div className="row" key={i}>
              <Secret value={c} onChange={(v) => setS({ ...s, communities: s.communities.map((x, j) => (j === i ? v : x)) })} placeholder="community" />
              <button className="btn ghost sm danger" onClick={() => setS({ ...s, communities: s.communities.filter((_, j) => j !== i) })}><Trash2 size={14} /></button>
            </div>
          ))}
          <div><button className="btn sm" onClick={() => setS({ ...s, communities: [...s.communities, ""] })}><Plus size={14} />Add community</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>SNMPv3 users (authenticated/encrypted traps)</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Devices sending SNMPv3 traps require the device Engine ID (available in the device configuration), unless INFORM is used.</p>
        {s.v3_users.map((u, i) => (
          <div className="form-grid" key={i} style={{ borderTop: i ? "1px solid var(--line)" : 0, paddingTop: i ? 12 : 0, marginBottom: 12 }}>
            <Field label="User"><Input value={u.username} onChange={(v) => setU(i, "username", v)} /></Field>
            <Field label="Device Engine ID (hex)"><Input value={u.engine_id} onChange={(v) => setU(i, "engine_id", v)} placeholder="80001f8880..." /></Field>
            <Field label="Auth"><div className="row"><Select value={u.auth_protocol || "SHA"} onChange={(v) => setU(i, "auth_protocol", v)} options={["SHA", "SHA256", "MD5"]} /><Secret value={u.auth_key} onChange={(v) => setU(i, "auth_key", v)} placeholder="auth password" /></div></Field>
            <Field label="Privacy"><div className="row"><Select value={u.priv_protocol || "AES"} onChange={(v) => setU(i, "priv_protocol", v)} options={["AES", "DES"]} /><Secret value={u.priv_key} onChange={(v) => setU(i, "priv_key", v)} placeholder="priv password" /></div></Field>
            <div><button className="btn sm danger" onClick={() => setS({ ...s, v3_users: s.v3_users.filter((_, j) => j !== i) })}><Trash2 size={14} />Delete user</button></div>
          </div>
        ))}
        <button className="btn sm" onClick={() => setS({ ...s, v3_users: [...s.v3_users, { username: "", auth_protocol: "SHA", priv_protocol: "AES" }] })}><Plus size={14} />Add user v3</button>
      </div>
      <div><button className="btn primary" onClick={save}><Save size={15} />Save receiver configuration</button></div>
    </div>
  );
}

function UsersSettings() {
  const { me } = useApp();
  const toast = useToast();
  const { data, reload } = useApi("/users");
  const [edit, setEdit] = useState(null);
  const save = async () => {
    try { edit.id ? await api.put(`/users/${edit.id}`, edit) : await api.post("/users", edit); toast("Saved"); setEdit(null); reload(); }
    catch (e) { toast(e.message, true); }
  };
  const remove = async (u) => { if (!(await confirmDelete(u.username))) return; try { await api.del(`/users/${u.id}`); reload(); } catch (e) { toast(e.message, true); } };
  const reset2fa = async (u) => {
    if (!(await askConfirm({ title: `Reset 2FA for ${u.username}?`, message: "Use this if the user loses or changes their phone. All their sessions will be revoked, and they must re-enable 2FA at next sign-in.", okText: "Reset", danger: true }))) return;
    try { await api.post(`/users/${u.id}/reset-2fa`); toast(`2FA reset for ${u.username}`); reload(); } catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card">
      <div className="toolbar"><b className="grow">User</b><button className="btn primary sm" onClick={() => setEdit({ role: "viewer" })}><Plus size={14} />Add</button></div>
      <Table rows={data || []} columns={[
        { key: "username", label: "Username", render: (u) => <b>{u.username}</b> },
        { key: "full_name", label: "Full name" },
        { key: "role", label: "Role", render: (u) => <span className={`badge ${u.role === "admin" ? "accent" : ""}`}>{u.role === "admin" ? "Administrator" : "Read-only"}</span> },
        { key: "totp_enabled", label: "2FA", render: (u) => u.totp_enabled ? <span className="badge ok">Enabled</span> : <span className={`badge ${u.require_2fa ? "warn" : ""}`}>{u.require_2fa ? "Not enabled (required)" : "Not enabled"}</span> },
        { key: "last_login", label: "Last sign-in", render: (u) => <span className="small muted">{u.last_login ? fmtTime(u.last_login) : "–"}</span> },
        { key: "a", label: "", sortable: false, render: (u) => <div className="row"><button className="btn ghost sm" onClick={() => setEdit({ ...u, password: "" })}>Edit</button>
          {u.id !== me.id && u.totp_enabled && <button className="btn ghost sm" onClick={() => reset2fa(u)}>Reset 2FA</button>}
          {u.id !== me.id && <button className="btn ghost sm danger" onClick={() => remove(u)}><Trash2 size={14} /></button>}</div> },
      ]} />
      {edit && (
        <Modal title={edit.id ? `Edit ${edit.username}` : "Add user"} onClose={() => setEdit(null)} width={520}
          footer={<><button className="btn" onClick={() => setEdit(null)}>Cancel</button><button className="btn primary" onClick={save}>Save</button></>}>
          <div className="stack" style={{ gap: 12 }}>
            <Field label="Username"><Input value={edit.username} onChange={(v) => setEdit({ ...edit, username: v })} disabled={!!edit.id} /></Field>
            <Field label="Full name"><Input value={edit.full_name} onChange={(v) => setEdit({ ...edit, full_name: v })} /></Field>
            <Field label="Role"><Select value={edit.role} onChange={(v) => setEdit({ ...edit, role: v })} options={[["viewer", "Read-only (helpdesk, managers)"], ["admin", "Administrator (create/edit/delete)"]]} /></Field>
            <Field label={edit.id ? "New password (leave blank to keep current)" : "Password"} hint="At least 8 characters"><Input type="password" value={edit.password} onChange={(v) => setEdit({ ...edit, password: v })} /></Field>
          </div>
        </Modal>
      )}
    </div>
  );
}

function AccountSettings() {
  const { me, setMe, isAdmin, logout } = useApp();
  return (
    <div className="stack" style={{ gap: 16 }}>
      <PasswordCard />
      <TwoFactorCard me={me} onChange={(u) => setMe({ ...me, ...u })} />
      <SessionsCard isAdmin={isAdmin} onSelfRevoked={logout} />
    </div>
  );
}

function PasswordCard() {
  const toast = useToast();
  const [f, setF] = useState({ old_password: "", new_password: "", confirm: "" });
  const save = async () => {
    if (f.new_password !== f.confirm) return toast("The passwords do not match", true);
    try { await api.post("/auth/password", f); toast("Password changed — all other sessions have been revoked"); setF({ old_password: "", new_password: "", confirm: "" }); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card card-pad" style={{ maxWidth: 480 }}>
      <h3 style={{ marginTop: 0 }}>Change password</h3>
      <div className="stack" style={{ gap: 12 }}>
        <Field label="Current password"><Input type="password" value={f.old_password} onChange={(v) => setF({ ...f, old_password: v })} /></Field>
        <Field label="New password" hint="At least 8 characters"><Input type="password" value={f.new_password} onChange={(v) => setF({ ...f, new_password: v })} /></Field>
        <Field label="Confirm password"><Input type="password" value={f.confirm} onChange={(v) => setF({ ...f, confirm: v })} /></Field>
        <div><button className="btn primary" onClick={save}><KeyRound size={15} />Change password</button></div>
      </div>
    </div>
  );
}

function DataSettings() {
  const toast = useToast();
  const { refresh } = useApp();
  const file = useRef();
  const exportData = async () => {
    const res = await fetch("/api/export", { credentials: "same-origin", headers: { "X-Requested-With": "itops" } });
    const blob = await res.blob();
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `itops-export-${new Date().toISOString().slice(0, 10)}.json`; a.click();
  };
  const importData = async (e) => {
    const fl = e.target.files[0]; if (!fl) return;
    try { const r = await api.post("/import", JSON.parse(await fl.text())); toast(`Imported ${r.imported} records`); refresh(); }
    catch (err) { toast(err.message, true); }
    e.target.value = "";
  };
  const [prod, setProd] = useState(false);
  useEffect(() => { api.get("/health").then((h) => setProd(!!h.production)).catch(() => {}); }, []);
  const reset = async () => {
    const ok = await askConfirm({ title: "Delete all infrastructure data?", message: "This deletes all sites, assets, checks, alerts, and critical systems (e.g. to remove sample data). User accounts and alert receiver settings are retained.", requireText: "XOA", okText: "Delete all", danger: true });
    if (!ok) return;
    try { await api.post("/reset-data", { confirm: "XOA" }); toast("Data deleted"); refresh(); } catch (err) { toast(err.message, true); }
  };
  return (
    <div className="stack" style={{ maxWidth: 720 }}>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Configuration backup</h3>
        <p className="muted">Export all sites, assets, checks, and critical systems to a JSON file (device passwords remain encrypted and can only be imported on the same server with the same SECRET_KEY).</p>
        {DEMO && <div className="alert-box info" style={{ marginBottom: 10 }}>File downloads are unavailable in the demo; this feature is available in a production installation.</div>}
        <div className="row"><button className="btn" onClick={exportData}><Download size={15} />Export file</button>
          <button className="btn" onClick={() => file.current.click()}><Upload size={15} />Import file</button>
          <input type="file" accept=".json" ref={file} style={{ display: "none" }} onChange={importData} /></div>
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0, color: "var(--fail)" }}>Delete data</h3>
        <p className="muted">Use this to remove sample data before adding your production infrastructure. User accounts and alert settings are retained.</p>
        {prod
          ? <div className="alert-box ok">Running in production (ITOPS_ENV=production): this feature is locked. All attempts are recorded in the audit log and generate alerts.</div>
          : <button className="btn danger" onClick={reset}><Trash2 size={15} />Delete all infrastructure data</button>}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { route, isAdmin } = useApp();
  const [tab, setTab] = useState(route.params.tab || (isAdmin ? "notify" : "account"));
  const tabs = isAdmin
    ? [{ key: "notify", label: "Alert channels", icon: BellRing }, { key: "receivers", label: "Syslog / Trap receivers", icon: Radio }, { key: "security", label: "Security monitoring", icon: ShieldCheck }, { key: "users", label: "User", icon: Users }, { key: "account", label: "My account", icon: KeyRound }, { key: "data", label: "Data", icon: Database }]
    : [{ key: "account", label: "My account", icon: KeyRound }];
  return (
    <>
      <PageHead crumb="Administrator › Settings" title="Settings" desc="Alert delivery channels, users, and configuration backups." />
      <Tabs value={tab} onChange={setTab} tabs={tabs} />
      {tab === "notify" && <NotifySettings />}
      {tab === "users" && <UsersSettings />}
      {tab === "receivers" && <ReceiverSettings />}
      {tab === "security" && <SecuritySettings />}
      {tab === "account" && <AccountSettings />}
      {tab === "data" && <DataSettings />}
    </>
  );
}
