import React, { useState } from "react";
import { ShieldCheck, ShieldAlert, Smartphone, LogOut, MonitorSmartphone } from "lucide-react";
import { api } from "../api";
import { Field, Input, useApi, useToast, Table, fmtTime, askConfirm } from "../ui";

const svgSrc = (svg) => `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;
const group4 = (s) => (s || "").replace(/(.{4})/g, "$1 ").trim();

// Enable 2FA: generate a QR code → scan it with an authenticator app → enter the six-digit code to confirm
export function TwoFactorSetup({ onDone, forced }) {
  const toast = useToast();
  const [st, setSt] = useState(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const start = async () => {
    setBusy(true); setErr("");
    try { setSt(await api.post("/auth/2fa/setup")); } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const confirm = async (e) => {
    e && e.preventDefault();
    setBusy(true); setErr("");
    try { const u = await api.post("/auth/2fa/enable", { code }); toast("Two-factor authentication enabled"); onDone && onDone(u); }
    catch (e2) { setErr(e2.message); } finally { setBusy(false); }
  };
  return (
    <div className="stack" style={{ gap: 12 }}>
      {forced && <div className="alert-box warn">The <b>administrator</b> account must use two-factor authentication (2FA). You must enable it before accessing the system.</div>}
      {!st && (
        <>
          <div className="muted" style={{ lineHeight: 1.6 }}>
            You need an authenticator app on your phone: <b>Google Authenticator</b>, <b>Microsoft Authenticator</b> or an equivalent app.
            After enabling this, each sign-in requires a six-digit code from the app.
          </div>
          <div><button className="btn primary" onClick={start} disabled={busy}><Smartphone size={15} />{busy ? "Generating..." : "Generate QR code"}</button></div>
        </>
      )}
      {st && (
        <form onSubmit={confirm} className="stack" style={{ gap: 12 }}>
          <div className="row" style={{ alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
            <img src={svgSrc(st.qr_svg)} alt="2FA QR code" width={180} height={180} style={{ border: "1px solid var(--border)", borderRadius: 8, background: "#fff" }} />
            <div className="stack" style={{ gap: 8, flex: 1, minWidth: 220 }}>
              <div><b>1.</b> Open your authenticator app → <b>Add</b> → <b>Scan QR code</b>.</div>
              <div className="small muted">Unable to scan? Enter the secret key manually:</div>
              <code className="mono" style={{ userSelect: "all", fontSize: 13, wordBreak: "break-all" }}>{group4(st.secret)}</code>
              <div><b>2.</b> Enter the six-digit code shown in the app:</div>
              <Field><Input value={code} onChange={(v) => setCode(v.replace(/\D/g, "").slice(0, 6))} autoFocus inputMode="numeric" autoComplete="one-time-code" placeholder="123456" /></Field>
            </div>
          </div>
          {err && <div className="alert-box fail">{err}</div>}
          <div className="row"><button className="btn primary" disabled={busy || code.length !== 6}><ShieldCheck size={15} />Verify and enable 2FA</button>
            <button type="button" className="btn ghost" onClick={start} disabled={busy}>Generate a new code</button></div>
        </form>
      )}
      {!st && err && <div className="alert-box fail">{err}</div>}
    </div>
  );
}

// Blocking screen: the administrator has not enabled 2FA when it is mandatory
export function ForcedTwoFactor({ me, onDone, onLogout }) {
  return (
    <div className="login-wrap">
      <div className="card login" style={{ maxWidth: 560 }}>
        <h2 style={{ marginTop: 0 }}><ShieldAlert size={20} style={{ verticalAlign: -3 }} /> Enable two-factor authentication</h2>
        <p className="muted" style={{ marginTop: 0 }}>Hello <b>{me.full_name || me.username}</b>.</p>
        <TwoFactorSetup forced onDone={onDone} />
        <div style={{ marginTop: 16 }}><button className="btn ghost sm" onClick={onLogout}><LogOut size={14} />Sign out</button></div>
      </div>
    </div>
  );
}

// Card in "My account"
export function TwoFactorCard({ me, onChange }) {
  const toast = useToast();
  const [f, setF] = useState({ password: "", code: "" });
  const [showSetup, setShowSetup] = useState(false);
  const disable = async () => {
    try { onChange(await api.post("/auth/2fa/disable", f)); toast("Disabled 2FA"); setF({ password: "", code: "" }); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card card-pad" style={{ maxWidth: 560 }}>
      <h3 style={{ marginTop: 0 }}>Two-factor Authentication (2FA)</h3>
      {me.totp_enabled ? (
        <div className="stack" style={{ gap: 12 }}>
          <div><span className="badge ok"><ShieldCheck size={13} />Enabled</span>
            {me.require_2fa && <span className="small muted" style={{ marginLeft: 8 }}>Required for the administrator account — it cannot be disabled by the user.</span>}</div>
          {me.require_2fa
            ? <div className="small muted">If you change or lose your phone, ask another admin to select <b>Reset 2FA</b> on the Users tab (or run the VS Code task "9. Reset 2FA for admin").</div>
            : <div className="stack" style={{ gap: 10, maxWidth: 360 }}>
                <Field label="Password"><Input type="password" value={f.password} onChange={(v) => setF({ ...f, password: v })} /></Field>
                <Field label="Current six-digit code"><Input value={f.code} onChange={(v) => setF({ ...f, code: v.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" /></Field>
                <div><button className="btn danger" onClick={disable}>Disable 2FA</button></div>
              </div>}
        </div>
      ) : showSetup ? (
        <TwoFactorSetup onDone={(u) => { setShowSetup(false); onChange(u); }} />
      ) : (
        <div className="stack" style={{ gap: 12 }}>
          <div><span className="badge warn"><ShieldAlert size={13} />Not enabled</span></div>
          <div className="small muted">Enable this to protect the account if the password is compromised.</div>
          <div><button className="btn primary" onClick={() => setShowSetup(true)}><Smartphone size={15} />Enable 2FA</button></div>
        </div>
      )}
    </div>
  );
}

const uaShort = (ua) => {
  if (!ua) return "–";
  const b = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(" ")[0];
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} · ${os}` : b;
};

// Active Sessions: view and revoke
export function SessionsCard({ isAdmin, onSelfRevoked }) {
  const toast = useToast();
  const [all, setAll] = useState(false);
  const { data, reload } = useApi(`/auth/sessions${all ? "?all=1" : ""}`, { deps: [all] });
  const revoke = async (s) => {
    const ok = await askConfirm({ title: s.current ? "Sign out this session?" : `Revoke session for ${s.username}?`,
      message: `${uaShort(s.user_agent)} · ${s.ip}. That device will need to sign in again.`, okText: "Revoke", danger: true });
    if (!ok) return;
    try { const r = await api.del(`/auth/sessions/${s.id}`); toast("Session revoked"); if (r.current) onSelfRevoked && onSelfRevoked(); else reload(); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card" style={{ maxWidth: 900 }}>
      <div className="toolbar"><b className="grow"><MonitorSmartphone size={16} style={{ verticalAlign: -3 }} /> Active Sessions</b>
        {isAdmin && <label className="row small"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />All Users</label>}</div>
      <Table rows={data || []} columns={[
        ...(all ? [{ key: "username", label: "Username", render: (s) => <b>{s.username}</b> }] : []),
        { key: "user_agent", label: "Device", render: (s) => <span title={s.user_agent}>{uaShort(s.user_agent)}{s.current && <span className="badge accent" style={{ marginLeft: 6 }}>Current Session</span>}</span> },
        { key: "ip", label: "IP", render: (s) => <span className="mono small">{s.ip}</span> },
        { key: "mfa", label: "2FA", render: (s) => s.mfa ? <span className="badge ok">Yes</span> : <span className="badge">None</span> },
        { key: "created_at", label: "Signed in at", render: (s) => <span className="small muted">{fmtTime(s.created_at)}</span> },
        { key: "last_seen", label: "Last Activity", render: (s) => <span className="small muted">{fmtTime(s.last_seen)}</span> },
        { key: "a", label: "", sortable: false, render: (s) => <button className="btn ghost sm danger" onClick={() => revoke(s)}>Revoke</button> },
      ]} />
    </div>
  );
}
