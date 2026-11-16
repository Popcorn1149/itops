import React, { useEffect, useState } from "react";
import { ShieldCheck, Timer } from "lucide-react";
import { api } from "../api";
import { Field, Input, DEMO } from "../ui";
import ThemeSwitch from "../components/ThemeSwitch";

export default function Login({ onLogin, appName, notice }) {
  const [u, setU] = useState(DEMO ? "admin" : "");
  const [p, setP] = useState(DEMO ? "demo" : "");
  const [otp, setOtp] = useState("");
  const [needOtp, setNeedOtp] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  // Step 2 (2FA): the server issues a ticket valid for a limited time (default 3 minutes).
  // The password is NOT kept in memory or sent again; when time runs out the user must re-enter it.
  const [ticket, setTicket] = useState("");
  const [deadline, setDeadline] = useState(0);
  const [left, setLeft] = useState(0);
  const [limit, setLimit] = useState(180);   // seconds

  const backToPassword = (msg = "") => { setNeedOtp(false); setTicket(""); setDeadline(0); setOtp(""); setP(""); setErr(msg); };

  useEffect(() => {
    if (!needOtp || !deadline) return undefined;
    const tickFn = () => {
      const s = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      setLeft(s);
      if (s <= 0) backToPassword(`Time's up: the 2FA step expired after ${limit % 60 ? `${limit} seconds` : limit === 60 ? "1 minute" : `${limit / 60} minutes`}. Please enter your password again.`);
    };
    tickFn();
    const i = setInterval(tickFn, 1000);
    return () => clearInterval(i);
  }, [needOtp, deadline, limit]);

  const submit = async (e) => {
    e.preventDefault();
    if (needOtp && deadline && Date.now() >= deadline) return;
    setBusy(true); setErr("");
    try {
      const body = needOtp ? { mfa_ticket: ticket, otp } : { username: u, password: p };
      const r = await api.post("/auth/login", body);
      onLogin(r.user);
    } catch (e2) {
      const d = e2.detail && typeof e2.detail === "object" ? e2.detail : {};
      if (d.mfa_expired) {
        backToPassword(e2.message);            // ticket expired / invalid → back to the password step
      } else if (d.need_otp && d.mfa_ticket) {
        const ttl = Number(d.expires_in) || 180;
        setTicket(d.mfa_ticket); setDeadline(Date.now() + ttl * 1000); setLeft(ttl); setLimit(ttl);
        setNeedOtp(true); setOtp(""); setP("");  // password is correct → drop it from memory
      } else if (d.need_otp) {
        setErr(e2.message); setOtp("");        // already on step 2 → invalid code, the timer keeps running
      } else {
        setErr(e2.message);
      }
    } finally {
      setBusy(false);
    }
  };
  const back = () => backToPassword();
  const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <div className="login-wrap">
      <div style={{ position: "fixed", top: 14, right: 14 }}><ThemeSwitch /></div>
      <form className="card login" onSubmit={submit}>
        <div className="brand"><div className="brand-logo">IT</div>{appName}</div>
        <h2>{needOtp ? "Two-factor Authentication" : "Sign In"}</h2>
        <p className="muted" style={{ marginTop: 0 }}>{needOtp ? <>Enter the 6-digit code from the authenticator app for <b>{u}</b>.</> : "Internal IT Infrastructure Dashboard"}</p>
        {DEMO && <div className="alert-box info" style={{ marginBottom: 12 }}>Demo with sample data. Sign in as <b>admin</b> (administrator) or <b>helpdesk</b> (read-only), or any password. Changes are temporary and will be reset when the page is reloaded.</div>}
        {notice && !needOtp && <div className="alert-box warn" style={{ marginBottom: 12 }}>{notice}</div>}
        <div className="stack" style={{ gap: 12 }}>
          {!needOtp ? (
            <>
              <Field label="Username"><Input value={u} onChange={setU} autoFocus autoComplete="username" /></Field>
              <Field label="Password"><Input type="password" value={p} onChange={setP} autoComplete="current-password" /></Field>
            </>
          ) : (
            <>
              <Field label="Verification Code"><Input value={otp} onChange={(v) => setOtp(v.replace(/\D/g, "").slice(0, 6))} autoFocus inputMode="numeric" autoComplete="one-time-code" placeholder="123456" /></Field>
              <div className="row small" data-testid="otp-timer" role="timer" aria-live="off"
                style={{ gap: 6, color: left <= 30 ? "var(--fail)" : "var(--muted)", fontWeight: left <= 30 ? 600 : 400 }}>
                <Timer size={14} />Time left to enter the code: <b style={{ fontVariantNumeric: "tabular-nums" }}>{mmss}</b>
              </div>
            </>
          )}
          {err && <div className="alert-box fail">{err}</div>}
          <button className="btn primary" style={{ justifyContent: "center", padding: 10 }} disabled={busy || (needOtp && (otp.length !== 6 || left <= 0))}>
            {needOtp && <ShieldCheck size={15} />}{busy ? "Checking..." : needOtp ? "Confirm" : "Sign In"}
          </button>
          {needOtp && <button type="button" className="btn ghost sm" onClick={back}>← Sign in with another account</button>}
        </div>
      </form>
    </div>
  );
}
