import React, { Fragment, useEffect, useState } from "react";
import { Search } from "lucide-react";
import { useApi, PageHead, Table, fmtTime, Empty, CapNote } from "../ui";

const ACTION = { create: ["Create", "ok"], update: ["Edit", "info"], delete: ["Delete", "fail"], login: ["Sign In", ""], logout: ["Sign out", ""], ack: ["Acknowledge alert", "warn"], resolve: ["Resolve alert", "ok"], import: ["Import data", "info"], login_failed: ["Failed sign-in", "fail"],
  enable_2fa: ["Enable 2FA", "ok"], disable_2fa: ["Disable 2FA", "warn"], reset_2fa: ["Reset 2FA", "warn"], revoke: ["Revoke session", "warn"], backup: ["Back up", "info"], disable: ["Disable", "warn"] };

const show = (v) => (v === null || v === undefined || v === "" ? "∅" : typeof v === "object" ? JSON.stringify(v) : String(v));

// "What changed": before → after values (secrets are masked by the server)
function Changes({ c }) {
  if (!c || !c.before) return null;
  const keys = Object.keys({ ...c.before, ...c.after });
  return (
    <div className="small" style={{ marginTop: 4, display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 8px" }}>
      {keys.map((k) => {
        const b = c.before[k], a = c.after[k];
        if (k === "config" && b && typeof b === "object") return Object.keys({ ...b, ...(a || {}) }).map((ck) => (
          <Fragment key={k + ck}><span className="muted mono">config.{ck}</span><span><s className="faint">{show(b[ck])}</s> → <b>{show((a || {})[ck])}</b></span></Fragment>));
        return <Fragment key={k}><span className="muted mono">{k}</span><span><s className="faint">{show(b)}</s> → <b>{show(a)}</b></span></Fragment>;
      })}
    </div>
  );
}

export default function Audit() {
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  useEffect(() => { const t = setTimeout(() => setTerm(q.trim()), 350); return () => clearTimeout(t); }, [q]);
  const { data } = useApi(`/audit?limit=1000&q=${encodeURIComponent(term)}`, { interval: 30000, deps: [term] });   // search runs on the server over ALL entries
  const rows = data || [];
  return (
    <>
      <PageHead crumb="Operations › Audit log" title="Audit log" desc="Who · what · when · where (IP, browser) · what changed (before → after) · why. Audit records are append-only and cannot be edited or deleted." />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Search users, details, IP addresses, reasons..." value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} empty={<Empty title="No audit log entries" />} columns={[
          { key: "ts", label: "Time", render: (r) => <span className="small mono">{fmtTime(r.ts)}</span> },
          { key: "user", label: "User", render: (r) => <b>{r.user}</b> },
          { key: "action", label: "Action", render: (r) => { const [l, c] = ACTION[r.action] || [r.action, ""]; return <span className={`badge ${c}`}>{l}</span>; } },
          { key: "entity", label: "Entity", render: (r) => <span className="muted small">{r.entity}{r.entity_id ? ` #${r.entity_id}` : ""}</span> },
          { key: "detail", label: "Details", render: (r) => <div>{r.detail}{r.reason && <div className="small" style={{ marginTop: 2 }}><span className="muted">Reason:</span> {r.reason}</div>}<Changes c={r.changes} /></div> },
          { key: "ip", label: "Source", render: (r) => <span className="small mono" title={r.user_agent || ""}>{r.ip || "–"}</span> },
        ]} />
        <CapNote shown={rows.length} limit={1000} what="entries" hint="Search to find older ones." />
      </div>
    </>
  );
}
