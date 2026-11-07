import React, { useState } from "react";
import { api, auth } from "../api";
import { Field, Input, DEMO } from "../ui";

export default function Login({ onLogin, appName }) {
  const [u, setU] = useState(DEMO ? "admin" : "");
  const [p, setP] = useState(DEMO ? "demo" : "");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const r = await api.post("/auth/login", { username: u, password: p });
      auth.set(r.token);
      onLogin(r.user);
    } catch (e2) {
      setErr(e2.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <div className="brand"><div className="brand-logo">IT</div>{appName}</div>
        <h2>Đăng nhập</h2>
        <p className="muted" style={{ marginTop: 0 }}>Bảng điều khiển hạ tầng IT nội bộ</p>
        {DEMO && <div className="alert-box info" style={{ marginBottom: 12 }}>Bản demo với dữ liệu mẫu. Đăng nhập <b>admin</b> (quản trị) hoặc <b>helpdesk</b> (chỉ xem), mật khẩu bất kỳ. Mọi thay đổi chỉ lưu tạm, tải lại trang sẽ về như cũ.</div>}
        <div className="stack" style={{ gap: 12 }}>
          <Field label="Tài khoản"><Input value={u} onChange={setU} autoFocus autoComplete="username" /></Field>
          <Field label="Mật khẩu"><Input type="password" value={p} onChange={setP} autoComplete="current-password" /></Field>
          {err && <div className="alert-box fail">{err}</div>}
          <button className="btn primary" style={{ justifyContent: "center", padding: 10 }} disabled={busy}>{busy ? "Đang đăng nhập..." : "Đăng nhập"}</button>
        </div>
      </form>
    </div>
  );
}
