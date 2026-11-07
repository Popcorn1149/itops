import React, { useState } from "react";
import { ShieldCheck } from "lucide-react";
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
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const r = await api.post("/auth/login", { username: u, password: p, ...(needOtp ? { otp } : {}) });
      onLogin(r.user);
    } catch (e2) {
      if (e2.detail && e2.detail.need_otp) {
        if (needOtp) setErr(e2.message);       // đã ở bước 2 mà vẫn lỗi → mã sai
        setNeedOtp(true); setOtp("");
      } else {
        setErr(e2.message);
      }
    } finally {
      setBusy(false);
    }
  };
  const back = () => { setNeedOtp(false); setOtp(""); setErr(""); };
  return (
    <div className="login-wrap">
      <div style={{ position: "fixed", top: 14, right: 14 }}><ThemeSwitch /></div>
      <form className="card login" onSubmit={submit}>
        <div className="brand"><div className="brand-logo">IT</div>{appName}</div>
        <h2>{needOtp ? "Xác thực 2 lớp" : "Đăng nhập"}</h2>
        <p className="muted" style={{ marginTop: 0 }}>{needOtp ? <>Nhập mã 6 số trong ứng dụng xác thực của <b>{u}</b>.</> : "Bảng điều khiển hạ tầng IT nội bộ"}</p>
        {DEMO && <div className="alert-box info" style={{ marginBottom: 12 }}>Bản demo với dữ liệu mẫu. Đăng nhập <b>admin</b> (quản trị) hoặc <b>helpdesk</b> (chỉ xem), mật khẩu bất kỳ. Mọi thay đổi chỉ lưu tạm, tải lại trang sẽ về như cũ.</div>}
        {notice && !needOtp && <div className="alert-box warn" style={{ marginBottom: 12 }}>{notice}</div>}
        <div className="stack" style={{ gap: 12 }}>
          {!needOtp ? (
            <>
              <Field label="Tài khoản"><Input value={u} onChange={setU} autoFocus autoComplete="username" /></Field>
              <Field label="Mật khẩu"><Input type="password" value={p} onChange={setP} autoComplete="current-password" /></Field>
            </>
          ) : (
            <Field label="Mã xác thực"><Input value={otp} onChange={(v) => setOtp(v.replace(/\D/g, "").slice(0, 6))} autoFocus inputMode="numeric" autoComplete="one-time-code" placeholder="123456" /></Field>
          )}
          {err && <div className="alert-box fail">{err}</div>}
          <button className="btn primary" style={{ justifyContent: "center", padding: 10 }} disabled={busy || (needOtp && otp.length !== 6)}>
            {needOtp && <ShieldCheck size={15} />}{busy ? "Đang kiểm tra..." : needOtp ? "Xác nhận" : "Đăng nhập"}
          </button>
          {needOtp && <button type="button" className="btn ghost sm" onClick={back}>← Đăng nhập tài khoản khác</button>}
        </div>
      </form>
    </div>
  );
}
