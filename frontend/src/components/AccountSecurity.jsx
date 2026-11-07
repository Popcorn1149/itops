import React, { useState } from "react";
import { ShieldCheck, ShieldAlert, Smartphone, LogOut, MonitorSmartphone } from "lucide-react";
import { api } from "../api";
import { Field, Input, useApi, useToast, Table, fmtTime, askConfirm } from "../ui";

const svgSrc = (svg) => `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;
const group4 = (s) => (s || "").replace(/(.{4})/g, "$1 ").trim();

// Bật 2FA: tạo mã QR → quét bằng ứng dụng xác thực → nhập mã 6 số để xác nhận
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
    try { const u = await api.post("/auth/2fa/enable", { code }); toast("Đã bật xác thực 2 lớp"); onDone && onDone(u); }
    catch (e2) { setErr(e2.message); } finally { setBusy(false); }
  };
  return (
    <div className="stack" style={{ gap: 12 }}>
      {forced && <div className="alert-box warn">Tài khoản <b>quản trị</b> bắt buộc dùng xác thực 2 lớp (2FA). Bật xong mới vào được hệ thống.</div>}
      {!st && (
        <>
          <div className="muted" style={{ lineHeight: 1.6 }}>
            Cần một ứng dụng xác thực trên điện thoại: <b>Google Authenticator</b>, <b>Microsoft Authenticator</b> hoặc tương tự.
            Sau khi bật, mỗi lần đăng nhập sẽ cần thêm mã 6 số từ ứng dụng.
          </div>
          <div><button className="btn primary" onClick={start} disabled={busy}><Smartphone size={15} />{busy ? "Đang tạo..." : "Tạo mã QR"}</button></div>
        </>
      )}
      {st && (
        <form onSubmit={confirm} className="stack" style={{ gap: 12 }}>
          <div className="row" style={{ alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
            <img src={svgSrc(st.qr_svg)} alt="Mã QR 2FA" width={180} height={180} style={{ border: "1px solid var(--border)", borderRadius: 8, background: "#fff" }} />
            <div className="stack" style={{ gap: 8, flex: 1, minWidth: 220 }}>
              <div><b>1.</b> Mở ứng dụng xác thực → <b>Thêm</b> → <b>Quét mã QR</b>.</div>
              <div className="small muted">Không quét được? Nhập khoá thủ công:</div>
              <code className="mono" style={{ userSelect: "all", fontSize: 13, wordBreak: "break-all" }}>{group4(st.secret)}</code>
              <div><b>2.</b> Nhập mã 6 số đang hiện trong ứng dụng:</div>
              <Field><Input value={code} onChange={(v) => setCode(v.replace(/\D/g, "").slice(0, 6))} autoFocus inputMode="numeric" autoComplete="one-time-code" placeholder="123456" /></Field>
            </div>
          </div>
          {err && <div className="alert-box fail">{err}</div>}
          <div className="row"><button className="btn primary" disabled={busy || code.length !== 6}><ShieldCheck size={15} />Xác nhận và bật 2FA</button>
            <button type="button" className="btn ghost" onClick={start} disabled={busy}>Tạo mã khác</button></div>
        </form>
      )}
      {!st && err && <div className="alert-box fail">{err}</div>}
    </div>
  );
}

// Màn hình chặn: admin chưa bật 2FA khi hệ thống bắt buộc
export function ForcedTwoFactor({ me, onDone, onLogout }) {
  return (
    <div className="login-wrap">
      <div className="card login" style={{ maxWidth: 560 }}>
        <h2 style={{ marginTop: 0 }}><ShieldAlert size={20} style={{ verticalAlign: -3 }} /> Bật xác thực 2 lớp</h2>
        <p className="muted" style={{ marginTop: 0 }}>Xin chào <b>{me.full_name || me.username}</b>.</p>
        <TwoFactorSetup forced onDone={onDone} />
        <div style={{ marginTop: 16 }}><button className="btn ghost sm" onClick={onLogout}><LogOut size={14} />Đăng xuất</button></div>
      </div>
    </div>
  );
}

// Thẻ trong "Tài khoản của tôi"
export function TwoFactorCard({ me, onChange }) {
  const toast = useToast();
  const [f, setF] = useState({ password: "", code: "" });
  const [showSetup, setShowSetup] = useState(false);
  const disable = async () => {
    try { onChange(await api.post("/auth/2fa/disable", f)); toast("Đã tắt 2FA"); setF({ password: "", code: "" }); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card card-pad" style={{ maxWidth: 560 }}>
      <h3 style={{ marginTop: 0 }}>Xác thực 2 lớp (2FA)</h3>
      {me.totp_enabled ? (
        <div className="stack" style={{ gap: 12 }}>
          <div><span className="badge ok"><ShieldCheck size={13} />Đang bật</span>
            {me.require_2fa && <span className="small muted" style={{ marginLeft: 8 }}>Bắt buộc với tài khoản quản trị – không tự tắt được.</span>}</div>
          {me.require_2fa
            ? <div className="small muted">Đổi điện thoại hoặc mất điện thoại: nhờ một admin khác bấm <b>Đặt lại 2FA</b> ở tab Người dùng (hoặc chạy task VS Code "9. Đặt lại 2FA của admin").</div>
            : <div className="stack" style={{ gap: 10, maxWidth: 360 }}>
                <Field label="Mật khẩu"><Input type="password" value={f.password} onChange={(v) => setF({ ...f, password: v })} /></Field>
                <Field label="Mã 6 số hiện tại"><Input value={f.code} onChange={(v) => setF({ ...f, code: v.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" /></Field>
                <div><button className="btn danger" onClick={disable}>Tắt 2FA</button></div>
              </div>}
        </div>
      ) : showSetup ? (
        <TwoFactorSetup onDone={(u) => { setShowSetup(false); onChange(u); }} />
      ) : (
        <div className="stack" style={{ gap: 12 }}>
          <div><span className="badge warn"><ShieldAlert size={13} />Chưa bật</span></div>
          <div className="small muted">Nên bật để tài khoản an toàn hơn khi lộ mật khẩu.</div>
          <div><button className="btn primary" onClick={() => setShowSetup(true)}><Smartphone size={15} />Bật 2FA</button></div>
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

// Phiên đăng nhập đang hoạt động: xem và thu hồi
export function SessionsCard({ isAdmin, onSelfRevoked }) {
  const toast = useToast();
  const [all, setAll] = useState(false);
  const { data, reload } = useApi(`/auth/sessions${all ? "?all=1" : ""}`, { deps: [all] });
  const revoke = async (s) => {
    const ok = await askConfirm({ title: s.current ? "Đăng xuất phiên này?" : `Thu hồi phiên của ${s.username}?`,
      message: `${uaShort(s.user_agent)} · ${s.ip}. Thiết bị đó sẽ phải đăng nhập lại.`, okText: "Thu hồi", danger: true });
    if (!ok) return;
    try { const r = await api.del(`/auth/sessions/${s.id}`); toast("Đã thu hồi phiên"); if (r.current) onSelfRevoked && onSelfRevoked(); else reload(); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card" style={{ maxWidth: 900 }}>
      <div className="toolbar"><b className="grow"><MonitorSmartphone size={16} style={{ verticalAlign: -3 }} /> Phiên đăng nhập đang hoạt động</b>
        {isAdmin && <label className="row small"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />Tất cả người dùng</label>}</div>
      <Table rows={data || []} columns={[
        ...(all ? [{ key: "username", label: "Tài khoản", render: (s) => <b>{s.username}</b> }] : []),
        { key: "user_agent", label: "Thiết bị", render: (s) => <span title={s.user_agent}>{uaShort(s.user_agent)}{s.current && <span className="badge accent" style={{ marginLeft: 6 }}>Phiên này</span>}</span> },
        { key: "ip", label: "IP", render: (s) => <span className="mono small">{s.ip}</span> },
        { key: "mfa", label: "2FA", render: (s) => s.mfa ? <span className="badge ok">Có</span> : <span className="badge">Không</span> },
        { key: "created_at", label: "Đăng nhập lúc", render: (s) => <span className="small muted">{fmtTime(s.created_at)}</span> },
        { key: "last_seen", label: "Thao tác gần nhất", render: (s) => <span className="small muted">{fmtTime(s.last_seen)}</span> },
        { key: "a", label: "", sortable: false, render: (s) => <button className="btn ghost sm danger" onClick={() => revoke(s)}>Thu hồi</button> },
      ]} />
    </div>
  );
}
