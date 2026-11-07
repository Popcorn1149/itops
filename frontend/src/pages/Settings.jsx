import React, { useEffect, useRef, useState } from "react";
import { Send, Save, Download, Upload, Trash2, Plus, KeyRound, Users, BellRing, Database, Radio, ShieldCheck } from "lucide-react";
import { api, auth, SECRET } from "../api";
import { useApp } from "../App";
import { SecuritySettings, SourcesCard } from "../components/SecuritySettings";
import { useApi, PageHead, Tabs, Field, Input, Select, Toggle, useToast, Table, Modal, fmtTime, confirmDelete, askConfirm, DEMO } from "../ui";

function Secret({ value, onChange, placeholder }) {
  return <input className="input" type="password" autoComplete="new-password" value={value === SECRET ? "" : value || ""}
    placeholder={value === SECRET ? "•••••• (đã lưu)" : placeholder} onChange={(e) => onChange(e.target.value || (value === SECRET ? SECRET : ""))} />;
}

function NotifySettings() {
  const toast = useToast();
  const [s, setS] = useState(null);
  useEffect(() => { api.get("/settings/notify").then(setS); }, []);
  if (!s) return null;
  const set = (ch, k) => (v) => setS({ ...s, [ch]: { ...s[ch], [k]: v } });
  const save = async () => { try { setS(await api.put("/settings/notify", s)); toast("Đã lưu cấu hình cảnh báo"); } catch (e) { toast(e.message, true); } };
  const test = async (ch) => {
    await save();
    const r = await api.post(`/settings/notify/test/${ch}`);
    r[ch] === "ok" ? toast("Đã gửi tin nhắn thử ✓") : toast(`Gửi lỗi: ${r[ch]}`, true);
  };
  const t = s.telegram, e = s.email, w = s.webhook;
  return (
    <div className="stack">
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Telegram</h3><Toggle checked={t.enabled} onChange={set("telegram", "enabled")} label="Bật" /></div>
        <div className="form-grid">
          <Field label="Bot token" hint="Tạo bot với @BotFather"><Secret value={t.bot_token} onChange={set("telegram", "bot_token")} placeholder="123456:ABC..." /></Field>
          <Field label="Chat ID" hint="ID nhóm IT (thêm bot vào nhóm, dùng @userinfobot / getUpdates để lấy)"><Input value={t.chat_id} onChange={set("telegram", "chat_id")} placeholder="-100123456789" /></Field>
          <Field><Toggle checked={t.include_warnings ?? true} onChange={set("telegram", "include_warnings")} label="Gửi cả mức cảnh báo (không chỉ lỗi)" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("telegram")}><Send size={14} />Gửi thử</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Email (SMTP)</h3><Toggle checked={e.enabled} onChange={set("email", "enabled")} label="Bật" /></div>
        <div className="form-grid">
          <Field label="SMTP server"><Input value={e.host} onChange={set("email", "host")} placeholder="smtp.office365.com" /></Field>
          <Field label="Cổng"><Input type="number" value={e.port ?? 587} onChange={(v) => set("email", "port")(Number(v))} /></Field>
          <Field label="Bảo mật"><Select value={e.security || "starttls"} onChange={set("email", "security")} options={[["starttls", "STARTTLS (587)"], ["ssl", "SSL/TLS (465)"], ["none", "Không"]]} /></Field>
          <Field label="Người gửi (From)"><Input value={e.from} onChange={set("email", "from")} placeholder="itops@congty.vn" /></Field>
          <Field label="Tài khoản"><Input value={e.username} onChange={set("email", "username")} /></Field>
          <Field label="Mật khẩu"><Secret value={e.password} onChange={set("email", "password")} /></Field>
          <Field label="Gửi tới" full hint="Nhiều địa chỉ cách nhau dấu phẩy"><Input value={e.to} onChange={set("email", "to")} placeholder="it@congty.vn" /></Field>
          <Field><Toggle checked={e.include_warnings ?? true} onChange={set("email", "include_warnings")} label="Gửi cả mức cảnh báo" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("email")}><Send size={14} />Gửi thử</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}><h3 style={{ margin: 0 }} className="grow">Webhook (Slack, Teams, Google Chat, Discord...)</h3><Toggle checked={w.enabled} onChange={set("webhook", "enabled")} label="Bật" /></div>
        <div className="form-grid">
          <Field label="URL" full><Input value={w.url} onChange={set("webhook", "url")} placeholder="https://hooks.slack.com/..." /></Field>
          <Field><Toggle checked={w.include_warnings ?? true} onChange={set("webhook", "include_warnings")} label="Gửi cả mức cảnh báo" /></Field>
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="btn" onClick={() => test("webhook")}><Send size={14} />Gửi thử</button></div>
        </div>
      </div>
      <div><button className="btn primary" onClick={save}><Save size={15} />Lưu cấu hình</button></div>
    </div>
  );
}

function ReceiverSettings() {
  const toast = useToast();
  const [s, setS] = useState(null);
  useEffect(() => { api.get("/settings/receivers").then(setS).catch((e) => toast(e.message, true)); }, []);
  if (!s) return null;
  const save = async () => { try { setS(await api.put("/settings/receivers", { ...s, allowed_sources: (s.allowed_sources || []).map((x) => x.trim()).filter(Boolean) })); toast("Đã lưu cấu hình nhận"); } catch (e) { toast(e.message, true); } };
  const setU = (i, k, v) => setS({ ...s, v3_users: s.v3_users.map((u, j) => (j === i ? { ...u, [k]: v } : u)) });
  return (
    <div className="stack" style={{ maxWidth: 820 }}>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Cổng đang nghe</h3>
        <div className="kv"><div>Syslog UDP</div><div className="mono">{s.ports.syslog_udp}</div><div>Syslog TCP</div><div className="mono">{s.ports.syslog_tcp}</div><div>SNMP Trap UDP</div><div className="mono">{s.ports.snmp_trap}</div></div>
        <p className="muted small">Đổi cổng bằng biến môi trường SYSLOG_UDP_PORT / SYSLOG_TCP_PORT / TRAP_PORT trong .env và mapping cổng trong docker-compose.yml.</p>
      </div>
      <SourcesCard />
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>IP được phép gửi log / trap</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Mỗi dòng một IP hoặc subnet. Log/trap từ IP khác sẽ bị bỏ (đếm ở trang Log thiết bị). Để trống = nhận từ mọi nơi (không khuyến nghị).</p>
        <textarea className="input mono" style={{ minHeight: 110 }} value={(s.allowed_sources || []).join("\n")}
          onChange={(e) => setS({ ...s, allowed_sources: e.target.value.split("\n") })} placeholder={"10.0.0.0/8\n192.168.1.0/24"} />
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Community nhận trap (v1/v2c)</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Chỉ trap có community đúng mới được nhận. Nên đặt chuỗi riêng, khác community đọc.</p>
        <div className="stack" style={{ gap: 8 }}>
          {s.communities.map((c, i) => (
            <div className="row" key={i}>
              <Secret value={c} onChange={(v) => setS({ ...s, communities: s.communities.map((x, j) => (j === i ? v : x)) })} placeholder="community" />
              <button className="btn ghost sm danger" onClick={() => setS({ ...s, communities: s.communities.filter((_, j) => j !== i) })}><Trash2 size={14} /></button>
            </div>
          ))}
          <div><button className="btn sm" onClick={() => setS({ ...s, communities: [...s.communities, ""] })}><Plus size={14} />Thêm community</button></div>
        </div>
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Người dùng SNMPv3 (trap có xác thực/mã hoá)</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Thiết bị gửi trap v3 cần Engine ID của thiết bị (lấy từ cấu hình thiết bị) trừ khi dùng INFORM.</p>
        {s.v3_users.map((u, i) => (
          <div className="form-grid" key={i} style={{ borderTop: i ? "1px solid #f1efec" : 0, paddingTop: i ? 12 : 0, marginBottom: 12 }}>
            <Field label="User"><Input value={u.username} onChange={(v) => setU(i, "username", v)} /></Field>
            <Field label="Engine ID của thiết bị (hex)"><Input value={u.engine_id} onChange={(v) => setU(i, "engine_id", v)} placeholder="80001f8880..." /></Field>
            <Field label="Auth"><div className="row"><Select value={u.auth_protocol || "SHA"} onChange={(v) => setU(i, "auth_protocol", v)} options={["SHA", "SHA256", "MD5"]} /><Secret value={u.auth_key} onChange={(v) => setU(i, "auth_key", v)} placeholder="auth password" /></div></Field>
            <Field label="Privacy"><div className="row"><Select value={u.priv_protocol || "AES"} onChange={(v) => setU(i, "priv_protocol", v)} options={["AES", "DES"]} /><Secret value={u.priv_key} onChange={(v) => setU(i, "priv_key", v)} placeholder="priv password" /></div></Field>
            <div><button className="btn sm danger" onClick={() => setS({ ...s, v3_users: s.v3_users.filter((_, j) => j !== i) })}><Trash2 size={14} />Xoá user</button></div>
          </div>
        ))}
        <button className="btn sm" onClick={() => setS({ ...s, v3_users: [...s.v3_users, { username: "", auth_protocol: "SHA", priv_protocol: "AES" }] })}><Plus size={14} />Thêm user v3</button>
      </div>
      <div><button className="btn primary" onClick={save}><Save size={15} />Lưu cấu hình nhận</button></div>
    </div>
  );
}

function UsersSettings() {
  const { me } = useApp();
  const toast = useToast();
  const { data, reload } = useApi("/users");
  const [edit, setEdit] = useState(null);
  const save = async () => {
    try { edit.id ? await api.put(`/users/${edit.id}`, edit) : await api.post("/users", edit); toast("Đã lưu"); setEdit(null); reload(); }
    catch (e) { toast(e.message, true); }
  };
  const remove = async (u) => { if (!(await confirmDelete(u.username))) return; try { await api.del(`/users/${u.id}`); reload(); } catch (e) { toast(e.message, true); } };
  return (
    <div className="card">
      <div className="toolbar"><b className="grow">Người dùng</b><button className="btn primary sm" onClick={() => setEdit({ role: "viewer" })}><Plus size={14} />Thêm</button></div>
      <Table rows={data || []} columns={[
        { key: "username", label: "Tài khoản", render: (u) => <b>{u.username}</b> },
        { key: "full_name", label: "Họ tên" },
        { key: "role", label: "Quyền", render: (u) => <span className={`badge ${u.role === "admin" ? "accent" : ""}`}>{u.role === "admin" ? "Quản trị" : "Chỉ xem"}</span> },
        { key: "created_at", label: "Tạo lúc", render: (u) => <span className="small muted">{fmtTime(u.created_at)}</span> },
        { key: "a", label: "", sortable: false, render: (u) => <div className="row"><button className="btn ghost sm" onClick={() => setEdit({ ...u, password: "" })}>Sửa</button>{u.id !== me.id && <button className="btn ghost sm danger" onClick={() => remove(u)}><Trash2 size={14} /></button>}</div> },
      ]} />
      {edit && (
        <Modal title={edit.id ? `Sửa ${edit.username}` : "Thêm người dùng"} onClose={() => setEdit(null)} width={520}
          footer={<><button className="btn" onClick={() => setEdit(null)}>Huỷ</button><button className="btn primary" onClick={save}>Lưu</button></>}>
          <div className="stack" style={{ gap: 12 }}>
            <Field label="Tài khoản"><Input value={edit.username} onChange={(v) => setEdit({ ...edit, username: v })} disabled={!!edit.id} /></Field>
            <Field label="Họ tên"><Input value={edit.full_name} onChange={(v) => setEdit({ ...edit, full_name: v })} /></Field>
            <Field label="Quyền"><Select value={edit.role} onChange={(v) => setEdit({ ...edit, role: v })} options={[["viewer", "Chỉ xem (helpdesk, quản lý)"], ["admin", "Quản trị (thêm/sửa/xoá)"]]} /></Field>
            <Field label={edit.id ? "Mật khẩu mới (để trống nếu không đổi)" : "Mật khẩu"} hint="Tối thiểu 8 ký tự"><Input type="password" value={edit.password} onChange={(v) => setEdit({ ...edit, password: v })} /></Field>
          </div>
        </Modal>
      )}
    </div>
  );
}

function AccountSettings() {
  const toast = useToast();
  const [f, setF] = useState({ old_password: "", new_password: "", confirm: "" });
  const save = async () => {
    if (f.new_password !== f.confirm) return toast("Mật khẩu nhập lại không khớp", true);
    try { await api.post("/auth/password", f); toast("Đã đổi mật khẩu"); setF({ old_password: "", new_password: "", confirm: "" }); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <div className="card card-pad" style={{ maxWidth: 480 }}>
      <h3 style={{ marginTop: 0 }}>Đổi mật khẩu</h3>
      <div className="stack" style={{ gap: 12 }}>
        <Field label="Mật khẩu hiện tại"><Input type="password" value={f.old_password} onChange={(v) => setF({ ...f, old_password: v })} /></Field>
        <Field label="Mật khẩu mới" hint="Tối thiểu 8 ký tự"><Input type="password" value={f.new_password} onChange={(v) => setF({ ...f, new_password: v })} /></Field>
        <Field label="Nhập lại"><Input type="password" value={f.confirm} onChange={(v) => setF({ ...f, confirm: v })} /></Field>
        <div><button className="btn primary" onClick={save}><KeyRound size={15} />Đổi mật khẩu</button></div>
      </div>
    </div>
  );
}

function DataSettings() {
  const toast = useToast();
  const { refresh } = useApp();
  const file = useRef();
  const exportData = async () => {
    const res = await fetch("/api/export", { headers: { Authorization: `Bearer ${auth.token}` } });
    const blob = await res.blob();
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `itops-export-${new Date().toISOString().slice(0, 10)}.json`; a.click();
  };
  const importData = async (e) => {
    const fl = e.target.files[0]; if (!fl) return;
    try { const r = await api.post("/import", JSON.parse(await fl.text())); toast(`Đã nhập ${r.imported} bản ghi`); refresh(); }
    catch (err) { toast(err.message, true); }
    e.target.value = "";
  };
  const [prod, setProd] = useState(false);
  useEffect(() => { api.get("/health").then((h) => setProd(!!h.production)).catch(() => {}); }, []);
  const reset = async () => {
    const ok = await askConfirm({ title: "Xoá toàn bộ dữ liệu hạ tầng?", message: "Xoá hết site, tài sản, check, cảnh báo, hệ thống trọng yếu (VD: bỏ dữ liệu mẫu). Tài khoản và cấu hình cảnh báo được giữ lại.", requireText: "XOA", okText: "Xoá toàn bộ", danger: true });
    if (!ok) return;
    try { await api.post("/reset-data", { confirm: "XOA" }); toast("Đã xoá dữ liệu"); refresh(); } catch (err) { toast(err.message, true); }
  };
  return (
    <div className="stack" style={{ maxWidth: 720 }}>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Backup cấu hình</h3>
        <p className="muted">Xuất toàn bộ site, tài sản, check, hệ thống trọng yếu ra file JSON (mật khẩu thiết bị vẫn ở dạng mã hoá – chỉ nhập lại được trên cùng máy chủ có cùng SECRET_KEY).</p>
        {DEMO && <div className="alert-box info" style={{ marginBottom: 10 }}>Bản demo không tải file được – chức năng này hoạt động trên bản cài đặt thật.</div>}
        <div className="row"><button className="btn" onClick={exportData}><Download size={15} />Xuất file</button>
          <button className="btn" onClick={() => file.current.click()}><Upload size={15} />Nhập file</button>
          <input type="file" accept=".json" ref={file} style={{ display: "none" }} onChange={importData} /></div>
      </div>
      <div className="card card-pad">
        <h3 style={{ marginTop: 0, color: "var(--fail)" }}>Xoá dữ liệu</h3>
        <p className="muted">Dùng khi muốn bỏ dữ liệu mẫu và bắt đầu nhập hệ thống thật. Tài khoản người dùng và cấu hình cảnh báo được giữ lại.</p>
        {prod
          ? <div className="alert-box ok">Đang chạy thật (ITOPS_ENV=production): chức năng này bị khoá. Mọi lần thử đều được ghi audit log và cảnh báo.</div>
          : <button className="btn danger" onClick={reset}><Trash2 size={15} />Xoá toàn bộ dữ liệu hạ tầng</button>}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { route, isAdmin } = useApp();
  const [tab, setTab] = useState(route.params.tab || (isAdmin ? "notify" : "account"));
  const tabs = isAdmin
    ? [{ key: "notify", label: "Kênh cảnh báo", icon: BellRing }, { key: "receivers", label: "Nhận Syslog / Trap", icon: Radio }, { key: "security", label: "Giám sát an ninh", icon: ShieldCheck }, { key: "users", label: "Người dùng", icon: Users }, { key: "account", label: "Tài khoản của tôi", icon: KeyRound }, { key: "data", label: "Dữ liệu", icon: Database }]
    : [{ key: "account", label: "Tài khoản của tôi", icon: KeyRound }];
  return (
    <>
      <PageHead crumb="Quản trị › Cài đặt" title="Cài đặt" desc="Kênh gửi cảnh báo, người dùng, backup cấu hình." />
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
