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
      {allowDefault && <Field label="Kênh mặc định" hint="Các kênh đã bật ở tab Kênh cảnh báo"><Toggle checked={v.useDefault} onChange={set("useDefault")} label="Gửi cả kênh mặc định" /></Field>}
      <Field label="Email nhận riêng" hint="Cách nhau dấu phẩy"><Input value={v.emails} onChange={set("emails")} placeholder="truong.it@congty.vn" /></Field>
      <Field label="Telegram chat riêng" hint="Chat ID nhóm/người nhận (dùng bot ở Kênh cảnh báo)"><Input value={v.chat} onChange={set("chat")} placeholder="-1001234567890" /></Field>
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
    try { const { production, archive_path, ...body } = s; setS({ ...(await api.put("/secmon", body)), production, archive_path }); toast("Đã lưu cấu hình giám sát an ninh"); }
    catch (e) { toast(e.message, true); }
  };
  const runArc = async () => {
    try { const r = await api.post("/secmon/archive/run"); toast(r.made.length ? `Đã lưu ${r.made.length} ngày` : "Không có ngày nào cần lưu thêm"); loadArc(); }
    catch (e) { toast(e.message, true); }
  };
  const days = new Set((s.business.days || []).map(String));
  return (
    <div className="stack" style={{ maxWidth: 900 }}>
      {s.production
        ? <div className="alert-box ok"><ShieldCheck size={14} style={{ verticalAlign: -2 }} /> Đang chạy chế độ <b>production</b>: chức năng xoá toàn bộ dữ liệu bị khoá.</div>
        : <div className="alert-box info">Chưa bật chế độ chạy thật. Khi triển khai chính thức, đặt <span className="mono">ITOPS_ENV=production</span> trong .env để khoá chức năng xoá toàn bộ dữ liệu.</div>}

      <div className="card card-pad">
        <h3 style={{ marginTop: 0 }}>Business hours và SLA xử lý</h3>
        <p className="muted small" style={{ marginTop: 0 }}>Hạn ack tính từ lúc mở cảnh báo. Critical tính 24/7 (ngoài giờ dùng hạn riêng), Trouble/Attention chỉ tính trong business hours. Quá hạn sẽ được đánh dấu và gửi nhắc 1 lần.</p>
        <div className="form-grid">
          <Field label="Ngày làm việc">
            <div className="row wrap">{DAYS.map(([d, l]) => <label key={d} className="row small" style={{ gap: 4 }}><input type="checkbox" checked={days.has(d)}
              onChange={(e) => { const n = new Set(days); e.target.checked ? n.add(d) : n.delete(d); up("business", "days")([...n].map(Number).sort()); }} />{l}</label>)}</div>
          </Field>
          <Field label="Giờ bắt đầu – kết thúc"><div className="row"><Input value={s.business.start} onChange={up("business", "start")} /><span>–</span><Input value={s.business.end} onChange={up("business", "end")} /></div></Field>
        </div>
        <table className="tbl" style={{ marginTop: 10 }}>
          <thead><tr><th>Mức</th><th>Cách tính</th><th>Hạn ack (phút)</th><th>Hạn ack ngoài giờ (phút)</th></tr></thead>
          <tbody>{SEV.map(([k, l]) => (
            <tr key={k}><td><b>{l}</b></td>
              <td><Select value={s.sla[k].mode} onChange={upSla(k, "mode")} options={[["24x7", "24/7"], ["business", "Business hours"]]} /></td>
              <td><Input type="number" value={s.sla[k].ack_min} onChange={upSla(k, "ack_min")} /></td>
              <td>{s.sla[k].mode === "24x7" ? <Input type="number" value={s.sla[k].ack_min_off ?? s.sla[k].ack_min} onChange={upSla(k, "ack_min_off")} /> : <span className="faint">—</span>}</td></tr>))}
          </tbody>
        </table>
        <div style={{ marginTop: 8 }}><Toggle checked={s.sla.notify !== false} onChange={(v) => setS({ ...s, sla: { ...s.sla, notify: v } })} label="Gửi nhắc khi quá hạn ack" /></div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Cảnh báo thao tác của quản trị viên (UC-14)</h3>
          <Toggle checked={s.audit_alert.enabled} onChange={up("audit_alert", "enabled")} label="Bật" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Báo khi: đăng nhập IT Ops sai liên tục, tạo/xoá tài khoản, đổi vai trò, tắt/xoá check, rule log hoặc kịch bản, sửa kênh cảnh báo, nhập/xoá dữ liệu, sửa trang này.
          Người thực hiện <b>không tự ack/đóng</b> được cảnh báo về chính mình. Nên gửi cho trưởng IT / người phụ trách ISMS, không gửi chung nhóm admin.</p>
        <Targets value={s.audit_alert.targets} onChange={up("audit_alert", "targets")} />
        <div className="form-grid" style={{ marginTop: 8 }}>
          <Field label="Đăng nhập sai: số lần"><Input type="number" value={s.audit_alert.login_fail_threshold} onChange={num("audit_alert", "login_fail_threshold")} /></Field>
          <Field label="trong (phút)"><Input type="number" value={s.audit_alert.window_min} onChange={num("audit_alert", "window_min")} /></Field>
        </div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Log source im lặng (UC-13)</h3>
          <Toggle checked={s.silence.enabled} onChange={up("silence", "enabled")} label="Bật" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Chỉ áp dụng cho thiết bị đã từng gửi log. Không báo khi thiết bị đang DOWN (check giám sát đã báo). Switch: nếu có check SNMP thì chỉ báo khi SNMP vẫn trả lời.
          Server Linux nên gửi nhịp đều đặn, ví dụ cron <span className="mono">*/10 * * * * logger -t itops-heartbeat alive</span>, để dùng được threshold ngắn.</p>
        <div className="form-grid">
          <Field label="Firewall / router (phút)"><Input type="number" value={s.silence.firewall} onChange={num("silence", "firewall")} /></Field>
          <Field label="Server / VM (phút)"><Input type="number" value={s.silence.server} onChange={num("silence", "server")} /></Field>
          <Field label="Switch / AP (phút)"><Input type="number" value={s.silence.switch} onChange={num("silence", "switch")} /></Field>
          <Field label="Thiết bị khác (phút)"><Input type="number" value={s.silence.other} onChange={num("silence", "other")} /></Field>
        </div>
      </div>

      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }} className="grow">Archive log và chuỗi hash</h3>
          <Toggle checked={s.archive.enabled} onChange={up("archive", "enabled")} label="Bật" /></div>
        <p className="muted small" style={{ marginTop: 0 }}>Mỗi ngày lúc {s.archive.run_at}, log + audit + cảnh báo của ngày hôm trước được nén thành <span className="mono">itops-YYYY-MM-DD.jsonl.gz</span>,
          tính SHA-256 và nối vào <span className="mono">hash-chain.csv</span>. Sửa hay xoá bất kỳ file nào đều bị phát hiện. Thư mục nên là ổ NAS có snapshot chỉ đọc.</p>
        <div className="form-grid">
          <Field label="Thư mục archive" hint={`Hiện tại: ${s.archive_path}`} full><Input value={s.archive.dir} onChange={up("archive", "dir")} placeholder="\\\\NAS01\\itops-archive hoặc /mnt/nas/itops" /></Field>
          <Field label="Giữ trong CSDL (ngày)"><Input type="number" value={s.archive.db_days} onChange={num("archive", "db_days")} /></Field>
          <Field label="Giữ file archive (ngày)"><Input type="number" value={s.archive.keep_days} onChange={num("archive", "keep_days")} /></Field>
          <Field label="Giờ chạy"><Input value={s.archive.run_at} onChange={up("archive", "run_at")} /></Field>
        </div>
        <h4 style={{ marginBottom: 6 }}>Gửi hash hằng ngày cho</h4>
        <Targets value={s.archive.hash_targets} onChange={up("archive", "hash_targets")} allowDefault={false} />
      </div>
      <div className="row"><button className="btn primary" onClick={save}><Save size={15} />Lưu cấu hình</button></div>

      <div className="card">
        <div className="row card-pad" style={{ paddingBottom: 0 }}>
          <h3 style={{ margin: 0 }} className="grow"><Archive size={16} style={{ verticalAlign: -3 }} /> Kiểm tra toàn vẹn archive</h3>
          {arc && (arc.ok ? <span className="badge ok">Chuỗi hash hợp lệ</span> : <span className="badge fail">Phát hiện sai lệch</span>)}
          <button className="btn" onClick={loadArc}><RefreshCw size={14} />Kiểm tra lại</button>
          <button className="btn" onClick={runArc}><Archive size={14} />Lưu ngay các ngày còn thiếu</button>
        </div>
        <Table rowKey="day" empty="Chưa có ngày nào được archive." rows={(arc?.days || []).slice(0, 60)} columns={[
          { key: "day", label: "Ngày", render: (r) => <span className="mono">{r.day}</span> },
          { key: "rows", label: "Bản ghi" },
          { key: "size", label: "Dung lượng", render: (r) => r.exists ? `${(r.size / 1024).toFixed(1)} KB` : <span className="faint">đã xoá theo hạn giữ</span> },
          { key: "sha256", label: "SHA-256", render: (r) => <span className="mono small">{r.sha256.slice(0, 16)}…</span> },
          { key: "ok", label: "Toàn vẹn", render: (r) => (r.chain_ok && (r.file_ok || !r.exists))
            ? <CheckCircle2 size={16} color="var(--ok)" /> : <span className="row small" style={{ color: "var(--fail)" }}><XCircle size={16} />{!r.chain_ok ? "chuỗi sai" : "file bị sửa"}</span> },
        ]} />
      </div>
    </div>
  );
}

// D: nguồn đang gửi log tới IT Ops – trả lời "log của thiết bị có tới không"
export function SourcesCard() {
  const [d, setD] = useState(null);
  const load = () => api.get("/receivers/sources").then(setD).catch(() => {});
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  const ago = (s) => s < 60 ? `${s} giây` : s < 3600 ? `${Math.floor(s / 60)} phút` : `${Math.floor(s / 3600)} giờ`;
  return (
    <div className="card">
      <div className="row card-pad" style={{ paddingBottom: 0 }}>
        <h3 style={{ margin: 0 }} className="grow"><Radio size={16} style={{ verticalAlign: -3 }} /> Nguồn đang gửi tới IT Ops</h3>
        <span className="small muted">tự làm mới 5 giây · tính từ lúc IT Ops khởi động</span>
      </div>
      <p className="muted small card-pad" style={{ margin: 0, paddingTop: 6 }}>Thiết bị không có trong bảng = gói tin chưa tới máy IT Ops (kiểm tra cấu hình trên thiết bị, Packet Capture cổng 514, Windows Firewall).
        Có trong bảng nhưng <b>bị chặn</b> = thêm IP vào danh sách được phép ở trên.</p>
      <Table rowKey="ip" empty="Chưa nhận gói nào kể từ khi khởi động." rows={d?.sources || []} columns={[
        { key: "ip", label: "IP source", render: (r) => <span className="mono">{r.ip}</span> },
        { key: "asset", label: "Tài sản", render: (r) => r.asset || <span className="faint">chưa khai báo</span> },
        { key: "kind", label: "Loại" },
        { key: "count", label: "Số gói" },
        { key: "last", label: "Gần nhất", render: (r) => `${ago(r.ago_s)} trước` },
        { key: "blocked", label: "Status", render: (r) => r.blocked ? <span className="badge fail">Bị chặn (ngoài danh sách IP)</span> : <span className="badge ok">Nhận</span> },
      ]} />
    </div>
  );
}
