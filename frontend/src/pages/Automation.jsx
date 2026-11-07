import React, { useMemo, useState } from "react";
import { Zap, Plus, Play, FlaskConical, Pencil, Trash2, History, BookOpen, Code2, ListChecks, X, Ban } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import {
  useApi, PageHead, Tabs, Table, Modal, Field, Input, Select, Toggle, useToast, timeAgo, fmtTime, Empty, confirmDelete, Stat, DEMO,
} from "../ui";

const GROUPS = [
  ["RPT", "Báo cáo", "Hạ tầng tuần này ra sao, ai cần biết?"],
  ["INC", "Cảnh báo – Sự cố", "Cái gì hỏng, báo ai, xử lý thế nào?"],
  ["PRE", "Phòng ngừa – Dự báo", "Cái gì sắp hỏng?"],
  ["LCM", "Bảo trì – Vòng đời", "Cái gì cần thay, gia hạn, rà soát?"],
];
const LEVELS = [["L0", "L0 · chỉ báo"], ["L1", "L1 · báo kèm gợi ý"], ["L2", "L2 · làm sau khi duyệt"], ["L3", "L3 · tự làm (đảo ngược được)"]];
const CRON_PRESETS = [
  ["30 7 * * *", "07:30 hằng ngày"], ["0 8 * * 1-5", "08:00 Thứ Hai–Thứ Sáu"], ["0 8 * * 1", "08:00 Thứ Hai hằng tuần"],
  ["0 16 * * 5", "16:00 Thứ Sáu hằng tuần"], ["0 8 1 * *", "08:00 ngày 1 hằng tháng"], ["0 9 1 1,4,7,10 *", "09:00 đầu mỗi quý"],
];
const EVENTS = [["alert_opened", "Cảnh báo mở"], ["alert_resolved", "Cảnh báo đóng"], ["alert_escalated", "Cảnh báo nặng lên"]];
const TARGET_TYPES = [["default", "Kênh mặc định (Cài đặt)"], ["telegram", "Telegram (chat ID)"], ["email", "Email"], ["webhook", "Webhook"]];
const STATUS = { ok: ["ok", "Thành công"], skipped: ["", "Không có gì để gửi"], error: ["fail", "Lỗi"] };
const TRIG = { schedule: "Theo lịch", interval: "Định kỳ", event: "Sự kiện", hook: "Khi có cảnh báo", manual: "Chạy tay", test: "Chạy thử", tick: "Định kỳ" };

// ------------------------------------------------------------------ người nhận
function Targets({ value, onChange, allowEmpty }) {
  const list = value?.length ? value : allowEmpty ? [] : [{ type: "default" }];
  const set = (i, patch) => onChange(list.map((t, j) => (j === i ? { ...t, ...patch } : t)));
  const key = { telegram: "chat", email: "to", webhook: "url" };
  const ph = { telegram: "-1001234567890", email: "truong-it@congty.vn, quan-ly@congty.vn", webhook: "https://chat.googleapis.com/..." };
  return (
    <div className="auto-targets">
      {list.map((t, i) => (
        <div key={i} className="auto-target">
          <Select value={t.type} onChange={(v) => set(i, { type: v })} options={TARGET_TYPES} />
          {t.type !== "default" ? <Input value={t[key[t.type]]} onChange={(v) => set(i, { [key[t.type]]: v })} placeholder={ph[t.type]} />
            : <span className="small faint">Telegram / Email / Webhook đã bật ở Cài đặt</span>}
          <button className="btn icon sm" title="Bỏ" onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button>
        </div>
      ))}
      <button className="btn sm" onClick={() => onChange([...list, { type: "telegram", chat: "" }])}><Plus size={13} />Thêm người nhận</button>
      {allowEmpty && !list.length && <span className="small faint" style={{ marginLeft: 8 }}>Trống = gửi tới kênh mặc định</span>}
    </div>
  );
}

function MultiCheck({ options, value, onChange }) {
  const v = value || [];
  return <div className="row wrap" style={{ gap: 10 }}>{options.map(([k, l]) => (
    <label key={k} className="check-row small"><input type="checkbox" checked={v.includes(k)}
      onChange={(e) => onChange(e.target.checked ? [...v, k] : v.filter((x) => x !== k))} />{l}</label>))}</div>;
}

// ------------------------------------------------------------------ tham số đặc biệt
function Steps({ value, onChange }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((s, i) => (
    <div key={i} className="auto-subcard">
      <div className="row wrap" style={{ gap: 8 }}>
        <b className="small">Bước {i + 1}</b>
        <Input value={s.label} onChange={(v) => set(i, { label: v })} placeholder="Tên bước (VD Trưởng nhóm)" style={{ maxWidth: 200 }} />
        <span className="small">sau</span><Input type="number" value={s.after_min} onChange={(v) => set(i, { after_min: Number(v) })} style={{ width: 80 }} />
        <span className="small">phút chưa ai nhận · mức</span>
        <MultiCheck options={[["High", "High"], ["Medium", "Medium"], ["Low", "Low"]]} value={s.severities} onChange={(v) => set(i, { severities: v })} />
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button>
      </div>
      <div className="small muted" style={{ margin: "6px 0 4px" }}>Báo cho:</div>
      <Targets value={s.targets} onChange={(v) => set(i, { targets: v })} allowEmpty />
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { label: "", after_min: 30, severities: ["High"], targets: [] }])}><Plus size={13} />Thêm bước</button>
  </div>;
}

function Rules({ value, onChange }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((r, i) => (
    <div key={i} className="auto-subcard">
      <div className="row" style={{ gap: 8 }}><span className="small">Khi tiêu đề/tên check chứa</span>
        <Input value={r.contains} onChange={(v) => set(i, { contains: v })} placeholder="VD VNPT" style={{ maxWidth: 200 }} />
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={14} /></button></div>
      <textarea className="input" rows={3} style={{ marginTop: 6 }} placeholder={"Mỗi dòng 1 bước\nGọi tổng đài 18001166\nĐọc mã hợp đồng ..."}
        value={(r.steps || []).join("\n")} onChange={(e) => set(i, { steps: e.target.value.split("\n") })} />
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { contains: "", steps: [] }])}><Plus size={13} />Thêm runbook riêng</button>
    <div className="small faint">Không có rule khớp → dùng runbook của hệ thống trọng yếu (nếu có), rồi tới runbook mặc định theo loại check.</div>
  </div>;
}

function Windows({ value, onChange, assets, sites }) {
  const list = value || [];
  const set = (i, p) => onChange(list.map((s, j) => (j === i ? { ...s, ...p } : s)));
  return <div className="auto-sub">{list.map((w, i) => (
    <div key={i} className="auto-subcard">
      <div className="form-grid">
        <Field label="Tên"><Input value={w.name} onChange={(v) => set(i, { name: v })} placeholder="VD Nâng cấp firmware switch" /></Field>
        <Field label="Bắt đầu (cron, giờ VN)" hint="VD 0 22 * * 6 = 22:00 Thứ Bảy hằng tuần"><Input value={w.cron} onChange={(v) => set(i, { cron: v })} placeholder="0 22 * * 6" /></Field>
        <Field label="Kéo dài (phút)"><Input type="number" value={w.duration_min} onChange={(v) => set(i, { duration_min: Number(v) })} /></Field>
        <Field label="Site"><select className="input" multiple value={(w.sites || []).map(String)} style={{ height: 70 }}
          onChange={(e) => set(i, { sites: [...e.target.selectedOptions].map((o) => Number(o.value)) })}>{sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
        <Field label="Thiết bị (gồm cả thiết bị phía sau)" full><select className="input" multiple value={(w.assets || []).map(String)} style={{ height: 90 }}
          onChange={(e) => set(i, { assets: [...e.target.selectedOptions].map((o) => Number(o.value)) })}>{assets.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.type}</option>)}</select></Field>
      </div>
      <button className="btn sm danger-text" onClick={() => onChange(list.filter((_, j) => j !== i))}><X size={13} />Bỏ khung này</button>
    </div>))}
    <button className="btn sm" onClick={() => onChange([...list, { name: "", cron: "0 22 * * 6", duration_min: 120, assets: [], sites: [] }])}><Plus size={13} />Thêm khung bảo trì</button>
  </div>;
}

function ParamField({ f, value, onChange, ctx }) {
  if (f.type === "bool") return <Toggle checked={value} onChange={onChange} label={f.label} />;
  if (f.type === "textarea") return <Field label={f.label} full><textarea className="input" rows={2} value={value || ""} onChange={(e) => onChange(e.target.value)} /></Field>;
  if (f.type === "multi") return <Field label={f.label}><MultiCheck options={f.options.map((o) => [o, o])} value={value} onChange={onChange} /></Field>;
  if (f.type === "list") return <Field label={f.label} hint="Cách nhau dấu phẩy"><Input value={(value || []).join(", ")}
    onChange={(v) => onChange(v.split(",").map((x) => Number(x.trim())).filter((x) => x > 0))} /></Field>;
  if (f.type === "steps") return <Field label={f.label} full><Steps value={value} onChange={onChange} /></Field>;
  if (f.type === "rules") return <Field label={f.label} full><Rules value={value} onChange={onChange} /></Field>;
  if (f.type === "windows") return <Field label={f.label} full><Windows value={value} onChange={onChange} assets={ctx.assets} sites={ctx.sites} /></Field>;
  return <Field label={f.label}><Input type="number" step={f.step || 1} value={value} onChange={(v) => onChange(v === "" ? "" : Number(v))} /></Field>;
}

// ------------------------------------------------------------------ trình sửa
export function AutomationEditor({ edit, catalog, onClose, onSaved }) {
  const toast = useToast();
  const sites = useApi("/sites").data || [];
  const assets = useApi("/assets").data || [];
  const code = edit.code;
  const tpl = catalog.templates.find((t) => t.code === code);
  const base = edit.id ? edit.effective : tpl.spec;
  const [f, setF] = useState({ name: edit.name || (code === "CUSTOM" ? "" : tpl.name), enabled: edit.id ? edit.enabled : true, spec: JSON.parse(JSON.stringify(base)) });
  const [mode, setMode] = useState("form");
  const [yaml, setYaml] = useState("");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const sp = f.spec;
  const setSpec = (k, v) => setF({ ...f, spec: { ...sp, [k]: v } });
  const setP = (k) => (v) => setSpec("params", { ...(sp.params || {}), [k]: v });
  const trg = sp.trigger || {};
  const setT = (p) => setSpec("trigger", { ...trg, ...p });
  const scope = sp.scope || { sites: "all" };
  const setScope = (p) => setSpec("scope", { ...scope, ...p });
  const content = sp.content || {};
  const setContent = (p) => setSpec("content", { ...content, ...p });

  const toYaml = async () => {
    try { setYaml((await api.post("/automation/to-yaml", { code, spec: sp, name: f.name, enabled: f.enabled })).yaml); setMode("yaml"); } catch (e) { toast(e.message, true); }
  };
  const fromYaml = async () => {
    try {
      const r = await api.post("/automation/from-yaml", { code, yaml });
      setF({ name: r.name ?? f.name, enabled: r.enabled ?? f.enabled, spec: r.spec }); setMode("form");
    } catch (e) { toast(e.message, true); }
  };
  const body = () => (mode === "yaml" ? { code, yaml, name: f.name } : { code, spec: sp, name: f.name, enabled: f.enabled });
  const save = async () => {
    if (!f.name.trim()) return toast("Nhập tên kịch bản", true);
    setBusy(true);
    try {
      const r = edit.id ? await api.put(`/automations/${edit.id}`, body()) : await api.post("/automations", body());
      toast(edit.id ? "Đã lưu kịch bản" : "Đã thêm kịch bản"); onSaved(r);
    } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true);
    try { setPreview(await api.post("/automations/preview", body())); } catch (e) { toast(e.message, true); } finally { setBusy(false); }
  };

  return (
    <Modal title={<span className="row"><Zap size={17} />{edit.id ? "Sửa" : "Thêm"} kịch bản <span className="badge">{code}</span></span>} onClose={onClose} width={820}
      footer={<>
        <button className="btn" onClick={test} disabled={busy}><FlaskConical size={15} />Chạy thử (không gửi)</button>
        <div className="grow" />
        <button className="btn" onClick={onClose}>Đóng</button>
        <button className="btn primary" onClick={save} disabled={busy}>Lưu</button>
      </>}>
      {tpl && code !== "CUSTOM" && <div className="alert-box info" style={{ marginBottom: 12 }}><b>{tpl.name}</b> – {tpl.desc}<div className="small muted" style={{ marginTop: 4 }}>KPI: {tpl.kpi} · Dữ liệu: {tpl.data}</div></div>}
      <div className="row" style={{ marginBottom: 12, gap: 8 }}>
        <div className="seg">
          <button className={mode === "form" ? "on" : ""} onClick={() => (mode === "yaml" ? fromYaml() : null)}><ListChecks size={13} /> Form</button>
          <button className={mode === "yaml" ? "on" : ""} onClick={() => (mode === "form" ? toYaml() : null)}><Code2 size={13} /> YAML</button>
        </div>
        <span className="small faint">YAML cùng định dạng mẫu trong tài liệu (dán nguyên khối id/name/trigger/... vào đây được)</span>
      </div>

      {mode === "yaml" ? <textarea className="input mono" rows={22} value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} style={{ fontSize: 12.5 }} /> : (
        <div className="form-grid">
          <Field label="Tên kịch bản *"><Input value={f.name} onChange={(v) => setF({ ...f, name: v })} placeholder="VD Tổng kết cuối ngày" /></Field>
          <Field label="Mức tự động" hint={tpl.reversible ? "L2–L3 chỉ cho hành động đảo ngược được" : "Template này chỉ gửi tin → L0/L1"}>
            <Select value={sp.level || "L0"} onChange={(v) => setSpec("level", v)} options={LEVELS.filter(([k]) => tpl.reversible || k === "L0" || k === "L1")} />
          </Field>
          <Toggle checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Đang bật" />

          <div className="section-title">Khi nào chạy</div>
          {trg.type === "hook" ? <div className="full small muted">Chạy mỗi khi có cảnh báo mở/đóng (trước khi gửi tin). Không cần lịch.</div> : <>
            <Field label="Loại trigger"><Select value={trg.type} onChange={(v) => setT({ type: v, ...(v === "schedule" ? { cron: trg.cron || "0 8 * * 1-5" } : v === "interval" ? { minutes: trg.minutes || 15 } : { on: trg.on || ["alert_opened"] }) })}
              options={[["schedule", "Theo lịch (giờ VN)"], ["interval", "Định kỳ mỗi N phút"], ["event", "Khi có sự kiện cảnh báo"]].filter(([k]) => tpl.triggers.includes(k))} /></Field>
            {trg.type === "schedule" && <Field label="Lịch (cron: phút giờ ngày tháng thứ)" hint={<span>Chọn nhanh: <select className="input" style={{ display: "inline", width: "auto", padding: "1px 4px", fontSize: 12 }}
              value="" onChange={(e) => e.target.value && setT({ cron: e.target.value })}><option value="">…</option>{CRON_PRESETS.map(([c, l]) => <option key={c} value={c}>{l}</option>)}</select></span>}>
              <Input value={trg.cron} onChange={(v) => setT({ cron: v })} className="input mono" /></Field>}
            {trg.type === "interval" && <Field label="Mỗi (phút)"><Input type="number" value={trg.minutes} onChange={(v) => setT({ minutes: Number(v) })} /></Field>}
            {trg.type === "event" && <Field label="Sự kiện"><MultiCheck options={EVENTS} value={trg.on} onChange={(v) => setT({ on: v })} /></Field>}
          </>}

          <div className="section-title">Phạm vi</div>
          <Field label="Site" hint="Không chọn = mọi site"><select className="input" multiple value={scope.sites === "all" ? [] : (scope.sites || []).map(String)} style={{ height: 70 }}
            onChange={(e) => { const v = [...e.target.selectedOptions].map((o) => Number(o.value)); setScope({ sites: v.length ? v : "all" }); }}>
            {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
          <Field label="Mức cảnh báo" hint="Không chọn = mọi mức · High = DOWN/Critical · Medium = Trouble · Low = Attention">
            <MultiCheck options={[["High", "High"], ["Medium", "Medium"], ["Low", "Low"]]} value={scope.severities} onChange={(v) => setScope({ severities: v })} /></Field>

          {tpl.fields.length > 0 && <div className="section-title">Tham số</div>}
          {tpl.fields.map((x) => <ParamField key={x.key} f={x} value={(sp.params || {})[x.key]} onChange={setP(x.key)} ctx={{ sites, assets }} />)}

          {code === "CUSTOM" && <>
            <div className="section-title">Nội dung</div>
            <Field label="Tiêu đề tin" hint={`Biến: ${catalog.placeholders.map((p) => `{${p}}`).join(" ")}`} full>
              <Input value={content.title} onChange={(v) => setContent({ title: v })} placeholder={trg.type === "event" ? "[HQ] {title}" : "Tình hình hạ tầng {time}"} /></Field>
            {trg.type === "event" ? <Field label="Nội dung tin" full><textarea className="input" rows={3} value={content.message || ""} onChange={(e) => setContent({ message: e.target.value })}
              placeholder="{asset} tại {site} – {severity} lúc {time}\n{message}" /></Field> : <>
              <Field label="Khối nội dung" full><MultiCheck options={catalog.blocks.map((b) => [b.key, b.label])} value={content.blocks} onChange={(v) => setContent({ blocks: v })} /></Field>
              <Field label="Gửi khi"><Select value={sp.send_when || "always"} onChange={(v) => setSpec("send_when", v)} options={[["always", "Luôn gửi"], ["has_items", "Chỉ khi có mục cần báo"]]} /></Field>
              <Field label="Lời mở đầu (tuỳ chọn)"><Input value={content.message} onChange={(v) => setContent({ message: v })} /></Field>
            </>}
          </>}

          {trg.type !== "hook" && <><div className="section-title">Gửi tới</div>
            <Field full><Targets value={sp.actions} onChange={(v) => setSpec("actions", v)} /></Field></>}
        </div>
      )}
      {preview && <PreviewBox r={preview} onClose={() => setPreview(null)} />}
    </Modal>
  );
}

function PreviewBox({ r, onClose }) {
  return (
    <div className="card card-pad" style={{ marginTop: 14, background: "#fbfaf8" }}>
      <div className="row" style={{ marginBottom: 6 }}><FlaskConical size={15} /><b>Kết quả chạy thử</b>
        <span className={`badge ${STATUS[r.status]?.[0] || ""}`}>{STATUS[r.status]?.[1] || r.status}</span>
        <span className="small muted">{r.summary}</span>
        <button className="btn icon sm" style={{ marginLeft: "auto" }} onClick={onClose}><X size={14} /></button></div>
      {r.output ? <pre className="auto-out">{r.output}</pre> : <div className="small muted">Không có tin nào được tạo ra với dữ liệu hiện tại.</div>}
      <div className="small faint" style={{ marginTop: 6 }}>Chạy thử không gửi tin và không thay đổi gì.</div>
    </div>
  );
}

// ------------------------------------------------------------------ trang
export default function Automation() {
  const { isAdmin } = useApp();
  const toast = useToast();
  const [tab, setTab] = useState("library");
  const [tick, setTick] = useState(0);
  const catalog = useApi("/automation/catalog").data;
  const autos = useApi("/automations", { interval: 30000, deps: [tick] }).data;
  const runs = useApi("/automation/runs?limit=200", { interval: 30000, deps: [tick, tab] }).data;
  const [edit, setEdit] = useState(null);
  const [out, setOut] = useState(null);
  const refresh = () => setTick((x) => x + 1);
  const byCode = useMemo(() => Object.fromEntries((autos || []).filter((a) => a.code !== "CUSTOM").map((a) => [a.code, a])), [autos]);
  if (!catalog || !autos) return null;
  const toggle = async (a, v) => { try { await api.put(`/automations/${a.id}`, { enabled: v }); refresh(); toast(v ? `Đã bật ${a.code}` : `Đã tắt ${a.code}`); } catch (e) { toast(e.message, true); } };
  const runNow = async (a, dry) => {
    try { const r = await api.post(`/automations/${a.id}/run?dry=${dry}`); setOut({ ...r, title: `${a.code} · ${a.name}`, dry }); refresh(); } catch (e) { toast(e.message, true); }
  };
  const del = async (a) => { if (await confirmDelete(a.name)) { await api.del(`/automations/${a.id}`); refresh(); } };
  const on = autos.filter((a) => a.enabled).length;
  const errors = autos.filter((a) => a.last_status === "error").length;

  return (
    <>
      <PageHead crumb="Vận hành › Tự động hoá" title="Tự động hoá"
        desc="Kịch bản khai báo: Khi nào chạy → Phạm vi → Nội dung → Gửi tới. Thư viện template lấy từ tài liệu “Bộ template tự động hoá”, chỉ gồm loại chạy được với dữ liệu hiện có.">
        {isAdmin && <button className="btn primary" onClick={() => setEdit({ code: "CUSTOM" })}><Plus size={16} />Tự tạo kịch bản</button>}
      </PageHead>
      <div className="stats">
        <Stat icon={Zap} label="Đang bật" value={on} sub={`${autos.length} kịch bản đã thêm`} tone={on ? "good" : ""} />
        <Stat icon={BookOpen} label="Template sẵn dùng" value={catalog.templates.length - 1} sub={`${catalog.unsupported.length} loại cần tích hợp thêm`} />
        <Stat icon={History} label="Lần chạy gần đây" value={(runs || []).filter((r) => !r.dry_run).length} sub="200 lần gần nhất" />
        <Stat icon={Ban} label="Lỗi" value={errors} sub={errors ? "xem tab Lịch sử" : "không có"} tone={errors ? "bad" : "good"} />
      </div>
      {DEMO && <div className="alert-box info" style={{ marginBottom: 12 }}>Bản demo: chạy thử hiển thị dữ liệu mẫu, không gửi tin.</div>}
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "library", label: "Thư viện template", icon: BookOpen, count: catalog.templates.length - 1 },
        { key: "mine", label: "Kịch bản của tôi", icon: Zap, count: autos.length },
        { key: "runs", label: "Lịch sử chạy", icon: History },
      ]} />

      {tab === "library" && <>
        {GROUPS.map(([g, label, q]) => (
          <div key={g} style={{ marginBottom: 18 }}>
            <div className="auto-group"><b>{label}</b> <span className="badge">{g}</span> <span className="small muted">{q}</span></div>
            <div className="auto-grid">
              {catalog.templates.filter((t) => t.group === g).map((t) => {
                const a = byCode[t.code];
                return (
                  <div key={t.code} className={`card card-pad auto-card ${a?.enabled ? "on" : ""}`}>
                    <div className="row" style={{ gap: 6 }}><span className="badge mono">{t.code}</span><b className="grow">{t.name}</b>
                      {a && <span className={`badge ${a.enabled ? "ok" : ""}`}>{a.enabled ? "Đang bật" : "Đã thêm · tắt"}</span>}</div>
                    <div className="small" style={{ margin: "8px 0" }}>{t.desc}</div>
                    <div className="small muted">⏱ {t.when} · {t.data}</div>
                    <div className="small faint" style={{ marginTop: 2 }}>KPI: {t.kpi}</div>
                    {isAdmin && <div className="row" style={{ gap: 6, marginTop: 10 }}>
                      {a ? <>
                        <Toggle checked={a.enabled} onChange={(v) => toggle(a, v)} label="" />
                        <button className="btn sm" onClick={() => setEdit(a)}><Pencil size={13} />Sửa</button>
                        <button className="btn sm" onClick={() => runNow(a, true)}><FlaskConical size={13} />Chạy thử</button>
                      </> : <button className="btn sm primary" onClick={() => setEdit({ code: t.code })}><Plus size={13} />Dùng template này</button>}
                    </div>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        <details className="card card-pad">
          <summary style={{ cursor: "pointer" }}><b>Chưa hỗ trợ ({catalog.unsupported.length})</b> <span className="small muted">– cần tích hợp hoặc dữ liệu mới, chưa đưa vào để tránh template chạy sai</span></summary>
          <div style={{ marginTop: 10 }}>{catalog.unsupported.map((u) => <div key={u.code} className="small" style={{ padding: "4px 0" }}><span className="badge mono">{u.code}</span> <b>{u.name}</b> <span className="muted">– {u.reason}</span></div>)}</div>
        </details>
      </>}

      {tab === "mine" && <div className="card">
        <Table rows={autos} rowKey="id" onRow={isAdmin ? setEdit : undefined}
          empty={<Empty icon={Zap} title="Chưa có kịch bản nào">Vào “Thư viện template” chọn template, hoặc bấm “Tự tạo kịch bản”.</Empty>}
          columns={[
            { key: "enabled", label: "", width: 60, render: (a) => <span onClick={(e) => e.stopPropagation()}><Toggle checked={a.enabled} onChange={(v) => toggle(a, v)} label="" /></span> },
            { key: "name", label: "Kịch bản", render: (a) => <div><div className="cell-title"><span className="badge mono">{a.code}</span> {a.name}</div><div className="cell-sub">{a.when} · {a.effective.level}</div></div> },
            { key: "next_run", label: "Lần tới", render: (a) => <span className="small">{a.next_run ? fmtTime(a.next_run) : a.enabled ? a.when : "—"}</span> },
            { key: "last_run_at", label: "Lần chạy gần nhất", render: (a) => a.last_run_at ? <div className="small"><span className={`badge ${STATUS[a.last_status]?.[0] || ""}`}>{STATUS[a.last_status]?.[1] || a.last_status}</span> {timeAgo(a.last_run_at)}<div className="faint" style={{ maxWidth: 320 }}>{a.last_summary}</div></div> : <span className="faint small">chưa chạy</span> },
            ...(isAdmin ? [{ key: "act", label: "", render: (a) => <div className="row" style={{ gap: 4 }} onClick={(e) => e.stopPropagation()}>
              <button className="btn sm" title="Chạy thử – xem trước, không gửi" onClick={() => runNow(a, true)}><FlaskConical size={13} /></button>
              <button className="btn sm" title="Chạy ngay và gửi" onClick={() => runNow(a, false)}><Play size={13} /></button>
              <button className="btn sm" title="Xoá" onClick={() => del(a)}><Trash2 size={13} /></button></div> }] : []),
          ]} />
      </div>}

      {tab === "runs" && <div className="card">
        <Table rows={runs || []} rowKey="id" onRow={(r) => setOut({ ...r, title: `${r.code} · ${r.name}` })}
          empty={<Empty icon={History} title="Chưa có lần chạy nào" />}
          columns={[
            { key: "ts", label: "Lúc", render: (r) => <span className="small">{fmtTime(r.ts)}</span> },
            { key: "name", label: "Kịch bản", render: (r) => <span className="small"><span className="badge mono">{r.code}</span> {r.name}</span> },
            { key: "trigger", label: "Kích hoạt", render: (r) => <span className="small">{TRIG[r.trigger] || r.trigger}{r.dry_run && " · thử"}</span> },
            { key: "status", label: "Kết quả", render: (r) => <span className={`badge ${STATUS[r.status]?.[0] || ""}`}>{STATUS[r.status]?.[1] || r.status}</span> },
            { key: "summary", label: "Tóm tắt", render: (r) => <span className="small">{r.summary}</span> },
            { key: "sent", label: "Gửi", render: (r) => <span className="small faint">{Object.entries(r.sent || {}).map(([k, v]) => `${k}: ${v}`).join(" · ") || (r.dry_run ? "không gửi" : "—")}</span> },
          ]} />
      </div>}

      {edit && <AutomationEditor edit={edit} catalog={catalog} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); refresh(); setTab("mine"); }} />}
      {out && <Modal title={out.title} onClose={() => setOut(null)} width={720} footer={<button className="btn" onClick={() => setOut(null)}>Đóng</button>}>
        <div className="row" style={{ marginBottom: 8, gap: 8 }}><span className={`badge ${STATUS[out.status]?.[0] || ""}`}>{STATUS[out.status]?.[1] || out.status}</span>
          <span className="small muted">{out.summary}</span>{out.dry && <span className="badge">chạy thử – không gửi</span>}</div>
        {out.output ? <pre className="auto-out">{out.output}</pre> : <div className="small muted">Không có tin nào được tạo ra.</div>}
        {out.sent && Object.keys(out.sent).length > 0 && <div className="small" style={{ marginTop: 8 }}><b>Đã gửi:</b> {Object.entries(out.sent).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>}
      </Modal>}
    </>
  );
}
