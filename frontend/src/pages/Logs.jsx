import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { Radio, Search, Send, Plus, Pencil, Trash2, FlaskConical, ListFilter, HelpCircle, ShieldQuestion, Copy, Pause, Play, ChevronDown } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { AssetForm } from "./Assets";
import {
  useApi, PageHead, Tabs, Table, Modal, Field, Input, Select, Toggle, useToast, timeAgo, fmtTime, Dot, Empty, confirmDelete, Stat, DEMO, SevBadge as AlertSev } from "../ui";
import { Bell, AlertTriangle, Inbox } from "lucide-react";

export const SEV = ["Khẩn cấp", "Báo động", "Nghiêm trọng", "Lỗi", "Cảnh báo", "Lưu ý", "Thông tin", "Debug"];
export const SEV_EN = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
const sevCls = (s) => (s <= 3 ? "fail" : s === 4 ? "warn" : s === 5 ? "info" : "");
export function SevBadge({ s }) {
  return <span className={`badge ${sevCls(s)}`} title={SEV_EN[s]}>{SEV[s] ?? s}</span>;
}
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const shortTime = (iso) => {
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString("vi-VN", { hour12: false }) : d.toLocaleString("vi-VN", { hour12: false, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
};

function Histogram({ series, bucket }) {
  const el = useRef();
  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current);
    c.setOption({
      grid: { left: 36, right: 10, top: 10, bottom: 22 },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      xAxis: { type: "time", axisLabel: { fontSize: 10 } },
      yAxis: { type: "value", minInterval: 1, axisLabel: { fontSize: 10 }, splitLine: { lineStyle: { color: "#f1efec" } } },
      series: [["error", "Lỗi trở lên", "#dc2626"], ["warning", "Cảnh báo", "#d97706"], ["info", "Thông tin", "#a8a29e"]].map(([k, n, col]) => ({
        name: n, type: "bar", stack: "s", barMaxWidth: 14, itemStyle: { color: col }, data: series.map((p) => [p.ts, p[k]]),
      })),
    });
    const ro = new ResizeObserver(() => c.resize()); ro.observe(el.current);
    return () => { ro.disconnect(); c.dispose(); };
  }, [series, bucket]);
  if (!series.length) return <div className="muted small" style={{ padding: "18px 0" }}>Chưa nhận được log nào trong 24 giờ qua.</div>;
  return <div ref={el} style={{ height: 130 }} />;
}

function ReceiverStatus({ r }) {
  const L = r?.listeners || {};
  const item = (k, label) => {
    const x = L[k];
    const last = r?.last?.[k.startsWith("syslog") ? "syslog" : "trap"];
    return (
      <span key={k} className={`chip ${x?.ok ? "green" : x ? "red" : ""}`} title={x?.error || ""}>
        <Dot status={x?.ok ? "ok" : x ? "fail" : "unknown"} />{label} :{x?.port ?? "—"}
        <span className="faint">{x?.ok ? (last ? `nhận ${timeAgo(new Date(last * 1000).toISOString())}` : "đang nghe") : x ? "lỗi mở cổng" : "tắt"}</span>
      </span>
    );
  };
  return (
    <div className="chips">
      {item("syslog_udp", "Syslog UDP")}{item("syslog_tcp", "Syslog TCP")}{item("snmp_trap", "SNMP Trap")}
      {(r?.dropped_rate > 0 || r?.dropped_queue > 0) && <span className="chip amber" title="Vượt giới hạn tốc độ mỗi nguồn">Bỏ {r.dropped_rate + r.dropped_queue} log do flood</span>}
      {r?.dropped_acl > 0 && <span className="chip red" title={"IP ngoài danh sách cho phép (Cài đặt › Nhận Syslog/Trap): " + (r.blocked || []).map(([ip, n]) => `${ip} (${n})`).join(", ")}>
        Chặn {r.dropped_acl} log từ IP lạ: {(r.blocked || []).slice(0, 3).map(([ip]) => ip).join(", ")}</span>}
    </div>
  );
}

function EventDetail({ e, onClose, onRule, onAddAsset, onSource }) {
  const { openAsset } = useApp();
  return (
    <Modal title={<span className="row"><SevBadge s={e.severity} />{e.kind === "trap" ? "SNMP Trap" : "Syslog"} · {fmtTime(e.ts)}</span>} onClose={onClose} width={760}
      footer={<>
        {!e.asset_id && <button className="btn" onClick={onAddAsset}><Plus size={14} />Thêm tài sản với IP này</button>}
        <button className="btn" onClick={onSource}><ListFilter size={14} />Log cùng nguồn</button>
        <button className="btn primary" onClick={onRule}><Bell size={14} />Tạo rule cảnh báo</button>
      </>}>
      <div className="kv" style={{ marginBottom: 14 }}>
        <div>Nguồn</div><div>{e.asset_id ? <a style={{ cursor: "pointer", textDecoration: "underline" }} onClick={() => openAsset(e.asset_id)}>{e.asset_name}</a> : <span className="badge warn">Nguồn lạ</span>} <span className="mono">{e.source_ip}</span></div>
        {e.host && <><div>Hostname</div><div>{e.host}</div></>}
        <div>Ứng dụng</div><div className="mono">{e.app || "—"}</div>
        <div>Mức độ</div><div>{SEV[e.severity]} ({SEV_EN[e.severity]}){e.facility != null ? ` · facility ${e.facility}` : ""}</div>
        {e.device_ts && <><div>Giờ trên thiết bị</div><div className="mono small">{e.device_ts}</div></>}
        {e.rule_id && <><div>Rule</div><div>Khớp rule #{e.rule_id}</div></>}
      </div>
      <div className="small" style={{ fontWeight: 600, marginBottom: 4 }}>Nội dung</div>
      <pre className="json" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{e.message}</pre>
      {e.kind === "trap" && e.data?.varbinds && <><div className="small" style={{ fontWeight: 600, margin: "10px 0 4px" }}>Varbinds</div>
        <pre className="json">{e.data.varbinds.map(([o, v]) => `${o} = ${v}`).join("\n")}</pre></>}
    </Modal>
  );
}

export function RuleForm({ rule, onClose, onSaved }) {
  const toast = useToast();
  const assets = useApi("/assets");
  const sites = useApi("/sites");
  const [f, setF] = useState({ kind: "syslog", action: "alert", max_severity: 7, alert_severity: "warning", threshold: 1, window_min: 5, auto_resolve_min: 0, enabled: true, ...rule });
  const [sample, setSample] = useState(rule?._sample || "");
  const [res, setRes] = useState(null);
  const set = (k) => (v) => setF({ ...f, [k]: v });
  const num = (k) => (v) => set(k)(v === "" ? "" : Number(v));
  const body = () => ({ ...f, asset_id: f.asset_id ? Number(f.asset_id) : null, site_id: f.site_id ? Number(f.site_id) : null, max_severity: Number(f.max_severity) });
  const save = async () => {
    try { f.id ? await api.put(`/event-rules/${f.id}`, body()) : await api.post("/event-rules", body()); toast("Đã lưu rule"); onSaved(); }
    catch (e) { toast(e.message, true); }
  };
  const test = async () => {
    try { setRes(await api.post("/event-rules/test", { ...body(), sample })); } catch (e) { toast(e.message, true); }
  };
  return (
    <Modal title={f.id ? `Rule: ${f.name}` : "Tạo rule cảnh báo từ log"} onClose={onClose} width={820}
      footer={<><button className="btn" onClick={test}><FlaskConical size={14} />Thử rule</button><button className="btn" onClick={onClose}>Huỷ</button><button className="btn primary" onClick={save}>Lưu</button></>}>
      {f.builtin && <div className="alert-box info" style={{ marginBottom: 12 }}>Rule có sẵn – bạn vẫn sửa hoặc tắt được.</div>}
      <div className="form-grid">
        <Field label="Tên rule *"><Input value={f.name} onChange={set("name")} placeholder="VD: Cổng uplink down" /></Field>
        <Field label="Hành động"><Select value={f.action} onChange={set("action")} options={[["alert", "Mở cảnh báo"], ["drop", "Bỏ qua (không lưu log)"]]} /></Field>
        <Field label="Loại log"><Select value={f.kind} onChange={set("kind")} options={[["syslog", "Syslog"], ["trap", "SNMP Trap"], ["any", "Cả hai"]]} /></Field>
        <Field label="Mức độ từ" hint="Khớp log có mức này hoặc nghiêm trọng hơn"><Select value={f.max_severity} onChange={set("max_severity")} options={SEV.map((s, i) => [i, `${s} (${SEV_EN[i]})${i === 7 ? " – mọi mức" : " trở lên"}`])} /></Field>
        <Field label="Nội dung khớp (regex)" full hint="Không phân biệt hoa/thường. Dùng (?P<key>...) để gom cảnh báo theo cổng/volume… VD: Interface (?P<key>\S+), changed state to down">
          <Input value={f.pattern} onChange={set("pattern")} placeholder="VD: Failed password|authentication error" /></Field>
        {f.kind !== "trap" && <Field label="Ứng dụng / tag (regex)"><Input value={f.app_pattern} onChange={set("app_pattern")} placeholder="VD: ^sshd$" /></Field>}
        {f.kind !== "syslog" && <Field label="Trap OID" hint="Nhiều OID cách nhau dấu phẩy"><Input value={f.trap_oids} onChange={set("trap_oids")} placeholder="1.3.6.1.6.3.1.1.5.3" /></Field>}
        <Field label="Giới hạn ở tài sản"><Select value={f.asset_id} onChange={set("asset_id")} placeholder="— Mọi nguồn —" options={(assets.data || []).map((a) => [a.id, a.name])} /></Field>
        <Field label="Giới hạn ở site"><Select value={f.site_id} onChange={set("site_id")} placeholder="— Mọi site —" options={(sites.data || []).map((s) => [s.id, s.name])} /></Field>
        {f.action === "alert" && <>
          <div className="section-title">Cảnh báo</div>
          <Field label="Mức cảnh báo"><Select value={f.alert_severity} onChange={set("alert_severity")} options={[["critical", "Critical (đỏ)"], ["trouble", "Trouble (cam)"], ["attention", "Attention (vàng)"]]} /></Field>
          <Field label="Chỉ báo khi lặp lại" hint="VD: 5 lần trong 5 phút (dò mật khẩu)">
            <div className="row"><Input type="number" value={f.threshold} onChange={num("threshold")} /><span className="muted">lần /</span><Input type="number" value={f.window_min} onChange={num("window_min")} /><span className="muted">phút</span></div></Field>
          <Field label="Gộp cảnh báo theo" hint="IP source: một IP thử nhiều user chỉ ra 1 cảnh báo, kèm danh sách user đã thử">
            <Select value={f.group_by || ""} onChange={set("group_by")} options={[["", "Khoá trong regex (?P<key>…)"], ["src_ip", "IP source ghi trong log"]]} /></Field>
          <Field label="Chỉ áp dụng cho khoá" hint="Danh sách cách nhau dấu phẩy, vd. IP tĩnh quan trọng. Trống = mọi khoá">
            <Input value={f.key_filter || ""} onChange={set("key_filter")} placeholder="10.0.0.1, 10.0.0.10" /></Field>
          <Field label="Log phục hồi (regex)" hint="Gặp dòng này thì tự đóng cảnh báo. VD: Interface (?P<key>\S+), changed state to up"><Input value={f.resolve_pattern} onChange={set("resolve_pattern")} /></Field>
          {f.kind !== "syslog" && <Field label="Trap OID phục hồi"><Input value={f.resolve_trap_oids} onChange={set("resolve_trap_oids")} placeholder="1.3.6.1.6.3.1.1.5.4" /></Field>}
          <Field label="Tự đóng sau (phút) không lặp lại" hint="0 = chỉ đóng khi có log phục hồi hoặc đóng tay"><Input type="number" value={f.auto_resolve_min} onChange={num("auto_resolve_min")} /></Field>
        </>}
        <Field label="Mô tả" full><Input value={f.description} onChange={set("description")} /></Field>
        <Field full><Toggle checked={f.enabled} onChange={set("enabled")} label="Đang bật" /></Field>
        <div className="section-title">Thử với một dòng log</div>
        <Field full><textarea className="input mono" style={{ minHeight: 60 }} value={sample} onChange={(e) => setSample(e.target.value)} placeholder="<187>Nov  2 21:00:01 SW-CORE %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down" /></Field>
      </div>
      {res && (
        <div className="stack" style={{ gap: 8, marginTop: 12 }}>
          {res.sample && <div className={`alert-box ${res.sample.match ? "ok" : res.sample.resolves ? "info" : "warn"}`}>
            {res.sample.match ? <>✓ Dòng mẫu <b>khớp</b>{res.sample.key && <> · khoá gom: <b>{res.sample.key}</b></>}</> : res.sample.resolves ? "↺ Dòng mẫu là log phục hồi (sẽ đóng cảnh báo)" : "✗ Dòng mẫu không khớp"}
            <div className="small" style={{ marginTop: 4 }}>Đọc được: mức <b>{SEV[res.sample.parsed.severity]}</b> · app <b>{res.sample.parsed.app || "—"}</b> · host <b>{res.sample.parsed.host || "—"}</b></div>
          </div>}
          <div className="alert-box info">Với log 24h qua: <b>{res.history.matches}</b>/{res.history.scanned} dòng khớp{res.history.matches > 50 ? " – có thể quá rộng, dễ bị spam cảnh báo" : ""}.</div>
          {res.history.examples.map((x) => <div key={x.id} className="small mono" style={{ padding: "4px 0", borderBottom: "1px solid #f1efec" }}>{shortTime(x.ts)} {x.source_ip} {x.message.slice(0, 160)}</div>)}
        </div>
      )}
    </Modal>
  );
}

function RulesTab() {
  const { isAdmin, tick } = useApp();
  const toast = useToast();
  const { data, reload } = useApi("/event-rules", { deps: [tick] });
  const [edit, setEdit] = useState(null);
  const toggle = async (r) => { await api.put(`/event-rules/${r.id}`, { enabled: !r.enabled }); reload(); };
  const remove = async (r) => { if (!(await confirmDelete(r.name))) return; await api.del(`/event-rules/${r.id}`); toast("Đã xoá rule"); reload(); };
  const cond = (r) => [r.kind === "trap" ? "Trap" : r.kind === "syslog" ? "Syslog" : "Syslog + Trap", r.max_severity < 7 && `mức ≤ ${SEV_EN[r.max_severity]}`,
    r.app_pattern && `app ~ ${r.app_pattern}`, r.trap_oids && `OID ${r.trap_oids}`, r.pattern && `“${r.pattern.length > 50 ? r.pattern.slice(0, 50) + "…" : r.pattern}”`,
    r.threshold > 1 && `≥${r.threshold} lần/${r.window_min}′`, r.asset_name && `tại ${r.asset_name}`].filter(Boolean).join(" · ");
  return (
    <div className="card">
      <div className="toolbar"><span className="muted small grow">Rule được xét theo thứ tự từ trên xuống; log khớp rule đầu tiên. Log phục hồi sẽ đóng cảnh báo tương ứng.</span>
        {isAdmin && <button className="btn primary sm" onClick={() => setEdit({})}><Plus size={14} />Thêm rule</button>}</div>
      <Table rows={data || []} onRow={(r) => isAdmin && setEdit(r)} columns={[
        { key: "enabled", label: "", sortable: false, render: (r) => <input type="checkbox" checked={r.enabled} disabled={!isAdmin} onClick={(e) => e.stopPropagation()} onChange={() => toggle(r)} /> },
        { key: "name", label: "Rule", render: (r) => <div><div className="cell-title" style={{ opacity: r.enabled ? 1 : 0.5 }}>{r.name}{r.builtin && <span className="badge" style={{ fontSize: 11 }}>có sẵn</span>}</div><div className="cell-sub">{r.description}</div></div> },
        { key: "cond", label: "Điều kiện", sortable: false, render: (r) => <span className="small mono" style={{ wordBreak: "break-word" }}>{cond(r)}</span> },
        { key: "action", label: "Hành động", render: (r) => r.action === "drop" ? <span className="badge">Bỏ qua</span> : <AlertSev sev={r.alert_severity} /> },
        { key: "hits", label: "Đã khớp", render: (r) => <div className="small">{r.hits}<div className="muted">{r.last_hit ? timeAgo(r.last_hit) : "chưa"}</div></div> },
        { key: "open_alerts", label: "Đang mở", render: (r) => r.open_alerts ? <span className="badge fail">{r.open_alerts}</span> : <span className="faint">—</span> },
        ...(isAdmin ? [{ key: "act", label: "", sortable: false, render: (r) => <div className="row" onClick={(e) => e.stopPropagation()}><button className="btn ghost sm" onClick={() => setEdit(r)}><Pencil size={14} /></button><button className="btn ghost sm danger" onClick={() => remove(r)}><Trash2 size={14} /></button></div> }] : []),
      ]} />
      {edit && <RuleForm rule={edit.id || edit._sample ? edit : null} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </div>
  );
}

function UnknownTab({ stats, reload }) {
  const [add, setAdd] = useState(null);
  const { nav } = useApp();
  const rows = stats?.unknown_sources || [];
  return (
    <div className="card">
      <div className="toolbar"><span className="muted small">Thiết bị gửi log tới nhưng chưa có trong danh sách tài sản (khớp theo IP hoặc hostname). Thêm vào để log được gắn đúng thiết bị trên bản đồ.</span></div>
      <Table rowKey="source_ip" rows={rows} empty={<Empty icon={ShieldQuestion} title="Không có nguồn lạ">Mọi thiết bị gửi log đều đã có trong danh sách tài sản.</Empty>} columns={[
        { key: "source_ip", label: "IP source", render: (r) => <b className="mono">{r.source_ip}</b> },
        { key: "host", label: "Hostname", render: (r) => r.host || <span className="faint">—</span> },
        { key: "count", label: "Số log 24h" },
        { key: "last", label: "Gần nhất", render: (r) => <span className="small muted">{timeAgo(r.last)}</span> },
        { key: "act", label: "", sortable: false, render: (r) => <div className="row" onClick={(e) => e.stopPropagation()}>
          <button className="btn sm" onClick={() => nav("logs", null, { source_ip: r.source_ip })}>Xem log</button>
          <button className="btn sm primary" onClick={() => setAdd(r)}><Plus size={14} />Thêm tài sản</button></div> },
      ]} />
      {add && <AssetForm preset={{ ip: add.source_ip, name: add.host || add.source_ip, type: "device" }} onClose={() => setAdd(null)} onSaved={() => { setAdd(null); reload(); }} />}
    </div>
  );
}

function Code({ children }) {
  const toast = useToast();
  const copy = async () => { try { await navigator.clipboard.writeText(children); toast("Đã chép"); } catch { toast("Không chép được – hãy bôi đen để copy", true); } };
  return (
    <div style={{ position: "relative" }}>
      <pre className="json" style={{ whiteSpace: "pre-wrap", paddingRight: 44 }}>{children}</pre>
      <button className="btn ghost sm" style={{ position: "absolute", top: 4, right: 4 }} onClick={copy} title="Chép"><Copy size={14} /></button>
    </div>
  );
}

function GuideTab({ ports }) {
  const [ip, setIp] = useState(typeof window !== "undefined" && !DEMO ? window.location.hostname : "10.0.20.60");
  const [open, setOpen] = useState("pfsense");
  const u = ports?.syslog_udp ?? 514, t = ports?.snmp_trap ?? 162;
  const G = [
    ["pfsense", "pfSense / OPNsense", <>
      <p><b>Syslog:</b> <i>Status › System Logs › Settings</i> → bật <b>Enable Remote Logging</b>, Remote log servers: <code>{ip}:{u}</code>, chọn <b>System Events, Gateway Monitor, VPN, DHCP</b>. Chỉ tick <i>Firewall Events</i> nếu muốn lưu log gói tin (rule “Bỏ qua filterlog” đang bật).</p>
      <p>Log Message Format: <b>syslog (RFC 5424)</b> để có hostname.</p>
      <p className="muted small">pfSense không gửi SNMP trap – status WAN/VPN lấy qua syslog + check REST API.</p></>],
    ["cisco", "Cisco IOS / IOS-XE (switch, router)", <Code>{`conf t
logging host ${ip}
logging trap informational
logging source-interface Vlan1
service timestamps log datetime localtime
snmp-server community <community-trap> RO
snmp-server enable traps snmp linkdown linkup coldstart warmstart
snmp-server host ${ip} version 2c <community-trap>
end
write memory`}</Code>],
    ["aruba", "HPE Aruba / ProCurve (AOS-S, 2530/2930)", <Code>{`configure
logging ${ip}
logging severity info
snmp-server community "<community-trap>" operator
snmp-server host ${ip} community "<community-trap>"
snmp-server enable traps link-change all
write memory`}</Code>],
    ["arubacx", "Aruba CX (6100/6200/6300…)", <Code>{`configure
logging ${ip} udp severity info vrf default
snmp-server vrf default
snmp-server community <community-trap>
snmp-server host ${ip} trap version v2c community <community-trap>
write memory`}</Code>],
    ["esxi", "VMware ESXi", <><Code>{`esxcli system syslog config set --loghost='udp://${ip}:${u}'
esxcli system syslog reload
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true
esxcli network firewall refresh
# SNMP trap (tuỳ chọn)
esxcli system snmp set --communities=<community-trap> --targets=${ip}@${t}/<community-trap> --enable=true
esxcli system snmp test`}</Code><p className="muted small">vCenter: Host › Configure › Advanced System Settings › Syslog.global.logHost = <code>udp://{ip}:{u}</code></p></>],
    ["synology", "Synology DSM", <><p><b>Syslog:</b> cài gói <i>Log Center</i> → <i>Log Sending</i> → Server: <code>{ip}</code>, Port <code>{u}</code>, UDP, Format <b>IETF (RFC 5424)</b>.</p>
      <p><b>Trap:</b> <i>Control Panel › Terminal & SNMP › SNMP</i> bật SNMPv1/v2c; cảnh báo ổ cứng/RAID sẽ đi qua syslog.</p></>],
    ["ups", "UPS APC (card mạng NMC)", <p><i>Configuration › Notification › SNMP Traps › Trap Receivers</i> → thêm <code>{ip}</code>, community = community đã khai báo ở Cài đặt. <i>Configuration › Logs › Syslog</i> → Server <code>{ip}</code> port <code>{u}</code>.</p>],
    ["fortigate", "FortiGate", <Code>{`config log syslogd setting
    set status enable
    set server "${ip}"
    set port ${u}
end
config system snmp community
    edit 1
        set name "<community-trap>"
        config hosts
            edit 1
                set ip ${ip} 255.255.255.255
            next
        end
    next
end`}</Code>],
    ["linux", "Linux (rsyslog)", <><Code>{`# /etc/rsyslog.d/90-itops.conf   (@ = UDP, @@ = TCP)
*.info  @${ip}:${u}
# rồi: sudo systemctl restart rsyslog`}</Code></>],
    ["windows", "Windows Server (NXLog CE)", <Code>{`<Input eventlog>
    Module  im_msvistalog
    Query   <QueryList><Query Id="0"><Select Path="System">*[System[(Level<=3)]]</Select><Select Path="Security">*[System[(EventID=4625 or EventID=4740)]]</Select></Query></QueryList>
</Input>
<Output itops>
    Module  om_udp
    Host    ${ip}
    Port    ${u}
    Exec    to_syslog_ietf();
</Output>
<Route r> Path eventlog => itops </Route>`}</Code>],
  ];
  return (
    <div className="stack">
      <div className="card card-pad">
        <div className="form-grid">
          <Field label="IP máy chủ IT Ops (thiết bị sẽ gửi log tới)" hint="IP nội bộ của VM chạy docker"><Input value={ip} onChange={setIp} /></Field>
          <div className="small muted" style={{ lineHeight: 1.7 }}>Syslog: UDP/TCP <b>{u}</b> · SNMP Trap: UDP <b>{t}</b><br />Nhớ mở firewall giữa thiết bị và máy chủ (VD rule pfSense LAN → {ip}:{u}/{t}).</div>
        </div>
      </div>
      {G.map(([k, title, body]) => (
        <div key={k} className="card">
          <div className="card-head" style={{ cursor: "pointer" }} onClick={() => setOpen(open === k ? "" : k)}>
            <h3 className="grow">{title}</h3><ChevronDown size={16} style={{ transform: open === k ? "rotate(180deg)" : "" }} />
          </div>
          {open === k && <div className="card-pad" style={{ lineHeight: 1.6 }}>{body}</div>}
        </div>
      ))}
    </div>
  );
}

export default function Logs() {
  const { route, isAdmin, tick, nav } = useApp();
  const toast = useToast();
  const [tab, setTab] = useState(route.params.tab || "logs");
  const [q, setQ] = useState(route.params.q || "");
  const [qd, setQd] = useState(q);
  const [sev, setSev] = useState(route.params.max_severity || "7");
  const [kind, setKind] = useState("");
  const [assetF] = useState(route.params.asset_id || "");
  const [srcF, setSrcF] = useState(route.params.source_ip || "");
  const [live, setLive] = useState(true);
  const [rows, setRows] = useState([]);
  const [more, setMore] = useState(false);
  const [detail, setDetail] = useState(null);
  const [ruleFrom, setRuleFrom] = useState(null);
  const [addFrom, setAddFrom] = useState(null);
  const stats = useApi("/events/stats?hours=24", { interval: live ? 15000 : 0, deps: [tick] });
  const ports = useApi(isAdmin ? "/settings/receivers" : null);
  useEffect(() => { const t = setTimeout(() => setQd(q), 300); return () => clearTimeout(t); }, [q]);
  const qs = new URLSearchParams({ q: qd, max_severity: sev, kind, limit: "150", ...(assetF ? { asset_id: assetF } : {}), ...(srcF ? { source_ip: srcF } : {}), ...(tab === "unknown-logs" ? { unknown: "true" } : {}) }).toString();
  const load = async () => { try { const d = await api.get(`/events?${qs}`); setRows(d); setMore(d.length === 150); } catch (e) { toast(e.message, true); } };
  useEffect(() => { if (tab === "logs") load(); }, [qs, tab, tick]);
  useEffect(() => { if (!live || tab !== "logs") return; const t = setInterval(load, 5000); return () => clearInterval(t); }, [live, qs, tab]);
  const loadMore = async () => { const d = await api.get(`/events?${qs}&before_id=${rows[rows.length - 1].id}`); setRows([...rows, ...d]); setMore(d.length === 150); };
  const sendTest = async (k) => {
    try { const r = await api.post("/events/send-test", { kind: k }); r.ok ? toast(`Đã nhận lại ${k === "trap" ? "trap" : "syslog"} thử ✓`) : toast("Không thấy log thử quay về – kiểm tra cổng nhận", true); load(); stats.reload(); }
    catch (e) { toast(e.message, true); }
  };
  const s = stats.data;
  return (
    <>
      <PageHead crumb="Vận hành › Log thiết bị" title="Log thiết bị" desc="Syslog và SNMP Trap do firewall, switch, ESXi, NAS, UPS… gửi về. Tự gắn vào tài sản theo IP; rule biến log quan trọng thành cảnh báo.">
        {isAdmin && !DEMO && <><button className="btn" onClick={() => sendTest("syslog")}><Send size={15} />Gửi thử syslog</button><button className="btn" onClick={() => sendTest("trap")}><Radio size={15} />Gửi thử trap</button></>}
      </PageHead>
      {s && <div className="stats">
        <Stat icon={Inbox} label="Log 24 giờ" value={s.total.toLocaleString("vi-VN")} sub={`${s.receiver.stored.toLocaleString("vi-VN")} log từ khi khởi động`} onClick={() => { setTab("logs"); setSev("7"); }} />
        <Stat icon={AlertTriangle} label="Lỗi trở lên" value={s.errors} sub="mức err/crit/alert/emerg" tone={s.errors ? "bad" : "good"} onClick={() => { setTab("logs"); setSev("3"); }} />
        <Stat icon={Bell} label="Cảnh báo (warning)" value={s.warnings} sub="trong 24 giờ" onClick={() => { setTab("logs"); setSev("4"); }} />
        <Stat icon={ShieldQuestion} label="Nguồn lạ" value={s.unknown_sources.length} sub="IP chưa có trong tài sản" tone={s.unknown_sources.length ? "bad" : "good"} onClick={() => setTab("unknown")} />
      </div>}
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "logs", label: "Log", icon: Inbox },
        { key: "rules", label: "Rule cảnh báo", icon: Bell },
        { key: "unknown", label: "Nguồn lạ", icon: ShieldQuestion, count: s?.unknown_sources.length ?? 0 },
        { key: "guide", label: "Hướng dẫn cấu hình thiết bị", icon: HelpCircle },
      ]} />
      {tab === "logs" && (
        <div className="card">
          <div className="card-pad" style={{ paddingBottom: 6 }}>
            <div className="row wrap" style={{ marginBottom: 8 }}><ReceiverStatus r={s?.receiver} /></div>
            {s && <Histogram series={s.series} bucket={s.bucket_min} />}
          </div>
          <div className="toolbar">
            <div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm nội dung, app, IP…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
            <div style={{ width: 190 }}><Select value={sev} onChange={setSev} options={[["7", "Mọi mức độ"], ["5", "Lưu ý trở lên"], ["4", "Cảnh báo trở lên"], ["3", "Lỗi trở lên"], ["2", "Nghiêm trọng trở lên"]]} /></div>
            <div style={{ width: 150 }}><Select value={kind} onChange={setKind} options={[["", "Syslog + Trap"], ["syslog", "Syslog"], ["trap", "SNMP Trap"]]} /></div>
            {(srcF || assetF) && <span className="chip" onClick={() => { setSrcF(""); nav("logs"); }}>Nguồn: {srcF || `tài sản #${assetF}`} ✕</span>}
            <button className={`btn sm ${live ? "primary" : ""}`} style={{ marginLeft: "auto" }} onClick={() => setLive(!live)}>{live ? <><Pause size={14} />Đang tự cập nhật</> : <><Play size={14} />Tự cập nhật</>}</button>
          </div>
          <Table rows={rows} onRow={setDetail} empty={<Empty icon={Inbox} title="Chưa có log">{isAdmin ? "Cấu hình thiết bị gửi syslog/trap về máy chủ này (xem tab Hướng dẫn), hoặc bấm “Gửi thử syslog”." : ""}</Empty>} columns={[
            { key: "ts", label: "Thời gian", width: 90, render: (e) => <span className="small mono">{shortTime(e.ts)}</span> },
            { key: "severity", label: "Mức", width: 90, render: (e) => <SevBadge s={e.severity} /> },
            { key: "source", label: "Nguồn", sort: (e) => e.asset_name || e.source_ip, render: (e) => <div className="small">{e.asset_name ? <b>{e.asset_name}</b> : <span className="badge warn" style={{ fontSize: 11 }}>lạ</span>}<div className="muted mono">{e.source_ip}{e.kind === "trap" ? " · trap" : ""}</div></div> },
            { key: "app", label: "App", render: (e) => <span className="small mono">{e.app || "—"}</span> },
            { key: "message", label: "Nội dung", sortable: false, render: (e) => <div className="small mono" style={{ maxWidth: 620, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", wordBreak: "break-word" }}>{e.message}</div> },
          ]} />
          {more && <div style={{ padding: 12, textAlign: "center" }}><button className="btn" onClick={loadMore}>Tải thêm</button></div>}
        </div>
      )}
      {tab === "rules" && <RulesTab />}
      {tab === "unknown" && <UnknownTab stats={s} reload={stats.reload} />}
      {tab === "guide" && <GuideTab ports={ports.data?.ports} />}
      {detail && <EventDetail e={detail} onClose={() => setDetail(null)}
        onSource={() => { setSrcF(detail.source_ip); setDetail(null); }}
        onAddAsset={() => { setAddFrom(detail); setDetail(null); }}
        onRule={() => { setRuleFrom({ name: `${detail.app || "Log"} – ${detail.message.slice(0, 30)}`, kind: detail.kind, pattern: detail.kind === "syslog" ? escRe(detail.message.slice(0, 60)) : "", trap_oids: detail.data?.trap_oid || "", _sample: detail.kind === "syslog" ? `<${(detail.facility ?? 1) * 8 + detail.severity}>${detail.message}` : "", alert_severity: detail.severity <= 3 ? "critical" : "warning" }); setDetail(null); }} />}
      {ruleFrom && <RuleForm rule={ruleFrom} onClose={() => setRuleFrom(null)} onSaved={() => { setRuleFrom(null); setTab("rules"); }} />}
      {addFrom && <AssetForm preset={{ ip: addFrom.source_ip, name: addFrom.host || addFrom.source_ip, type: "device" }} onClose={() => setAddFrom(null)} onSaved={() => { setAddFrom(null); load(); stats.reload(); }} />}
    </>
  );
}
