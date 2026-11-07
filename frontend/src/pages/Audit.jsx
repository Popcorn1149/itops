import React, { Fragment, useState } from "react";
import { Search } from "lucide-react";
import { useApi, PageHead, Table, fmtTime, Empty } from "../ui";

const ACTION = { create: ["Tạo", "ok"], update: ["Sửa", "info"], delete: ["Xoá", "fail"], login: ["Đăng nhập", ""], logout: ["Đăng xuất", ""], ack: ["Nhận cảnh báo", "warn"], resolve: ["Đóng cảnh báo", "ok"], import: ["Nhập dữ liệu", "info"], login_failed: ["Đăng nhập sai", "fail"],
  enable_2fa: ["Bật 2FA", "ok"], disable_2fa: ["Tắt 2FA", "warn"], reset_2fa: ["Đặt lại 2FA", "warn"], revoke: ["Thu hồi phiên", "warn"], backup: ["Sao lưu", "info"], disable: ["Tắt", "warn"] };

const show = (v) => (v === null || v === undefined || v === "" ? "∅" : typeof v === "object" ? JSON.stringify(v) : String(v));

// "Như thế nào": giá trị trước → sau (bí mật đã được server che)
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
  const { data } = useApi("/audit?limit=1000", { interval: 30000 });
  const [q, setQ] = useState("");
  const rows = (data || []).filter((r) => !q || `${r.user} ${r.detail} ${r.entity} ${r.ip || ""} ${r.reason || ""}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead crumb="Vận hành › Audit log" title="Audit log" desc="Ai · làm gì · khi nào · từ đâu (IP, trình duyệt) · thay đổi thế nào (trước → sau) · vì sao. Nhật ký chỉ ghi thêm, không sửa / xoá được." />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm người dùng, nội dung, IP, lý do..." value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} empty={<Empty title="Chưa có audit log" />} columns={[
          { key: "ts", label: "Thời gian", render: (r) => <span className="small mono">{fmtTime(r.ts)}</span> },
          { key: "user", label: "Người dùng", render: (r) => <b>{r.user}</b> },
          { key: "action", label: "Hành động", render: (r) => { const [l, c] = ACTION[r.action] || [r.action, ""]; return <span className={`badge ${c}`}>{l}</span>; } },
          { key: "entity", label: "Đối tượng", render: (r) => <span className="muted small">{r.entity}{r.entity_id ? ` #${r.entity_id}` : ""}</span> },
          { key: "detail", label: "Chi tiết", render: (r) => <div>{r.detail}{r.reason && <div className="small" style={{ marginTop: 2 }}><span className="muted">Lý do:</span> {r.reason}</div>}<Changes c={r.changes} /></div> },
          { key: "ip", label: "Từ đâu", render: (r) => <span className="small mono" title={r.user_agent || ""}>{r.ip || "–"}</span> },
        ]} />
      </div>
    </>
  );
}
