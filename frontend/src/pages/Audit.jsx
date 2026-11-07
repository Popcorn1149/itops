import React, { useState } from "react";
import { Search } from "lucide-react";
import { useApi, PageHead, Table, fmtTime, Empty } from "../ui";

const ACTION = { create: ["Tạo", "ok"], update: ["Sửa", "info"], delete: ["Xoá", "fail"], login: ["Đăng nhập", ""], ack: ["Nhận cảnh báo", "warn"], resolve: ["Đóng cảnh báo", "ok"], import: ["Nhập dữ liệu", "info"], login_failed: ["Đăng nhập sai", "fail"] };

export default function Audit() {
  const { data } = useApi("/audit?limit=1000", { interval: 30000 });
  const [q, setQ] = useState("");
  const rows = (data || []).filter((r) => !q || `${r.user} ${r.detail} ${r.entity}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead crumb="Vận hành › Audit log" title="Audit log" desc="Ai đã thêm, sửa, xoá gì và khi nào – hữu ích khi truy vết sự cố sau thay đổi cấu hình." />
      <div className="card">
        <div className="toolbar"><div className="search" style={{ width: 300 }}><Search size={16} /><input placeholder="Tìm người dùng, nội dung..." value={q} onChange={(e) => setQ(e.target.value)} /></div></div>
        <Table rows={rows} empty={<Empty title="Chưa có audit log" />} columns={[
          { key: "ts", label: "Thời gian", render: (r) => <span className="small mono">{fmtTime(r.ts)}</span> },
          { key: "user", label: "Người dùng", render: (r) => <b>{r.user}</b> },
          { key: "action", label: "Hành động", render: (r) => { const [l, c] = ACTION[r.action] || [r.action, ""]; return <span className={`badge ${c}`}>{l}</span>; } },
          { key: "entity", label: "Đối tượng", render: (r) => <span className="muted small">{r.entity}{r.entity_id ? ` #${r.entity_id}` : ""}</span> },
          { key: "detail", label: "Chi tiết" },
        ]} />
      </div>
    </>
  );
}
