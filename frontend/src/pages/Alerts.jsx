import React, { useState } from "react";
import { Check, CheckCheck, BellOff } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Table, Tabs, useToast, fmtTime, timeAgo, Empty, SevBadge, SEV, SEV_RANK } from "../ui";

function duration(a) {
  const end = a.resolved_at ? new Date(a.resolved_at) : new Date();
  const m = Math.round((end - new Date(a.opened_at)) / 60000);
  return m < 60 ? `${m} phút` : m < 1440 ? `${Math.floor(m / 60)} giờ ${m % 60} phút` : `${Math.floor(m / 1440)} ngày`;
}

export default function Alerts() {
  const { openCheck, openAsset, tick, refresh } = useApp();
  const [tab, setTab] = useState("active");
  const { data, reload } = useApi(`/alerts?status=${tab}`, { interval: 15000, deps: [tick, tab] });
  const toast = useToast();
  const act = async (a, action) => {
    try { await api.post(`/alerts/${a.id}/${action}`); toast(action === "ack" ? "Đã xác nhận – đang xử lý" : "Đã đóng cảnh báo"); reload(); refresh(); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <>
      <PageHead crumb="Vận hành › Cảnh báo" title="Cảnh báo" desc="DOWN = mất kết nối thật (tính vào uptime). Critical / Trouble / Attention = lỗi dịch vụ hoặc vượt threshold CPU/RAM/Disk – cảnh báo threshold chỉ đóng khi xuống dưới mức Rearm. Gửi qua Telegram / Email / Webhook (Cài đặt)." />
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "active", label: "Đang mở" }, { key: "acknowledged", label: "Đã nhận xử lý" }, { key: "resolved", label: "Đã xử lý" }, { key: "all", label: "Tất cả" },
      ]} />
      <div className="card">
        <Table rows={data || []} onRow={(a) => (a.check_id ? openCheck(a.check_id) : a.asset_id && openAsset(a.asset_id))}
          empty={<Empty icon={BellOff} title="Không có cảnh báo">{tab === "active" ? "Mọi hệ thống đang hoạt động bình thường." : ""}</Empty>} columns={[
            { key: "severity", label: "Mức", sort: (a) => (a.status === "resolved" ? -1 : SEV_RANK[a.severity] || 0), render: (a) => a.status === "resolved"
              ? <div className="row" style={{ gap: 4 }}><span className="badge ok">Đã xử lý</span><span className="small faint">{SEV[a.severity]?.label}</span></div>
              : <SevBadge sev={a.severity} /> },
            { key: "title", label: "Sự cố", render: (a) => <div><div className="cell-title">{a.title}
              {a.source === "event" && <span className="badge" style={{ fontSize: 11 }}>log{a.count > 1 ? ` ×${a.count}` : ""}</span>}
              {a.source === "audit" && <span className="badge accent" style={{ fontSize: 11 }} title="Người thực hiện không tự ack/đóng được">thao tác admin{a.actor ? ` · ${a.actor}` : ""}</span>}
              {a.source === "silence" && <span className="badge" style={{ fontSize: 11 }}>log im lặng</span>}
              {a.status !== "resolved" && a.sla_overdue && <span className="badge fail" style={{ fontSize: 11 }}>quá hạn SLA</span>}
              {a.metric && <span className="badge outline" style={{ fontSize: 11 }}>threshold {({ cpu: "CPU", mem: "RAM", disk: "Disk" })[a.metric]}</span>}</div><div className="cell-sub" style={{ maxWidth: 480 }}>{a.message}</div></div> },
            { key: "asset_name", label: "Tài sản / Site", render: (a) => <div className="small">{a.asset_name || "—"}<div className="muted">{a.site_name}</div></div> },
            { key: "opened_at", label: "Bắt đầu", render: (a) => <div className="small">{fmtTime(a.opened_at)}<div className="muted">{timeAgo(a.opened_at)}</div></div> },
            { key: "dur", label: "Thời gian", sortable: false, render: (a) => <span className="small">{duration(a)}</span> },
            { key: "sla_due", label: "Hạn ack", render: (a) => !a.sla_due ? <span className="faint">—</span>
              : a.acked_at ? <span className={`small ${a.sla_met ? "" : "muted"}`}>{a.sla_met ? "Đạt" : "Trễ"}</span>
              : <span className="small" style={{ color: a.sla_overdue ? "var(--fail)" : undefined }}>{fmtTime(a.sla_due)}</span> },
            { key: "acked_by", label: "Người nhận", render: (a) => a.acked_by ? <span className="badge info">{a.acked_by}</span> : <span className="faint">—</span> },
            { key: "act", label: "", sortable: false, render: (a) => a.status !== "resolved" && (
              <div className="row" onClick={(e) => e.stopPropagation()}>
                {a.status === "open" && <button className="btn sm" onClick={() => act(a, "ack")}><Check size={14} />Nhận</button>}
                <button className="btn sm" onClick={() => act(a, "resolve")}><CheckCheck size={14} />Đóng</button>
              </div>) },
          ]} />
      </div>
    </>
  );
}
