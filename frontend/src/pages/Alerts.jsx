import React, { useState } from "react";
import { Check, CheckCheck, BellOff } from "lucide-react";
import { api } from "../api";
import { useApp } from "../App";
import { useApi, PageHead, Table, Tabs, useToast, fmtTime, timeAgo, Empty, SevBadge, SEV, SEV_RANK, CapNote } from "../ui";

function duration(a, t) {
  const end = a.resolved_at ? new Date(a.resolved_at) : new Date();
  const minutes = Math.max(0, Math.round((end - new Date(a.opened_at)) / 60000));
  if (minutes < 60) return t("alertsPage.minutesUnit", { count: minutes });
  if (minutes < 1440) return `${t("alertsPage.hoursUnit", { count: Math.floor(minutes / 60) })} ${t("alertsPage.minutesUnit", { count: minutes % 60 })}`;
  return t("alertsPage.daysUnit", { count: Math.floor(minutes / 1440) });
}

export default function Alerts() {
  const { openCheck, openAsset, tick, refresh, t, lang } = useApp();
  const [tab, setTab] = useState("active");
  const { data, reload } = useApi(`/alerts?status=${tab}&locale=${lang}`, { interval: 15000, deps: [tick, tab] });
  const toast = useToast();
  const act = async (a, action) => {
    try { await api.post(`/alerts/${a.id}/${action}`); toast(action === "ack" ? t("alertsPage.acknowledgedToast") : t("alertsPage.resolvedToast")); reload(); refresh(); }
    catch (e) { toast(e.message, true); }
  };
  return (
    <>
      <PageHead crumb={t("alertsPage.breadcrumb")} title={t("alertsPage.title")} desc={t("alertsPage.description")} />
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "active", label: t("alertsPage.active") }, { key: "acknowledged", label: t("alertsPage.acknowledged") }, { key: "resolved", label: t("alertsPage.resolved") }, { key: "all", label: t("alertsPage.all") },
      ]} />
      <div className="card">
        <Table rows={data || []} onRow={(a) => (a.check_id ? openCheck(a.check_id) : a.asset_id && openAsset(a.asset_id))}
          empty={<Empty icon={BellOff} title={t("alertsPage.noAlerts")}>{tab === "active" ? t("alertsPage.systemsHealthy") : ""}</Empty>} columns={[
            { key: "severity", label: t("alertsPage.severity"), sort: (a) => (a.status === "resolved" ? -1 : SEV_RANK[a.severity] || 0), render: (a) => a.status === "resolved"
              ? <div className="row" style={{ gap: 4 }}><span className="badge ok">{t("alertsPage.resolved")}</span><span className="small faint">{SEV[a.severity]?.label}</span></div>
              : <SevBadge sev={a.severity} /> },
            { key: "title", label: t("alertsPage.incident"), render: (a) => <div><div className="cell-title">{a.title}
              {a.source === "event" && <span className="badge" style={{ fontSize: 11 }}>log{a.count > 1 ? ` ×${a.count}` : ""}</span>}
              {a.source === "audit" && <span className="badge accent" style={{ fontSize: 11 }} title="The actor cannot acknowledge or resolve their own audit alert">{t("alertsPage.adminAction")}{a.actor ? ` · ${a.actor}` : ""}</span>}
              {a.source === "silence" && <span className="badge" style={{ fontSize: 11 }}>{t("alertsPage.silentLog")}</span>}
              {a.status !== "resolved" && a.sla_overdue && <span className="badge fail" style={{ fontSize: 11 }}>{t("alertsPage.slaOverdue")}</span>}
              {a.metric && <span className="badge outline" style={{ fontSize: 11 }}>threshold {({ cpu: "CPU", mem: "RAM", disk: "Disk" })[a.metric]}</span>}</div><div className="cell-sub" style={{ maxWidth: 480 }}>{a.message}</div></div> },
            { key: "asset_name", label: t("alertsPage.assetSite"), render: (a) => <div className="small">{a.asset_name || "—"}<div className="muted">{a.site_name}</div></div> },
            { key: "opened_at", label: t("alertsPage.started"), render: (a) => <div className="small">{fmtTime(a.opened_at)}<div className="muted">{timeAgo(a.opened_at)}</div></div> },
            { key: "dur", label: t("alertsPage.duration"), sortable: false, render: (a) => <span className="small">{duration(a, t)}</span> },
            { key: "sla_due", label: t("alertsPage.ackDeadline"), render: (a) => !a.sla_due ? <span className="faint">—</span>
              : a.acked_at ? <span className={`small ${a.sla_met ? "" : "muted"}`}>{a.sla_met ? t("alertsPage.met") : t("alertsPage.late")}</span>
              : <span className="small" style={{ color: a.sla_overdue ? "var(--fail)" : undefined }}>{fmtTime(a.sla_due)}</span> },
            { key: "acked_by", label: t("alertsPage.assignee"), render: (a) => a.acked_by ? <span className="badge info">{a.acked_by}</span> : <span className="faint">—</span> },
            { key: "act", label: "", sortable: false, render: (a) => a.status !== "resolved" && (
              <div className="row" onClick={(e) => e.stopPropagation()}>
                {a.status === "open" && <button className="btn sm" onClick={() => act(a, "ack")}><Check size={14} />{t("alertsPage.confirm")}</button>}
                <button className="btn sm" onClick={() => act(a, "resolve")}><CheckCheck size={14} />{t("alertsPage.close")}</button>
              </div>) },
          ]} />
        <CapNote shown={(data || []).length} limit={200} what="alerts" hint="Older ones are not listed here." />
      </div>
    </>
  );
}
