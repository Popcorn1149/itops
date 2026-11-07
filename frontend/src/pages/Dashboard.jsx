import React from "react";
import { ShieldCheck, Archive, Bell, Unlink, RefreshCw, Activity, Boxes, AlertTriangle, Gauge } from "lucide-react";
import { useApp, go } from "../App";
import { useApi, PageHead, Stat, Dot, TypeIcon, typeMeta, timeAgo, StatusBadge, Empty, CHECK_TYPES, UsageBar, SiteHealth, InternetLine, SevBadge } from "../ui";

export function SourcesStrip({ data }) {
  const { openCheck, nav } = useApp();
  const sources = data.sources || [];
  const ok = sources.filter((s) => s.status === "ok").length;
  const groups = [...data.sites.map((s) => ({ id: s.id, name: s.name })), { id: null, name: "Khác" }]
    .map((g) => ({ ...g, items: sources.filter((s) => (s.site_id ?? null) === g.id) }))
    .filter((g) => g.items.length);
  return (
    <div className="card sources" style={{ marginBottom: 18 }}>
      <div className="sources-head">
        <RefreshCw size={17} className="muted" />
        <span className="muted">Nguồn giám sát</span>
        <b>{ok}/{sources.length}</b>
        <span className={ok === sources.length ? "small" : "small"} style={{ color: ok === sources.length ? "var(--ok)" : "var(--warn)" }}>
          {ok === sources.length ? "tất cả hoạt động" : `${sources.length - ok} nguồn có vấn đề`}
        </span>
        <button className="btn ghost sm" style={{ marginLeft: "auto", color: "var(--accent-ink)" }} onClick={() => nav("checks")}>Quản lý</button>
      </div>
      {groups.length === 0 && <div className="muted small">Chưa có nguồn nào. Vào <b>Giám sát</b> để thêm pfSense, ESXi, switch...</div>}
      {groups.map((g) => (
        <div className="src-row" key={g.id ?? "x"}>
          <div className="muted">{g.name}</div>
          <div className="chips">
            {g.items.map((s) => (
              <span key={s.id} className="chip" onClick={() => openCheck(s.id)} title={CHECK_TYPES[s.type]}>
                <Dot status={s.status} pulse />{s.name} <span className="faint">{s.type}</span>
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ResourcesCard({ r }) {
  const { nav, openAsset, openCheck } = useApp();
  if (!r) return null;
  const n = (k) => r.summary[k].attention + r.summary[k].trouble + r.summary[k].critical;
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="card-head"><Gauge size={17} /><h3>Tài nguyên CPU / RAM / Disk</h3>
        <span className="small muted" style={{ marginLeft: 8 }}>{r.total} thiết bị{r.problems ? ` · ${r.problems} vượt threshold` : " · tất cả trong threshold"}</span>
        <button className="btn sm" style={{ marginLeft: "auto" }} onClick={() => nav("resources")}>Xem tất cả</button></div>
      {r.total === 0 ? <div className="card-pad small muted">Chưa có số liệu. Thêm check SNMP / SSH / ESXi / pfSense để theo dõi CPU, RAM, ổ đĩa.</div> : <>
        <div className="card-pad row wrap" style={{ gap: 18, paddingBottom: 8 }}>
          {[["cpu", "CPU cao"], ["mem", "RAM cao"], ["disk", "Disk gần đầy"]].map(([k, l]) => (
            <div key={k} className="row" style={{ gap: 8 }}><Dot status={r.summary[k].critical ? "critical" : r.summary[k].trouble ? "trouble" : r.summary[k].attention ? "attention" : "ok"} /><b style={{ fontSize: 20 }}>{n(k)}</b><span className="muted">{l}</span></div>
          ))}
          {r.uncovered > 0 && <span className="small faint" style={{ marginLeft: "auto", alignSelf: "center" }}>{r.uncovered} thiết bị chưa có số liệu</span>}
        </div>
        <div className="res-top small faint" style={{ cursor: "default", paddingTop: 4, paddingBottom: 4 }}><span>Cao nhất</span><span>CPU</span><span>RAM</span><span>Disk</span></div>
        {r.top.map((x, i) => (
          <div key={i} className="res-top" onClick={() => (x.check_id ? openCheck(x.check_id) : x.asset_id && openAsset(x.asset_id))}>
            <div className="row" style={{ gap: 8, minWidth: 0 }}><Dot status={x.level === "ok" ? "ok" : x.level} /><TypeIcon type={x.type} size={14} />
              <span style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{x.name}</span></div>
            <UsageBar pct={x.cpu} level={x.levels.cpu} />
            <UsageBar pct={x.mem} level={x.levels.mem} />
            <UsageBar pct={x.disk} level={x.levels.disk} />
          </div>
        ))}
      </>}
    </div>
  );
}

export default function Dashboard() {
  const { nav, openCheck, tick } = useApp();
  const { data } = useApi("/dashboard", { interval: 20000, deps: [tick] });
  const sites = useApi("/sites", { interval: 60000, deps: [tick] });
  if (!data) return null;
  return (
    <>
      <PageHead title="Bảng điều khiển" desc="Tổng quan sức khoẻ hạ tầng: hệ thống trọng yếu, nguồn giám sát, cảnh báo đang mở." />
      <div className="stats">
        <Stat icon={ShieldCheck} label="Hệ thống trọng yếu" value={data.critical_total} sub={`${data.critical_high} mức High · ${data.critical_total - data.critical_high} mức khác`} tone="bad" onClick={() => nav("critical")} />
        <Stat icon={Archive} label="Chưa backup" value={data.critical_no_backup} sub="hệ thống chưa đánh dấu có backup" tone={data.critical_no_backup ? "bad" : "good"} onClick={() => nav("critical", null, { tab: "nobackup" })} />
        <Stat icon={Bell} label="Cảnh báo đang mở" value={data.alerts_open} sub={`${data.alerts_critical} DOWN/Critical · ${data.alerts_24h} trong 24h`} tone={data.alerts_open ? "bad" : "good"} onClick={() => nav("alerts")} />
        <Stat icon={Unlink} label="Chưa ghép máy chủ" value={data.critical_unmapped} sub="chưa biết chạy trên máy nào" tone={data.critical_unmapped ? "bad" : "good"} onClick={() => nav("critical", null, { tab: "unmapped" })} />
      </div>
      <SourcesStrip data={data} />

      <div className="grid2">
        <div className="card">
          <div className="card-head"><Bell size={17} /><h3>Cảnh báo đang mở</h3><button className="btn sm" style={{ marginLeft: "auto" }} onClick={() => nav("alerts")}>Xem tất cả</button></div>
          {data.alerts.length === 0 ? <Empty icon={ShieldCheck} title="Không có cảnh báo nào">Mọi thứ đang ổn 🎉</Empty> : data.alerts.map((a) => (
            <div key={a.id} className="risk-item" onClick={() => a.check_id && openCheck(a.check_id)}>
              <div className={`sev ${({ warning: "trouble" })[a.severity] || a.severity}`} />
              <div className="grow">
                <div style={{ fontWeight: 600 }} className="row wrap"><SevBadge sev={a.severity} />{a.title}</div>
                <div className="small muted">{a.message}</div>
              </div>
              <div className="small faint" style={{ whiteSpace: "nowrap" }}>{timeAgo(a.opened_at)}</div>
            </div>
          ))}
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-head"><Activity size={17} /><h3>Giám sát</h3><span className="muted small" style={{ marginLeft: "auto" }}>{data.checks_total} check</span></div>
            <div className="card-pad row wrap" style={{ gap: 18 }}>
              {[["ok", "Bình thường"], ["warn", "Attention/Trouble"], ["fail", "Critical/DOWN"], ["unknown", "Chưa chạy"]].map(([k, l]) => (
                <div key={k} className="row" style={{ gap: 8 }}><Dot status={k} /><b style={{ fontSize: 20 }}>{data.checks_status[k]}</b><span className="muted">{l}</span></div>
              ))}
            </div>
            {data.failing_checks.slice(0, 6).map((c) => (
              <div key={c.id} className="risk-item" onClick={() => openCheck(c.id)}>
                <div className={`sev ${c.severity || (c.status === "fail" ? "high" : "medium")}`} />
                <div className="grow"><div style={{ fontWeight: 600 }}>{c.name}</div><div className="small muted">{c.last_message}</div></div>
                {c.severity ? <SevBadge sev={c.severity} /> : <StatusBadge status={c.status} />}
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-head"><Boxes size={17} /><h3>Tài sản</h3><span className="muted small" style={{ marginLeft: "auto" }}>{data.assets_total} mục · {data.vms_on}/{data.vms} VM đang chạy</span></div>
            <div className="card-pad chips">
              {Object.entries(data.by_type).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
                <span key={t} className="chip" onClick={() => go(`assets?type=${t}`)}><TypeIcon type={t} size={14} />{typeMeta(t).label} <b>{n}</b></span>
              ))}
              {data.assets_down > 0 && <span className="chip red" onClick={() => nav("map")}><AlertTriangle size={14} />{data.assets_down} thiết bị down</span>}
            </div>
          </div>
        </div>
      </div>

      <ResourcesCard r={data.resources} />

      {sites.data && sites.data.length > 0 && (
        <div className="grid3" style={{ marginTop: 16 }}>
          {sites.data.map((s) => (
            <div className="card card-pad" key={s.id} style={{ cursor: "pointer" }} onClick={() => nav("sites")}>
              <div className="row"><b>{s.name}</b><span className="badge outline" style={{ marginLeft: "auto" }}>{s.kind}</span></div>
              {s.internet?.length > 0 && <div className="small" style={{ marginTop: 6 }}><InternetLine items={s.internet} /></div>}
              <div className="small muted" style={{ margin: "6px 0 10px" }}>{s.stats.hosts} host · {s.stats.vms_on}/{s.stats.vms} VM · {s.stats.devices} thiết bị · {s.stats.checks} check</div>
              <div className="row small">
                <SiteHealth s={s} />
                <span className="faint" style={{ marginLeft: "auto" }}>Cập nhật {timeAgo(s.last_sync)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
