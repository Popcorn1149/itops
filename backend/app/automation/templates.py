"""Thư viện template – lấy từ tài liệu "IT Ops Workspace – Bộ template tự động hoá".

Chỉ gồm template chạy được với dữ liệu hiện có của hệ thống (đều có test trong tests/test_automation.py).
Template cần tích hợp chưa có (Veeam/Synology, Redfish, kho cấu hình, Telegram callback, lịch sử Mbps...)
được liệt kê ở UNSUPPORTED để giao diện hiện rõ lý do.

Mỗi template: meta (tên, nhóm, mô tả, KPI) + spec mặc định + một trong các hàm:
  run(ctx) -> RunResult            chạy theo lịch / chu kỳ / bấm tay
  hook(ctx, item) -> dict | None   xử lý thông báo cảnh báo trước khi gửi (suppress / extra / note)
  tick=True                        hàm run được gọi mỗi phút (phần định kỳ của template hook)
"""
import statistics
from datetime import timedelta

from sqlalchemy import func

from .. import models
from ..models import now
from . import blocks as B
from .engine import Msg, RunResult, cron_match, expand_sevs, in_scope, to_local, to_utc_naive

DEFAULT_TARGETS = [{"type": "default"}]


def _spec(trigger, params=None, scope=None, level="L0", actions=None, **extra):
    return {"trigger": trigger, "scope": scope or {"sites": "all"}, "params": params or {}, "actions": actions or DEFAULT_TARGETS,
            "level": level, **extra}


def _skip(summary):
    return RunResult("skipped", summary)


def _dow_vi(t):
    return ["Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy", "Chủ nhật"][t.weekday()]


# ================================================================ RPT – Báo cáo
def rpt01(ctx):
    db, sc = ctx.db, ctx.scope
    t = ctx.now
    _, ov, _ = B.overview(db, sc)
    _, wan, _ = B.wan_lines(db, sc)
    _, al, n_al = B.open_alerts(db, sc, limit=int(ctx.p("max_alerts", 8)))
    _, inc, _ = B.incidents(db, sc, hours=24)
    _, ssl, n_ssl = B.ssl_expiring(db, sc, days=int(ctx.p("ssl_days", 14)))
    _, res, n_res = B.resources_top(db, sc, n=5)
    text = "\n".join([*ov, "WAN: " + " | ".join(wan), "Đang mở:" if n_al else "Đang mở: không có", *(al if n_al else []),
                      *inc, *(["Sắp hết hạn:", *ssl] if n_ssl else []), *(["Tài nguyên:", *res] if n_res else [])])
    subj = f"Bản tin IT {t.strftime('%H:%M')} – {_dow_vi(t)} {t.strftime('%d/%m')}"
    return RunResult("ok", f"{n_al} cảnh báo mở · {n_ssl} SSL sắp hết hạn", [Msg(subj, text, "info")])


def _period_report(ctx, days, title, include):
    db, sc = ctx.db, ctx.scope
    end = ctx.now.replace(hour=0, minute=0)
    if ctx.p("include_today"):
        end = ctx.now
    sections, decisions = [], []
    _, up, _ = B.uptime_by_site(db, sc, days=days, end=end)
    _, inc, n_inc = B.mtta_mttr(db, sc, days=days)
    _, noisy, _ = B.top_noisy(db, sc, days=days, n=int(ctx.p("top_n", 5)))
    _, logs, _ = B.log_top(db, sc, hours=days * 24, n=5)
    _, al, n_al = B.open_alerts(db, sc, limit=5)
    _, ssl, n_ssl = B.ssl_expiring(db, sc, days=30)
    _, res, n_res = B.resources_top(db, sc, n=5)
    target = float(ctx.p("uptime_target", 99.5))
    below = [line for line in up if "%" in line and float(line.split(": ")[1].split("%")[0]) < target]
    summary = [f"Uptime: {'đạt' if not below else 'KHÔNG đạt'} mục tiêu {target:g}%" + (f" ({len(below)} site dưới mục tiêu)" if below else ""),
               inc[0], f"Đang mở: {n_al} cảnh báo"]
    sections.append("Tóm tắt:\n" + "\n".join(summary))
    sections.append("Số liệu chính:\n" + "\n".join(up + inc[1:]))
    if "noisy" in include:
        sections.append("Sự cố đáng chú ý:\n" + "\n".join(noisy + ["Log nổi bật:"] + logs))
    if n_al:
        decisions.append(f"{n_al} cảnh báo còn mở – xem danh sách và giao người xử lý")
    if n_res:
        decisions += [f"Cân nhắc nâng cấp/dọn dẹp: {line[2:]}" for line in res[:3]]
    if n_ssl:
        decisions += [f"Gia hạn {line[2:]}" for line in ssl[:3]]
    if below:
        decisions.append("Uptime dưới mục tiêu ở: " + ", ".join(b[2:].split(":")[0] for b in below))
    sections.append("Việc cần quyết định:\n" + ("\n".join(f"- {d}" for d in decisions[:6]) if decisions else "- Không có"))
    start = (end - timedelta(days=days)).strftime("%d/%m")
    subj = f"{title} {start}–{(end - timedelta(minutes=1)).strftime('%d/%m/%Y')}"
    return RunResult("ok", f"{n_inc} sự cố · {len(decisions)} việc cần quyết định", [Msg(subj, "\n\n".join(sections), "info")])


def rpt02(ctx):
    return _period_report(ctx, 7, "Báo cáo tuần vận hành", include={"noisy"})


def rpt03(ctx):
    """SLA tháng trước so với mục tiêu; so với tháng trước nữa."""
    from .engine import uptime_between
    db, sc = ctx.db, ctx.scope
    first = ctx.now.replace(day=1, hour=0, minute=0)
    prev_end = first
    prev_start = (first - timedelta(days=1)).replace(day=1)
    pp_start = (prev_start - timedelta(days=1)).replace(day=1)
    target = float(ctx.p("uptime_target", 99.5))
    assets = {a.id: a for a in db.query(models.Asset)}
    sites = {s.id: s.name for s in db.query(models.Site)}
    checks = [c for c in db.query(models.Check) if in_scope(sc, site_id=c.site_id or (assets[c.asset_id].site_id if c.asset_id in assets else None),
                                                           asset=assets.get(c.asset_id))]
    ids = [c.id for c in checks]
    cur, old = uptime_between(db, ids, prev_start, prev_end), uptime_between(db, ids, pp_start, prev_start)

    def agg(data, group):
        out = {}
        for c in checks:
            t = data.get(c.id)
            if not t or not t[0]:
                continue
            k = group(c)
            if k is None:
                continue
            o = out.setdefault(k, [0, 0, 0.0])
            o[0] += t[0]; o[1] += t[1]; o[2] += t[2]
        return out
    by_site = lambda c: c.site_id or (assets[c.asset_id].site_id if c.asset_id in assets else None)  # noqa: E731
    crit = {cid: cs for cs in db.query(models.CriticalSystem) for cid in (cs.check_ids or [])}
    s_cur, s_old = agg(cur, by_site), agg(old, by_site)
    c_cur = agg(cur, lambda c: crit[c.id].name if c.id in crit else None)
    lines, worst = [], []
    for sid, (tot, dn, mins) in sorted(s_cur.items(), key=lambda x: x[0] or 0):
        pct = (tot - dn) / tot * 100
        o = s_old.get(sid)
        cmp = f" (tháng trước {(o[0] - o[1]) / o[0] * 100:.2f}%)" if o and o[0] else ""
        mark = "✓" if pct >= target else "✗"
        lines.append(f"{mark} {sites.get(sid, 'Chưa gán site')}: {pct:.3f}% · DOWN {B.fmt_dur(mins)}{cmp}")
        if pct < target:
            worst.append((pct, sites.get(sid, "?")))
    crit_lines = []
    for name, (tot, dn, mins) in sorted(c_cur.items()):
        pct = (tot - dn) / tot * 100
        crit_lines.append(f"{'✓' if pct >= target else '✗'} {name}: {pct:.3f}% · DOWN {B.fmt_dur(mins)}")
        if pct < target:
            worst.append((pct, name))
    days_cov = len({r.day for r in db.query(models.DailyUptime.day).filter(models.DailyUptime.day >= prev_start.strftime("%Y-%m-%d"),
                                                                         models.DailyUptime.day < prev_end.strftime("%Y-%m-%d"))})
    month_days = (prev_end - prev_start).days
    recs = [f"Tìm nguyên nhân gốc và phương án dự phòng cho {n} ({p:.2f}%)" for p, n in sorted(worst)[:3]]
    if not recs:
        recs = ["Duy trì: mọi site và hệ thống trọng yếu đạt mục tiêu"]
    if days_cov < month_days:
        recs.append(f"Lưu ý: chỉ có số liệu {days_cov}/{month_days} ngày (hệ thống chưa chạy liên tục) – kết quả chưa đại diện cả tháng")
    text = "\n\n".join([f"Mục tiêu uptime: {target:g}%", "Theo site:\n" + ("\n".join(lines) or "Chưa có dữ liệu"),
                        *(["Hệ thống trọng yếu:\n" + "\n".join(crit_lines)] if crit_lines else []),
                        "Kiến nghị:\n" + "\n".join(f"- {r}" for r in recs[:4])])
    subj = f"Báo cáo SLA tháng {prev_start.strftime('%m/%Y')}"
    return RunResult("ok", f"{len(worst)} mục dưới mục tiêu · {days_cov}/{month_days} ngày có số liệu", [Msg(subj, text, "info")])


def rpt04(ctx):
    _, lines, n = B.backup_risks(ctx.db, ctx.scope)
    if not n and ctx.p("skip_if_empty", True):
        return _skip("Không có rủi ro / hệ thống thiếu backup")
    return RunResult("ok", f"{n} mục rủi ro", [Msg(f"Backup & rủi ro – {ctx.now.strftime('%d/%m/%Y')}", "\n".join(lines), "info")])


def rpt06(ctx):
    _, lines, n = B.asset_changes(ctx.db, ctx.scope, days=int(ctx.p("days", 30)), silent_days=int(ctx.p("silent_days", 7)))
    return RunResult("ok", f"{n} mục cần xem", [Msg(f"Biến động tài sản – {ctx.now.strftime('%m/%Y')}", "\n".join(lines), "info")])


# ================================================================ INC – Cảnh báo / sự cố (hook)
def _alert_of(ctx, item):
    aid = (item.get("ctx") or {}).get("alert_id")
    return ctx.db.get(models.Alert, aid) if aid else None


def _ancestors(db, asset_id, limit=10):
    out, seen = [], set()
    a = db.get(models.Asset, asset_id) if asset_id else None
    while a and a.parent_id and a.parent_id not in seen and len(out) < limit:
        seen.add(a.parent_id)
        a = db.get(models.Asset, a.parent_id)
        if a:
            out.append(a)
    return out


def _descendants(db, asset_id):
    kids = {}
    for a in db.query(models.Asset.id, models.Asset.parent_id):
        kids.setdefault(a.parent_id, []).append(a.id)
    out, stack = [], list(kids.get(asset_id, []))
    while stack:
        x = stack.pop()
        if x in out or x == asset_id:
            continue
        out.append(x)
        stack += kids.get(x, [])
    return out


def inc01_hook(ctx, item):
    """Gom theo nguyên nhân gốc: tài sản cha DOWN → chặn cảnh báo của tài sản con; tin của cha kèm số thiết bị bị ảnh hưởng."""
    c = item.get("ctx") or {}
    if c.get("kind") not in ("open", "escalate"):
        return None
    al = _alert_of(ctx, item)
    if not al or not al.asset_id:
        return None
    db = ctx.db
    for anc in _ancestors(db, al.asset_id):
        parent_down = db.query(models.Alert).filter(models.Alert.asset_id == anc.id, models.Alert.status != "resolved",
                                                    models.Alert.severity == "down").first()
        if parent_down:
            return {"suppress": True, "note": f"Chặn: {al.title} – do {anc.name} (cha) đang DOWN"}
    if al.severity == "down":
        kids = _descendants(db, al.asset_id)
        if kids:
            names = [a.name for a in db.query(models.Asset).filter(models.Asset.id.in_(kids)).limit(8)]
            item["text"] += f"\n\n⚠ {len(kids)} thiết bị phía sau bị ảnh hưởng: {', '.join(names)}{'…' if len(kids) > 8 else ''}" \
                            "\nCảnh báo riêng của các thiết bị này sẽ được gom vào sự cố này."
            return {"note": f"{al.title}: gom {len(kids)} thiết bị phía sau"}
    return None


def inc02_hook(ctx, item):
    """Chống chập chờn: ≥ N lần đổi status trong M phút → gộp thành 1 tin 'chập chờn', ngừng gửi lẻ."""
    c = item.get("ctx") or {}
    cid = c.get("check_id")
    if not cid or c.get("kind") not in ("open", "resolve"):
        return None
    mins, need = int(ctx.p("window_min", 10)), int(ctx.p("changes", 3))
    since = now() - timedelta(minutes=mins)
    rows = ctx.db.query(models.CheckResult.down, models.CheckResult.status).filter(
        models.CheckResult.check_id == cid, models.CheckResult.ts >= since).order_by(models.CheckResult.id).all()
    seq = [bool(d) if d is not None else st == "fail" for d, st in rows]          # chỉ tính lên/xuống (DOWN ↔ không DOWN)
    changes = sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
    if changes < need:
        return None
    flap = ctx.state.setdefault("flapping", {})
    last = flap.get(str(cid))
    chk = ctx.db.get(models.Check, cid)
    name = chk.name if chk else f"check {cid}"
    if last and (now() - _parse(last)) < timedelta(minutes=int(ctx.p("quiet_min", 60))):
        return {"suppress": True, "note": f"Chặn tin lẻ: {name} đang chập chờn ({changes} lần/{mins} phút)"}
    flap[str(cid)] = now().isoformat()
    extra = {"subject": f"{name} chập chờn", "severity": "warning", "ctx": {"kind": "flap", "check_id": cid},
             "text": f"Đổi status {changes} lần trong {mins} phút. Tạm ngừng gửi tin lẻ trong {ctx.p('quiet_min', 60)} phút.\n"
                     f"Gần nhất: {item['subject']}"}
    return {"suppress": True, "extra": [extra], "note": f"{name}: chập chờn ({changes} lần/{mins} phút) – gộp thành 1 tin"}


def _parse(s):
    from datetime import datetime
    return datetime.fromisoformat(s)


RUNBOOKS = {
    "wan": ["Xem đèn modem/ONT của nhà mạng", "Ping gateway nhà mạng từ firewall (Diagnostics › Ping)",
            "Kiểm tra Gateway Monitor trên pfSense", "Gọi tổng đài nhà mạng, đọc mã hợp đồng/khách hàng"],
    "ping": ["Ping lại từ máy khác cùng mạng để loại trừ lỗi đường đi", "Kiểm tra cổng switch nối thiết bị (đèn, status port)",
             "Kiểm tra nguồn điện / UPS của thiết bị", "Nếu là VM: xem status trên ESXi"],
    "snmp": ["Kiểm tra thiết bị còn ping được không", "Kiểm tra dịch vụ SNMP và community/ACL trên thiết bị",
             "Kiểm tra firewall có chặn UDP 161 không"],
    "http": ["Mở thử URL trên trình duyệt", "Kiểm tra dịch vụ web/app pool trên máy chủ", "Kiểm tra DNS và chứng chỉ SSL"],
    "ssh": ["Kiểm tra máy chủ còn ping được không", "Đăng nhập console/iLO nếu SSH không vào được", "Xem dung lượng ổ đĩa và RAM"],
    "cpu": ["Xem tiến trình dùng CPU cao (top / Task Manager)", "So với lịch backup/quét virus đang chạy", "Cân nhắc thêm vCPU nếu kéo dài"],
    "mem": ["Xem tiến trình dùng RAM nhiều", "Kiểm tra rò rỉ bộ nhớ (dịch vụ chạy lâu ngày)", "Cân nhắc thêm RAM"],
    "disk": ["Xem thư mục chiếm nhiều dung lượng", "Dọn log/bản backup cũ", "Mở rộng ổ hoặc chuyển dữ liệu"],
    "internet": ["Kiểm tra các line WAN khác còn chạy không", "Xem Gateway Monitor trên firewall", "Gọi nhà mạng nếu mọi line đều mất"],
}


def inc05_hook(ctx, item):
    """Runbook đính kèm: gắn 3–5 bước kiểm tra vào tin cảnh báo theo loại check / chỉ số / hệ thống trọng yếu."""
    c = item.get("ctx") or {}
    if c.get("kind") not in ("open", "escalate"):
        return None
    al = _alert_of(ctx, item)
    if not al:
        return None
    db = ctx.db
    chk = db.get(models.Check, al.check_id) if al.check_id else None
    custom = ctx.p("rules") or []
    steps, src = None, ""
    for r in custom:      # rule riêng: {contains: "VNPT", steps: [...]}
        if r.get("contains") and r["contains"].lower() in (al.title + " " + (chk.name if chk else "")).lower() and r.get("steps"):
            steps, src = r["steps"], f"rule '{r['contains']}'"
            break
    if not steps and chk:
        crit = next((cs for cs in db.query(models.CriticalSystem) if chk.id in (cs.check_ids or []) and (cs.runbook or "").strip()), None)
        if crit:
            steps, src = [s.strip("-• ").strip() for s in crit.runbook.splitlines() if s.strip()], f"hệ thống {crit.name}"
    if not steps:
        from ..topology import wan_role
        key = al.metric or ("wan" if chk and (wan_role(chk) or chk.type == "internet") else chk.type if chk else None)
        if key == "internet":
            key = "wan"
        steps, src = RUNBOOKS.get(key or ""), key or ""
    if not steps:
        return None
    item["text"] += "\n\nCách xử lý:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps[:5], 1))
    return {"note": f"Gắn runbook ({src}) vào: {al.title}"}


def inc03(ctx):
    """Leo thang: cảnh báo chưa ai Nhận sau X phút → báo bước tiếp theo."""
    db = ctx.db
    steps = ctx.p("steps") or []
    done = ctx.state.setdefault("done", {})
    msgs, notes = [], []
    open_ids = set()
    for al in db.query(models.Alert).filter(models.Alert.status == "open", models.Alert.suppressed == False):  # noqa: E712
        open_ids.add(str(al.id))
        age = (now() - al.opened_at).total_seconds() / 60
        for i, st in enumerate(steps):
            if i in done.get(str(al.id), []):
                continue
            if al.severity not in expand_sevs(st.get("severities") or ["High"]) or age < float(st.get("after_min", 15)):
                continue
            label = st.get("label") or f"bước {i + 1}"
            msgs.append(Msg(f"[Leo thang – {label}] {al.title}",
                            f"Chưa ai nhận sau {int(age)} phút (mở lúc {B.fmt_local(al.opened_at)}).\n{al.message}\n\n"
                            "Bấm Nhận trên trang Cảnh báo để dừng leo thang.", "critical" if al.severity in B.HIGH else "warning",
                            st.get("targets") or None))
            done.setdefault(str(al.id), []).append(i)
            al.escalation_level = max(al.escalation_level or 0, i + 1)
            notes.append(f"{al.title} → {label}")
    for k in list(done):             # dọn bộ nhớ của cảnh báo đã nhận/đóng
        if k not in open_ids:
            done.pop(k)
    if not msgs:
        return _skip("Không có cảnh báo cần leo thang")
    return RunResult("ok", "; ".join(notes)[:300], msgs)


def inc08(ctx):
    """Thông báo người dùng: hệ thống trọng yếu DOWN > X phút → gửi tin gián đoạn; xanh lại → gửi tin khôi phục."""
    db = ctx.db
    mins = float(ctx.p("down_minutes", 10))
    levels = ctx.p("levels") or ["High"]
    sent = ctx.state.setdefault("down", {})
    msgs = []
    for cs in db.query(models.CriticalSystem):
        if cs.level not in levels:
            continue
        ids = list(cs.check_ids or [])
        if cs.asset_id:
            ids += [c.id for c in db.query(models.Check.id).filter(models.Check.asset_id == cs.asset_id)]
        if not ids:
            continue
        al = db.query(models.Alert).filter(models.Alert.check_id.in_(ids), models.Alert.status != "resolved",
                                           models.Alert.severity == "down", models.Alert.metric.is_(None)).order_by(models.Alert.opened_at).first()
        key = str(cs.id)
        if al and (now() - al.opened_at).total_seconds() / 60 >= mins and key not in sent:
            sent[key] = al.opened_at.isoformat()
            msgs.append(Msg(f"{cs.name} đang gián đoạn", ctx.p("msg_down", "{system} đang gián đoạn. IT đã nhận thông tin và đang xử lý. "
                                                            "Sẽ báo lại khi dịch vụ hoạt động trở lại.").format(system=cs.name), "warning"))
        elif not al and key in sent:
            dur = (now() - _parse(sent.pop(key))).total_seconds() / 60
            msgs.append(Msg(f"{cs.name} đã hoạt động trở lại", ctx.p("msg_up", "{system} đã hoạt động bình thường trở lại "
                                                                 "(gián đoạn khoảng {minutes} phút). Cảm ơn mọi người đã chờ.")
                            .format(system=cs.name, minutes=int(dur)), "resolved"))
    if not msgs:
        return _skip("Không có hệ thống trọng yếu đổi status")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


# ================================================================ PRE – Phòng ngừa / dự báo
def _linreg(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sxx
    return slope, my - slope * mx


def pre01(ctx):
    """Dự báo đầy ổ: hồi quy tuyến tính % disk theo ngày; báo nếu sẽ chạm threshold trong N ngày."""
    db = ctx.db
    target, horizon = float(ctx.p("target_pct", 90)), float(ctx.p("horizon_days", 14))
    window, min_h = int(ctx.p("window_days", 14)), float(ctx.p("min_hours", 24))
    since = now() - timedelta(days=window)
    assets = {a.id: a for a in db.query(models.Asset)}
    found = []
    for c in db.query(models.Check).filter(models.Check.enabled == True):  # noqa: E712
        rs = (c.last_data or {}).get("res") or {}
        if rs.get("disk") is None:
            continue
        a = assets.get(c.asset_id)
        if not in_scope(ctx.scope, site_id=c.site_id or (a.site_id if a else None), asset=a, name=c.name):
            continue
        pts = [(r.ts, r.metrics.get("disk")) for r in db.query(models.CheckResult.ts, models.CheckResult.metrics)
               .filter(models.CheckResult.check_id == c.id, models.CheckResult.ts >= since, models.CheckResult.metrics.isnot(None))
               if r.metrics and r.metrics.get("disk") is not None]
        if len(pts) < 6 or (pts[-1][0] - pts[0][0]).total_seconds() / 3600 < min_h:
            continue
        t0 = pts[0][0]
        xs = [(t - t0).total_seconds() / 86400 for t, _ in pts]
        ys = [v for _, v in pts]
        slope, _ = _linreg(xs, ys)
        cur = ys[-1]
        if cur >= target:
            found.append((0, f"- {a.name if a else c.name} ({rs.get('disk_name') or 'Disk'}): đã {cur:g}% ≥ {target:g}%"))
        elif slope > 0.01:
            days = (target - cur) / slope
            if days <= horizon:
                eta = (ctx.now + timedelta(days=days)).strftime("%d/%m")
                found.append((days, f"- {a.name if a else c.name} ({rs.get('disk_name') or 'Disk'}): {cur:g}% → chạm {target:g}% khoảng {eta} "
                                    f"(còn ~{days:.0f} ngày, tăng {slope:.2f}%/ngày)"))
    if not found:
        return _skip("Không ổ nào dự kiến đầy trong khoảng dự báo")
    found.sort()
    return RunResult("ok", f"{len(found)} ổ sắp đầy", [Msg(f"Dự báo đầy ổ: {len(found)} ổ trong {horizon:g} ngày tới",
                                                         "\n".join(x for _, x in found) + "\n\nDự báo theo xu hướng; cần ≥ 7 ngày số liệu để chính xác.",
                                                         "warning")])


def pre02(ctx):
    """SSL hết hạn: nhắc ở mốc 30 / 14 / 7 ngày, mốc cuối là Critical."""
    db = ctx.db
    marks = sorted({int(x) for x in (ctx.p("days") or [30, 14, 7])}, reverse=True)
    sent = ctx.state.setdefault("sent", {})
    msgs = []
    for c in db.query(models.Check).filter(models.Check.type == "http", models.Check.enabled == True):  # noqa: E712
        d = (c.last_data or {}).get("cert_days")
        if d is None:
            continue
        key = str(c.id)
        if d > marks[0]:
            sent.pop(key, None)            # đã gia hạn → reset
            continue
        hit = min(m for m in marks if d <= m)
        if sent.get(key) is not None and sent[key] <= hit:
            continue
        sent[key] = hit
        host = c.target.split("://")[-1].split("/")[0]
        last = hit == marks[-1]
        msgs.append(Msg(f"SSL {host} {'đã hết hạn' if d < 0 else f'còn {d} ngày'}",
                        f"Chứng chỉ của {host} ({c.name}) {'đã hết hạn' if d < 0 else f'hết hạn sau {d} ngày'}. Mốc nhắc: {hit} ngày."
                        + ("\nĐây là lần nhắc cuối – cần gia hạn ngay." if last else ""), "critical" if last else "warning"))
    if not msgs:
        return _skip("Không có chứng chỉ chạm mốc nhắc mới")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


def pre04(ctx):
    """Độ trễ tăng dần: trung bình 15 phút gần nhất vượt đường nền 7 ngày + k·độ lệch chuẩn."""
    db = ctx.db
    k, recent_min = float(ctx.p("sigma", 3)), int(ctx.p("recent_min", 15))
    min_delta, base_h = float(ctx.p("min_delta_ms", 5)), float(ctx.p("min_baseline_hours", 24))
    cool = ctx.state.setdefault("cool", {})
    cut = now() - timedelta(minutes=recent_min)
    since = now() - timedelta(days=7)
    found = []
    for c in db.query(models.Check).filter(models.Check.enabled == True, models.Check.type.in_(("ping", "internet", "tcp", "http"))):  # noqa: E712
        if not in_scope(ctx.scope, site_id=c.site_id, name=c.name):
            continue
        rows = db.query(models.CheckResult.ts, models.CheckResult.latency).filter(
            models.CheckResult.check_id == c.id, models.CheckResult.ts >= since, models.CheckResult.latency.isnot(None),
            models.CheckResult.status != "fail").order_by(models.CheckResult.ts).all()
        base = [v for t, v in rows if t < cut]
        rec = [v for t, v in rows if t >= cut]
        if len(base) < 30 or len(rec) < 3 or (cut - rows[0][0]).total_seconds() / 3600 < base_h:
            continue
        mu, sd = statistics.fmean(base), statistics.pstdev(base)
        r = statistics.fmean(rec)
        if r > mu + k * sd and r - mu >= min_delta:
            key = str(c.id)
            if key in cool and now() - _parse(cool[key]) < timedelta(hours=float(ctx.p("cooldown_hours", 6))):
                continue
            cool[key] = now().isoformat()
            found.append(f"- {c.name}: {r:.1f} ms trong {recent_min} phút (bình thường {mu:.1f} ± {sd:.1f} ms)")
    if not found:
        return _skip("Độ trễ trong mức bình thường")
    return RunResult("ok", f"{len(found)} check độ trễ tăng bất thường",
                     [Msg("Cảnh báo sớm: độ trễ tăng bất thường", "\n".join(found) + "\n\nChưa down, nhưng nên kiểm tra đường truyền.", "info")])


def pre08(ctx):
    """Log bất thường: số log lỗi/cảnh báo 1 giờ qua gấp X lần trung bình cùng khung giờ 7 ngày trước."""
    db = ctx.db
    mult, min_count = float(ctx.p("multiplier", 3)), int(ctx.p("min_count", 30))
    t1 = now()
    t0 = t1 - timedelta(hours=1)
    cur = dict(db.query(models.Event.source_ip, func.count()).filter(models.Event.ts >= t0, models.Event.severity <= 4,
                                                                    models.Event.source_ip != "127.0.0.1").group_by(models.Event.source_ip).all())
    cool = ctx.state.setdefault("cool", {})
    found = []
    for ip, n in cur.items():
        if n < min_count:
            continue
        hist = []
        for d in range(1, 8):
            hist.append(db.query(func.count(models.Event.id)).filter(models.Event.source_ip == ip, models.Event.severity <= 4,
                                                                      models.Event.ts >= t0 - timedelta(days=d), models.Event.ts < t1 - timedelta(days=d)).scalar())
        base = sum(hist) / 7
        if n >= mult * max(base, 1):
            if ip in cool and now() - _parse(cool[ip]) < timedelta(hours=float(ctx.p("cooldown_hours", 3))):
                continue
            cool[ip] = now().isoformat()
            sample = db.query(models.Event).filter(models.Event.source_ip == ip, models.Event.ts >= t0, models.Event.severity <= 4) \
                .order_by(models.Event.id.desc()).limit(10).all()
            host = sample[0].host if sample else ""
            found.append(f"■ {host or ip} ({ip}): {n} log lỗi/cảnh báo trong 1 giờ (bình thường ~{base:.0f})\n"
                         + "\n".join(f"  {e.message[:140]}" for e in sample))
    if not found:
        return _skip("Lượng log trong mức bình thường")
    return RunResult("ok", f"{len(found)} log source tăng bất thường", [Msg("Log bất thường", "\n\n".join(found), "info")])


# ================================================================ LCM – Bảo trì / vòng đời
def _in_window(w, t):
    """Đang trong khung bảo trì? (cron = giờ bắt đầu, duration_min = độ dài)."""
    dur = int(w.get("duration_min", 60))
    for m in range(0, dur):
        if cron_match(w["cron"], t - timedelta(minutes=m)):
            return True
    return False


def _window_targets(db, w):
    assets = {a.id: a for a in db.query(models.Asset)}
    ids = set(w.get("assets") or [])
    sites = set(w.get("sites") or [])
    for a in assets.values():
        if a.site_id in sites:
            ids.add(a.id)
    for aid in list(ids):            # gồm cả thiết bị phía sau
        ids.update(_descendants(db, aid))
    return ids


def lcm01_hook(ctx, item):
    """Lịch bảo trì: trong khung giờ → không gửi cảnh báo của thiết bị trong phạm vi."""
    c = item.get("ctx") or {}
    al = _alert_of(ctx, item)
    asset_id = c.get("asset_id") or (al.asset_id if al else None)
    if not asset_id:
        return None
    for w in ctx.p("windows") or []:
        if _in_window(w, ctx.now) and asset_id in _window_targets(ctx.db, w):
            return {"suppress": True, "note": f"Bảo trì '{w.get('name', '')}': không gửi {item['subject']}"}
    return None


def lcm01(ctx):
    """Phần định kỳ: nhắc trước 1 ngày; hết giờ bảo trì → chạy lại mọi check trong phạm vi và gửi kết quả."""
    db = ctx.db
    msgs = []
    for w in ctx.p("windows") or []:
        name = w.get("name") or "Bảo trì"
        tg = _window_targets(db, w)
        if cron_match(w["cron"], ctx.now + timedelta(hours=float(ctx.p("remind_hours", 24)))):
            start = ctx.now + timedelta(hours=float(ctx.p("remind_hours", 24)))
            msgs.append(Msg(f"Nhắc lịch bảo trì: {name}", f"Bắt đầu {start.strftime('%H:%M %d/%m')}, kéo dài {w.get('duration_min', 60)} phút, "
                                                         f"{len(tg)} thiết bị. Cảnh báo của các thiết bị này sẽ tạm không gửi trong khung giờ.", "info"))
        if cron_match(w["cron"], ctx.now - timedelta(minutes=int(w.get("duration_min", 60)))):
            checks = db.query(models.Check).filter(models.Check.enabled == True, models.Check.asset_id.in_(tg or [-1])).all()  # noqa: E712
            ctx.state.setdefault("post_check", {})[name] = [c.id for c in checks]
            ok = sum(1 for c in checks if c.status == "ok")
            bad = [c.name for c in checks if c.status != "ok"]
            msgs.append(Msg(f"Sau bảo trì '{name}': {ok}/{len(checks)} xanh",
                            ("Còn lỗi: " + ", ".join(bad[:10])) if bad else "Tất cả check đã xanh. Cảnh báo đã bật lại.",
                            "warning" if bad else "resolved"))
            if not ctx.dry_run:
                _rerun_checks([c.id for c in checks])
    if not msgs:
        return _skip("Không có mốc bảo trì")
    return RunResult("ok", "; ".join(m.subject for m in msgs), msgs)


def _rerun_checks(ids):
    import asyncio
    from .. import scheduler
    for cid in ids:
        try:
            asyncio.get_running_loop().create_task(scheduler.run_check(cid))
        except RuntimeError:
            pass


SUGGEST = {"switch": "Ping + SNMP", "router": "Ping + SNMP", "firewall": "Ping + SNMP (hoặc pfSense API)", "ap": "Ping + SNMP",
           "server": "Ping + SSH", "vm": "Ping + SSH", "host": "Ping + ESXi", "nas": "Ping + SNMP", "ups": "SNMP",
           "website": "HTTP + SSL", "printer": "Ping", "camera": "Ping"}


def lcm02(ctx):
    """Onboard: tài sản chưa có check + Nguồn lạ gửi log → gợi ý bộ check và checklist."""
    db = ctx.db
    has = {c.asset_id for c in db.query(models.Check.asset_id).filter(models.Check.asset_id.isnot(None))}
    since = now() - timedelta(days=int(ctx.p("days", 7)))
    lines = []
    for a in db.query(models.Asset).filter(models.Asset.created_at >= since):
        if a.id in has or a.type in ("container",) or not in_scope(ctx.scope, site_id=a.site_id, asset=a):
            continue
        miss = [x for x, ok in (("site", a.site_id), ("người phụ trách", (a.owner or "").strip()), ("IP", (a.ip or "").strip())) if not ok]
        lines.append(f"- {a.name} ({a.type}): nên thêm {SUGGEST.get(a.type, 'Ping')}" + (f" · thiếu {', '.join(miss)}" if miss else ""))
    unk = B.unknown_sources(db, int(ctx.p("days", 7)))
    for ip, n in unk[:10]:
        lines.append(f"- Nguồn lạ {ip}: {n} log – tạo tài sản rồi thêm check")
    if not lines:
        return _skip("Không có tài sản mới cần onboard")
    return RunResult("ok", f"{len(lines)} mục cần onboard", [Msg("Onboard tài sản", "\n".join(lines) +
                                                               "\n\nChecklist: site · người phụ trách · mức trọng yếu · backup", "info")])


def lcm03(ctx):
    """Offboard: tài sản không phản hồi > N ngày → đề nghị archive (không tự xoá, không tự tắt)."""
    db = ctx.db
    days = int(ctx.p("days", 30))
    cut = now() - timedelta(days=days)
    has = {c.asset_id for c in db.query(models.Check.asset_id).filter(models.Check.enabled == True, models.Check.asset_id.isnot(None))}  # noqa: E712
    lines = []
    for a in db.query(models.Asset):
        if a.id not in has or not in_scope(ctx.scope, site_id=a.site_id, asset=a):
            continue
        silent_since = a.last_seen or a.created_at
        if a.status in ("down", "unknown") and silent_since and silent_since < cut:
            lines.append(f"- {a.name} ({a.ip or a.type}): không phản hồi từ {B.fmt_local(silent_since)}")
    if not lines:
        return _skip(f"Không có tài sản im lặng > {days} ngày")
    return RunResult("ok", f"{len(lines)} tài sản nên rà soát", [Msg(f"Đề nghị archive {len(lines)} tài sản", "\n".join(lines) +
                                                                  "\n\nXác nhận trên trang Tài sản: tắt check / chuyển status 'Tắt'. "
                                                                  "Hệ thống không tự xoá.", "info")])


def lcm06(ctx):
    """Rà soát dữ liệu định kỳ (đầu quý)."""
    db = ctx.db
    lines = []
    assets = [a for a in db.query(models.Asset) if in_scope(ctx.scope, site_id=a.site_id, asset=a) and a.type not in ("vm", "container")]
    no_owner = [a.name for a in assets if not (a.owner or "").strip()]
    no_site = [a.name for a in assets if not a.site_id]
    old_off = [c.name for c in db.query(models.Check).filter(models.Check.enabled == False)  # noqa: E712
               if not c.last_checked or c.last_checked < now() - timedelta(days=14)]
    rules = [r.name for r in db.query(models.EventRule).filter(models.EventRule.enabled == True)  # noqa: E712
             if (not r.last_hit or r.last_hit < now() - timedelta(days=90)) and (r.created_at or now() - timedelta(days=91)) < now() - timedelta(days=90)]
    users = [u.username for u in db.query(models.User) if (u.last_login or u.created_at) < now() - timedelta(days=90)]
    crit_no = [c.name for c in db.query(models.CriticalSystem) if not (c.owner or "").strip()]
    for label, xs in (("Tài sản thiếu người phụ trách", no_owner), ("Tài sản chưa gán site", no_site), ("Check tắt > 14 ngày", old_off),
                      ("Rule log 90 ngày không khớp", rules), ("Tài khoản không đăng nhập > 90 ngày", users),
                      ("Hệ thống trọng yếu thiếu người phụ trách", crit_no)):
        lines.append(f"{label}: {len(xs)}" + (" – " + ", ".join(xs[:10]) + ("…" if len(xs) > 10 else "") if xs else ""))
    total = len(no_owner) + len(no_site) + len(old_off) + len(rules) + len(users) + len(crit_no)
    return RunResult("ok", f"{total} mục cần dọn", [Msg(f"Rà soát dữ liệu quý – {ctx.now.strftime('%m/%Y')}", "\n".join(lines), "info")])


# ================================================================ xem trước cho template hook (nút Chạy thử)
def inc01_preview(ctx):
    db = ctx.db
    lines = []
    for al in db.query(models.Alert).filter(models.Alert.status != "resolved", models.Alert.severity == "down", models.Alert.asset_id.isnot(None)):
        kids = _descendants(db, al.asset_id)
        if kids:
            child = db.query(models.Alert).filter(models.Alert.asset_id.in_(kids), models.Alert.status != "resolved").count()
            lines.append(f"- {al.title}: {len(kids)} thiết bị phía sau · {child} cảnh báo con sẽ bị gom")
    tree = sum(1 for a in db.query(models.Asset.parent_id) if a.parent_id)
    head = f"Cây cha–con hiện có {tree} liên kết. Khi thiết bị cha DOWN, cảnh báo của thiết bị con không gửi riêng."
    return RunResult("ok", f"{len(lines)} sự cố gốc đang mở", [Msg("Xem trước: gom theo nguyên nhân gốc",
                                                                 head + "\n\n" + ("\n".join(lines) or "Hiện không có thiết bị cha nào DOWN."))])


def inc02_preview(ctx):
    db = ctx.db
    mins, need = int(ctx.p("window_min", 10)), int(ctx.p("changes", 3))
    since = now() - timedelta(minutes=mins)
    lines = []
    for c in db.query(models.Check).filter(models.Check.enabled == True):  # noqa: E712
        rows = db.query(models.CheckResult.down, models.CheckResult.status).filter(
            models.CheckResult.check_id == c.id, models.CheckResult.ts >= since).order_by(models.CheckResult.id).all()
        seq = [bool(d) if d is not None else st == "fail" for d, st in rows]
        n = sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
        if n >= need:
            lines.append(f"- {c.name}: {n} lần đổi status trong {mins} phút")
    return RunResult("ok", f"{len(lines)} check đang chập chờn", [Msg("Xem trước: chống chập chờn",
                                                                    f"Rule: ≥ {need} lần đổi status trong {mins} phút → gộp 1 tin, ngừng tin lẻ "
                                                                    f"{ctx.p('quiet_min', 60)} phút.\n\n" + ("\n".join(lines) or "Hiện không có check nào chập chờn."))])


def inc05_preview(ctx):
    db = ctx.db
    shown = []
    for al in db.query(models.Alert).filter(models.Alert.status != "resolved").order_by(models.Alert.opened_at.desc()).limit(3):
        item = {"subject": al.title, "text": "", "ctx": {"kind": "open", "alert_id": al.id}}
        v = inc05_hook(ctx, item)
        if v:
            shown.append(f"■ {al.title}{item['text']}")
    if not shown:
        shown = ["Ví dụ khi WAN down:\nCách xử lý:\n" + "\n".join(f"{i}. {x}" for i, x in enumerate(RUNBOOKS["wan"], 1))]
    return RunResult("ok", f"{len(shown)} ví dụ", [Msg("Xem trước: runbook đính kèm", "\n\n".join(shown))])


def lcm01_preview(ctx):
    from .engine import next_run
    db = ctx.db
    ws = ctx.p("windows") or []
    if not ws:
        return RunResult("ok", "Chưa có khung bảo trì", [Msg("Xem trước: lịch bảo trì", "Chưa khai báo khung bảo trì nào. Thêm khung: tên, giờ bắt đầu (cron), "
                                                                                    "thời lượng, thiết bị hoặc site.")])
    lines = []
    for w in ws:
        n = next_run(w["cron"], ctx.now)
        tg = _window_targets(db, w)
        lines.append(f"- {w.get('name', 'Bảo trì')}: {'ĐANG DIỄN RA' if _in_window(w, ctx.now) else 'lần tới ' + (n.strftime('%H:%M %d/%m') if n else '?')}"
                     f" · {w.get('duration_min', 60)} phút · {len(tg)} thiết bị")
    return RunResult("ok", f"{len(ws)} khung bảo trì", [Msg("Xem trước: lịch bảo trì", "\n".join(lines))])


# ================================================================ Kịch bản tự tạo
PLACEHOLDERS = ("title", "message", "severity", "asset", "site", "check", "time")


def custom(ctx, event=None):
    db = ctx.db
    content = ctx.spec.get("content") or {}
    if event is not None:                      # theo sự kiện cảnh báo
        c = event.get("ctx") or {}
        kind = {"open": "alert_opened", "resolve": "alert_resolved", "escalate": "alert_escalated"}.get(c.get("kind"))
        if kind not in ((ctx.spec.get("trigger") or {}).get("on") or []):
            return _skip("Sự kiện không khớp trigger")
        al = db.get(models.Alert, c["alert_id"]) if c.get("alert_id") else None
        asset = db.get(models.Asset, al.asset_id) if al and al.asset_id else None
        site_id = (al.site_id if al else None) or (asset.site_id if asset else None)
        sev = al.severity if al else ""
        if not in_scope(ctx.scope, site_id=site_id, asset=asset, severity=sev if kind != "alert_resolved" else None,
                        name=(al.title if al else event["subject"])):
            return _skip("Ngoài phạm vi")
        site = db.get(models.Site, site_id) if site_id else None
        chk = db.get(models.Check, al.check_id) if al and al.check_id else None
        vals = {"title": event["subject"], "message": event["text"], "severity": B.SEV_LABEL.get(sev, sev or "Đã xử lý"),
                "asset": asset.name if asset else "", "site": site.name if site else "", "check": chk.name if chk else "",
                "time": ctx.now.strftime("%H:%M %d/%m")}
        subj = _fmt(content.get("title") or "{title}", vals)
        text = _fmt(content.get("message") or "{message}", vals)
        return RunResult("ok", subj, [Msg(subj, text, "resolved" if kind == "alert_resolved" else "warning")])
    names = content.get("blocks") or ["overview", "open_alerts"]
    text, items = B.render(db, ctx.scope, names, content.get("block_params") or {})
    if ctx.spec.get("send_when", "always") == "has_items" and not items:
        return _skip("Không có gì để báo (send_when: has_items)")
    subj = _fmt(content.get("title") or ctx.auto.name, {"time": ctx.now.strftime("%H:%M %d/%m")})
    intro = content.get("message")
    return RunResult("ok", f"{items} mục", [Msg(subj, (intro + "\n\n" if intro else "") + text, "info")])


def _fmt(tpl, vals):
    out = str(tpl)
    for k, v in vals.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _validate_custom(spec):
    content = spec.get("content") or {}
    bad = [b for b in content.get("blocks") or [] if b not in B.BLOCKS]
    if bad:
        raise ValueError(f"Khối không tồn tại: {', '.join(bad)}. Dùng: {', '.join(B.BLOCKS)}")
    if spec.get("send_when", "always") not in ("always", "has_items"):
        raise ValueError("send_when phải là always hoặc has_items")
    if (spec.get("trigger") or {}).get("type") in ("schedule", "interval") and not content.get("blocks"):
        raise ValueError("Kịch bản theo lịch cần content.blocks (VD [overview, open_alerts])")


def _validate_windows(spec):
    for w in (spec.get("params") or {}).get("windows") or []:
        from .engine import parse_cron
        if not isinstance(w, dict) or not w.get("cron"):
            raise ValueError("Mỗi khung bảo trì cần cron (giờ bắt đầu) và duration_min")
        parse_cron(w["cron"])
        if not (w.get("assets") or w.get("sites")):
            raise ValueError(f"Khung '{w.get('name', '')}' cần assets hoặc sites")


def _validate_steps(spec):
    for s in (spec.get("params") or {}).get("steps") or []:
        if not isinstance(s, dict) or not isinstance(s.get("after_min"), (int, float)):
            raise ValueError("Mỗi bước leo thang cần after_min (phút)")


# ================================================================ danh mục
def T(code, group, name, desc, spec, *, run=None, hook=None, tick=False, kpi="", data="Có sẵn", triggers=None, reversible=False,
      fields=None, validate=None, wants_event=False, preview=None):
    return {"code": code, "group": group, "name": name, "desc": desc, "spec": spec, "run": run, "hook": hook, "tick": tick, "kpi": kpi,
            "preview": preview,
            "data": data, "triggers": triggers or (["schedule", "interval", "event"] if code == "CUSTOM" else ["schedule", "interval"]),
            "reversible": reversible, "fields": fields or [], "validate": validate, "wants_event": wants_event}


F = lambda key, label, kind="number", **kw: {"key": key, "label": label, "type": kind, **kw}  # noqa: E731

TEMPLATES = {t["code"]: t for t in [
    T("RPT-01", "RPT", "Bản tin sáng", "Thiết bị đang đỏ, cảnh báo mở, sự cố 24h, status WAN/line Internet, SSL sắp hết hạn, tài nguyên vượt threshold.",
      _spec({"type": "schedule", "cron": "30 7 * * *"}, {"ssl_days": 14, "max_alerts": 8}), run=rpt01,
      kpi="Đúng giờ 100%; IT không phải tự gom tin mỗi sáng",
      fields=[F("ssl_days", "Báo SSL hết hạn trong (ngày)"), F("max_alerts", "Số cảnh báo liệt kê tối đa")]),
    T("RPT-02", "RPT", "Báo cáo tuần vận hành", "Uptime theo site, số sự cố, MTTA/MTTR, top thiết bị lỗi nhiều, log nổi bật, việc cần quyết định.",
      _spec({"type": "schedule", "cron": "0 8 * * 1"}, {"uptime_target": 99.5, "top_n": 5}), run=rpt02,
      kpi="Quản lý đọc trong 24h; không cần hỏi thêm số liệu", data="Có sẵn · MTTA cần mọi người bấm Nhận",
      fields=[F("uptime_target", "Mục tiêu uptime (%)", step=0.1), F("top_n", "Top N thiết bị")]),
    T("RPT-03", "RPT", "Báo cáo SLA tháng", "% uptime tháng trước theo site và hệ thống trọng yếu so với mục tiêu, phút DOWN, so với tháng trước nữa, kiến nghị.",
      _spec({"type": "schedule", "cron": "0 8 1 * *"}, {"uptime_target": 99.5}), run=rpt03,
      kpi="Ban giám đốc có số SLA đúng hạn mỗi tháng", data="Có sẵn (gộp uptime theo ngày) · đúng khi hệ thống chạy liên tục",
      fields=[F("uptime_target", "Mục tiêu uptime (%)", step=0.1)]),
    T("RPT-04", "RPT", "Backup & rủi ro", "Hệ thống trọng yếu chưa backup, điểm đơn lẻ gây sập (SPOF), phụ thuộc đang lỗi trên bản đồ.",
      _spec({"type": "schedule", "cron": "0 16 * * 5"}, {"skip_if_empty": True}), run=rpt04, data="Có sẵn (cờ backup)",
      kpi="0 hệ thống High thiếu backup", fields=[F("skip_if_empty", "Không gửi khi không có rủi ro", "bool")]),
    T("RPT-06", "RPT", "Biến động tài sản", "Tài sản mới, Nguồn lạ chưa xử lý, tài sản im lặng, tài sản thiếu người phụ trách.",
      _spec({"type": "schedule", "cron": "0 9 1 * *"}, {"days": 30, "silent_days": 7}), run=rpt06,
      kpi="100% tài sản có người phụ trách", fields=[F("days", "Kỳ báo cáo (ngày)"), F("silent_days", "Im lặng quá (ngày)")]),

    T("INC-01", "INC", "Gom theo nguyên nhân gốc", "Thiết bị cha (firewall, switch, host) DOWN → chặn cảnh báo của thiết bị phía sau, chỉ gửi 1 tin kèm số thiết bị bị ảnh hưởng.",
      _spec({"type": "hook"}, level="L3"), hook=inc01_hook, preview=inc01_preview, triggers=["hook"], reversible=True, data="Có sẵn (cây cha–con trên bản đồ)",
      kpi="Số tin mỗi sự cố ≤ 2"),
    T("INC-02", "INC", "Chống chập chờn", "≥ N lần đổi status trong M phút → gộp thành 1 tin 'chập chờn', tạm ngừng gửi tin lẻ.",
      _spec({"type": "hook"}, {"changes": 3, "window_min": 10, "quiet_min": 60}, level="L3"), hook=inc02_hook, preview=inc02_preview, triggers=["hook"], reversible=True,
      kpi="Không còn chuỗi tin bật/tắt liên tục",
      fields=[F("changes", "Số lần đổi status"), F("window_min", "Trong (phút)"), F("quiet_min", "Ngừng gửi tin lẻ (phút)")]),
    T("INC-03", "INC", "Leo thang theo mức", "Cảnh báo chưa ai bấm Nhận sau X phút → báo bước tiếp theo (trưởng nhóm, quản lý).",
      _spec({"type": "interval", "minutes": 1}, {"steps": [
          {"label": "Trưởng nhóm", "after_min": 15, "severities": ["High"], "targets": []},
          {"label": "Quản lý", "after_min": 60, "severities": ["High"], "targets": []},
          {"label": "Nhóm IT (Medium)", "after_min": 30, "severities": ["Medium"], "targets": []}]}, level="L3"),
      run=inc03, triggers=["interval"], reversible=True, data="Có sẵn · cần điền người nhận từng bước",
      kpi="MTTA High < 15 phút", validate=_validate_steps, fields=[F("steps", "Các bước leo thang", "steps")]),
    T("INC-05", "INC", "Runbook đính kèm", "Gắn 3–5 bước kiểm tra vào tin cảnh báo theo loại check (WAN, ping, SNMP, HTTP, SSH, CPU/RAM/Disk) hoặc runbook của hệ thống trọng yếu.",
      _spec({"type": "hook"}, {"rules": []}, level="L1"), hook=inc05_hook, preview=inc05_preview, triggers=["hook"], data="Có sẵn (runbook mặc định + runbook hệ thống trọng yếu)",
      kpi="On-call xử lý được ngay không cần hỏi", fields=[F("rules", "Runbook riêng theo từ khoá", "rules")]),
    T("INC-08", "INC", "Thông báo người dùng", "Hệ thống trọng yếu DOWN quá X phút → gửi tin 'đang gián đoạn' tới nhóm chung; xanh lại → gửi tin khôi phục.",
      _spec({"type": "interval", "minutes": 1}, {"down_minutes": 10, "levels": ["High"],
                                                 "msg_down": "{system} đang gián đoạn. IT đã nhận thông tin và đang xử lý. Sẽ báo lại khi dịch vụ hoạt động trở lại.",
                                                 "msg_up": "{system} đã hoạt động bình thường trở lại (gián đoạn khoảng {minutes} phút). Cảm ơn mọi người đã chờ."},
            level="L2"),
      run=inc08, triggers=["interval"], reversible=True, data="Có sẵn (hệ thống trọng yếu + check gắn kèm)",
      kpi="Người dùng biết sự cố trước khi gọi IT",
      fields=[F("down_minutes", "Gửi khi DOWN quá (phút)"), F("levels", "Mức trọng yếu", "multi", options=["High", "Medium", "Low"]),
              F("msg_down", "Mẫu tin gián đoạn", "textarea"), F("msg_up", "Mẫu tin khôi phục", "textarea")]),

    T("PRE-01", "PRE", "Dự báo đầy ổ / datastore", "Hồi quy tuyến tính % dùng ổ (Linux, Windows, datastore, volume NAS) – báo nếu sẽ chạm threshold trong N ngày.",
      _spec({"type": "schedule", "cron": "0 8 * * *"}, {"target_pct": 90, "horizon_days": 14, "window_days": 14, "min_hours": 24}), run=pre01,
      data="Có sẵn (lịch sử CPU/RAM/Disk) · chính xác sau ≥ 7 ngày", kpi="≥ 50% sự cố đầy ổ được báo trước",
      fields=[F("target_pct", "Threshold đầy (%)"), F("horizon_days", "Báo nếu đầy trong (ngày)"), F("window_days", "Dựa trên số liệu (ngày)"),
              F("min_hours", "Cần tối thiểu (giờ số liệu)")]),
    T("PRE-02", "PRE", "SSL hết hạn", "Nhắc 3 lần ở mốc 30 / 14 / 7 ngày, lần cuối mức Critical. Gia hạn xong tự reset.",
      _spec({"type": "schedule", "cron": "0 9 * * *"}, {"days": [30, 14, 7]}), run=pre02, data="Có sẵn (check HTTP có SSL)",
      kpi="0 sự cố vì SSL hết hạn", fields=[F("days", "Mốc nhắc (ngày)", "list")]),
    T("PRE-04", "PRE", "Độ trễ tăng bất thường", "Trung bình 15 phút gần nhất vượt đường nền 7 ngày + 3 độ lệch chuẩn → cảnh báo sớm trước khi down.",
      _spec({"type": "interval", "minutes": 5}, {"sigma": 3, "recent_min": 15, "min_delta_ms": 5, "min_baseline_hours": 24, "cooldown_hours": 6}),
      run=pre04, data="Có sẵn (lịch sử độ trễ) · chính xác sau ≥ 7 ngày", kpi="Phát hiện đường truyền xấu trước khi rớt",
      fields=[F("sigma", "Số độ lệch chuẩn", step=0.5), F("recent_min", "Window gần nhất (phút)"), F("min_delta_ms", "Tăng tối thiểu (ms)"),
              F("min_baseline_hours", "Cần đường nền tối thiểu (giờ)"), F("cooldown_hours", "Không nhắc lại trong (giờ)")]),
    T("PRE-08", "PRE", "Log bất thường", "Số log lỗi/cảnh báo 1 giờ qua gấp X lần trung bình cùng khung giờ 7 ngày trước → báo kèm 10 dòng tiêu biểu.",
      _spec({"type": "interval", "minutes": 15}, {"multiplier": 3, "min_count": 30, "cooldown_hours": 3}), run=pre08, data="Có sẵn (log thiết bị)",
      kpi="Phát hiện thiết bị bất thường qua log", fields=[F("multiplier", "Gấp (lần)"), F("min_count", "Tối thiểu (log/giờ)"),
                                                          F("cooldown_hours", "Không nhắc lại trong (giờ)")]),

    T("LCM-01", "LCM", "Lịch bảo trì", "Trong khung giờ bảo trì: không gửi cảnh báo của thiết bị trong phạm vi. Nhắc trước 1 ngày; hết giờ chạy lại mọi check và gửi kết quả.",
      _spec({"type": "hook"}, {"windows": [], "remind_hours": 24}, level="L3"), hook=lcm01_hook, run=lcm01, preview=lcm01_preview, tick=True, triggers=["hook"],
      reversible=True, validate=_validate_windows, kpi="0 cảnh báo giả trong khung giờ bảo trì",
      fields=[F("windows", "Khung bảo trì", "windows"), F("remind_hours", "Nhắc trước (giờ)")]),
    T("LCM-02", "LCM", "Onboard tài sản", "Tài sản mới chưa có check / Nguồn lạ gửi log → gợi ý bộ check theo loại và checklist bắt buộc.",
      _spec({"type": "schedule", "cron": "0 9 * * *"}, {"days": 7}, level="L1"), run=lcm02, kpi="Tài sản mới có check trong 24h",
      fields=[F("days", "Tài sản tạo trong (ngày)")]),
    T("LCM-03", "LCM", "Offboard / thanh lý", "Tài sản không phản hồi quá N ngày → đề nghị archive. Không tự xoá, không tự tắt.",
      _spec({"type": "schedule", "cron": "0 9 * * 1"}, {"days": 30}, level="L1"), run=lcm03, kpi="Danh sách tài sản luôn đúng thực tế",
      fields=[F("days", "Không phản hồi quá (ngày)")]),
    T("LCM-06", "LCM", "Rà soát dữ liệu định kỳ", "Đầu quý: tài sản thiếu người phụ trách/site, check tắt lâu, rule log không khớp, tài khoản không đăng nhập.",
      _spec({"type": "schedule", "cron": "0 9 1 1,4,7,10 *"}), run=lcm06, kpi="Dữ liệu tài sản sạch mỗi quý"),

    T("CUSTOM", "CUSTOM", "Kịch bản tự tạo", "Tự chọn trigger (lịch / chu kỳ / sự kiện cảnh báo), phạm vi, nội dung và người nhận.",
      _spec({"type": "schedule", "cron": "0 8 * * 1-5"}, content={"title": "Tình hình hạ tầng {time}", "blocks": ["overview", "open_alerts"]},
            send_when="always"),
      run=custom, wants_event=True, validate=_validate_custom),
]}

UNSUPPORTED = [
    ("RPT-05", "WAN & băng thông", "Cần lưu lịch sử Mbps theo đường WAN (hiện chỉ có lần đọc gần nhất)"),
    ("INC-04", "Xử lý ngay trên Telegram", "Cần Telegram bot nhận callback (máy chạy IT Ops phải có địa chỉ public)"),
    ("INC-06", "Tự khắc phục có kiểm soát", "Cần danh sách lệnh SSH được phép + bước duyệt"),
    ("INC-07", "Hồ sơ sự cố + postmortem", "Cần bảng hồ sơ sự cố"),
    ("PRE-03", "WAN sắp bão hoà", "Cần lịch sử Mbps + băng thông hợp đồng từng đường"),
    ("PRE-05", "Sức khoẻ phần cứng", "Cần Redfish (iLO/iDRAC) hoặc trap RAID/SMART đã chuẩn hoá"),
    ("PRE-06", "Kiểm chứng backup", "Cần tích hợp Veeam / Synology Active Backup + RPO"),
    ("PRE-07", "Cấu hình bị thay đổi", "Cần kho lưu cấu hình qua SSH"),
    ("LCM-04", "Bảo hành, license, hợp đồng", "Cần trường ngày hết hạn, nhà cung cấp, chi phí"),
    ("LCM-05", "Firmware / bản vá", "Cần bảng phiên bản tối thiểu"),
    ("LCM-07", "Thay thế theo tuổi thọ", "Cần trường ngày mua"),
    ("LCM-08", "Diễn tập khôi phục", "Cần bảng kết quả test + RTO"),
]


def public_catalog():
    from .engine import describe_cron
    out = []
    for t in TEMPLATES.values():
        trg = t["spec"]["trigger"]
        when = describe_cron(trg["cron"]) if trg.get("type") == "schedule" else (
            f"mỗi {trg['minutes']} phút" if trg.get("type") == "interval" else "khi có cảnh báo" if trg.get("type") in ("hook", "event") else "")
        out.append({k: t[k] for k in ("code", "group", "name", "desc", "kpi", "data", "fields")} | {"spec": t["spec"], "when": when,
                                                                                                   "triggers": t["triggers"],
                                                                                                   "reversible": t["reversible"]})
    return {"templates": out, "unsupported": [{"code": c, "name": n, "reason": r} for c, n, r in UNSUPPORTED],
            "blocks": [{"key": k, "label": v[0]} for k, v in B.BLOCKS.items()], "placeholders": list(PLACEHOLDERS)}


__all__ = ["TEMPLATES", "public_catalog", "to_local", "to_utc_naive"]
