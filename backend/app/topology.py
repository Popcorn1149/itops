"""Bản đồ hệ thống, hệ thống trọng yếu và điểm rủi ro – tính từ dữ liệu tài sản/check/cảnh báo."""
from datetime import timedelta

from sqlalchemy.orm import Session

from . import models
from .models import now

ORDER = {"ok": 0, "unknown": 1, "warn": 2, "fail": 3}
LEVEL_RANK = {"High": 3, "Medium": 2, "Low": 1}
ASSET_ORDER = ["firewall", "router", "switch", "ap", "host", "server", "nas", "vm", "container", "service", "website", "ups", "printer", "camera", "device", "other"]


def _worst(sts):
    sts = list(sts)
    return max(sts, key=lambda s: ORDER.get(s, 1)) if sts else "unknown"


def critical_view(db: Session) -> list[dict]:
    crit = db.query(models.CriticalSystem).order_by(models.CriticalSystem.id).all()
    assets = {a.id: a for a in db.query(models.Asset).all()}
    checks = db.query(models.Check).all()
    by_id = {c.id: c for c in checks}
    alerts = db.query(models.Alert).filter(models.Alert.status != "resolved").all()
    sites = {s.id: s.name for s in db.query(models.Site).all()}
    out = []
    for c in crit:
        a = assets.get(c.asset_id) if c.asset_id else None
        cks = [by_id[i] for i in (c.check_ids or []) if i in by_id]
        if a:
            cks += [k for k in checks if k.asset_id == a.id and k not in cks]
        ck_ids = {k.id for k in cks}
        al = [x for x in alerts if x.check_id in ck_ids or (a and x.asset_id == a.id)]
        host = assets.get(a.parent_id) if a and a.parent_id else None
        backup_ok = bool(c.hosted_externally or c.backup or (a and a.backup))
        status = _worst(k.status for k in cks if k.enabled) if cks else "unknown"
        if a and a.status in ("down",) and status != "fail":
            status = "fail"
        out.append({
            "id": c.id, "name": c.name, "description": c.description, "layer": c.layer, "level": c.level,
            "asset_id": c.asset_id, "hosted_externally": c.hosted_externally, "external_note": c.external_note,
            "backup": c.backup, "backup_note": c.backup_note or (a.backup_note if a else ""), "backup_ok": backup_ok,
            "owner": c.owner, "url": c.url, "depends_on": c.depends_on or [], "check_ids": c.check_ids or [], "runbook": c.runbook,
            "asset": {"id": a.id, "name": a.name, "type": a.type, "ip": a.ip, "status": a.status, "backup": a.backup} if a else None,
            "host": {"id": host.id, "name": host.name, "type": host.type} if host else None,
            "site": sites.get(a.site_id) if a else None,
            "checks": [{"id": k.id, "name": k.name, "type": k.type, "status": k.status, "last_message": k.last_message} for k in cks],
            "alerts": len(al), "status": status,
        })
    return out


def _node(a: models.Asset, crit_level: dict) -> dict:
    live = (a.meta or {}).get("live", {})
    sub = a.ip or ""
    if a.type == "vm" and (a.meta or {}).get("power") == "poweredOff":
        sub = (sub + " · tắt").strip(" ·")
    return {"id": f"a{a.id}", "asset_id": a.id, "name": a.name, "type": a.type, "status": a.status, "ip": a.ip,
            "sub": sub, "model": a.model, "vendor": a.vendor, "critical": crit_level.get(a.id), "backup": a.backup,
            "cpu": live.get("cpu"), "children": []}


# ---------------------------------------------------------------- đường Internet / WAN (tự nhận, không cần phân loại tay)
import ipaddress as _ip

def is_public(target: str) -> bool:
    """IP public (dùng để GỢI Ý gán Line Internet, không tự gán)."""
    t = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
    try:
        a = _ip.ip_address(t)
    except ValueError:
        return False          # tên miền: không tự đoán (có thể là website/dịch vụ)
    return a.is_global


def wan_role(chk) -> str | None:
    """Check có phải "Line Internet" không – do người dùng gán khi thêm check (mỗi check = 1 line).

    - Loại check "Line Internet" (internet) → luôn là line.
    - Loại khác (ping, tcp...) → chỉ khi chọn "Vai trò: Line Internet" (map_role = 'wan').
    """
    if chk.type == "internet":
        return "check Line Internet"
    if (chk.config or {}).get("map_role") == "wan":
        return "gán Line Internet"
    return None


def internet_lines(db: Session) -> dict:
    """{site_id: [line]} – mỗi check được gán "Line Internet" là 1 line."""
    assets = {a.id: a for a in db.query(models.Asset).all()}
    out: dict = {}
    for c in db.query(models.Check).filter(models.Check.enabled == True).order_by(models.Check.name).all():  # noqa: E712
        why = wan_role(c)
        if not why:
            continue
        sid = c.site_id or (assets[c.asset_id].site_id if c.asset_id in assets else None)
        d = c.last_data or {}
        lat = d.get("latency_ms") if c.type == "internet" else c.last_latency
        down = c.severity == "down" or c.status == "fail"
        out.setdefault(sid, []).append({
            "id": c.id, "name": c.name, "type": c.type, "target": c.target, "why": why,
            "status": "unknown" if c.status == "unknown" else "fail" if down else c.status, "down": down,
            "latency_ms": round(lat, 1) if isinstance(lat, (int, float)) and not down else None,
            "loss": d.get("loss"), "public_ip": d.get("public_ip"), "message": c.last_message})
    return out


def line_status(lines: list) -> tuple[str | None, str]:
    """x/y line: x = số line không DOWN, y = tổng số line.
    Tất cả DOWN → down · có line DOWN hoặc chập chờn → warning · còn lại → up."""
    if not lines:
        return None, ""
    known = [x for x in lines if x["status"] != "unknown"]
    if not known:
        return "unknown", f"0/{len(lines)} line · chưa chạy"
    n_down = sum(1 for x in known if x["down"])
    n_up = len(lines) - n_down - (len(lines) - len(known))
    text = f"{n_up}/{len(lines)} line" + (f" · {n_down} down" if n_down else "")
    if n_down == len(known):
        return "down", text
    return ("warning" if n_down or any(x["status"] == "warn" for x in known) else "up"), text


def build_topology(db: Session) -> dict:
    sites = db.query(models.Site).order_by(models.Site.sort, models.Site.id).all()
    assets = db.query(models.Asset).all()
    crit = db.query(models.CriticalSystem).all()
    crit_level = {}
    for c in crit:
        if c.asset_id and LEVEL_RANK.get(c.level, 0) > LEVEL_RANK.get(crit_level.get(c.asset_id), 0):
            crit_level[c.asset_id] = c.level

    nodes = {a.id: _node(a, crit_level) for a in assets}
    ids = set(nodes)
    for a in assets:
        if a.parent_id in ids and a.parent_id != a.id:
            nodes[a.parent_id]["children"].append(nodes[a.id])

    def sort_children(n):
        n["children"].sort(key=lambda x: (ASSET_ORDER.index(x["type"]) if x["type"] in ASSET_ORDER else 99, x["name"].lower()))
        for ch in n["children"]:
            sort_children(ch)

    def rollup(n):
        sts = [n.get("status", "unknown")]
        for ch in n["children"]:
            sts.append(rollup(ch))
        n["worst"] = _worst({"up": "ok", "down": "fail", "warning": "warn"}.get(s, "unknown") for s in sts)
        n["count"] = 1 + sum(ch["count"] for ch in n["children"])
        return n["worst"]

    # ---- đường Internet: tự gom từ check Internet/ping WAN và WAN của firewall ----
    amap_site = {a.id: a.site_id for a in assets}
    lines = internet_lines(db)

    all_checks = db.query(models.Check.site_id, models.Check.asset_id).filter(models.Check.enabled == True).all()  # noqa: E712
    site_has_checks = {sid or amap_site.get(aid) for sid, aid in all_checks}
    site_nodes = []
    groups = [(s.id, s.name, s.kind) for s in sites] + [(None, "Chưa gán site", "none")]
    for sid, sname, kind in groups:
        roots = [nodes[a.id] for a in assets if a.site_id == sid and (a.parent_id not in ids or a.parent_id == a.id)]
        if sid is None and not roots:
            continue
        fws = [r for r in roots if r["type"] == "firewall"]
        if fws:
            gate = fws[0]
            for r in roots:
                if r is not gate and r["type"] not in ("firewall", "website", "cloud"):
                    gate["children"].append(r)
            roots = [r for r in roots if r["type"] in ("firewall", "website", "cloud")]
        s_inet = lines.get(sid, [])
        st, sub = line_status(s_inet)
        if st is None:   # chưa có check Internet cho site này
            st = "up" if roots else "unknown"
            sub = "" if (roots or sid in site_has_checks) else "chưa giám sát"
        else:
            sub = f"Internet {sub}"
        sn = {"id": f"s{sid}", "site_id": sid, "name": sname, "type": "site", "kind": kind, "status": st, "sub": sub,
              "internet": bool(s_inet), "children": roots}
        site_nodes.append(sn)

    ext = [c for c in crit if c.hosted_externally]
    if ext:
        site_nodes.append({"id": "ext", "name": "Dịch vụ bên ngoài", "type": "site", "kind": "cloud", "status": "unknown",
                           "children": [{"id": f"c{c.id}", "name": c.name, "type": "service", "status": "unknown",
                                         "sub": c.external_note, "critical": c.level, "children": []} for c in ext]})
    r_st, r_sub = line_status([x for v in lines.values() for x in v])
    root = {"id": "internet", "name": "Internet", "type": "internet", "status": r_st or "unknown",
            "sub": r_sub if r_st else "chưa gán Line Internet", "children": site_nodes}
    sort_children_root = root["children"]
    for s in sort_children_root:
        for ch in s["children"]:
            sort_children(ch)
    rollup(root)

    # ---- flow graph: critical systems → assets → hosts ----
    cv = critical_view(db)
    gnodes, edges, seen = [], [], set()
    amap = {a.id: a for a in assets}

    def add_asset(aid):
        while aid and aid in amap and f"a{aid}" not in seen:
            a = amap[aid]
            seen.add(f"a{aid}")
            gnodes.append({"id": f"a{aid}", "name": a.name, "kind": "asset", "type": a.type, "status": a.status, "asset_id": aid})
            if a.parent_id and a.parent_id in amap:
                edges.append({"source": f"a{aid}", "target": f"a{a.parent_id}", "label": "nằm trên"})
            aid = a.parent_id

    for c in cv:
        gnodes.append({"id": f"c{c['id']}", "name": c["name"], "kind": "critical", "level": c["level"], "status": c["status"], "layer": c["layer"]})
        if c["asset_id"]:
            add_asset(c["asset_id"])
            edges.append({"source": f"c{c['id']}", "target": f"a{c['asset_id']}", "label": "chạy trên"})
        for d in c["depends_on"]:
            edges.append({"source": f"c{c['id']}", "target": f"c{d}", "label": "phụ thuộc"})
    valid = {n["id"] for n in gnodes}
    edges = [e for e in edges if e["source"] in valid and e["target"] in valid]
    return {"tree": root, "flow": {"nodes": gnodes, "edges": edges}}


def build_risks(db: Session) -> list[dict]:
    risks = []
    cv = critical_view(db)
    assets = db.query(models.Asset).all()
    amap = {a.id: a for a in assets}
    checks = db.query(models.Check).filter(models.Check.enabled == True).all()  # noqa: E712

    def add(sev, kind, title, detail, link=None):
        risks.append({"severity": sev, "kind": kind, "title": title, "detail": detail, "link": link})

    for c in cv:
        lv = "high" if c["level"] == "High" else "medium"
        if not c["backup_ok"]:
            add(lv, "Chưa backup", c["name"], f"Hệ thống mức {c['level']} chưa được đánh dấu có backup"
                + (f" (chạy trên {c['asset']['name']})" if c["asset"] else ""), {"page": "critical", "id": c["id"]})
        if not c["asset_id"] and not c["hosted_externally"]:
            add("medium", "Chưa ghép máy chủ", c["name"], "Không biết hệ thống này chạy trên máy nào", {"page": "critical", "id": c["id"]})
        if not c["checks"]:
            add("medium" if c["level"] == "High" else "low", "Chưa giám sát", c["name"], "Không có check nào theo dõi hệ thống này", {"page": "critical", "id": c["id"]})
        if c["status"] == "fail":
            add("high", "Đang lỗi", c["name"], "Hệ thống trọng yếu đang có check lỗi", {"page": "critical", "id": c["id"]})

    # điểm tập trung: một host gánh nhiều hệ thống High
    per_host = {}
    for c in cv:
        if c["level"] != "High" or not c["asset"]:
            continue
        a = amap.get(c["asset_id"])
        host = amap.get(a.parent_id) if a and a.type in ("vm", "container") and a.parent_id else a
        if host:
            per_host.setdefault(host.id, []).append(c["name"])
    for hid, names in per_host.items():
        if len(names) >= 2:
            add("medium", "Điểm tập trung", amap[hid].name, f"{len(names)} hệ thống High cùng phụ thuộc: {', '.join(names)}", {"page": "asset", "id": hid})

    for a in assets:
        if a.status == "down" and a.type not in ("vm", "container"):
            add("high", "Thiết bị down", a.name, f"{a.type} {a.ip}".strip(), {"page": "asset", "id": a.id})
        meta = a.meta or {}
        if a.type == "vm" and (meta.get("oldest_snapshot_days") or 0) > 7:
            add("low", "Snapshot cũ", a.name, f"Snapshot đã {meta['oldest_snapshot_days']} ngày – dễ đầy datastore", {"page": "asset", "id": a.id})
        if meta.get("missing"):
            add("low", "Không còn thấy", a.name, "Tài sản không còn xuất hiện ở nguồn đồng bộ (đã xoá/di chuyển?)", {"page": "asset", "id": a.id})

    t = now()
    for k in checks:
        d = k.last_data or {}
        if k.type == "http" and isinstance(d.get("cert_days"), int) and d["cert_days"] < 21:
            add("high" if d["cert_days"] < 7 else "medium", "SSL sắp hết hạn", k.name, f"Chứng chỉ còn {d['cert_days']} ngày ({k.target})", {"page": "check", "id": k.id})
        for ds in d.get("datastores", []) or []:
            if ds.get("used_pct", 0) >= 85:
                add("high" if ds["used_pct"] >= 95 else "medium", "Datastore đầy", ds["name"], f"Đã dùng {ds['used_pct']}% (còn {ds.get('free_gb')} GB)", {"page": "check", "id": k.id})
        for g in d.get("gateways", []) or []:
            if str(g.get("status")).lower() not in ("online", "none", ""):
                add("high", "WAN lỗi", f"{k.name} – {g.get('name')}", f"Gateway {g.get('status')} · loss {g.get('loss')}", {"page": "check", "id": k.id})
        if k.last_checked and (t - k.last_checked) > timedelta(seconds=max(300, (k.interval or 60) * 5)):
            add("medium", "Nguồn không cập nhật", k.name, f"Lần chạy cuối {int((t - k.last_checked).total_seconds() // 60)} phút trước", {"page": "check", "id": k.id})
        if k.status == "fail":
            add("high", "Check lỗi", k.name, k.last_message[:200], {"page": "check", "id": k.id})

    order = {"high": 0, "medium": 1, "low": 2}
    risks.sort(key=lambda r: order[r["severity"]])
    return risks
