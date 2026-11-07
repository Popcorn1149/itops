"""Máy ảo / container chạy trên một host ảo hoá (ESXi, Proxmox, Hyper-V, Docker): số lượng, cấp phát, hiệu năng."""
from . import models

GUEST_TYPES = ("vm", "container")
PLATFORM_LABEL = {"esxi": "VMware ESXi", "proxmox": "Proxmox VE", "hyperv": "Hyper-V", "docker": "Docker"}
KIND_LABEL = {"vm": "VM", "qemu": "VM", "lxc": "LXC", "hyperv": "VM", "docker": "Container"}
RUNNING = {"poweredOn", "running", "Running"}


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def guest_row(a: models.Asset) -> dict:
    m = a.meta or {}
    res = m.get("res") or {}
    power = m.get("power")
    running = power in RUNNING if power else a.status == "up"
    kind = m.get("kind") or ("docker" if a.type == "container" else "vm")
    vcpu = m.get("vcpu")
    mem_gb = round(m["mem_mb"] / 1024, 1) if m.get("mem_mb") else (res.get("mem_total_gb") or None)
    disks = res.get("disks") or ([{"pct": res["disk"], "size_gb": res.get("disk_size_gb"), "used_gb": res.get("disk_used_gb")}] if res.get("disk") is not None else [])
    d_total = sum(d.get("size_gb") or 0 for d in disks) or None
    d_used = sum(d.get("used_gb") or 0 for d in disks) if d_total else None
    cpu_p, mem_p = (res.get("cpu"), res.get("mem")) if running else (None, None)
    usage = {   # đang dùng / được cấp – hiển thị dạng "1 / 8 GB"
        "cpu_used": round(cpu_p * vcpu / 100, 2) if cpu_p is not None and vcpu else None, "cpu_total": vcpu,
        "mem_used_gb": round(mem_p * mem_gb / 100, 1) if mem_p is not None and mem_gb else None, "mem_total_gb": mem_gb,
        "disk_used_gb": round(d_used, 1) if running and d_used is not None else None,
        "disk_total_gb": round(d_total, 1) if d_total else m.get("disk_alloc_gb"),
    }
    return {**usage,"id": a.id, "name": a.name, "type": a.type, "kind": kind, "kind_label": KIND_LABEL.get(kind, kind),
            "platform": m.get("platform", ""), "status": a.status, "running": running, "power": power,
            "ip": a.ip, "ips": m.get("ips") or ([a.ip] if a.ip else []), "os": a.os,
            "vcpu": m.get("vcpu"), "mem_gb": round(m["mem_mb"] / 1024, 1) if m.get("mem_mb") else None,
            "disk_alloc_gb": m.get("disk_alloc_gb"), "uptime_s": m.get("uptime_s"),
            "cpu": res.get("cpu") if running else None, "mem": res.get("mem") if running else None,
            "disk": res.get("disk") if running else None, "disk_name": res.get("disk_name"),
            "snapshots": m.get("snapshots"), "oldest_snapshot_days": m.get("oldest_snapshot_days"),
            "tools": m.get("tools") or m.get("heartbeat") or "", "missing": bool(m.get("missing")), "via": m.get("via", ""),
            "backup": bool(a.backup) if hasattr(a, "backup") else None}


def guests_view(db, host: models.Asset, snap_warn_days: int = 7) -> dict:
    kids = db.query(models.Asset).filter(models.Asset.parent_id == host.id, models.Asset.type.in_(GUEST_TYPES)).all()
    rows = sorted((guest_row(k) for k in kids), key=lambda r: (r["missing"], not r["running"], -(r["cpu"] or 0), r["name"].lower()))
    live_rows = [r for r in rows if not r["missing"]]   # VM không còn thấy trên host: vẫn liệt kê, không tính vào số lượng
    run_rows = [r for r in live_rows if r["running"] and r["kind"] != "docker"]
    hm = host.meta or {}
    hres = hm.get("res") or {}
    # ESXi API có cả core vật lý và luồng → tính theo luồng (đúng cách ESXi chia lịch); SNMP / Proxmox / Hyper-V chỉ có CPU logic
    threads = _num(hm.get("threads"))
    cores = threads or _num(hm.get("cores") or hres.get("cores"))
    cpu_unit = "luồng CPU" if threads or hm.get("platform") != "esxi" or not hm.get("cores") else "core"
    host_mem = _num(hm.get("mem_gb") or hres.get("mem_total_gb"))
    platforms = sorted({r["platform"] for r in rows if r["platform"]} | ({hm["platform"]} if hm.get("platform") else set()))
    vms = [r for r in live_rows if r["type"] == "vm"]
    vcpu = sum(r["vcpu"] or 0 for r in live_rows if r["running"] and r["kind"] != "docker")
    mem = sum(r["mem_gb"] or 0 for r in live_rows if r["running"] and r["kind"] != "docker")
    old = [r for r in live_rows if (r["oldest_snapshot_days"] or 0) > snap_warn_days]
    hot = [r for r in live_rows if (r["cpu"] or 0) >= 90 or (r["mem"] or 0) >= 95 or (r["disk"] or 0) >= 90]
    return {
        "host": {"id": host.id, "name": host.name, "cores": cores, "cpu_unit": cpu_unit, "physical_cores": _num(hm.get("cores")) if threads else None,
                 "mem_gb": host_mem,
                 "cpu": hres.get("cpu", hm.get("cpu_pct")), "mem": hres.get("mem", hm.get("mem_pct"))},
        "platforms": [PLATFORM_LABEL.get(p, p) for p in platforms],
        "summary": {
            "total": len(live_rows), "running": sum(r["running"] for r in live_rows), "stopped": sum(not r["running"] for r in live_rows),
            "vms": len(vms), "containers": len(live_rows) - len(vms), "missing": sum(r["missing"] for r in rows),
            "vcpu_alloc": vcpu, "vcpu_ratio": round(vcpu / cores, 2) if cores else None,
            "mem_alloc_gb": round(mem, 1), "mem_ratio": round(mem / host_mem, 2) if host_mem else None,
            "old_snapshots": len(old), "hot": len(hot),
            "no_backup": sum(1 for r in vms if r["backup"] is False),
            # chỉ có mức cấp phát, chưa có mức dùng (đọc qua SNMP, chưa có tài khoản ESXi)
            "allocation_only": bool(run_rows) and all(r["cpu"] is None and r["mem"] is None for r in run_rows),
        },
        "guests": rows,
        "perf": perf_source(db, host),
    }


def perf_source(db, host: models.Asset) -> dict | None:
    """Check SNMP đang đọc VM ESXi của host (để nhập tài khoản ESXi chỉ đọc lấy CPU/RAM/Disk VM). None nếu đã có check API."""
    checks = db.query(models.Check).filter(models.Check.asset_id == host.id, models.Check.enabled == True).all()  # noqa: E712
    if any(c.type in ("esxi", "proxmox") for c in checks):
        return None
    for c in checks:
        d = c.last_data or {}
        if c.type == "snmp" and (d.get("vm_inventory") or d.get("vms")):
            cfg = c.config or {}
            vp = d.get("vm_perf") or {}
            return {"check_id": c.id, "check_name": c.name, "user": cfg.get("esxi_user", ""), "has_credentials": bool(cfg.get("esxi_user")),
                    "ok": vp.get("ok"), "note": vp.get("note", "")}
    return None


def guest_counts(db) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for a in db.query(models.Asset).filter(models.Asset.parent_id.isnot(None), models.Asset.type.in_(GUEST_TYPES)).all():
        r = guest_row(a)
        if r["missing"]:
            continue
        c = out.setdefault(a.parent_id, {"total": 0, "running": 0})
        c["total"] += 1
        c["running"] += r["running"]
    return out
