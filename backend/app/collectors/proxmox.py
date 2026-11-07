"""Proxmox VE qua REST API (API token, không cần mật khẩu root).

Lấy: node (CPU/RAM/rootfs/uptime), storage, VM (QEMU) và container (LXC) trên từng node:
status, vCPU, RAM cấp phát / đang dùng, CPU %, disk, uptime, snapshot. Tùy chọn qua QEMU guest agent: IP và
dung lượng ổ trong guest. VM/LXC tự đưa lên bản đồ, gắn dưới node (host).

Quyền tối thiểu: role PVEAuditor trên "/" cho user của token (tắt Privilege Separation hoặc gán quyền cho chính token).
Đọc guest agent cần thêm quyền VM.GuestAgent.Audit (PVE 9) / VM.Monitor (PVE 8) – thiếu thì bỏ qua, không lỗi.
"""
import asyncio
import time
from datetime import datetime, timezone

import httpx

from .base import Result, apply_resources, worst

POWER = {"running": "up", "stopped": "off", "paused": "off", "suspended": "off"}
GB = 1073741824


async def _get(c: httpx.AsyncClient, path: str):
    r = await c.get(f"/api2/json{path}")
    r.raise_for_status()
    return (r.json() or {}).get("data")


async def _try(c, path):
    try:
        return await _get(c, path)
    except Exception:
        return None


def _pct(used, total):
    return round(used / total * 100, 1) if used is not None and total else None


async def _guest_extra(c, sem, node, g, cfg):
    """Snapshot (QEMU + LXC) và guest agent (QEMU đang chạy). Lỗi/thiếu quyền → bỏ qua."""
    kind, vmid = g["_kind"], g["vmid"]
    async with sem:
        if cfg.get("snapshot_check", True):
            snaps = await _try(c, f"/nodes/{node}/{kind}/{vmid}/snapshot") or []
            real = [s for s in snaps if s.get("name") != "current"]
            g["_snaps"] = len(real)
            times = [s["snaptime"] for s in real if s.get("snaptime")]
            g["_oldest"] = int((time.time() - min(times)) // 86400) if times else None
        if kind == "qemu" and g.get("status") == "running" and cfg.get("guest_agent", True):
            net = await _try(c, f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
            ips = []
            for itf in ((net or {}).get("result") or []):
                if itf.get("name", "").startswith(("lo", "Loopback")):
                    continue
                for a in itf.get("ip-addresses") or []:
                    ip = a.get("ip-address", "")
                    if a.get("ip-address-type") == "ipv4" and not ip.startswith(("127.", "169.254.")):
                        ips.append(ip)
            g["_ips"] = ips
            fs = await _try(c, f"/nodes/{node}/qemu/{vmid}/agent/get-fsinfo")
            disks = []
            for f in ((fs or {}).get("result") or []):
                tot, used = f.get("total-bytes"), f.get("used-bytes")
                if tot and used is not None and f.get("type") not in ("squashfs", "tmpfs", "overlay") and tot > 512 * 1048576:
                    disks.append({"name": f.get("mountpoint") or f.get("name"), "pct": _pct(used, tot),
                                  "size_gb": round(tot / GB, 1), "used_gb": round(used / GB, 1)})
            g["_gdisks"] = sorted(disks, key=lambda d: -d["pct"])[:20]


async def proxmox(target: str, cfg: dict) -> Result:
    token_id, secret = str(cfg.get("token_id", "")).strip(), str(cfg.get("token_secret", "")).strip()
    if not token_id or not secret:
        return Result("fail", "Thiếu API token (token ID + secret)", down=False)
    host = target if "://" in target else f"https://{target}:{int(cfg.get('port', 8006))}"
    headers = {"Authorization": f"PVEAPIToken={token_id}={secret}"}
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(base_url=host, headers=headers, verify=bool(cfg.get("verify_ssl", False)),
                                     timeout=float(cfg.get("timeout", 15))) as c:
            ver = await _get(c, "/version")
            ms = (time.perf_counter() - t0) * 1000
            nodes = await _get(c, "/nodes") or []
            statuses, notes, discovered = ["ok"], [], []
            data = {"product": f"Proxmox VE {ver.get('version', '')}".strip(), "nodes": [], "storages": []}
            cpu_vals, mem_vals, storages = [], [], []
            mem_total = 0.0
            vm_total = vm_on = lxc_total = lxc_on = 0
            sem = asyncio.Semaphore(8)
            for n in nodes:
                name = n.get("node")
                online = n.get("status") == "online"
                hkey = f"pve:{name}"
                ncpu = round(n["cpu"] * 100, 1) if online and n.get("cpu") is not None else None
                nmem = _pct(n.get("mem"), n.get("maxmem")) if online else None
                st = await _try(c, f"/nodes/{name}/status") if online else None
                cpuinfo = (st or {}).get("cpuinfo") or {}
                rootfs = (st or {}).get("rootfs") or {}
                if ncpu is not None:
                    cpu_vals.append(ncpu)
                if nmem is not None:
                    mem_vals.append(nmem)
                mem_total += (n.get("maxmem") or 0) / GB
                if not online:
                    statuses.append("fail" if len(nodes) == 1 else "warn")
                    notes.append(f"Node {name} offline")
                discovered.append({
                    "key": hkey, "type": "host", "name": name, "status": "up" if online else "down",
                    "model": cpuinfo.get("model", "")[:128], "os": (st or {}).get("pveversion", "") or data["product"],
                    "meta": {"platform": "proxmox", "cpu_pct": ncpu, "mem_pct": nmem, "cores": n.get("maxcpu") or cpuinfo.get("cpus"),
                             "sockets": cpuinfo.get("sockets"), "mem_gb": round((n.get("maxmem") or 0) / GB),
                             "uptime_s": n.get("uptime"),
                             "res": {"cpu": ncpu, "mem": nmem, "mem_total_gb": round((n.get("maxmem") or 0) / GB, 1),
                                     "cores": n.get("maxcpu"),
                                     **({"disk": _pct(rootfs.get("used"), rootfs.get("total")), "disk_name": "rootfs"} if rootfs.get("total") else {})}
                             if online else None}})
                data["nodes"].append({"name": name, "status": n.get("status"), "cpu_pct": ncpu, "mem_pct": nmem})
                if not online:
                    continue
                for s in await _try(c, f"/nodes/{name}/storage") or []:
                    if s.get("active") and s.get("total"):
                        if s.get("shared") and any(x["name"] == s["storage"] for x in storages):
                            continue
                        d = {"name": s["storage"] if len(nodes) == 1 or s.get("shared") else f"{name}/{s['storage']}",
                             "pct": _pct(s.get("used"), s.get("total")), "size_gb": round(s["total"] / GB, 1),
                             "used_gb": round((s.get("used") or 0) / GB, 1)}
                        storages.append(d)
                        data["storages"].append({**d, "type": s.get("type")})
                guests = []
                for kind in ("qemu", "lxc"):
                    for g in await _try(c, f"/nodes/{name}/{kind}") or []:
                        if g.get("template"):
                            continue
                        g["_kind"] = kind
                        guests.append(g)
                await asyncio.gather(*[_guest_extra(c, sem, name, g, cfg) for g in guests])
                for g in guests:
                    kind, run = g["_kind"], g.get("status") == "running"
                    if kind == "qemu":
                        vm_total += 1; vm_on += run
                    else:
                        lxc_total += 1; lxc_on += run
                    vres = {}
                    if run:
                        if g.get("cpu") is not None:
                            vres["cpu"] = round(min(100.0, g["cpu"] * 100), 1)
                        if g.get("maxmem"):
                            vres["mem"] = _pct(g.get("mem"), g["maxmem"])
                            vres["mem_total_gb"] = round(g["maxmem"] / GB, 1)
                        gd = g.get("_gdisks") or ([{"name": "rootfs", "pct": _pct(g.get("disk"), g.get("maxdisk")),
                                                    "size_gb": round(g["maxdisk"] / GB, 1), "used_gb": round((g.get("disk") or 0) / GB, 1)}]
                                                  if kind == "lxc" and g.get("maxdisk") and g.get("disk") else [])
                        if gd:
                            vres["disks"], vres["disk"], vres["disk_name"] = gd, gd[0]["pct"], gd[0]["name"]
                    gname = g.get("name") or f"{kind}-{g['vmid']}"
                    discovered.append({
                        "key": f"pve:{name}:{g['vmid']}", "parent_key": hkey, "type": "vm" if kind == "qemu" else "container",
                        "name": gname, "status": POWER.get(g.get("status"), "unknown"), "ip": (g.get("_ips") or [""])[0],
                        "os": "QEMU/KVM" if kind == "qemu" else "LXC",
                        "meta": {"platform": "proxmox", "kind": kind, "vmid": g["vmid"], "power": g.get("status"),
                                 "vcpu": g.get("cpus"), "mem_mb": round((g.get("maxmem") or 0) / 1048576),
                                 "disk_alloc_gb": round((g.get("maxdisk") or 0) / GB, 1), "uptime_s": g.get("uptime"),
                                 "ips": g.get("_ips") or [], "snapshots": g.get("_snaps"), "oldest_snapshot_days": g.get("_oldest"),
                                 "netin": g.get("netin"), "netout": g.get("netout"), "res": vres or None}})
                    if g.get("_oldest") is not None and g["_oldest"] > int(cfg.get("snapshot_warn_days", 7)):
                        statuses.append("warn")
                        notes.append(f"{gname} có snapshot {g['_oldest']} ngày")
            data.update(vm_total=vm_total, vm_on=vm_on, lxc_total=lxc_total, lxc_on=lxc_on)
            res_notes: list = []
            metrics = apply_resources(data, cfg, statuses, res_notes, cpu=max(cpu_vals) if cpu_vals else None,
                                      mem=max(mem_vals) if mem_vals else None, disks=storages,
                                      mem_total_gb=mem_total or None, disk_label="Storage")
            parts = [f"{len(nodes)} node", f"{vm_on}/{vm_total} VM chạy"] + ([f"{lxc_on}/{lxc_total} LXC"] if lxc_total else [])
            return Result(worst(*statuses), " · ".join(parts + res_notes + notes[:5]), ms, metrics.get("cpu"), data, discovered)
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = " – kiểm tra token ID/secret và quyền PVEAuditor" if code in (401, 403) else ""
        return Result("fail", f"Proxmox API HTTP {code}{hint}", down=code not in (401, 403))
    except Exception as e:
        return Result("fail", f"Không kết nối được Proxmox: {type(e).__name__} {e}"[:300], down=True)
