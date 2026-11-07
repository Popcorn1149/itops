"""VMware ESXi / vCenter qua pyVmomi: host, datastore, danh sách VM (tự đưa lên bản đồ)."""
import asyncio
import ssl
import time
from datetime import datetime, timezone

from .base import Result, apply_resources, worst

POWER = {"poweredOn": "up", "poweredOff": "off", "suspended": "off"}


def _collect(target: str, cfg: dict) -> Result:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim

    ctx = ssl.create_default_context()
    if not cfg.get("verify_ssl", False):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    si = SmartConnect(host=target, user=cfg.get("username", "root"), pwd=cfg.get("password", ""),
                      port=int(cfg.get("port", 443)), sslContext=ctx, connectionPoolTimeout=20)
    ms = (time.perf_counter() - t0) * 1000
    try:
        content = si.RetrieveContent()
        about = content.about
        vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        hosts = list(vm_view.view)
        vm_view.Destroy()
        ds_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True)
        datastores = list(ds_view.view)
        ds_view.Destroy()

        discovered, statuses, notes = [], ["ok"], []
        data = {"product": about.fullName, "hosts": [], "datastores": []}
        vm_total = vm_on = 0
        cpu_values = []
        for h in hosts:
            s = h.summary
            hw, qs = s.hardware, s.quickStats
            cpu_total = (hw.cpuMhz or 0) * (hw.numCpuCores or 0)
            cpu_pct = round((qs.overallCpuUsage or 0) / cpu_total * 100, 1) if cpu_total else None
            mem_pct = round((qs.overallMemoryUsage or 0) / ((hw.memorySize or 1) / 1048576) * 100, 1) if hw.memorySize else None
            if cpu_pct is not None:
                cpu_values.append(cpu_pct)
            conn = str(s.runtime.connectionState)
            overall = str(s.overallStatus)
            hstatus = "up" if conn == "connected" and overall in ("green", "gray") else "warning" if conn == "connected" else "down"
            if hstatus != "up":
                statuses.append("warn" if hstatus == "warning" else "fail")
                notes.append(f"Host {s.config.name}: {conn}/{overall}")
            hkey = f"host:{h._moId}"
            hinfo = {"key": hkey, "type": "host", "name": s.config.name, "status": hstatus,
                     "vendor": hw.vendor or "", "model": hw.model or "", "os": f"ESXi {s.config.product.version}" if s.config.product else "",
                     "meta": {"platform": "esxi", "cpu_pct": cpu_pct, "mem_pct": mem_pct, "cores": hw.numCpuCores, "threads": getattr(hw, "numCpuThreads", None), "mem_gb": round((hw.memorySize or 0) / 1073741824),
                              "uptime_s": qs.uptime, "overall": overall,
                              "res": {"cpu": cpu_pct, "mem": mem_pct, "mem_total_gb": round((hw.memorySize or 0) / 1073741824, 1), "cores": hw.numCpuCores}}}
            discovered.append(hinfo)
            data["hosts"].append({"name": s.config.name, "cpu_pct": cpu_pct, "mem_pct": mem_pct, "status": hstatus})

            for vm in h.vm:
                try:
                    vs = vm.summary
                except Exception:
                    continue
                cfgs, guest, rt = vs.config, vs.guest, vs.runtime
                if cfgs is None or cfgs.template:
                    continue
                vm_total += 1
                power = str(rt.powerState)
                if power == "poweredOn":
                    vm_on += 1
                snaps = 0
                oldest_snap_days = None
                try:
                    if vm.snapshot:
                        stack = list(vm.snapshot.rootSnapshotList)
                        while stack:
                            sn = stack.pop()
                            snaps += 1
                            age = (datetime.now(timezone.utc) - sn.createTime).days
                            oldest_snap_days = max(oldest_snap_days or 0, age)
                            stack.extend(sn.childSnapshotList)
                except Exception:
                    pass
                # tài nguyên của VM: CPU theo MHz host, RAM guest đang dùng, ổ đĩa trong guest (cần VMware Tools)
                vres = {}
                try:
                    if power == "poweredOn" and hw.cpuMhz and cfgs.numCpu and vs.quickStats.overallCpuUsage is not None:
                        vres["cpu"] = round(min(100.0, vs.quickStats.overallCpuUsage / (cfgs.numCpu * hw.cpuMhz) * 100), 1)
                    if power == "poweredOn" and cfgs.memorySizeMB and vs.quickStats.guestMemoryUsage is not None:
                        vres["mem"] = round(vs.quickStats.guestMemoryUsage / cfgs.memorySizeMB * 100, 1)
                    gdisks = []
                    for gd in (vm.guest.disk or []) if power == "poweredOn" else []:
                        if gd.capacity:
                            gdisks.append({"name": gd.diskPath, "pct": round((gd.capacity - gd.freeSpace) / gd.capacity * 100, 1),
                                           "size_gb": round(gd.capacity / 1073741824, 1), "used_gb": round((gd.capacity - gd.freeSpace) / 1073741824, 1)})
                    if gdisks:
                        gdisks.sort(key=lambda d: -d["pct"])
                        vres["disks"], vres["disk"], vres["disk_name"] = gdisks[:20], gdisks[0]["pct"], gdisks[0]["name"]
                    if vres:
                        vres["mem_total_gb"] = round(cfgs.memorySizeMB / 1024, 1)
                except Exception:
                    pass
                discovered.append({
                    "key": f"vm:{vm._moId}", "parent_key": hkey, "type": "vm", "name": cfgs.name,
                    "status": POWER.get(power, "unknown"), "ip": (guest.ipAddress or "") if guest else "",
                    "os": (cfgs.guestFullName or "") if cfgs else "",
                    "meta": {"platform": "esxi", "kind": "vm", "via": "api", "power": power, "vcpu": cfgs.numCpu, "mem_mb": cfgs.memorySizeMB,
                             "uptime_s": getattr(vs.quickStats, "uptimeSeconds", None),
                             "disk_alloc_gb": round((getattr(vs.storage, "committed", 0) or 0) / 1073741824, 1) if getattr(vs, "storage", None) else None,
                             "tools": str(guest.toolsRunningStatus) if guest else "", "overall": str(vs.overallStatus),
                             "snapshots": snaps, "oldest_snapshot_days": oldest_snap_days,
                             "cpu_mhz": vs.quickStats.overallCpuUsage, "mem_used_mb": vs.quickStats.guestMemoryUsage,
                             "annotation": (cfgs.annotation or "")[:200], "res": vres or None},
                })
                if oldest_snap_days is not None and oldest_snap_days > int(cfg.get("snapshot_warn_days", 7)):
                    notes.append(f"VM {cfgs.name} có snapshot {oldest_snap_days} ngày")
                    statuses.append("warn")

        ds_list = []
        for ds in datastores:
            s = ds.summary
            if not s.capacity:
                continue
            used = round((s.capacity - s.freeSpace) / s.capacity * 100, 1)
            data["datastores"].append({"name": s.name, "used_pct": used, "capacity_gb": round(s.capacity / 1073741824), "free_gb": round(s.freeSpace / 1073741824)})
            ds_list.append({"name": s.name, "pct": used, "size_gb": round(s.capacity / 1073741824, 1),
                            "used_gb": round((s.capacity - s.freeSpace) / 1073741824, 1)})

        data["vm_total"], data["vm_on"] = vm_total, vm_on
        mems = [h["mem_pct"] for h in data["hosts"] if h["mem_pct"] is not None]
        mem_total = sum((h.summary.hardware.memorySize or 0) for h in hosts) / 1073741824
        res_notes: list = []
        metrics = apply_resources(data, cfg, statuses, res_notes,
                                  cpu=max(cpu_values) if cpu_values else None, mem=max(mems) if mems else None,
                                  disks=ds_list, mem_total_gb=mem_total or None, disk_label="Datastore")
        cpu = metrics.get("cpu")
        msg = " · ".join([f"{len(hosts)} host", f"{vm_on}/{vm_total} VM chạy"] + res_notes + notes)
        return Result(worst(*statuses), msg, ms, cpu, data, discovered)
    finally:
        Disconnect(si)


async def esxi(target: str, cfg: dict) -> Result:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_collect, target, cfg), timeout=float(cfg.get("timeout", 60)))
    except asyncio.TimeoutError:
        return Result("fail", "ESXi/vCenter quá thời gian phản hồi")
    except Exception as e:
        msg = getattr(e, "msg", None) or str(e)
        return Result("fail", f"ESXi lỗi: {type(e).__name__} {msg}"[:300])
