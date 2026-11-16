"""SSH to Linux hosts (or custom commands): uptime, load, RAM, disks, and Docker containers."""
import asyncio
import base64
import json
import re
import time

import asyncssh

from .base import Result, apply_resources, worst

LINUX_SCRIPT = r"""
echo "##HOST"; hostname
echo "##OS"; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -sr
echo "##UPTIME"; cat /proc/uptime
echo "##LOAD"; cat /proc/loadavg
echo "##NPROC"; nproc 2>/dev/null || echo 1
echo "##MEM"; free -m | awk '/Mem:/ {print $2, $7} /Swap:/ {print "swap", $2, $3}'
echo "##CPU"; head -1 /proc/stat; sleep 1; head -1 /proc/stat
echo "##DISK"; df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | awk 'NR>1 {print $6, $5, $2, $3}'
echo "##DOCKER"; (docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null || true)
"""


WINDOWS_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
"##HOST"; $env:COMPUTERNAME
"##OS"; $os.Caption
"##UPTIME"; [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
"##WCPU"; [int](Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
"##NPROC"; [Environment]::ProcessorCount
"##WMEM"; "$($os.TotalVisibleMemorySize) $($os.FreePhysicalMemory)"
"##WDISK"; Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID) $($_.Size) $($_.FreeSpace)" }
"##WSVC"; Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | ForEach-Object { $_.Name }
"""


# FreeBSD / pfSense / OPNsense – chạy qua "sh -s" (shell sign-in of pfSense là menu rc.initial)
FREEBSD_SCRIPT = r"""
echo "##HOST"; hostname
echo "##OS"; if [ -f /etc/version ]; then echo "pfSense $(cat /etc/version) / $(uname -r)"; elif [ -f /usr/local/opnsense/version/core ]; then echo "OPNsense / $(uname -r)"; else uname -sr; fi
echo "##BOOT"; sysctl -n kern.boottime | sed 's/^{ sec = \([0-9]*\).*/\1/'; date +%s
echo "##NPROC"; sysctl -n hw.ncpu
echo "##CPT"; sysctl -n kern.cp_time; sleep 1; sysctl -n kern.cp_time
echo "##BMEM"; for k in hw.physmem hw.pagesize vm.stats.vm.v_page_count vm.stats.vm.v_inactive_count vm.stats.vm.v_cache_count vm.stats.vm.v_free_count; do echo "$k $(sysctl -n $k 2>/dev/null || echo 0)"; done
echo "##SWAP"; swapinfo -k 2>/dev/null | awk 'NR>1 {t+=$2; u+=$3} END {print t+0, u+0}'
echo "##BDISK"; df -kT 2>/dev/null | awk 'NR>1 {print $1, $2, $3, $4, $5, $7}'
"""
SKIP_BSD_FS = {"devfs", "tmpfs", "fdescfs", "procfs", "linprocfs", "nullfs", "autofs", "cd9660", "unionfs", "mfs"}


def parse_freebsd(s: dict) -> dict:
    """Section dict → {cpu, mem, mem_total_gb, swap, disks, uptime_s, nproc}. RAM theo công thức Dashboard pfSense."""
    out: dict = {"disks": []}
    try:
        boot, nowt = [int(x) for x in (s.get("BOOT") or [])[:2]]
        out["uptime_s"] = nowt - boot
    except Exception:
        pass
    try:
        out["nproc"] = int((s.get("NPROC") or ["1"])[0])
    except ValueError:
        pass
    try:
        a, b = [[int(x) for x in l.split()] for l in (s.get("CPT") or [])[:2]]   # user nice sys intr idle
        dt = sum(b) - sum(a)
        out["cpu"] = round((1 - (b[4] - a[4]) / dt) * 100, 1) if dt > 0 else None
    except Exception:
        pass
    m = {}
    for line in s.get("BMEM", []):
        p = line.split()
        if len(p) == 2 and p[1].isdigit():
            m[p[0]] = int(p[1])
    pages = m.get("vm.stats.vm.v_page_count", 0)
    if pages:
        used = pages - (m.get("vm.stats.vm.v_inactive_count", 0) + m.get("vm.stats.vm.v_cache_count", 0) + m.get("vm.stats.vm.v_free_count", 0))
        out["mem"] = max(0.0, used / pages * 100)
        out["mem_total_gb"] = (m.get("hw.physmem") or pages * (m.get("hw.pagesize") or 4096)) / 1073741824
    try:
        t, u = [int(x) for x in (s.get("SWAP") or ["0 0"])[0].split()[:2]]
        if t:
            out["swap"] = u / t * 100
    except ValueError:
        pass
    pools: dict = {}
    for line in s.get("BDISK", []):
        p = line.split()
        if len(p) < 6 or not p[2].isdigit():
            continue
        dev, fstype, size, used, avail, mount = p[0], p[1].lower(), int(p[2]), int(p[3]), int(p[4]), p[5]
        if fstype in SKIP_BSD_FS or not size or mount.startswith(("/dev", "/proc")):
            continue
        if fstype == "zfs":
            pool = dev.split("/")[0]
            z = pools.setdefault(pool, {"used": 0, "avail": avail, "mounts": []})
            z["used"] += used
            z["avail"] = avail
            z["mounts"].append(mount)
            continue
        out["disks"].append({"name": mount, "mount": mount, "pct": round(used / (used + avail) * 100, 1) if used + avail else 0,
                             "size_gb": round(size / 1048576, 1), "used_gb": round(used / 1048576, 1)})
    for pool, z in pools.items():
        total = z["used"] + z["avail"]
        if total:
            label = "/" if "/" in z["mounts"] else sorted(z["mounts"], key=len)[0]
            out["disks"].append({"name": f"{label} (zfs {pool})", "mount": label, "pct": round(z["used"] / total * 100, 1),
                                 "size_gb": round(total / 1048576, 1), "used_gb": round(z["used"] / 1048576, 1)})
    return out


async def freebsd_resources(target: str, cfg: dict, prefix: str = "") -> dict:
    """Đăng nhập SSH and đọc tài nguyên FreeBSD/pfSense. prefix='cli_' khi dùng kèm check pfSense (SNMP + CLI)."""
    kw = dict(host=target, port=int(cfg.get(f"{prefix}port") or 22), username=cfg.get(f"{prefix}username") or "admin",
              known_hosts=None, connect_timeout=float(cfg.get("timeout", 10)))
    if cfg.get(f"{prefix}private_key"):
        kw["client_keys"] = [asyncssh.import_private_key(cfg[f"{prefix}private_key"])]
    if cfg.get(f"{prefix}password"):
        kw["password"] = cfg[f"{prefix}password"]
    async with asyncssh.connect(**kw) as conn:
        r = await asyncio.wait_for(conn.run("sh -s", input=FREEBSD_SCRIPT, check=False), timeout=30)
    s = _sections(r.stdout or "")
    out = parse_freebsd(s)
    out["hostname"] = (s.get("HOST") or [""])[0]
    out["os"] = (s.get("OS") or [""])[0]
    if "mem" not in out and "cpu" not in out:
        raise RuntimeError(f"unable to read metrics (shell returned: {(r.stdout or r.stderr or '')[:120]!r})")
    return out


def windows_command() -> str:
    import base64
    return "powershell -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(WINDOWS_PS.encode("utf-16-le")).decode()


def parse_windows(s: dict) -> dict:
    """Section dict (##WCPU/##WMEM/##WDISK) → {cpu, mem, mem_total_gb, disks, stopped_services}."""
    out = {"disks": []}
    try:
        out["cpu"] = float((s.get("WCPU") or [""])[0])
    except ValueError:
        pass
    try:
        total, free = [int(x) for x in (s.get("WMEM") or [""])[0].split()[:2]]
        out["mem"] = (total - free) / total * 100
        out["mem_total_gb"] = total / 1048576
    except (ValueError, ZeroDivisionError):
        pass
    for line in s.get("WDISK", []):
        p = line.split()
        if len(p) == 3 and p[1].isdigit() and p[2].isdigit() and int(p[1]):
            size, free = int(p[1]), int(p[2])
            out["disks"].append({"name": p[0], "mount": p[0], "pct": round((size - free) / size * 100, 1),
                                 "size_gb": round(size / 1073741824, 1), "used_gb": round((size - free) / 1073741824, 1)})
    out["stopped_services"] = [x.strip() for x in s.get("WSVC", []) if x.strip()]
    return out


def _sections(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("##"):
            cur = line[2:].strip()
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out


HYPERV_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$h=Get-VMHost
$vms=@(Get-VM | ForEach-Object {
  $v=$_
  $ips=@($v.NetworkAdapters.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' })
  $snaps=@(Get-VMSnapshot -VM $v)
  $old=$null
  if($snaps.Count){ $old=[int]((Get-Date)-($snaps | Sort-Object CreationTime | Select-Object -First 1).CreationTime).TotalDays }
  $vhd=@(Get-VHD -VMId $v.VMId)
  [ordered]@{name=$v.Name;id="$($v.VMId)";state="$($v.State)";cpu=$v.CPUUsage;vcpu=$v.ProcessorCount;
    mem_assigned=$v.MemoryAssigned;mem_startup=$v.MemoryStartup;mem_demand=$v.MemoryDemand;dynamic=$v.DynamicMemoryEnabled;
    uptime=[int]$v.Uptime.TotalSeconds;gen=$v.Generation;ips=$ips;snaps=$snaps.Count;oldest=$old;heartbeat="$($v.Heartbeat)";
    vhd_size=($vhd | Measure-Object Size -Sum).Sum;vhd_file=($vhd | Measure-Object FileSize -Sum).Sum}
})
"##HV "+(@{host=@{cores=$h.LogicalProcessorCount;mem=$h.MemoryCapacity};vms=$vms} | ConvertTo-Json -Compress -Depth 4)
"""
HV_POWER = {"Running": "up", "Off": "off", "Saved": "off", "Paused": "off", "Starting": "warning", "Stopping": "warning"}


def parse_hyperv(text: str, warn_days: int = 7) -> tuple[list, dict, list]:
    """Trả (discovered VM, thông tin host, ghi chú). VM gắn dưới assets of check (host Hyper-V)."""
    line = next((l for l in (text or "").splitlines() if l.startswith("##HV ")), "")
    if not line:
        return [], {}, ["Unable to read Hyper-V (the Hyper-V role is not installed or the user lacks Hyper-V Administrators permissions)"]
    try:
        js = json.loads(line[5:])
    except ValueError:
        return [], {}, ["Invalid Hyper-V data"]
    vms = js.get("vms") or []
    if isinstance(vms, dict):
        vms = [vms]
    out, notes = [], []
    for v in vms:
        run = v.get("state") == "Running"
        ma, md = v.get("mem_assigned") or 0, v.get("mem_demand") or 0
        vres = {}
        if run:
            if v.get("cpu") is not None:
                vres["cpu"] = float(v["cpu"])
            if ma:
                vres["mem"] = round(md / ma * 100, 1)
                vres["mem_total_gb"] = round(ma / 1073741824, 1)
        ips = v.get("ips") or []
        if isinstance(ips, str):
            ips = [ips]
        out.append({"key": f"hv:{v.get('id')}", "type": "vm", "name": v.get("name"), "status": HV_POWER.get(v.get("state"), "unknown"),
                    "ip": ips[0] if ips else "", "os": f"Hyper-V Gen {v.get('gen')}",
                    "meta": {"platform": "hyperv", "kind": "hyperv", "power": v.get("state"), "vcpu": v.get("vcpu"),
                             "mem_mb": round(max(ma, v.get("mem_startup") or 0) / 1048576), "dynamic_mem": v.get("dynamic"),
                             "uptime_s": v.get("uptime"), "ips": ips, "snapshots": v.get("snaps"), "oldest_snapshot_days": v.get("oldest"),
                             "heartbeat": v.get("heartbeat"), "disk_alloc_gb": round((v.get("vhd_size") or 0) / 1073741824, 1),
                             "disk_file_gb": round((v.get("vhd_file") or 0) / 1073741824, 1), "res": vres or None}})
        if v.get("oldest") is not None and v["oldest"] > warn_days:
            notes.append(f"VM {v.get('name')} has a snapshot {v['oldest']} days")
    h = js.get("host") or {}
    return out, {"cores": h.get("cores"), "mem_gb": round((h.get("mem") or 0) / 1073741824)}, notes


def custom_command_allowed() -> bool:
    """Lệnh SSH tuỳ chỉnh chạy BẤT KỲ lệnh nào bằng account đã lưu → mặc định disabled. Bật: ALLOW_SSH_COMMAND=1."""
    import os
    return os.environ.get("ALLOW_SSH_COMMAND", "0").strip().lower() in ("1", "true", "yes", "on")


async def ssh(target: str, cfg: dict) -> Result:
    if str(cfg.get("command") or "").strip() and not custom_command_allowed():
        return Result("fail", "Custom SSH commands are locked (ALLOW_SSH_COMMAND is not enabled). Leave the command field empty to use the default collector.")
    kw = dict(host=target, port=int(cfg.get("port", 22)), username=cfg.get("username", "root"), known_hosts=None,
              connect_timeout=float(cfg.get("timeout", 10)))
    if cfg.get("private_key"):
        kw["client_keys"] = [asyncssh.import_private_key(cfg["private_key"])]
    if cfg.get("password"):
        kw["password"] = cfg["password"]
    t0 = time.perf_counter()
    if cfg.get("platform") == "freebsd" and not cfg.get("command"):
        try:
            b = await freebsd_resources(target, cfg)
        except Exception as e:
            return Result("fail", f"SSH error: {type(e).__name__} {e}"[:300])
        ms = (time.perf_counter() - t0) * 1000
        data, statuses, notes = {"hostname": b.get("hostname"), "os": b.get("os"), "nproc": b.get("nproc"), "disks": b["disks"]}, ["ok"], []
        if b.get("uptime_s"):
            data["uptime"] = f"{b['uptime_s'] // 86400}d {b['uptime_s'] % 86400 // 3600}h"
        metrics = apply_resources(data, cfg, statuses, notes, cpu=b.get("cpu"), mem=b.get("mem"), disks=b["disks"],
                                  mem_total_gb=b.get("mem_total_gb"), swap=b.get("swap"), cores=b.get("nproc"))
        msg = " · ".join([data.get("hostname") or target, f"up {data.get('uptime', '?')}"] + notes)
        return Result(worst(*statuses), msg, ms, metrics.get("cpu"), data)
    try:
        async with asyncssh.connect(**kw) as conn:
            ms = (time.perf_counter() - t0) * 1000
            command = cfg.get("command") or (windows_command() if cfg.get("platform") == "windows" else LINUX_SCRIPT)
            r = await asyncio.wait_for(conn.run(command, check=False), timeout=30)
            win_ev = hv_out = None
            if cfg.get("platform") == "windows" and cfg.get("hyperv") and not cfg.get("command"):
                hv_r = await asyncio.wait_for(conn.run("powershell -NoProfile -NonInteractive -EncodedCommand " +
                                                       base64.b64encode(HYPERV_PS.encode("utf-16-le")).decode(), check=False), timeout=60)
                hv_out = hv_r.stdout or ""
            if cfg.get("platform") == "windows" and cfg.get("win_events") and not cfg.get("command"):
                from .winevents import collect as win_collect
                try:
                    win_ev = await win_collect(conn, target, "")
                except Exception as e:   # đọc event error không làm check SSH error
                    win_ev = (0, [f"Windows Event read error: {type(e).__name__} {e}"[:200]])
    except Exception as e:
        return Result("fail", f"SSH error: {type(e).__name__} {e}"[:300])

    out = r.stdout or ""
    if cfg.get("command"):  # lệnh tuỳ chỉnh: exit code 0 = ok, 1 = warn, khác = fail
        st = "ok" if r.exit_status == 0 else "warn" if r.exit_status == 1 else "fail"
        num = re.search(r"-?\d+(\.\d+)?", out)
        return Result(st, (out.strip() or f"exit {r.exit_status}")[:300], ms, float(num.group()) if num else None, {"output": out[:2000]})

    s = _sections(out)
    data, notes, statuses = {}, [], ["ok"]
    data["hostname"] = (s.get("HOST") or [""])[0]
    data["os"] = (s.get("OS") or [""])[0]
    try:
        up = float((s.get("UPTIME") or ["0"])[0].split()[0])
        d, h = int(up // 86400), int(up % 86400 // 3600)
        data["uptime"] = f"{d}d {h}h"
    except Exception:
        pass
    try:
        load1 = float((s.get("LOAD") or ["0"])[0].split()[0])
        nproc = int((s.get("NPROC") or ["1"])[0])
        data["load1"], data["nproc"] = load1, nproc
        if load1 > nproc * float(cfg.get("load_warn_factor", 2)):
            statuses.append("warn"); notes.append(f"load cao {load1}")
    except Exception:
        pass
    if cfg.get("platform") == "windows":
        try:
            up = int((s.get("UPTIME") or ["0"])[0]); data["uptime"] = f"{up // 86400}d {up % 86400 // 3600}h"
            data["nproc"] = int((s.get("NPROC") or ["1"])[0])
        except ValueError:
            pass
        w = parse_windows(s)
        data["disks"] = w["disks"]
        metrics = apply_resources(data, cfg, statuses, notes, cpu=w.get("cpu"), mem=w.get("mem"), disks=w["disks"],
                                  mem_total_gb=w.get("mem_total_gb"), cores=data.get("nproc"))
        must = [x.strip().lower() for x in str(cfg.get("watch_services", "")).split(",") if x.strip()]
        bad = [x for x in w["stopped_services"] if x.lower() in must]
        if bad:
            statuses.append("fail"); notes.append("Stopped services: " + ", ".join(bad))
        data["stopped_services"] = w["stopped_services"][:50]
        if win_ev is not None:
            data["win_events"] = {"read": win_ev[0], "notes": win_ev[1]}
            for n in win_ev[1]:
                statuses.append("warn"); notes.append(n)
        discovered = []
        if hv_out is not None:
            discovered, hv_host, hv_notes = parse_hyperv(hv_out, int(cfg.get("snapshot_warn_days", 7)))
            on = sum(1 for d in discovered if d["status"] == "up")
            data["hyperv"] = {"vm_total": len(discovered), "vm_on": on, **hv_host}
            notes.insert(0, f"Hyper-V {on}/{len(discovered)} VMs running")
            for n in hv_notes:
                statuses.append("warn"); notes.append(n)
        msg = " · ".join([data.get("hostname") or target, f"up {data.get('uptime', '?')}"] + notes)
        return Result(worst(*statuses), msg, ms, metrics.get("cpu"), data, discovered)

    mem_pct = mem_total = swap = None
    for line in s.get("MEM", []):
        p = line.split()
        try:
            if p and p[0] == "swap":
                swap = int(p[2]) / int(p[1]) * 100 if int(p[1]) else None
            elif len(p) == 2:
                total, avail = int(p[0]), int(p[1])
                mem_pct = round((total - avail) / total * 100, 1) if total else None
                mem_total = total / 1024
        except (ValueError, ZeroDivisionError):
            pass
    data["mem_pct"] = mem_pct
    cpu = None
    try:
        a, b = [[int(x) for x in l.split()[1:]] for l in (s.get("CPU") or [])[:2]]
        idle = lambda v: v[3] + (v[4] if len(v) > 4 else 0)   # idle + iowait
        dt = sum(b) - sum(a)
        cpu = round((1 - (idle(b) - idle(a)) / dt) * 100, 1) if dt > 0 else None
    except Exception:
        pass
    disks = []
    for line in s.get("DISK", []):
        parts = line.split()
        if len(parts) >= 2 and parts[1].endswith("%"):
            d = {"mount": parts[0], "name": parts[0], "pct": int(parts[1][:-1])}
            if len(parts) >= 4 and parts[2].isdigit():
                d["size_gb"] = round(int(parts[2]) / 1048576, 1)
                d["used_gb"] = round(int(parts[3]) / 1048576, 1)
            disks.append(d)
    data["disks"] = disks
    metrics = apply_resources(data, cfg, statuses, notes, cpu=cpu, mem=mem_pct, disks=disks, mem_total_gb=mem_total,
                              swap=swap, cores=data.get("nproc"))
    max_disk = metrics.get("disk")
    containers = []
    for line in s.get("DOCKER", []):
        p = line.split("|")
        if len(p) == 3:
            containers.append({"name": p[0], "status": p[1], "image": p[2], "running": p[1].startswith("Up")})
    if containers:
        data["containers"] = containers
        stopped = [c["name"] for c in containers if not c["running"]]
        notes.append(f"{len(containers) - len(stopped)}/{len(containers)} running containers")
        must = [x.strip() for x in str(cfg.get("watch_containers", "")).split(",") if x.strip()]
        bad = [m for m in must if m in stopped or m not in [c["name"] for c in containers]]
        if bad:
            statuses.append("fail"); notes.append("Stopped containers: " + ", ".join(bad))

    discovered = []
    if cfg.get("discover_containers", True):
        for c in containers:
            discovered.append({"key": f"ctr:{c['name']}", "type": "container", "name": c["name"],
                               "status": "up" if c["running"] else "down", "os": c["image"],
                               "meta": {"platform": "docker", "kind": "docker", "status": c["status"], "power": "running" if c["running"] else "stopped"}})

    msg = " · ".join([data.get("hostname") or target, f"up {data.get('uptime', '?')}"] + notes)
    return Result(worst(*statuses), msg, ms, metrics.get("cpu") if metrics.get("cpu") is not None else (max_disk if max_disk is not None else mem_pct), data, discovered)
