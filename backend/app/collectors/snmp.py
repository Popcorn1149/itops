"""SNMP v2c/v3 cho switch, router, AP, UPS, NAS, iLO/iDRAC, pfSense (bsnmpd)...

Thu: sysName/sysDescr/uptime, bảng cổng (up/down, tốc độ, alias), CPU (HOST-RESOURCES),
cộng thêm theo profile: UPS (RFC1628), Synology. Có thể khai báo OID tuỳ chỉnh.
"""
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd, bulk_walk_cmd,
    usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol, usmNoAuthProtocol, usmNoPrivProtocol,
)

import re
import time

from .base import Result, apply_resources, fmt_uptime, worst

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0",
       "objid": "1.3.6.1.2.1.1.2.0"}
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IF_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
HR_UPTIME = "1.3.6.1.2.1.25.1.1.0"           # uptime của hệ điều hành (sysUpTime chỉ là uptime của dịch vụ SNMP)
IF_HC_IN, IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.31.1.1.1.10"   # bộ đếm 64-bit
IF_IN, IF_OUT = "1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.16"             # bộ đếm 32-bit (dự phòng)

# cổng ảo không tính vào "x/y cổng up"
VIRTUAL_IF = re.compile(r"^(lo\d*|pflog\d*|pfsync\d*|enc\d*|ipfw\d*|gif\d*|gre\d*|null\d*|Null\d*|loopback.*|InLoopBack.*|stf\d*|usbus\d*)$", re.I)
# cổng có khả năng là WAN: PPPoE, tên/alias chứa WAN hoặc tên nhà mạng
WAN_HINT = re.compile(r"(^pppoe\d*$|^wan|wan|fpt|vnpt|viettel|cmc|netnam|spt|isp|internet)", re.I)

# lưu bộ đếm lần trước để tính Mbps: {(target, ifIndex): (t, in_octets, out_octets)}
_COUNTERS: dict = {}


def compute_rates(target: str, t: float, counters: dict, bits: int = 64) -> dict:
    """Tính Mbps vào/ra cho từng cổng từ chênh lệch bộ đếm giữa 2 lần đọc. Xử lý tràn 32-bit / reset bộ đếm."""
    out = {}
    wrap = 2 ** bits
    for idx, (i, o) in counters.items():
        key = (target, idx)
        prev = _COUNTERS.get(key)
        _COUNTERS[key] = (t, i, o)
        if not prev or t - prev[0] <= 0:
            continue
        dt = t - prev[0]
        di, do = i - prev[1], o - prev[2]
        if di < 0:
            di = di + wrap if bits == 32 else None
        if do < 0:
            do = do + wrap if bits == 32 else None
        if di is None or do is None:   # bộ đếm reset (thiết bị khởi động lại) → bỏ qua lần này
            continue
        out[idx] = (round(di * 8 / dt / 1e6, 3), round(do * 8 / dt / 1e6, 3))
    return out

PROFILE_OIDS = {
    "ups": {
        "battery_status": "1.3.6.1.2.1.33.1.2.1.0",  # 2 normal, 3 low, 4 depleted
        "battery_charge": "1.3.6.1.2.1.33.1.2.4.0",
        "runtime_min": "1.3.6.1.2.1.33.1.2.3.0",
        "output_source": "1.3.6.1.2.1.33.1.4.1.0",   # 3 normal, 5 battery
    },
    "synology": {
        "system_status": "1.3.6.1.4.1.6574.1.1.0",   # 1 normal
        "temperature": "1.3.6.1.4.1.6574.1.2.0",
        "power_status": "1.3.6.1.4.1.6574.1.3.0",
        "dsm_version": "1.3.6.1.4.1.6574.1.5.3.0",
    },
}

AUTH = {"SHA": usmHMACSHAAuthProtocol, "MD5": usmHMACMD5AuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol, "": usmNoAuthProtocol}
PRIV = {"AES": usmAesCfb128Protocol, "DES": usmDESPrivProtocol, "": usmNoPrivProtocol}


def _auth(cfg: dict):
    if str(cfg.get("version", "2c")) == "3":
        return UsmUserData(
            cfg.get("username", ""),
            authKey=cfg.get("password") or None,
            privKey=cfg.get("priv_key") or None,
            authProtocol=AUTH.get(cfg.get("auth_protocol", "SHA"), usmHMACSHAAuthProtocol) if cfg.get("password") else usmNoAuthProtocol,
            privProtocol=PRIV.get(cfg.get("priv_protocol", "AES"), usmAesCfb128Protocol) if cfg.get("priv_key") else usmNoPrivProtocol,
        )
    return CommunityData(cfg.get("community") or "public", mpModel=1)


def _val(v):
    s = v.prettyPrint()
    try:
        return int(s)
    except ValueError:
        return s


async def _get(engine, auth, tgt, oids: dict) -> dict:
    err, stat, _, binds = await get_cmd(engine, auth, tgt, ContextData(), *[ObjectType(ObjectIdentity(o)) for o in oids.values()])
    if err:
        raise RuntimeError(str(err))
    out = {}
    for (k, _), (_, v) in zip(oids.items(), binds, strict=False):
        if v.__class__.__name__ not in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            out[k] = _val(v)
    return out


async def _walk(engine, auth, tgt, oid: str, limit: int = 2000) -> dict:
    out = {}
    async for err, stat, _, binds in bulk_walk_cmd(engine, auth, tgt, ContextData(), 0, 30, ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
        if err or stat:
            break
        for name, v in binds:
            out[str(name)[len(oid) + 1:]] = _val(v)
        if len(out) >= limit:
            break
    return out


# ---- tài nguyên
HR_ST = "1.3.6.1.2.1.25.2.3.1"           # hrStorageTable: .2 type .3 descr .4 unit .5 size .6 used
ST_RAM, ST_VMEM, ST_DISK, ST_FLASH, ST_NET = "25.2.1.2", "25.2.1.3", "25.2.1.4", "25.2.1.9", "25.2.1.10"
SKIP_MOUNT = re.compile(r"^(/dev|/proc|/sys|/run|/snap|/var/run|/boot/efi|/System/Volumes|/private/var/vm)(/|$)|devfs|tmpfs|^/mnt/cdrom", re.I)
UCD_MEM = {"total": "1.3.6.1.4.1.2021.4.5.0", "avail": "1.3.6.1.4.1.2021.4.6.0", "buf": "1.3.6.1.4.1.2021.4.14.0",
           "cached": "1.3.6.1.4.1.2021.4.15.0", "idle": "1.3.6.1.4.1.2021.11.11.0", "swap_total": "1.3.6.1.4.1.2021.4.3.0",
           "swap_avail": "1.3.6.1.4.1.2021.4.4.0"}
CISCO_CPU = ["1.3.6.1.4.1.9.9.109.1.1.1.1.8", "1.3.6.1.4.1.9.9.109.1.1.1.1.5"]   # cpmCPUTotal5minRev / 5min (IOS cũ)
CISCO_MEM_USED, CISCO_MEM_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.5", "1.3.6.1.4.1.9.9.48.1.1.1.6"
CISCO_MEM2_USED, CISCO_MEM2_FREE = "1.3.6.1.4.1.9.9.109.1.1.1.1.12", "1.3.6.1.4.1.9.9.109.1.1.1.1.13"  # KB (IOS-XE / Nexus)
HP_CPU = "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0"
HP_MEM_TOTAL, HP_MEM_FREE = "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5", "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6"


def _u32(v):
    """hrStorageSize/Used là Integer32 – ổ lớn bị tràn thành số âm."""
    return v + 2 ** 32 if isinstance(v, int) and v < 0 else v


HR_MEMSIZE = "1.3.6.1.2.1.25.2.2.0"     # hrMemorySize (KB) – tổng RAM vật lý
FS_DESCR = re.compile(r"^(?P<mount>[^,]+), type: (?P<fstype>[\w.-]+)(?:, dev: (?P<dev>.*))?$")   # bsnmpd (FreeBSD/pfSense)
SKIP_FSTYPE = {"devfs", "tmpfs", "fdescfs", "procfs", "linprocfs", "nullfs", "mfs", "md", "autofs", "cd9660", "unionfs"}


def parse_storage(rows: dict, mem_size_kb: int | None = None) -> dict:
    """rows: {idx: {type, descr, unit, size, used}} → {mem, mem_total_gb, swap, disks, mem_note?}.

    Hỗ trợ net-snmp (Linux/Synology), Windows, và bsnmpd của FreeBSD/pfSense (dữ liệu RAM/disk theo kiểu riêng).
    """
    out = {"disks": []}
    by_descr = {str(r.get("descr", "")).lower(): r for r in rows.values()}
    bsd_real = by_descr.get("real memory metrics")
    if bsd_real:
        # bsnmpd: size = RAM tiến trình đang dùng (vmtotal.t_rm), không phải tổng → chia cho hrMemorySize.
        # Các dòng RAM khác là bộ nhớ kernel (malloc type) – bỏ qua.
        if mem_size_kb and isinstance(bsd_real.get("size"), int):
            used_kb = bsd_real["size"] * (bsd_real.get("unit") or 4096) / 1024
            out["mem"] = min(100.0, used_kb / mem_size_kb * 100)
            out["mem_total_gb"] = mem_size_kb / 1048576
            out["mem_note"] = "RAM tiến trình đang dùng (SNMP của pfSense/FreeBSD không tính wired/ARC)"
    else:
        ram = [r for r in rows.values() if str(r.get("type", "")).endswith(ST_RAM) and r.get("size")]
        if ram:
            r = max(ram, key=lambda x: x["size"])
            unit = r.get("unit") or 1
            used = r["used"]
            # net-snmp (Linux/Synology): "Physical memory" gồm cả buffer/cache → trừ ra cho giống free/htop
            for name in ("memory buffers", "cached memory"):
                b = by_descr.get(name)
                if b and isinstance(b.get("used"), int) and (b.get("unit") or 1) == unit:
                    used -= b["used"]
            used = max(used, 0)
            out["mem"] = used / r["size"] * 100
            out["mem_total_gb"] = r["size"] * unit / 1073741824
        elif mem_size_kb:
            out["mem_total_gb"] = mem_size_kb / 1048576
    vm = [r for r in rows.values() if str(r.get("type", "")).endswith(ST_VMEM) and r.get("size")
          and "swap" in str(r.get("descr", "")).lower()]
    if vm:
        out["swap"] = sum(r["used"] * (r.get("unit") or 1) for r in vm) / sum(r["size"] * (r.get("unit") or 1) for r in vm) * 100
    seen = set()
    pools: dict = {}      # ZFS: gom các dataset cùng pool thành 1 dòng
    for r in rows.values():
        t = str(r.get("type", ""))
        name = str(r.get("descr", "")).strip()
        m_fs = FS_DESCR.match(name)
        is_fs_type = ".25.3.9." in t or t.startswith("1.3.6.1.2.1.25.3.9")   # bsnmpd ghi kiểu hệ thống tệp (hrFS*)
        if not (t.endswith(ST_DISK) or t.endswith(ST_FLASH) or t.endswith(ST_NET) or is_fs_type or m_fs):
            continue
        if not r.get("size"):
            continue
        unit = r.get("unit") or 1
        if m_fs:
            fstype = m_fs["fstype"].lower()
            if fstype in SKIP_FSTYPE:
                continue
            name = m_fs["mount"].strip()
            if fstype == "zfs" and m_fs["dev"]:
                pool = m_fs["dev"].split("/")[0]
                p = pools.setdefault(pool, {"used": 0, "avail": None, "mounts": []})
                p["used"] += r["used"] * unit
                p["avail"] = (r["size"] - r["used"]) * unit
                p["mounts"].append(name)
                continue
        if SKIP_MOUNT.search(name):
            continue
        # Windows: "C:\\ Label:OS  Serial Number 1234" → "C:"
        m = re.match(r"^([A-Za-z]:)\\", name)
        if m:
            name = m.group(1)
        key = (r["size"], r["used"])          # nhiều mount chung 1 thiết bị (btrfs, bind) → giữ 1 dòng
        if key in seen:
            continue
        seen.add(key)
        out["disks"].append({"name": name, "pct": r["used"] / r["size"] * 100,
                             "size_gb": round(r["size"] * unit / 1073741824, 1), "used_gb": round(r["used"] * unit / 1073741824, 1)})
    for pool, p in pools.items():
        total = p["used"] + (p["avail"] or 0)
        if total:
            label = "/" if "/" in p["mounts"] else sorted(p["mounts"], key=len)[0]
            out["disks"].append({"name": f"{label} (zfs {pool})", "pct": p["used"] / total * 100,
                                 "size_gb": round(total / 1073741824, 1), "used_gb": round(p["used"] / 1073741824, 1)})
    return out


async def read_resources(engine, auth, tgt) -> dict:
    """CPU/RAM/Disk theo thứ tự ưu tiên: HOST-RESOURCES-MIB → UCD (Linux) → Cisco → HP/Aruba."""
    res: dict = {}
    cpu = await _walk(engine, auth, tgt, HR_CPU, 256)
    loads = [v for v in cpu.values() if isinstance(v, int)]
    if loads:
        res["cpu"] = sum(loads) / len(loads)
        res["cores"] = len(loads)

    # UCD-SNMP-MIB (net-snmp: Linux, Synology, gói NET-SNMP trên pfSense/FreeBSD) – chính xác nhất, ưu tiên dùng
    try:
        u = await _get(engine, auth, tgt, UCD_MEM)
    except Exception:
        u = {}
    try:
        msz = (await _get(engine, auth, tgt, {"m": HR_MEMSIZE})).get("m")
        msz = msz if isinstance(msz, int) and msz > 0 else None
    except Exception:
        msz = None
    ucd = {k: v for k, v in u.items() if isinstance(v, int)}
    if ucd.get("total", 0) > 0 and "avail" in ucd:
        # memAvailReal = trang trống; cộng buffer + cache (Linux) / inactive (FreeBSD) → giống "available" của free / Dashboard pfSense
        free = ucd["avail"] + ucd.get("buf", 0) + ucd.get("cached", 0)
        res["mem"] = max(0.0, (ucd["total"] - min(free, ucd["total"])) / ucd["total"] * 100)
        res["mem_total_gb"] = ucd["total"] / 1048576
        res["mem_src"] = "UCD-SNMP"
        if ucd.get("swap_total", 0) > 0 and "swap_avail" in ucd:
            res["swap"] = (ucd["swap_total"] - ucd["swap_avail"]) / ucd["swap_total"] * 100
    if "cpu" not in res and "idle" in ucd:
        res["cpu"] = 100 - ucd["idle"]

    cols = {}
    for c, k in (("2", "type"), ("3", "descr"), ("4", "unit"), ("5", "size"), ("6", "used")):
        for idx, v in (await _walk(engine, auth, tgt, f"{HR_ST}.{c}", 500)).items():
            cols.setdefault(idx, {})[k] = _u32(v) if k in ("size", "used") else v
    if cols:
        st = parse_storage(cols, msz)
        res["disks"] = st["disks"]
        from_storage = "mem" not in res and "mem" in st
        for k in ("mem", "mem_total_gb", "swap"):
            if k in st and k not in res:
                res[k] = st[k]
        if from_storage:                      # chỉ khi RAM thật sự lấy từ hrStorage mới kèm ghi chú "ước tính"
            res["mem_src"] = "HOST-RESOURCES"
            if st.get("mem_note"):
                res["mem_note"] = st["mem_note"]
    if msz:
        res["mem_total_gb"] = msz / 1048576     # hrMemorySize là tổng RAM vật lý đáng tin nhất
    # dữ liệu thô để chẩn đoán khi số liệu lệch (hiện trong "Chẩn đoán SNMP")
    def _short(t):
        t = str(t)
        for suf, n in ((ST_RAM, "ram"), (ST_VMEM, "vmem"), (ST_DISK, "disk"), (ST_FLASH, "flash"), (ST_NET, "netdisk"), ("25.2.1.1", "other")):
            if t.endswith(suf):
                return n
        return "fs" if "25.3.9." in t else t[-14:]
    diag_rows = []
    for r in cols.values():
        unit = r.get("unit") or 1
        if isinstance(r.get("size"), int):
            diag_rows.append({"descr": str(r.get("descr", ""))[:70], "type": _short(r.get("type", "")),
                              "size_mb": round(r["size"] * unit / 1048576, 1), "used_mb": round((r.get("used") or 0) * unit / 1048576, 1)})
    diag_rows.sort(key=lambda x: (x["type"] not in ("ram", "vmem", "disk", "fs"), -x["size_mb"]))
    res["_diag"] = {"hr_memory_mb": round(msz / 1024) if msz else None,
                    "ucd_mb": {k: round(v / 1024) for k, v in ucd.items() if k not in ("idle",)} or None,
                    "storage": diag_rows[:40], "storage_count": len(diag_rows)}

    if "cpu" not in res:   # Cisco
        for oid in CISCO_CPU:
            v = [x for x in (await _walk(engine, auth, tgt, oid, 16)).values() if isinstance(x, int)]
            if v:
                res["cpu"] = max(v); break
    if "mem" not in res:
        for uo, fo, scale in ((CISCO_MEM_USED, CISCO_MEM_FREE, 1), (CISCO_MEM2_USED, CISCO_MEM2_FREE, 1024)):
            used, free = await _walk(engine, auth, tgt, uo, 16), await _walk(engine, auth, tgt, fo, 16)
            if used:
                idx = sorted(used)[0]          # pool đầu tiên = Processor
                u, f = used.get(idx), free.get(idx)
                if isinstance(u, int) and isinstance(f, int) and u + f:
                    res["mem"] = u / (u + f) * 100
                    res["mem_total_gb"] = (u + f) * scale / 1073741824
                    break
    if "cpu" not in res or "mem" not in res:   # HP ProCurve / Aruba
        try:
            h = await _get(engine, auth, tgt, {"cpu": HP_CPU, "total": HP_MEM_TOTAL, "free": HP_MEM_FREE})
        except Exception:
            h = {}
        if "cpu" not in res and isinstance(h.get("cpu"), int):
            res["cpu"] = h["cpu"]
        if "mem" not in res and isinstance(h.get("total"), int) and h["total"] > 0 and isinstance(h.get("free"), int):
            res["mem"] = (h["total"] - h["free"]) / h["total"] * 100
            res["mem_total_gb"] = h["total"] / 1073741824
    return res


# ---- máy ảo trên ESXi (VMWARE-VMINFO-MIB): tên, HĐH, RAM cấp, trạng thái nguồn, vCPU. Không có hiệu năng từng VM.
VMW_VM = "1.3.6.1.4.1.6876.2.1.1"   # .2 tên .3 file cấu hình .4 HĐH .5 RAM (MB) .6 power .8 guest state .9 vCPU .10 UUID
VMW_POWER = {"poweredon": "up", "on": "up", "poweredoff": "off", "off": "off", "suspended": "off"}


def parse_vminfo(rows: dict) -> list[dict]:
    """rows: {"<cột>.<idx>": giá trị} từ walk VMW_VM → danh sách VM để đưa lên bản đồ (gắn dưới host của check)."""
    vms: dict[str, dict] = {}
    for k, v in rows.items():
        col, _, idx = k.partition(".")
        if idx:
            vms.setdefault(idx, {})[col] = v
    out = []
    for idx, c in sorted(vms.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        name = str(c.get("2") or "").strip()
        if not name:
            continue
        power = str(c.get("6") or "").strip()
        guest = str(c.get("8") or "").strip().lower()
        status = VMW_POWER.get(power.lower()) or ("up" if guest == "running" else "off" if guest in ("notrunning", "off") else "unknown")
        uuid = str(c.get("10") or "").strip()
        out.append({"key": f"vmw:{uuid or c.get('3') or name}", "type": "vm", "name": name, "status": status, "os": str(c.get("4") or "")[:128],
                    "meta": {"platform": "esxi", "kind": "vm", "power": "poweredOn" if status == "up" else "poweredOff",
                             "vcpu": c.get("9") if isinstance(c.get("9"), int) else None,
                             "mem_mb": c.get("5") if isinstance(c.get("5"), int) else None, "guest_state": guest,
                             "config_file": str(c.get("3") or "")[:200], "via": "snmp"}})
    return out


async def _merge_esxi_perf(target: str, cfg: dict, vms: list[dict]):
    """Gọi API ESXi (tài khoản chỉ đọc) lấy CPU/RAM/Disk, IP, VMware Tools của từng VM rồi gộp theo tên vào danh sách SNMP."""
    import importlib
    api = importlib.import_module("app.collectors.esxi")
    r = await api.esxi(target, {"username": cfg["esxi_user"], "password": cfg["esxi_password"], "port": int(cfg.get("esxi_port", 443)),
                                "verify_ssl": False, "timeout": 40, "snapshot_warn_days": 10 ** 6})
    api_vms = [d for d in (r.discovered or []) if d.get("type") == "vm"]
    if not api_vms:
        return f"API ESXi: {r.message}"[:160] if r.status == "fail" else "API ESXi không trả VM"
    if not vms:
        for d in api_vms:
            d.pop("parent_key", None)
            for k in ("snapshots", "oldest_snapshot_days"):
                d["meta"].pop(k, None)
        return api_vms
    by_name = {d["name"]: d for d in api_vms}
    hit = 0
    for v in vms:
        a = by_name.get(v["name"])
        if not a:
            continue
        hit += 1
        am = a.get("meta") or {}
        for k in ("res", "tools", "ips", "uptime_s", "disk_alloc_gb", "guest_os"):
            if am.get(k) not in (None, "", []):
                v["meta"][k] = am[k]
        if a.get("ip"):
            v["ip"] = a["ip"]
        if a.get("os") and len(a["os"]) > len(v.get("os") or ""):
            v["os"] = a["os"]
        v["meta"]["perf_via"] = "api"
    return f"hiệu năng {hit}/{len(vms)} VM qua API"


async def snmp(target: str, cfg: dict) -> Result:
    engine = SnmpEngine()
    try:
        tgt = await UdpTransportTarget.create((target, int(cfg.get("port", 161))), timeout=float(cfg.get("timeout", 3)), retries=int(cfg.get("retries", 1)))
        auth = _auth(cfg)
        try:
            sysinfo = await _get(engine, auth, tgt, SYS)
        except Exception as e:
            return Result("fail", f"SNMP không phản hồi: {e}"[:300])
        if not sysinfo:
            return Result("fail", "SNMP không phản hồi (sai community/ACL?)")

        data = {"sys_name": sysinfo.get("name", ""), "sys_descr": str(sysinfo.get("descr", ""))[:300],
                "location": sysinfo.get("location", ""), "uptime": fmt_uptime((sysinfo.get("uptime") or 0) / 100)}
        statuses = ["ok"]
        notes = []
        value = None

        # uptime thật của hệ điều hành (nếu có HOST-RESOURCES-MIB)
        try:
            hr = await _get(engine, auth, tgt, {"up": HR_UPTIME})
            if isinstance(hr.get("up"), int):
                data["uptime"] = fmt_uptime(hr["up"] / 100)
                data["snmp_uptime"] = fmt_uptime((sysinfo.get("uptime") or 0) / 100)
        except Exception:
            pass

        # interfaces
        if cfg.get("interfaces", True):
            descr = await _walk(engine, auth, tgt, IF_DESCR)
            oper = await _walk(engine, auth, tgt, IF_OPER)
            admin = await _walk(engine, auth, tgt, IF_ADMIN)
            names = await _walk(engine, auth, tgt, IF_NAME)
            alias = await _walk(engine, auth, tgt, IF_ALIAS)
            speed = await _walk(engine, auth, tgt, IF_SPEED)
            t_now = time.monotonic()
            bits = 64
            hc_in = await _walk(engine, auth, tgt, IF_HC_IN)
            hc_out = await _walk(engine, auth, tgt, IF_HC_OUT)
            if not hc_in:   # SNMP v1 hoặc thiết bị không có bộ đếm 64-bit
                bits = 32
                hc_in = await _walk(engine, auth, tgt, IF_IN)
                hc_out = await _walk(engine, auth, tgt, IF_OUT)
            counters = {i: (hc_in[i], hc_out.get(i, 0)) for i in hc_in if isinstance(hc_in[i], int) and isinstance(hc_out.get(i, 0), int)}
            rates = compute_rates(target, t_now, counters, bits)
            data["traffic_ready"] = bool(rates) or not counters

            ports = []
            for idx, d in descr.items():
                name = names.get(idx) or d
                al = alias.get(idx, "")
                o = "up" if oper.get(idx) == 1 else "down"
                a = "up" if admin.get(idx) == 1 else "down"
                r = rates.get(idx)
                p = {"idx": idx, "name": name, "alias": al, "oper": o, "admin": a, "speed": speed.get(idx, 0),
                     "in_mbps": r[0] if r else None, "out_mbps": r[1] if r else None,
                     "virtual": bool(VIRTUAL_IF.match(name)), "wan": bool(WAN_HINT.search(name) or WAN_HINT.search(al))}
                # status thực tế: SNMP báo down nhưng vẫn có lưu lượng (hay gặp với PPPoE/tunnel) → coi là đang chạy
                active = bool(r) and (r[0] + r[1]) > 0.0005
                p["state"] = "up" if o == "up" else ("active" if active else ("disabled" if a == "down" else "down"))
                ports.append(p)
            real = [p for p in ports if not p["virtual"] and p["admin"] == "up"]
            up = sum(1 for p in real if p["state"] in ("up", "active"))
            data["ports"] = ports[:300]
            data["ports_up"], data["ports_total"] = up, len(real)
            notes.append(f"{up}/{len(real)} cổng up")
            wans = [p for p in real if p["wan"]]
            if wans:
                w_up = [p for p in wans if p["state"] in ("up", "active")]
                data["wan_up"], data["wan_total"] = len(w_up), len(wans)
                if rates or not counters:
                    notes.append(f"WAN {len(w_up)}/{len(wans)}")
            if rates:
                tin = sum(p["in_mbps"] or 0 for p in real if not p["virtual"] and p["wan"]) if wans else None
                tout = sum(p["out_mbps"] or 0 for p in real if not p["virtual"] and p["wan"]) if wans else None
                if wans:
                    data["wan_in_mbps"], data["wan_out_mbps"] = round(tin, 2), round(tout, 2)
                    notes.append(f"WAN ↓{tin:.1f} ↑{tout:.1f} Mbps")
            elif counters:
                notes.append("đang đo lưu lượng (cần 2 lần đọc)")
            watch = [w.strip().lower() for w in str(cfg.get("watch_ports", "")).split(",") if w.strip()]
            def _watched(p):
                return p["name"].lower() in watch or p["alias"].lower() in watch or p["idx"] in watch
            # chỉ báo down khi chắc chắn: chưa có số liệu lưu lượng thì không kết luận cổng ảo/PPPoE là down
            down_watched = [p["alias"] or p["name"] for p in ports if _watched(p) and (
                p["state"] == "disabled" or (p["state"] == "down" and (rates or not p["wan"])))]
            if down_watched:
                statuses.append("fail")
                notes.append("Cổng quan trọng down: " + ", ".join(down_watched))

        # tài nguyên: CPU / RAM / Disk
        metrics = {}
        if cfg.get("resources", True):
            try:
                r = await read_resources(engine, auth, tgt)
            except Exception:
                r = {}
            diag = r.pop("_diag", None)
            mem_src = r.pop("mem_src", None)
            metrics = apply_resources(data, cfg, statuses, notes, **r)
            if diag:
                data["snmp_diag"] = {"sys_object_id": str(sysinfo.get("objid", "")), "mem_source": mem_src, **diag}
            if metrics.get("cpu") is not None:
                data["cpu"] = metrics["cpu"]
            value = metrics.get("cpu") if metrics.get("cpu") is not None else metrics.get("mem")

        # profile
        prof = cfg.get("profile", "generic")
        if prof in PROFILE_OIDS:
            extra = await _get(engine, auth, tgt, PROFILE_OIDS[prof])
            data.update(extra)
            if prof == "ups":
                if extra.get("output_source") == 5:
                    statuses.append("warn"); notes.append("UPS đang chạy pin")
                if extra.get("battery_status") in (3, 4):
                    statuses.append("fail"); notes.append("Pin yếu")
                if "battery_charge" in extra:
                    value = extra["battery_charge"]; notes.append(f"Pin {value}%")
            if prof == "synology":
                if extra.get("system_status") not in (None, 1):
                    statuses.append("fail"); notes.append("Synology báo lỗi hệ thống")
                if "temperature" in extra:
                    notes.append(f"{extra['temperature']}°C")

        # custom OIDs: [{name, oid, warn_above, fail_above}]
        for c in cfg.get("extra_oids", []) or []:
            try:
                r = await _get(engine, auth, tgt, {c["name"]: c["oid"]})
                v = r.get(c["name"])
                data[c["name"]] = v
                if isinstance(v, int):
                    if c.get("fail_above") not in (None, "") and v > float(c["fail_above"]):
                        statuses.append("fail"); notes.append(f"{c['name']}={v}")
                    elif c.get("warn_above") not in (None, "") and v > float(c["warn_above"]):
                        statuses.append("warn"); notes.append(f"{c['name']}={v}")
            except Exception:
                pass

        # máy ảo nếu là ESXi
        discovered = []
        is_vmware = str(sysinfo.get("objid", "")).startswith("1.3.6.1.4.1.6876") or "vmware" in data["sys_descr"].lower() or "esx" in data["sys_descr"].lower()
        if is_vmware and cfg.get("vm_inventory", True):
            vm_err, vm_rows = "", {}
            try:
                vm_rows = await _walk(engine, auth, tgt, VMW_VM, limit=6000)
                discovered = parse_vminfo(vm_rows)
            except Exception as e:
                vm_err = f"{type(e).__name__}: {e}"[:200]
            data["vm_inventory"] = {"rows": len(vm_rows), "vms": len(discovered), "error": vm_err,
                                    "sample": dict(list(vm_rows.items())[:12])}   # chẩn đoán
            # SNMP của ESXi không có hiệu năng từng VM → nếu có tài khoản ESXi chỉ đọc, lấy thêm CPU/RAM/Disk qua API và gộp vào
            if cfg.get("esxi_user") and cfg.get("esxi_password"):
                try:
                    perf_note = await _merge_esxi_perf(target, cfg, discovered)
                except Exception as e:
                    perf_note = f"API ESXi lỗi: {type(e).__name__} {e}"[:200]
                if isinstance(perf_note, list):
                    discovered = perf_note   # bảng VM SNMP trống → dùng danh sách từ API
                    perf_note = "hiệu năng VM qua API"
                ok = perf_note.startswith("hiệu năng")
                data["vm_perf"] = {"ok": ok, "note": perf_note}
                notes.append(perf_note)
                if not ok:
                    statuses.append("warn")
            if discovered:
                on = sum(1 for d in discovered if d["status"] == "up")
                data["vms"] = {"total": len(discovered), "on": on}
                notes.insert(0, f"{on}/{len(discovered)} VM chạy")
            else:
                notes.append("chưa đọc được danh sách VM qua SNMP" + (f" ({vm_err})" if vm_err else " (bảng VMWARE-VMINFO-MIB trống)"))

        msg = " · ".join([data["sys_name"] or target, f"uptime {data['uptime']}"] + notes)
        return Result(worst(*statuses), msg, None, value, data, discovered)
    finally:
        try:
            engine.close_dispatcher()
        except Exception:
            pass
