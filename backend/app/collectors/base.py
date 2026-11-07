from dataclasses import dataclass, field


@dataclass
class Result:
    status: str = "ok"          # ok | warn | fail
    message: str = ""
    latency: float | None = None  # ms
    value: float | None = None    # số chính để vẽ biểu đồ (CPU %, disk %, ...)
    data: dict = field(default_factory=dict)
    discovered: list = field(default_factory=list)  # tài sản phát hiện được (ESXi VMs...)
    down: bool | None = None      # True = không kết nối được thiết bị/dịch vụ (DOWN thật). None = tự suy ra


def worst(*statuses: str) -> str:
    order = {"ok": 0, "unknown": 1, "warn": 2, "fail": 3}
    return max(statuses, key=lambda s: order.get(s, 1)) if statuses else "unknown"


def fmt_uptime(seconds: float | int | None) -> str:
    if seconds is None:
        return ""
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    return f"{d}d {h}h" if d else f"{h}h {m}m"


# ---------------------------------------------------------------- tài nguyên CPU / RAM / Disk (dùng chung mọi collector)
# 3 mức vượt threshold kiểu OpManager + Rearm (giá trị phải xuống dưới mới đóng cảnh báo – chống bật/tắt liên tục).
LEVELS = ("attention", "trouble", "critical")
LEVEL_RANK = {"ok": 0, "attention": 1, "trouble": 2, "critical": 3}
LEVEL_NAME = {"attention": "Attention", "trouble": "Trouble", "critical": "Critical"}
RES_DEFAULTS = {
    "cpu": {"attention": 80, "trouble": 90, "critical": 95, "rearm": 75},
    "mem": {"attention": 85, "trouble": 92, "critical": 97, "rearm": 80},
    "disk": {"attention": 80, "trouble": 90, "critical": 95, "rearm": 75},
}
RES_LABEL = {"cpu": "CPU", "mem": "RAM", "disk": "Disk"}
_LEGACY = {"trouble": "warn", "critical": "fail"}   # khoá cũ: cpu_warn / cpu_fail …


def _num(v):
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def res_threshold(cfg: dict, key: str, level: str) -> float | None:
    """Threshold của 1 mức. Để trống/0 = tắt mức đó. Đọc được khoá cũ (cpu_warn/cpu_fail, datastore_warn/fail)."""
    level = {"warn": "trouble", "fail": "critical"}.get(level, level)
    names = [f"{key}_{level}"]
    if level in _LEGACY:
        names.append(f"{key}_{_LEGACY[level]}")
        if key == "disk":
            names.append(f"datastore_{_LEGACY[level]}")
    for k in names:
        if k in cfg:
            v = _num(cfg.get(k))
            return v if v else None
    if level == "attention" and any(f"{key}_{x}" in cfg for x in ("warn", "fail")) and f"{key}_attention" not in cfg:
        return None   # check cũ chỉ có 2 mức → không tự thêm mức Attention
    return float(RES_DEFAULTS[key][level])


def res_thresholds(cfg: dict) -> dict:
    return {f"{k}_{l}": res_threshold(cfg, k, l) for k in RES_DEFAULTS for l in (*LEVELS, "rearm")}


def level_of(cfg: dict, key: str, v) -> str | None:
    if v is None:
        return None
    for lv in ("critical", "trouble", "attention"):
        t = res_threshold(cfg, key, lv)
        if t is not None and v >= t:
            return lv
    return "ok"


def worst_level(levels) -> str:
    return max([x for x in levels if x] or ["ok"], key=lambda x: LEVEL_RANK.get(x, 0))


def apply_resources(data: dict, cfg: dict, statuses: list, notes: list, *, cpu=None, mem=None, disks=None,
                    mem_total_gb=None, swap=None, cores=None, disk_label: str = "Disk", mem_note: str | None = None) -> dict:
    """Chuẩn hoá số liệu tài nguyên vào data['res'] và xếp mức Attention/Trouble/Critical.

    Vượt threshold KHÔNG làm check lỗi (không tính vào uptime) – bộ lập lịch mở cảnh báo riêng cho từng chỉ số.
    `statuses` giữ để tương thích, không bị thay đổi.
    Trả về metrics {cpu, mem, disk} để lưu lịch sử.
    """
    cpu, mem = _num(cpu), _num(mem)
    clean = []
    for d in disks or []:
        p = _num(d.get("pct"))
        if p is None:
            continue
        clean.append({"name": str(d.get("name", "?"))[:80], "pct": round(p, 1),
                      "size_gb": d.get("size_gb"), "used_gb": d.get("used_gb")})
    clean.sort(key=lambda d: -d["pct"])
    disk = clean[0]["pct"] if clean else None
    res = {"cpu": round(cpu, 1) if cpu is not None else None, "mem": round(mem, 1) if mem is not None else None,
           "disk": disk, "disk_name": clean[0]["name"] if clean else None, "disks": clean[:40]}
    if mem_total_gb:
        res["mem_total_gb"] = round(float(mem_total_gb), 1)
    if swap is not None:
        res["swap"] = round(float(swap), 1)
    if cores:
        res["cores"] = cores
    if mem_note:
        res["mem_note"] = mem_note
    levels = {}
    for key, v in (("cpu", res["cpu"]), ("mem", res["mem"]), ("disk", disk)):
        if v is None:
            continue
        lv = level_of(cfg, key, v)
        levels[key] = lv
        label = (disk_label if key == "disk" else RES_LABEL[key]) + (f" {res['disk_name']}" if key == "disk" and (len(clean) > 1 or disk_label != "Disk") else "")
        if lv != "ok":
            notes.append(f"{label} {v:g}% ({LEVEL_NAME[lv]} ≥ {res_threshold(cfg, key, lv):g}%)")
        else:
            notes.append(f"{label} {v:g}%")
    for d in clean:
        d["level"] = level_of(cfg, "disk", d["pct"])
    extra = [d for d in clean[1:] if d["level"] not in (None, "ok")]
    if extra:
        notes.append("Ổ khác vượt threshold: " + ", ".join(f"{d['name']} {d['pct']:g}%" for d in extra[:3]))
    res["levels"] = levels
    res["level"] = worst_level(levels.values())
    if any(v is not None for v in (res["cpu"], res["mem"], disk)):
        data["res"] = res
    return {"cpu": res["cpu"], "mem": res["mem"], "disk": disk}


# ---------------------------------------------------------------- mức độ sự cố (kiểu OpManager)
# down      : không kết nối được (ping/SNMP/SSH/API không trả lời, web không truy cập được) – DUY NHẤT mức tính vào uptime
# critical  : kết nối được nhưng có lỗi nghiêm trọng (cổng quan trọng down, container dừng...) hoặc vượt threshold Critical
# trouble   : cảnh báo (độ trễ cao, vượt threshold Trouble...)
# attention : cần chú ý (vượt threshold Attention)
SEV_RANK = {None: 0, "ok": 0, "attention": 1, "trouble": 2, "warning": 2, "critical": 3, "down": 4}
SEV_NAME = {"attention": "Attention", "trouble": "Trouble", "warning": "Trouble", "critical": "Critical", "down": "DOWN"}


def max_sev(*sevs):
    s = max(sevs, key=lambda x: SEV_RANK.get(x, 0)) if sevs else None
    return None if s in (None, "ok") else s


def classify(res: "Result") -> tuple[str | None, bool]:
    """(mức của kết quả check – chưa tính tài nguyên, có phải DOWN thật không)."""
    if res.status == "fail":
        down = res.down if res.down is not None else not res.data   # không lấy được dữ liệu nào = không kết nối được
        return ("down" if down else "critical"), bool(down)
    if res.status == "warn":
        return "trouble", False
    return None, False


def status_of(sev: str | None, raw: str) -> str:
    """Màu/status của check: ok · warn (Attention/Trouble) · fail (Critical/DOWN) · unknown."""
    if raw == "unknown" and not sev:
        return "unknown"
    return "fail" if sev in ("critical", "down") else "warn" if sev else "ok"
