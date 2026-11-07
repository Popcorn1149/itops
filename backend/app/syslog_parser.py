"""Phân tích dòng syslog: RFC5424, RFC3164 (BSD), biến thể pfSense / Cisco IOS / ESXi / Synology."""
import re

SEVERITY = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
SEV_VI = ["Khẩn cấp", "Báo động", "Nghiêm trọng", "Lỗi", "Cảnh báo", "Lưu ý", "Thông tin", "Debug"]

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+) ?(.*)$", re.S)
_BSD_TS = re.compile(r"^(?:\*|\.)?([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d(?:\.\d+)?(?: \d{4})?)(?: [A-Z]{2,5})?:? ")
_ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) ")
_TAG = re.compile(r"^([A-Za-z0-9_.\-/()]+?)(?:\[(\d+)\])?: ")
_CISCO_SEQ = re.compile(r"^\d+: ")
_CISCO_MNEM = re.compile(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+): ")


def parse(raw: str) -> dict:
    """Trả về dict: facility, severity, device_ts, host, app, message."""
    line = raw.rstrip("\r\n\x00").lstrip("\ufeff")
    out = {"facility": 1, "severity": 5, "device_ts": "", "host": "", "app": "", "message": line}
    m = _PRI.match(line)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            out["facility"], out["severity"] = pri >> 3, pri & 7
        line = line[m.end():]

    m = _5424.match(line)
    if m:
        ts, host, app, procid, msgid, sd, msg = m.groups()
        out.update(device_ts="" if ts == "-" else ts, host="" if host == "-" else host, app="" if app == "-" else app,
                   message=msg.lstrip("\ufeff").strip())
        if sd != "-":
            out["sd"] = sd
        return _cisco(out)

    rest = _CISCO_SEQ.sub("", line, count=1)
    m = _BSD_TS.match(rest) or _ISO_TS.match(rest)
    if m:
        out["device_ts"] = m.group(1)
        rest = rest[m.end():]
        # hostname có mặt nếu token đầu KHÔNG phải tag (không kết thúc bằng ':' / không có [pid]:)
        if not _TAG.match(rest) and not rest.startswith("%"):
            parts = rest.split(" ", 1)
            if len(parts) == 2 and re.match(r"^[A-Za-z0-9_.\-:]+$", parts[0]):
                out["host"], rest = parts[0].rstrip(":"), parts[1]
    t = _TAG.match(rest)
    if t:
        out["app"] = t.group(1)
        rest = rest[t.end():]
    out["message"] = rest.strip()
    return _cisco(out)


def _cisco(out: dict) -> dict:
    """Cisco/Aruba dạng %LINK-3-UPDOWN: lấy mnemonic làm app và mức độ từ mã."""
    m = _CISCO_MNEM.search(out["message"])
    if m and (not out["app"] or out["app"].isdigit()):
        out["app"] = f"{m.group(1)}-{m.group(3)}"
        out["severity"] = min(out["severity"], int(m.group(2)))
        out["message"] = out["message"][m.end():].strip() or out["message"]
    return out
