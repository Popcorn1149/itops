"""Normalize asset data (CVE module – part 1).

All subsequent components (CVE matching, prioritization, and reporting) read only the normalized fields defined here, not raw agent strings.
Extension:
  - To add an operating system: write parse_<family>() and register it in OS_PARSERS.
  - To add software-name rules: add entries to NAME_RULES (regex → canonical name) or VENDOR_ALIASES."""
import re

# ------------------------------------------------------------------ hệ điều hành
_WIN_BUILD = re.compile(r"build\s+(\d+)(?:\.(\d+))?", re.I)
_WIN_REL = re.compile(r"^\s*(\d{2}H\d|\d{4})\b", re.I)      # 23H2 | 1809


def parse_windows(os_name: str, os_version: str) -> dict:
    """'23H2 (build 22631.4317)' → release 23H2, build 22631, ubr 4317 (UBR = số bản vá tích luỹ đã cài)."""
    out = {"os_release": "", "os_build": "", "os_ubr": None}
    m = _WIN_BUILD.search(os_version or "")
    if m:
        out["os_build"] = m.group(1)
        out["os_ubr"] = int(m.group(2)) if m.group(2) else None
    r = _WIN_REL.match(os_version or "")
    if r:
        out["os_release"] = r.group(1).upper()
    return out


def parse_linux(os_name: str, os_version: str) -> dict:
    """'Ubuntu 22.04.4 LTS' → release 22.04 (bản phát hành dùng để chọn đúng nguồn OVAL/USN)."""
    m = re.search(r"(\d+(?:\.\d+)?)", f"{os_version} {os_name}")
    return {"os_release": m.group(1) if m else "", "os_build": (os_version or "")[:32], "os_ubr": None}


def parse_darwin(os_name: str, os_version: str) -> dict:
    """os_name 'macOS 15.1', os_version = mã build '24B83'."""
    m = re.search(r"(\d+(?:\.\d+){0,2})", os_name or "")
    return {"os_release": m.group(1) if m else "", "os_build": (os_version or "")[:32], "os_ubr": None}


OS_PARSERS = {"windows": parse_windows, "linux": parse_linux, "darwin": parse_darwin}


def parse_os(os_family: str, os_name: str, os_version: str) -> dict:
    fn = OS_PARSERS.get(os_family or "")
    return fn(os_name or "", os_version or "") if fn else {"os_release": "", "os_build": "", "os_ubr": None}


# ------------------------------------------------------------------ định danh machines
# Số serial "giả" do nhà sản xuất bo mạch để mặc định – không dùng để nhận ra machines.
_BAD_SERIAL = re.compile(r"^(|0+|1234567890|none|null|n/?a|default string|to be filled by o\.?e\.?m\.?|system serial number|"
                         r"not specified|not applicable|chassis serial number|serial number|o\.?e\.?m\.?)$", re.I)


def valid_serial(s: str) -> bool:
    return not _BAD_SERIAL.match((s or "").strip())


def same_machine(a_machine_id: str, a_serial: str, b_machine_id: str, b_serial: str) -> bool:
    """Hai bản ghi là cùng một machines vật lý/VM: trùng machine-id, hoặc trùng serial hợp lệ."""
    if a_machine_id and b_machine_id and a_machine_id.lower() == b_machine_id.lower():
        return True
    return valid_serial(a_serial) and valid_serial(b_serial) and a_serial.strip().lower() == b_serial.strip().lower()


# ------------------------------------------------------------------ phần mềm
VENDOR_ALIASES = {
    "microsoft corporation": "microsoft", "microsoft corp.": "microsoft", "microsoft": "microsoft",
    "google llc": "google", "google inc.": "google", "google, inc.": "google",
    "mozilla": "mozilla", "mozilla corporation": "mozilla",
    "adobe inc.": "adobe", "adobe systems incorporated": "adobe",
    "oracle corporation": "oracle", "oracle america, inc.": "oracle",
    "the git development community": "git", "python software foundation": "python",
    "openjs foundation": "nodejs", "node.js foundation": "nodejs",
    "igor pavlov": "7-zip", "don ho": "notepad++", "videolan": "videolan",
    "ubuntu developers": "canonical", "canonical": "canonical",
}
_VENDOR_SUFFIX = re.compile(r"[,\s]+(corporation|corp\.?|inc\.?|incorporated|ltd\.?|limited|llc|gmbh|co\.?|s\.?a\.?|a\.?g\.?|b\.?v\.?)\s*$", re.I)

# (regex trên tên đã hạ chữ thường) → tên chuẩn. Thứ tự quan trọng: quy tắc cụ thể đứng trước.
NAME_RULES = [
    (r"^google chrome\b", "chrome"),
    (r"^microsoft edge\b(?!.*webview)", "edge"),
    (r"^microsoft edge webview2", "edge webview2"),
    (r"^mozilla firefox\b", "firefox"),
    (r"^7-zip\b", "7-zip"),
    (r"^notepad\+\+", "notepad++"),
    (r"^vlc media player", "vlc"),
    (r"^adobe acrobat reader|^adobe acrobat dc|^adobe reader", "acrobat reader"),
    (r"^python \d+\.\d+.*", "python"),
    (r"^git\b", "git"),
    (r"^node\.?js\b", "node.js"),
    (r"^microsoft visual studio code\b", "vscode"),
    (r"^microsoft office\b|^microsoft 365\b", "office"),
    (r"^java\b.*\b(?:update|\d+)", "java"),
    (r"^openssh\b", "openssh"),
    (r"^teamviewer\b", "teamviewer"),
    (r"^anydesk\b", "anydesk"),
    (r"^zoom\b", "zoom"),
    (r"^winrar\b", "winrar"),
]
_NAME_RULES = [(re.compile(p, re.I), n) for p, n in NAME_RULES]
_ARCH = re.compile(r"\s*[\(\[]?\b(x64|x86|64-bit|32-bit|amd64|arm64|x86_64)\b[\)\]]?", re.I)
_TRAIL_VER = re.compile(r"[\s\-_]+v?\d+(?:[.\-_]\d+)+[a-z0-9.\-]*\s*$", re.I)
_LANG = re.compile(r"\s*[\(\[]?\b(en-us|vi-vn|mui)\b[\)\]]?", re.I)


def norm_vendor(publisher: str) -> str:
    p = re.sub(r"<[^>]*>", "", publisher or "").strip().lower()      # "Ubuntu Developers <...@...>" → bỏ email
    if p in VENDOR_ALIASES:
        return VENDOR_ALIASES[p]
    p = _VENDOR_SUFFIX.sub("", p).strip(" ,.")
    return VENDOR_ALIASES.get(p, p)[:128]


def norm_name(name: str) -> str:
    n = (name or "").strip()
    for rx, out in _NAME_RULES:
        if rx.search(n):
            return out
    n = _ARCH.sub("", n)
    n = _LANG.sub("", n)
    n = _TRAIL_VER.sub("", n)
    return re.sub(r"\s+", " ", n).strip(" -_").lower()[:255]


def norm_version(version: str) -> str:
    v = (version or "").strip()
    v = re.sub(r"^v(?=\d)", "", v, flags=re.I)
    return v.split(" ")[0][:128]


def normalize_software(items: list[dict], dedupe: bool = False) -> list[dict]:
    """Thêm norm_name / norm_vendor / norm_version. dedupe=True: bỏ dòng trùng (cùng phần mềm, cùng sessions bản –
    e.g. đọc ở cả HKLM and HKCU, bản x64 and x86) – dùng khi khớp CVE; khi lưu thì giữ đủ dòng gốc."""
    seen, out = set(), []
    for s in items:
        d = dict(s)
        d["norm_name"] = norm_name(d.get("name", ""))
        d["norm_vendor"] = norm_vendor(d.get("publisher", ""))
        d["norm_version"] = norm_version(d.get("version", ""))
        k = (d["norm_name"], d["norm_version"], d.get("source_pkg") or "")
        if dedupe and (not d["norm_name"] or k in seen):
            continue
        seen.add(k)
        out.append(d)
    return out
