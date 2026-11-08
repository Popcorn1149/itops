"""Danh mục sự kiện máy trạm – CHỈ những sự kiện cần người xử lý (ADR 0004).

Không có ở đây = không thu: đăng nhập/đăng xuất thành công (4624/4634/4647/4672), đăng nhập của dịch vụ, tiến trình
(4688), tường lửa cho phép kết nối (5156)… – các log này chiếm phần lớn khối lượng và gần như luôn là hoạt động bình thường.

Mỗi mục dịch sự kiện sang tiếng Việt theo 4 ý cho IT helpdesk:  Ai · Từ đâu · Chuyện gì · Nên làm gì.
"""
import re

ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
                "backup operators", "server operators", "dnsadmins", "group policy creator owners",
                "quản trị viên", "sudo", "wheel", "admin"}

LOGON_TYPE = {"2": "đăng nhập tại máy", "3": "qua mạng (chia sẻ file, dịch vụ)", "4": "tác vụ hẹn giờ", "5": "dịch vụ",
              "7": "mở khoá màn hình", "8": "qua mạng (mật khẩu dạng rõ)", "10": "Remote Desktop (RDP)",
              "11": "đăng nhập bằng thông tin lưu sẵn"}

FAIL_REASON = {
    "0xc000006a": "sai mật khẩu", "0xc0000064": "tài khoản không tồn tại", "0xc0000072": "tài khoản đang bị vô hiệu hoá",
    "0xc0000234": "tài khoản đang bị khoá", "0xc0000071": "mật khẩu đã hết hạn", "0xc0000193": "tài khoản đã hết hạn",
    "0xc000006f": "đăng nhập ngoài giờ cho phép", "0xc0000070": "không được phép đăng nhập từ máy này",
    "0xc0000224": "bắt buộc đổi mật khẩu", "0xc000015b": "không có quyền kiểu đăng nhập này",
    "0xc0000133": "lệch giờ giữa máy và domain controller", "0xc000005e": "không có máy chủ đăng nhập (DC) phản hồi",
}


def _v(d: dict, *keys) -> str:
    for k in keys:
        x = d.get(k)
        if x not in (None, "", "-", "NULL", "%%1793"):
            return str(x).strip()
    return ""


def _acct(d: dict, user_key="TargetUserName", dom_key="TargetDomainName") -> str:
    u, dom = _v(d, user_key), _v(d, dom_key)
    if not u:
        return ""
    return f"{dom}\\{u}" if dom and dom.upper() not in ("NT AUTHORITY", "WORKGROUP") and "\\" not in u else u


def _member(d: dict) -> str:
    m = _v(d, "MemberName")
    if m.upper().startswith("CN="):                        # CN=Nguyen Van A,OU=...  → Nguyen Van A
        m = m[3:].split(",")[0]
    return m or _v(d, "MemberSid")


def _src(d: dict) -> str:
    ip, ws = _v(d, "IpAddress"), _v(d, "WorkstationName", "CallerComputerName")
    if ip in ("::1", "127.0.0.1"):
        ip = "chính máy này"
    return " · ".join(x for x in (ws, ip) if x)


# ---------------------------------------------------------------- Windows
# key: (kênh, nhà cung cấp, Event ID). Mỗi mục: category, severity, title, render(d, host) → (who, where, what, advice),
#   group(d) → khoá gom các lần lặp lại, skip(d) → True = bỏ (nhiễu), alert = dict cảnh báo (tuỳ chọn).
def _r4625(d, host):
    reason = FAIL_REASON.get(_v(d, "SubStatus").lower()) or FAIL_REASON.get(_v(d, "Status").lower()) or "thông tin đăng nhập không hợp lệ"
    lt = LOGON_TYPE.get(_v(d, "LogonType"), "")
    return (_acct(d) or "(không rõ tài khoản)", _src(d) or "không rõ nguồn",
            f"Đăng nhập thất bại vào {host}: {reason}" + (f" – kiểu {lt}" if lt else "") + ".",
            "Một vài lần: thường do người dùng gõ sai/mật khẩu cũ lưu trong ứng dụng, ổ mạng, điện thoại. "
            "Lặp nhiều lần từ cùng nguồn hoặc thử nhiều tài khoản: nghi dò mật khẩu – kiểm tra máy nguồn, chặn IP nếu từ ngoài.")


def _r4740(d, host):
    # 4740: TargetDomainName chứa TÊN MÁY gây khoá (không phải domain) → không ghép vào tên tài khoản
    return (_v(d, "TargetUserName") or "(không rõ)", _v(d, "CallerComputerName", "TargetDomainName") or "không rõ máy",
            f"Tài khoản bị KHOÁ do nhập sai mật khẩu quá số lần cho phép (ghi nhận tại {host}).",
            "Gọi xác nhận với người dùng. Nếu đúng là họ: mở khoá (AD Users & Computers → Account → Unlock) và kiểm tra "
            "máy nguồn có ứng dụng/ổ mạng/điện thoại còn lưu mật khẩu cũ. Không phải họ: đổi mật khẩu, kiểm tra máy nguồn.")


def _r_group(d, host):
    grp = _v(d, "TargetUserName")
    admin = grp.lower() in ADMIN_GROUPS
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(không rõ)", host,
            f"Đã thêm {_member(d) or '(không rõ)'} vào nhóm \"{grp}\"" + (" – nhóm có QUYỀN QUẢN TRỊ." if admin else "."),
            "Xác nhận thay đổi này có phiếu yêu cầu/được duyệt. Không ai yêu cầu: gỡ thành viên ra ngay, đổi mật khẩu "
            "tài khoản đã thực hiện và kiểm tra máy đó." if admin else "Xác nhận thay đổi có được yêu cầu.")


def _r4720(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(không rõ)", host,
            f"Tạo tài khoản mới: {_acct(d) or '(không rõ)'}.",
            "Đối chiếu với yêu cầu tạo tài khoản. Tài khoản cục bộ lạ trên máy trạm thường là dấu hiệu bị xâm nhập.")


def _r4726(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(không rõ)", host,
            f"Xoá tài khoản: {_acct(d) or '(không rõ)'}.", "Đối chiếu với yêu cầu nghỉ việc/thu hồi tài khoản.")


def _r1102(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(không rõ)", host,
            "Nhật ký bảo mật (Security log) của máy vừa bị XOÁ.",
            "Rất hiếm khi cần làm việc này. Nếu không có ai trong IT chủ động xoá: coi như máy có thể đã bị xâm nhập "
            "(kẻ tấn công xoá dấu vết) – cách ly máy khỏi mạng và báo trưởng nhóm.")


def _r41(d, host):
    return ("Hệ thống", host, "Máy khởi động lại mà KHÔNG tắt đúng cách (mất điện, treo, giữ nút nguồn"
            + (f", lỗi màn hình xanh mã {_v(d, 'BugcheckCode')}" if _v(d, "BugcheckCode") not in ("", "0") else "") + ").",
            "Một lần: hỏi người dùng có tắt nóng/mất điện không. Lặp lại: kiểm tra nguồn/UPS, nhiệt độ, driver, RAM, "
            "và ổ đĩa (xem thêm sự kiện lỗi ổ đĩa).")


def _r6008(d, host):
    return ("Hệ thống", host, "Lần tắt máy trước đó là bất thường (không tắt đúng cách).", _r41(d, host)[3])


def _svc_name(d):
    return _v(d, "param1", "ServiceName") or "(không rõ dịch vụ)"


def _r7031(d, host):
    return ("Hệ thống", host, f"Dịch vụ \"{_svc_name(d)}\" bị dừng bất thường"
            + (f" (lần thứ {_v(d, 'param2')})" if _v(d, "param2") else "") + "; Windows sẽ tự khởi động lại nếu có cấu hình.",
            "Kiểm tra dịch vụ đã chạy lại chưa (services.msc). Lặp lại nhiều lần: xem log của ứng dụng, cập nhật/cài lại.")


def _r7045(d, host):
    return (_v(d, "AccountName") or "LocalSystem", host,
            f"Có dịch vụ MỚI được cài: \"{_svc_name(d)}\" – chạy {_v(d, 'ImagePath') or '(không rõ đường dẫn)'}.",
            "Bình thường khi cài phần mềm/driver. Dịch vụ lạ, chạy từ thư mục Temp/AppData/Users, hoặc dùng powershell/cmd: "
            "nghi mã độc – cách ly máy và kiểm tra.")


def _r_disk(d, host):
    return ("Hệ thống", host, f"Lỗi ổ đĩa: {_v(d, 'param1', 'DeviceName') or 'ổ đĩa'} báo lỗi đọc/ghi hoặc cấu trúc file hỏng.",
            "Sao lưu dữ liệu người dùng NGAY, kiểm tra SMART (CrystalDiskInfo), chạy chkdsk. Lỗi lặp lại: thay ổ.")


def _r_wu(d, host):
    return ("Windows Update", host, f"Cài bản cập nhật thất bại: {_v(d, 'updateTitle') or '(không rõ)'}"
            + (f" – mã lỗi {_v(d, 'errorCode')}" if _v(d, "errorCode") else "") + ".",
            "Thử cài lại; lỗi lặp lại: chạy Windows Update Troubleshooter / kiểm tra dung lượng ổ C.")


def _av_path(d, host):
    p = _v(d, "Path")
    for pre in ("containerfile:_", "file:_", "process:_", "regkey:_"):
        p = p.replace(pre, "")
    return (p.split(";")[0] + (f" (trên {host})" if p else "")) if p else host


def _r1116(d, host):
    return (_v(d, "Detection User") or "(không rõ)", _av_path(d, host),
            f"Windows Defender PHÁT HIỆN mã độc \"{_v(d, 'Threat Name')}\" (mức {_v(d, 'Severity Name') or '?'}, "
            f"loại {_v(d, 'Category Name') or '?'})" + (f" – tiến trình {_v(d, 'Process Name')}" if _v(d, "Process Name") else "") + ".",
            "Xem sự kiện \"đã xử lý\" ngay sau đó. Chưa xử lý được hoặc lặp lại: ngắt mạng máy, quét toàn bộ, "
            "hỏi người dùng nguồn file (email, USB, web).")


def _r1117(d, host):
    return (_v(d, "Detection User") or "(không rõ)", _av_path(d, host),
            f"Windows Defender đã xử lý \"{_v(d, 'Threat Name')}\": {_v(d, 'Action Name') or 'đã xử lý'}.",
            "Theo dõi xem có tái phát không; tái phát = nguồn lây vẫn còn (USB, email, phần mềm crack).")


def _r5001(d, host):
    return ("Windows Defender", host, "Bảo vệ THỜI GIAN THỰC của Windows Defender đã bị TẮT.",
            "Bật lại ngay (Windows Security → Virus & threat protection). Nếu tự tắt lại: kiểm tra GPO, phần mềm diệt virus "
            "khác, hoặc mã độc đang vô hiệu hoá Defender.")


def _r2001(d, host):
    return ("Windows Defender", host, "Cập nhật mẫu nhận diện virus của Windows Defender THẤT BẠI"
            + (f": {_v(d, 'Error Description')}" if _v(d, "Error Description") else "") + ".",
            "Kiểm tra máy có ra Internet/WSUS được không; chạy cập nhật tay trong Windows Security.")


def _machine_acct(d):
    u = _v(d, "TargetUserName")
    return not u or u.endswith("$")


WINDOWS = [
    # Tài khoản (kênh Security, nhà cung cấp Microsoft-Windows-Security-Auditing)
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4625], key="win:4625", category="account",
         severity="info", title="Đăng nhập thất bại", render=_r4625, skip=_machine_acct,
         group=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_v(d, 'IpAddress', 'WorkstationName').lower()}",
         alert=dict(name="Nghi dò mật khẩu", severity="trouble", threshold=10, window=10,
                    by=lambda d: _v(d, "IpAddress", "WorkstationName").lower() or "?")),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4740], key="win:4740", category="account",
         severity="attention", title="Tài khoản bị khoá", render=_r4740, group=lambda d: _v(d, "TargetUserName").lower(),
         alert=dict(name="Tài khoản bị khoá", severity="attention", by=lambda d: _v(d, "TargetUserName").lower())),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4720], key="win:4720", category="account",
         severity="attention", title="Tạo tài khoản mới", render=_r4720, group=lambda d: _v(d, "TargetUserName").lower(),
         alert=dict(name="Tạo tài khoản mới", severity="attention", by=lambda d: _v(d, "TargetUserName").lower())),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4726], key="win:4726", category="account",
         severity="info", title="Xoá tài khoản", render=_r4726, group=lambda d: _v(d, "TargetUserName").lower()),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4728, 4732, 4756], key="win:group-add",
         category="account", severity="attention", title="Thêm thành viên vào nhóm", render=_r_group,
         severity_fn=lambda d: "critical" if _v(d, "TargetUserName").lower() in ADMIN_GROUPS else "attention",
         title_fn=lambda d: "Thêm vào nhóm QUẢN TRỊ" if _v(d, "TargetUserName").lower() in ADMIN_GROUPS else "Thêm thành viên vào nhóm",
         group=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_member(d).lower()}",
         alert=dict(name="Thêm tài khoản vào nhóm quản trị", severity="critical",
                    when=lambda d: _v(d, "TargetUserName").lower() in ADMIN_GROUPS,
                    by=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_member(d).lower()}")),
    dict(channel="Security", provider="Microsoft-Windows-Eventlog", ids=[1102], key="win:1102", category="security",
         severity="critical", title="Nhật ký bảo mật bị xoá", render=_r1102, group=lambda d: "",
         alert=dict(name="Nhật ký bảo mật bị xoá", severity="critical", by=lambda d: "")),
    # Hệ thống
    dict(channel="System", provider="Microsoft-Windows-Kernel-Power", ids=[41], key="win:41", category="system",
         severity="attention", title="Tắt máy đột ngột", render=_r41, group=lambda d: "",
         alert=dict(name="Máy tắt đột ngột", severity="attention", by=lambda d: "")),
    dict(channel="System", provider="EventLog", ids=[6008], key="win:6008", category="system",
         severity="info", title="Lần tắt máy trước bất thường", render=_r6008, group=lambda d: ""),
    dict(channel="System", provider="Service Control Manager", ids=[7031, 7034], key="win:svc-crash", category="service",
         severity="trouble", title="Dịch vụ dừng bất thường", render=_r7031, group=lambda d: _svc_name(d).lower(),
         alert=dict(name="Dịch vụ dừng bất thường", severity="trouble", by=lambda d: _svc_name(d).lower())),
    dict(channel="System", provider="Service Control Manager", ids=[7045], key="win:7045", category="security",
         severity="attention", title="Cài dịch vụ mới", render=_r7045, group=lambda d: _svc_name(d).lower()),
    dict(channel="System", provider="Disk", ids=[7, 51, 153], key="win:disk", category="disk",
         severity="critical", title="Lỗi ổ đĩa", render=_r_disk, group=lambda d: _v(d, "param1", "DeviceName").lower(),
         alert=dict(name="Lỗi ổ đĩa", severity="critical", by=lambda d: "")),
    dict(channel="System", provider="Ntfs", ids=[55], key="win:ntfs", category="disk",
         severity="critical", title="Hệ thống file bị hỏng", render=_r_disk, group=lambda d: "",
         alert=dict(name="Lỗi ổ đĩa", severity="critical", by=lambda d: "")),
    dict(channel="System", provider="Microsoft-Windows-WindowsUpdateClient", ids=[20], key="win:wu-fail", category="system",
         severity="info", title="Cập nhật Windows thất bại", render=_r_wu, group=lambda d: _v(d, "updateTitle").lower()[:120]),
    # Windows Defender
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[1116, 1006], key="win:av-detect", category="security", severity="critical", title="Phát hiện mã độc",
         render=_r1116, group=lambda d: _v(d, "Threat Name").lower(),
         alert=dict(name="Phát hiện mã độc", severity="critical", by=lambda d: _v(d, "Threat Name").lower())),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[1117, 1007], key="win:av-action", category="security", severity="info", title="Defender đã xử lý mã độc",
         render=_r1117, group=lambda d: _v(d, "Threat Name").lower()),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[5001], key="win:av-rtp-off", category="security", severity="critical", title="Defender: tắt bảo vệ thời gian thực",
         render=_r5001, group=lambda d: "",
         alert=dict(name="Defender bị tắt bảo vệ thời gian thực", severity="critical", by=lambda d: "")),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[2001], key="win:av-sig-fail", category="security", severity="info", title="Defender: cập nhật mẫu thất bại",
         render=_r2001, group=lambda d: ""),
]


# ---------------------------------------------------------------- Linux / macOS (agent đã nhận diện, gửi kèm "kind")
def _lx(what, advice, who_key="user", where_key="src"):
    def r(d, host):
        return (_v(d, who_key) or "(không rõ)", _v(d, where_key) or host, what.format(host=host, **{k: _v(d, k) for k in
                ("user", "src", "unit", "process", "device", "group", "result", "service")}), advice)
    return r


UNIX = [
    dict(kind="auth_fail", key="unix:auth-fail", category="account", severity="info", title="Đăng nhập thất bại",
         render=_lx("Đăng nhập thất bại vào {host} qua {service} (tài khoản {user}).",
                    "Một vài lần: gõ sai. Nhiều lần từ cùng IP hoặc nhiều tài khoản: dò mật khẩu – chặn IP, tắt đăng nhập SSH "
                    "bằng mật khẩu (chỉ dùng key)."),
         group=lambda d: f"{_v(d, 'user').lower()}|{_v(d, 'src')}",
         alert=dict(name="Nghi dò mật khẩu", severity="trouble", threshold=10, window=10, by=lambda d: _v(d, "src") or "?")),
    dict(kind="sudo_fail", key="unix:sudo-fail", category="account", severity="attention", title="Dùng sudo sai mật khẩu",
         render=_lx("Tài khoản {user} nhập sai mật khẩu khi dùng sudo trên {host}.",
                    "Xác nhận với người dùng. Không phải họ: tài khoản có thể đã bị lộ."),
         group=lambda d: _v(d, "user").lower()),
    dict(kind="user_added", key="unix:user-add", category="account", severity="attention", title="Tạo tài khoản mới",
         render=_lx("Tạo tài khoản mới {user} trên {host}.", "Đối chiếu với yêu cầu tạo tài khoản."),
         group=lambda d: _v(d, "user").lower(),
         alert=dict(name="Tạo tài khoản mới", severity="attention", by=lambda d: _v(d, "user").lower())),
    dict(kind="group_admin", key="unix:admin-add", category="account", severity="critical", title="Thêm vào nhóm QUẢN TRỊ",
         render=_lx("Thêm {user} vào nhóm quản trị \"{group}\" trên {host}.",
                    "Xác nhận có yêu cầu. Không ai yêu cầu: gỡ ra ngay (gpasswd -d), kiểm tra ai đã thực hiện."),
         group=lambda d: f"{_v(d, 'user').lower()}|{_v(d, 'group').lower()}",
         alert=dict(name="Thêm tài khoản vào nhóm quản trị", severity="critical", by=lambda d: _v(d, "user").lower())),
    dict(kind="oom", key="unix:oom", category="system", severity="trouble", title="Hết bộ nhớ – tiến trình bị dừng",
         render=_lx("Hết RAM: hệ thống buộc phải dừng tiến trình {process} trên {host}.",
                    "Kiểm tra tiến trình ngốn RAM, giới hạn bộ nhớ của dịch vụ, cân nhắc nâng RAM."),
         group=lambda d: _v(d, "process").lower(),
         alert=dict(name="Hết bộ nhớ (OOM)", severity="trouble", by=lambda d: "")),
    dict(kind="service_failed", key="unix:svc-fail", category="service", severity="trouble", title="Dịch vụ lỗi",
         render=_lx("Dịch vụ {unit} trên {host} dừng lỗi ({result}).",
                    "Xem log: journalctl -u <dịch vụ> -n 100. Kiểm tra dịch vụ đã chạy lại chưa: systemctl status."),
         group=lambda d: _v(d, "unit").lower(),
         alert=dict(name="Dịch vụ dừng bất thường", severity="trouble", by=lambda d: _v(d, "unit").lower())),
    dict(kind="disk_error", key="unix:disk", category="disk", severity="critical", title="Lỗi ổ đĩa",
         render=_lx("Lỗi đọc/ghi ổ đĩa {device} trên {host}.",
                    "Sao lưu dữ liệu ngay, kiểm tra SMART (smartctl -a), thay ổ nếu lỗi lặp lại."),
         group=lambda d: _v(d, "device").lower(),
         alert=dict(name="Lỗi ổ đĩa", severity="critical", by=lambda d: "")),
    dict(kind="unclean_shutdown", key="unix:unclean", category="system", severity="attention", title="Tắt máy đột ngột",
         render=_lx("Lần chạy trước của {host} kết thúc không đúng cách (mất điện/treo).",
                    "Kiểm tra nguồn/UPS, log trước thời điểm đó (journalctl -b -1 -e)."),
         group=lambda d: "", alert=dict(name="Máy tắt đột ngột", severity="attention", by=lambda d: "")),
]
UNIX_KINDS = {c["kind"] for c in UNIX}

_WIN_INDEX = {}
for _c in WINDOWS:
    for _i in _c["ids"]:
        _WIN_INDEX[(_c["channel"].lower(), _i)] = _WIN_INDEX.get((_c["channel"].lower(), _i), []) + [_c]
_UNIX_INDEX = {c["kind"]: c for c in UNIX}


def lookup(os_family: str, ev: dict):
    """Tìm mục danh mục cho sự kiện agent gửi lên; None = không nằm trong chính sách → bỏ."""
    if os_family == "windows":
        for c in _WIN_INDEX.get(((ev.get("channel") or "").lower(), int(ev.get("event_id") or 0)), []):
            prov = (ev.get("provider") or "").lower()
            if prov == c["provider"].lower() or prov.endswith(c["provider"].lower()):
                return c
        return None
    return _UNIX_INDEX.get(ev.get("kind") or "")


def windows_queries() -> list[dict]:
    """Truy vấn event log gửi cho agent Windows: kênh → danh sách Event ID. Không lọc theo nhà cung cấp ở agent
    (tên provider khác nhau giữa các bản Windows, vd. Ntfs / Microsoft-Windows-Ntfs) – server lọc lại khi nhận."""
    by = {}
    for c in WINDOWS:
        by.setdefault(c["channel"], set()).update(c["ids"])
    return [{"channel": ch, "ids": sorted(ids)} for ch, ids in by.items()]


def catalog_rows() -> list[dict]:
    """Danh mục để hiện trên giao diện (Cài đặt → Máy trạm)."""
    out = []
    for c in WINDOWS:
        out.append({"key": c["key"], "os": "windows", "ids": c["ids"], "channel": c["channel"], "title": c["title"],
                    "category": c["category"], "severity": c["severity"], "alert": (c.get("alert") or {}).get("name", ""),
                    "threshold": (c.get("alert") or {}).get("threshold", 1)})
    for c in UNIX:
        out.append({"key": c["key"], "os": "linux/macos", "ids": [], "channel": c["kind"], "title": c["title"],
                    "category": c["category"], "severity": c["severity"], "alert": (c.get("alert") or {}).get("name", ""),
                    "threshold": (c.get("alert") or {}).get("threshold", 1)})
    return out


NOISE_IDS = (4624, 4634, 4647, 4648, 4672, 4688, 4689, 5156, 5158)   # chặn cả khi agent cũ/lỗi lỡ gửi lên
_SPACE = re.compile(r"\s+")


def clean_message(m: str, limit: int = 1500) -> str:
    return _SPACE.sub(" ", (m or "")).strip()[:limit]
