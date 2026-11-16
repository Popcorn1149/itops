"""Endpoint event catalog – Only events that require human action (ADR 0004).

None means the event is not collected: successful sign-ins/sign-outs (4624/4634/4647/4672), service logons,
process creation (4688), permitted firewall connections (5156), and other high-volume routine activity.

Each catalog entry renders four helpdesk fields: who, where, what happened, and recommended action.
"""
import re

ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
                "backup operators", "server operators", "dnsadmins", "group policy creator owners",
                "administrator", "sudo", "wheel", "admin"}

LOGON_TYPE = {"2": "interactive logon", "3": "over the network (file sharing, services)", "4": "scheduled task", "5": "service",
              "7": "screen unlock", "8": "over the network (clear-text password)", "10": "Remote Desktop (RDP)",
              "11": "logon using cached credentials"}

FAIL_REASON = {
    "0xc000006a": "incorrect password", "0xc0000064": "account does not exist", "0xc0000072": "account is disabled",
    "0xc0000234": "account is locked", "0xc0000071": "password has expired", "0xc0000193": "account has expired",
    "0xc000006f": "logon outside permitted hours", "0xc0000070": "logon from this host is not permitted",
    "0xc0000224": "password change required", "0xc000015b": "this logon type is not permitted",
    "0xc0000133": "time difference between host and domain controller", "0xc000005e": "no domain controller responded",
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
        ip = "this host"
    return " · ".join(x for x in (ws, ip) if x)


# ---------------------------------------------------------------- Windows
# key: (kênh, nhà cung cấp, Event ID). Mỗi items: category, severity, title, render(d, host) → (who, where, what, advice),
#   group(d) → khoá gom các lần lặp lại, skip(d) → True = bỏ (nhiễu), alert = dict alerts (tuỳ chọn).
def _r4625(d, host):
    reason = FAIL_REASON.get(_v(d, "SubStatus").lower()) or FAIL_REASON.get(_v(d, "Status").lower()) or "invalid credentials"
    lt = LOGON_TYPE.get(_v(d, "LogonType"), "")
    return (_acct(d) or "(unknown account)", _src(d) or "unknown source",
            f"Sign-in failed on {host}: {reason}" + (f" – logon type {lt}" if lt else "") + ".",
            "A few attempts: often caused by a user mistyping a password or an outdated password saved in an application, network drive, or phone. "
            "Repeated attempts from the same source or against multiple accounts may indicate password spraying – investigate the source host and block the IP if it is external.")


def _r4740(d, host):
    # 4740: TargetDomainName chứa TÊN MÁY gây khoá (không phải domain) → không ghép ando tên account
    return (_v(d, "TargetUserName") or "(unknown)", _v(d, "CallerComputerName", "TargetDomainName") or "unknown host",
            f"Account locked out after exceeding the permitted number of incorrect password attempts (recorded on {host}).",
            "Confirm with the user. If legitimate, unlock the account (Active Directory Users and Computers → Account → Unlock) "
            "and check whether an application, mapped drive, or phone still stores an old password. If the activity is not theirs, "
            "reset the password and investigate the source host.")


def _r_group(d, host):
    grp = _v(d, "TargetUserName")
    admin = grp.lower() in ADMIN_GROUPS
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(unknown)", host,
            f"Added {_member(d) or '(unknown)'} to group \"{grp}\"" + (" – group has ADMINISTRATIVE PRIVILEGES." if admin else "."),
            "Verify that this change has an approved request. If unauthorized, remove the member immediately, reset the initiating "
            "account password, and investigate the endpoint." if admin else "Verify that this membership change was requested and approved.")


def _r4720(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(unknown)", host,
            f"Create a new account: {_acct(d) or '(unknown)'}.",
            "Verify against the approved account-creation request. An unfamiliar local account on a workstation may indicate compromise.")


def _r4726(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(unknown)", host,
            f"Delete account: {_acct(d) or '(unknown)'}.", "Verify against the approved offboarding request or revoked account record.")


def _r1102(d, host):
    return (_acct(d, "SubjectUserName", "SubjectDomainName") or "(unknown)", host,
            "The computer's Security log has been CLEARED.",
            "Clearing this log is rarely required. If no authorized IT administrator performed the action, treat the endpoint as "
            "potentially compromised, isolate it from the network, and escalate for investigation.")


def _r41(d, host):
    return ("System", host, "The computer restarted without a proper shutdown (power loss, system hang, or forced power-off"
            + (f", blue-screen error code {_v(d, 'BugcheckCode')}" if _v(d, "BugcheckCode") not in ("", "0") else "") + ").",
            "For a single occurrence, confirm whether there was a power loss or forced shutdown. If repeated, check the power supply/UPS, "
            "temperature, drivers, RAM, and storage; review related disk events.")


def _r6008(d, host):
    return ("System", host, "The previous shutdown was unexpected (the computer was not shut down properly).", _r41(d, host)[3])


def _svc_name(d):
    return _v(d, "param1", "ServiceName") or "(unknown service)"


def _r7031(d, host):
    return ("System", host, f"Service \"{_svc_name(d)}\" stopped unexpectedly"
            + (f" (occurrence {_v(d, 'param2')})" if _v(d, "param2") else "") + "; Windows will attempt to restart it if recovery is configured.",
            "Check whether the service has restarted (services.msc). If repeated, review application logs and update or reinstall the application.")


def _r7045(d, host):
    return (_v(d, "AccountName") or "LocalSystem", host,
            f"A new service was installed: \"{_svc_name(d)}\" – executable path: {_v(d, 'ImagePath') or '(unknown path)'}.",
            "This is expected during software or driver installation. An unfamiliar service running from Temp, AppData, or a user profile, "
            "or launched through PowerShell/cmd, may indicate malware. Isolate the endpoint and investigate.")


def _r_disk(d, host):
    return ("System", host, f"Disk error: {_v(d, 'param1', 'DeviceName') or 'the disk'} reported an I/O or file-system error.",
            "Back up user data IMMEDIATELY, check SMART (CrystalDiskInfo), and run chkdsk. Replace the disk if errors recur.")


def _r_wu(d, host):
    return ("Windows Update", host, f"Update installation failed: {_v(d, 'updateTitle') or '(unknown)'}"
             + (f" – error code {_v(d, 'errorCode')}" if _v(d, "errorCode") else "") + ".",
            "Retry the installation. If it fails repeatedly, run the Windows Update Troubleshooter and check free space on drive C:.")


def _av_path(d, host):
    p = _v(d, "Path")
    for pre in ("containerfile:_", "file:_", "process:_", "regkey:_"):
        p = p.replace(pre, "")
    return (p.split(";")[0] + (f" (on {host})" if p else "")) if p else host


def _r1116(d, host):
    return (_v(d, "Detection User") or "(unknown)", _av_path(d, host),
            f"Windows Defender DETECTED malware \"{_v(d, 'Threat Name')}\" (severity {_v(d, 'Severity Name') or '?'}, "
            f"category {_v(d, 'Category Name') or '?'})" + (f" – process {_v(d, 'Process Name')}" if _v(d, "Process Name") else "") + ".",
            "Review the following remediation event. If the threat was not remediated or recurs, isolate the endpoint, run a full scan, "
            "and identify the file source (email, USB, or web).")


def _r1117(d, host):
    return (_v(d, "Detection User") or "(unknown)", _av_path(d, host),
            f"Windows Defender remediated \"{_v(d, 'Threat Name')}\": {_v(d, 'Action Name') or 'remediated'}.",
            "Monitor for recurrence. A recurrence suggests the infection source remains (USB, email, or cracked software).")


def _r5001(d, host):
    return ("Windows Defender", host, "Windows Defender REAL-TIME PROTECTION is DISABLED.",
            "Re-enable protection immediately (Windows Security → Virus & threat protection). If it is disabled again, review Group Policy, "
            "other antivirus software, and possible malware attempting to disable Defender.")


def _r2001(d, host):
    return ("Windows Defender", host, "Windows Defender security intelligence update FAILED"
            + (f": {_v(d, 'Error Description')}" if _v(d, "Error Description") else "") + ".",
            "Check Internet/WSUS connectivity, then retry the update manually from Windows Security.")


def _machine_acct(d):
    u = _v(d, "TargetUserName")
    return not u or u.endswith("$")


WINDOWS = [
    # Tài khoản (kênh Security, nhà cung cấp Microsoft-Windows-Security-Auditing)
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4625], key="win:4625", category="account",
         severity="info", title="Failed sign-in", render=_r4625, skip=_machine_acct,
         group=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_v(d, 'IpAddress', 'WorkstationName').lower()}",
         alert=dict(name="Possible password attack", severity="trouble", threshold=10, window=10,
                    by=lambda d: _v(d, "IpAddress", "WorkstationName").lower() or "?")),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4740], key="win:4740", category="account",
         severity="attention", title="Account locked out", render=_r4740, group=lambda d: _v(d, "TargetUserName").lower(),
         alert=dict(name="Account locked out", severity="attention", by=lambda d: _v(d, "TargetUserName").lower())),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4720], key="win:4720", category="account",
         severity="attention", title="New account created", render=_r4720, group=lambda d: _v(d, "TargetUserName").lower(),
         alert=dict(name="New account created", severity="attention", by=lambda d: _v(d, "TargetUserName").lower())),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4726], key="win:4726", category="account",
         severity="info", title="Account deleted", render=_r4726, group=lambda d: _v(d, "TargetUserName").lower()),
    dict(channel="Security", provider="Microsoft-Windows-Security-Auditing", ids=[4728, 4732, 4756], key="win:group-add",
         category="account", severity="attention", title="Member added to group", render=_r_group,
         severity_fn=lambda d: "critical" if _v(d, "TargetUserName").lower() in ADMIN_GROUPS else "attention",
         title_fn=lambda d: "Added to privileged group" if _v(d, "TargetUserName").lower() in ADMIN_GROUPS else "Member added to group",
         group=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_member(d).lower()}",
         alert=dict(name="Privileged group membership changed", severity="critical",
                    when=lambda d: _v(d, "TargetUserName").lower() in ADMIN_GROUPS,
                    by=lambda d: f"{_v(d, 'TargetUserName').lower()}|{_member(d).lower()}")),
    dict(channel="Security", provider="Microsoft-Windows-Eventlog", ids=[1102], key="win:1102", category="security",
         severity="critical", title="Security log cleared", render=_r1102, group=lambda d: "",
         alert=dict(name="Security log cleared", severity="critical", by=lambda d: "")),
    # System
    dict(channel="System", provider="Microsoft-Windows-Kernel-Power", ids=[41], key="win:41", category="system",
         severity="attention", title="Unexpected shutdown", render=_r41, group=lambda d: "",
         alert=dict(name="Unexpected system shutdown", severity="attention", by=lambda d: "")),
    dict(channel="System", provider="EventLog", ids=[6008], key="win:6008", category="system",
         severity="info", title="Previous shutdown was unexpected", render=_r6008, group=lambda d: ""),
    dict(channel="System", provider="Service Control Manager", ids=[7031, 7034], key="win:svc-crash", category="service",
         severity="trouble", title="Service stopped unexpectedly", render=_r7031, group=lambda d: _svc_name(d).lower(),
         alert=dict(name="Service stopped unexpectedly", severity="trouble", by=lambda d: _svc_name(d).lower())),
    dict(channel="System", provider="Service Control Manager", ids=[7045], key="win:7045", category="security",
         severity="attention", title="New service installed", render=_r7045, group=lambda d: _svc_name(d).lower()),
    dict(channel="System", provider="Disk", ids=[7, 51, 153], key="win:disk", category="disk",
         severity="critical", title="Disk error", render=_r_disk, group=lambda d: _v(d, "param1", "DeviceName").lower(),
         alert=dict(name="Disk error", severity="critical", by=lambda d: "")),
    dict(channel="System", provider="Ntfs", ids=[55], key="win:ntfs", category="disk",
         severity="critical", title="File system corruption", render=_r_disk, group=lambda d: "",
         alert=dict(name="Disk error", severity="critical", by=lambda d: "")),
    dict(channel="System", provider="Microsoft-Windows-WindowsUpdateClient", ids=[20], key="win:wu-fail", category="system",
         severity="info", title="Windows Update failed", render=_r_wu, group=lambda d: _v(d, "updateTitle").lower()[:120]),
    # Windows Defender
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[1116, 1006], key="win:av-detect", category="security", severity="critical", title="Threat detected",
         render=_r1116, group=lambda d: _v(d, "Threat Name").lower(),
         alert=dict(name="Threat detected", severity="critical", by=lambda d: _v(d, "Threat Name").lower())),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[1117, 1007], key="win:av-action", category="security", severity="info", title="Defender remediated threat",
         render=_r1117, group=lambda d: _v(d, "Threat Name").lower()),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[5001], key="win:av-rtp-off", category="security", severity="critical", title="Defender real-time protection disabled",
         render=_r5001, group=lambda d: "",
         alert=dict(name="Defender real-time protection disabled", severity="critical", by=lambda d: "")),
    dict(channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
         ids=[2001], key="win:av-sig-fail", category="security", severity="info", title="Defender signature update failed",
         render=_r2001, group=lambda d: ""),
]


# ---------------------------------------------------------------- Linux / macOS (agent received diện, gửi kèm "kind")
def _lx(what, advice, who_key="user", where_key="src"):
    def r(d, host):
        return (_v(d, who_key) or "(unknown)", _v(d, where_key) or host, what.format(host=host, **{k: _v(d, k) for k in
                ("user", "src", "unit", "process", "device", "group", "result", "service")}), advice)
    return r


UNIX = [
    dict(kind="auth_fail", key="unix:auth-fail", category="account", severity="info", title="Failed sign-in",
         render=_lx("Failed sign-in to {host} via {service} (account {user}).",
                    "A few attempts may be user error. Repeated attempts from the same IP or against multiple accounts may indicate password spraying. "
                    "Block the source IP and consider disabling SSH password authentication in favor of key-based authentication."),
         group=lambda d: f"{_v(d, 'user').lower()}|{_v(d, 'src')}",
         alert=dict(name="Possible password attack", severity="trouble", threshold=10, window=10, by=lambda d: _v(d, "src") or "?")),
    dict(kind="sudo_fail", key="unix:sudo-fail", category="account", severity="attention", title="Incorrect password used with sudo",
         render=_lx("Account {user} entered an incorrect password when using sudo on {host}.",
                    "Confirm with the user. If they did not perform the action, the account may be compromised."),
         group=lambda d: _v(d, "user").lower()),
    dict(kind="user_added", key="unix:user-add", category="account", severity="attention", title="New account created",
         render=_lx("New account {user} created on {host}.", "Verify against the approved account-creation request."),
         group=lambda d: _v(d, "user").lower(),
         alert=dict(name="New account created", severity="attention", by=lambda d: _v(d, "user").lower())),
    dict(kind="group_admin", key="unix:admin-add", category="account", severity="critical", title="Added to privileged group",
         render=_lx("Added {user} to privileged group \"{group}\" on {host}.",
                    "Verify that the change was approved. If unauthorized, remove the member immediately (gpasswd -d) and investigate who performed it."),
         group=lambda d: f"{_v(d, 'user').lower()}|{_v(d, 'group').lower()}",
         alert=dict(name="Privileged group membership changed", severity="critical", by=lambda d: _v(d, "user").lower())),
    dict(kind="oom", key="unix:oom", category="system", severity="trouble", title="Out of memory – process terminated",
         render=_lx("Out of memory: the system terminated process {process} on {host}.",
                    "Identify the process consuming memory, review service memory limits, and consider adding RAM."),
         group=lambda d: _v(d, "process").lower(),
         alert=dict(name="Out of memory (OOM)", severity="trouble", by=lambda d: "")),
    dict(kind="service_failed", key="unix:svc-fail", category="service", severity="trouble", title="Service failure",
         render=_lx("Service {unit} on {host} stopped unexpectedly ({result}).",
                    "Review logs with journalctl -u <service> -n 100 and verify recovery with systemctl status."),
         group=lambda d: _v(d, "unit").lower(),
         alert=dict(name="Service stopped unexpectedly", severity="trouble", by=lambda d: _v(d, "unit").lower())),
    dict(kind="disk_error", key="unix:disk", category="disk", severity="critical", title="Disk error",
         render=_lx("Disk read/write error on {device} at {host}.",
                    "Back up data immediately, check SMART with smartctl -a, and replace the disk if errors recur."),
         group=lambda d: _v(d, "device").lower(),
         alert=dict(name="Disk error", severity="critical", by=lambda d: "")),
    dict(kind="unclean_shutdown", key="unix:unclean", category="system", severity="attention", title="Unexpected shutdown",
         render=_lx("The previous run on {host} ended unexpectedly (power loss/system hang).",
                    "Check the power supply/UPS and review logs from the previous boot with journalctl -b -1 -e."),
         group=lambda d: "", alert=dict(name="Unexpected system shutdown", severity="attention", by=lambda d: "")),
]
UNIX_KINDS = {c["kind"] for c in UNIX}

_WIN_INDEX = {}
for _c in WINDOWS:
    for _i in _c["ids"]:
        _WIN_INDEX[(_c["channel"].lower(), _i)] = _WIN_INDEX.get((_c["channel"].lower(), _i), []) + [_c]
_UNIX_INDEX = {c["kind"]: c for c in UNIX}


def lookup(os_family: str, ev: dict):
    """Tìm items danh items cho sự kiện agent gửi lên; None = không nằm trong chính sách → bỏ."""
    if os_family == "windows":
        for c in _WIN_INDEX.get(((ev.get("channel") or "").lower(), int(ev.get("event_id") or 0)), []):
            prov = (ev.get("provider") or "").lower()
            if prov == c["provider"].lower() or prov.endswith(c["provider"].lower()):
                return c
        return None
    return _UNIX_INDEX.get(ev.get("kind") or "")


def windows_queries() -> list[dict]:
    """Truy vấn event log gửi cho agent Windows: kênh → danh sách Event ID. Không lọc theo nhà cung cấp ở agent
    (tên provider khác nhau giữa các bản Windows, e.g. Ntfs / Microsoft-Windows-Ntfs) – server lọc lại khi nhận."""
    by = {}
    for c in WINDOWS:
        by.setdefault(c["channel"], set()).update(c["ids"])
    return [{"channel": ch, "ids": sorted(ids)} for ch, ids in by.items()]


def catalog_rows() -> list[dict]:
    """Danh items để hiện trên giao diện (Cài đặt → Máy trạm)."""
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


NOISE_IDS = (4624, 4634, 4647, 4648, 4672, 4688, 4689, 5156, 5158)   # chặn cả khi agent cũ/error lỡ gửi lên
_SPACE = re.compile(r"\s+")


def clean_message(m: str, limit: int = 1500) -> str:
    return _SPACE.sub(" ", (m or "")).strip()[:limit]
