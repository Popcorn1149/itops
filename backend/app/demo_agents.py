"""Máy trạm MẪU cho DỮ LIỆU MẪU (DEMO_DATA=true) – xem trang Máy trạm khi chưa cài agent thật.

Dữ liệu đi qua ĐÚNG đường xử lý của agent thật (agents.process_report): lọc, dịch tiếng Việt, gộp, cảnh báo.
Máy mẫu có uid bắt đầu bằng "demo-". Tắt bằng DEMO_AGENTS=0.
"""
import asyncio
import logging
import os
import random
from datetime import timedelta

from . import agents as ag
from . import models
from .db import SessionLocal

log = logging.getLogger("itops.demo_agents")

# (tên, hệ điều hành, loại, người dùng, IP, model, RAM GB, CPU nền, RAM nền, ổ C %)
MACHINES = [
    ("PC-KT01", "windows", "client", "CTY\\lan.nt", "10.10.5.21", "Dell OptiPlex 7010", 16, 8, 55, 71),
    ("PC-KT02", "windows", "client", "CTY\\hung.pv", "10.10.5.22", "Dell OptiPlex 7010", 16, 6, 48, 64),
    ("PC-NS01", "windows", "client", "CTY\\thu.tt", "10.10.5.31", "HP ProDesk 400 G9", 8, 12, 78, 93),     # ổ gần đầy
    ("PC-KD03", "windows", "client", "CTY\\minh.lq", "10.10.6.13", "Lenovo ThinkCentre M70q", 16, 15, 61, 58),
    ("PC-KD04", "windows", "client", "", "10.10.6.14", "Lenovo ThinkCentre M70q", 16, 3, 35, 47),
    ("LT-GD01", "windows", "client", "CTY\\giamdoc", "10.10.7.10", "Lenovo ThinkPad X1 Carbon Gen 12", 32, 10, 52, 66),
    ("LT-IT02", "windows", "client", "CTY\\it.admin", "10.10.9.12", "Dell Latitude 5440", 16, 18, 67, 54),
    ("PC-LA", "windows", "client", "CTY\\tam.dh", "10.10.9.99", "HP EliteDesk 800 G6", 8, 22, 81, 77),    # máy bị dùng dò mật khẩu
    ("SRV-FILE01", "windows", "server", "", "10.10.1.20", "VMware Virtual Platform", 16, 14, 62, 82),
    ("SRV-DC01", "windows", "server", "", "10.10.1.10", "VMware Virtual Platform", 8, 9, 58, 46),
    ("srv-web01", "linux", "server", "", "10.10.1.40", "VMware Virtual Platform", 8, 20, 71, 62),
    ("MBP-TK01", "darwin", "client", "thiet.ke", "10.10.8.21", "MacBookPro18,3", 16, 14, 69, 58),
]

SOFTWARE_WIN = [("Google Chrome", "131.0.6778.86", "Google LLC"), ("Microsoft Edge", "131.0.2903.70", "Microsoft Corporation"),
                ("Microsoft 365 Apps for business - vi-vn", "16.0.18129.20158", "Microsoft Corporation"),
                ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov"), ("Zalo", "24.10.1", "VNG Corp."), ("UltraViewer version 6.6", "6.6.76", "DucFabulous"),
                ("Foxit PDF Reader", "2024.3.0.26795", "Foxit Software Inc."), ("MISA SME 2024", "R27", "MISA JSC"),
                ("Microsoft Teams", "24295.605.3225.8804", "Microsoft Corporation"), ("UniKey 4.6 RC2", "4.6", "Pham Kim Long")]
EXTRA = {"PC-KD03": [("AnyDesk", "8.1.0", "AnyDesk Software GmbH"), ("WinRAR 5.50 (64-bit)", "5.50.0", "win.rar GmbH")],
         "LT-IT02": [("PuTTY release 0.81 (64-bit)", "0.81.0.0", "Simon Tatham"), ("Wireshark 4.4.1 x64", "4.4.1", "The Wireshark developer community")],
         "PC-LA": [("TeamViewer", "15.59.3", "TeamViewer"), ("CCleaner", "6.29", "Piriform Software")]}
SERVICES_WIN = [("Spooler", "Print Spooler", "running", "auto"), ("WinDefend", "Microsoft Defender Antivirus Service", "running", "auto"),
                ("wuauserv", "Windows Update", "stopped", "manual"), ("BITS", "Background Intelligent Transfer Service", "running", "auto-delayed"),
                ("Dnscache", "DNS Client", "running", "auto"), ("W32Time", "Windows Time", "running", "auto"),
                ("TermService", "Remote Desktop Services", "stopped", "manual"), ("LanmanServer", "Server", "running", "auto"),
                ("ITOpsAgent", "IT Ops Agent", "running", "auto-delayed")]


def enabled() -> bool:
    return os.environ.get("DEMO_DATA", "false").lower() in ("1", "true", "yes") and os.environ.get("DEMO_AGENTS", "1") != "0"


def _system(m):
    name, osf, kind, user, ip, model, ram = m[:7]
    os_name = {"windows": "Windows 11 Pro" if kind == "client" else "Windows Server 2022 Standard",
               "linux": "Ubuntu 24.04.1 LTS", "darwin": "macOS 15.1"}[osf]
    ver = {"windows": "24H2 (build 26100.2314)" if kind == "client" else "21H2 (build 20348.2849)", "linux": "24.04", "darwin": "24B83"}[osf]
    return ag.SystemInfo(hostname=name, domain="cty.local" if osf == "windows" else "", os_name=os_name, os_version=ver, os_kind=kind,
                         arch="arm64" if osf == "darwin" else "amd64", manufacturer=model.split(" ")[0] if osf != "darwin" else "Apple",
                         model=model, serial=f"DEMO{abs(hash(name)) % 10**7:07d}", cpu_model="Intel(R) Core(TM) i5-12500" if osf == "windows" else "Apple M1 Pro" if osf == "darwin" else "Intel Xeon Silver 4310",
                         cpu_cores=12 if osf != "linux" else 4, ram_mb=ram * 1024, ips=[ip], logged_user=user)


def _metrics(m, jitter=True):
    cpu, mem, disk = m[7], m[8], m[9]
    j = (lambda x, d: max(0.5, min(99, x + random.uniform(-d, d)))) if jitter else (lambda x, d: x)
    disks = [ag.Disk(mount="C:" if m[1] == "windows" else "/" if m[1] == "linux" else "Macintosh HD", total_gb=237 if m[2] == "client" else 500,
                     used_pct=round(disk, 1))]
    if m[0] == "SRV-FILE01":
        disks.append(ag.Disk(mount="D:", total_gb=4000, used_pct=88.4))
    return ag.Metrics(cpu=round(j(cpu, 6), 1), mem=round(j(mem, 4), 1), disks=disks, uptime_s=random.randint(3600, 9 * 86400))


def _ev(name, eid, data, minutes_ago, channel="Security", provider="Microsoft-Windows-Security-Auditing", rec=0):
    return ag.AgentEventIn(channel=channel, provider=provider, event_id=eid, record_id=rec, ts=ag.utcnow() - timedelta(minutes=minutes_ago),
                           data=data, message="")


def _events(name):
    """Sự cố mẫu theo từng máy – đúng tên trường của Windows thật."""
    out = []
    if name == "SRV-DC01":
        # 14 lần đăng nhập RDP sai từ PC-LA trong vài phút → "Nghi dò mật khẩu"; sau đó tài khoản bị khoá
        for i, u in enumerate(["administrator"] * 6 + ["admin", "ketoan", "lan.nt", "lan.nt", "lan.nt", "backup", "sa", "test"]):
            out.append(_ev(name, 4625, {"TargetUserName": u, "TargetDomainName": "CTY", "IpAddress": "10.10.9.99", "WorkstationName": "PC-LA",
                                        "LogonType": "10", "Status": "0xc000006d", "SubStatus": "0xc000006a" if u != "admin" else "0xc0000064"},
                           50 - i * 0.2, rec=900100 + i))
        out.append(_ev(name, 4740, {"TargetUserName": "lan.nt", "TargetDomainName": "PC-LA", "SubjectUserName": "SRV-DC01$"}, 46, rec=900200))
        out.append(_ev(name, 4732, {"TargetUserName": "Administrators", "MemberName": "CN=Tran Minh Tam,OU=Users,DC=cty,DC=local",
                                    "SubjectUserName": "it.admin", "SubjectDomainName": "CTY"}, 180, rec=900300))
        out.append(_ev(name, 4720, {"TargetUserName": "nv.moi01", "TargetDomainName": "CTY", "SubjectUserName": "it.admin", "SubjectDomainName": "CTY"}, 600, rec=900310))
    if name == "PC-KT01":
        out.append(_ev(name, 4625, {"TargetUserName": "lan.nt", "TargetDomainName": "CTY", "IpAddress": "127.0.0.1", "WorkstationName": "PC-KT01",
                                    "LogonType": "7", "SubStatus": "0xc000006a"}, 35, rec=500))
        out.append(_ev(name, 4625, {"TargetUserName": "lan.nt", "TargetDomainName": "CTY", "IpAddress": "127.0.0.1", "WorkstationName": "PC-KT01",
                                    "LogonType": "7", "SubStatus": "0xc000006a"}, 34, rec=501))
    if name == "PC-KD03":
        out.append(_ev(name, 1116, {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Severity Name": "Severe", "Category Name": "Trojan",
                                    "Path": "file:_C:\\Users\\minh.lq\\Downloads\\HoaDon_T11.pdf.exe", "Detection User": "CTY\\minh.lq",
                                    "Process Name": "C:\\Windows\\explorer.exe"}, 95,
                       channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender", rec=7001))
        out.append(_ev(name, 1117, {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Action Name": "Cách ly (Quarantine)", "Detection User": "CTY\\minh.lq",
                                    "Path": "file:_C:\\Users\\minh.lq\\Downloads\\HoaDon_T11.pdf.exe"}, 94,
                       channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender", rec=7002))
    if name == "PC-NS01":
        out.append(_ev(name, 41, {"BugcheckCode": "0"}, 300, channel="System", provider="Microsoft-Windows-Kernel-Power", rec=3001))
        out.append(_ev(name, 6008, {}, 299, channel="System", provider="EventLog", rec=3002))
    if name == "SRV-FILE01":
        for i in range(3):
            out.append(_ev(name, 7031, {"param1": "Veeam Agent for Microsoft Windows", "param2": str(i + 1)}, 140 - i * 3,
                           channel="System", provider="Service Control Manager", rec=4100 + i))
        out.append(_ev(name, 153, {"param1": "\\Device\\Harddisk1\\DR1"}, 20, channel="System", provider="Disk", rec=4200))
    if name == "LT-IT02":
        out.append(_ev(name, 7045, {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "AccountName": "LocalSystem"}, 240,
                       channel="System", provider="Service Control Manager", rec=8100))
    if name == "srv-web01":
        for i in range(12):
            out.append(ag.AgentEventIn(channel="journal", provider="sshd", kind="auth_fail", record_id=10**15 + i, ts=ag.utcnow() - timedelta(minutes=70 - i * 0.3),
                                       data={"user": ["root", "admin", "ubuntu", "oracle"][i % 4], "src": "185.220.101.47", "service": "SSH"}))
        out.append(ag.AgentEventIn(channel="journal", provider="systemd", kind="service_failed", record_id=10**15 + 50, ts=ag.utcnow() - timedelta(minutes=25),
                                   data={"unit": "php8.3-fpm.service", "result": "exit-code"}))
    if name == "MBP-TK01":
        out.append(ag.AgentEventIn(channel="unifiedlog", provider="sudo", kind="sudo_fail", record_id=10**15 + 1, ts=ag.utcnow() - timedelta(minutes=400),
                                   data={"user": "thiet.ke"}))
    return out


def _defender(name):
    if name == "PC-LA":
        return {"realtime": False, "antivirus_enabled": True, "signature_age_days": 12, "signature_version": "1.419.212.0",
                "running_mode": "Normal", "quick_scan_age_days": 30, "full_scan_age_days": 4294967295, "tamper_protection": False}
    if name == "SRV-FILE01":
        return {"realtime": True, "antivirus_enabled": True, "signature_age_days": 0, "signature_version": "1.421.15.0",
                "running_mode": "Passive Mode", "other_av": "Kaspersky Endpoint Security"}
    return {"realtime": True, "antivirus_enabled": True, "signature_age_days": random.choice([0, 0, 1]), "signature_version": "1.421.15.0",
            "running_mode": "Normal", "quick_scan_age_days": random.randint(0, 6), "full_scan_age_days": random.randint(5, 60), "tamper_protection": True,
            "product_version": "4.18.24090.11"}


def seed():
    with SessionLocal() as db:
        if db.query(models.Agent).filter(models.Agent.uid.like("demo-%")).first():
            return
        for m in MACHINES:
            a = models.Agent(uid=f"demo-{m[0].lower()}", key_hash="demo-khong-dang-nhap-duoc", hostname=m[0], os_family=m[1], os_kind=m[2],
                             agent_version="1.0.0", ip=m[4], ips=[], summary={}, enrolled_at=ag.utcnow() - timedelta(days=random.randint(3, 20)))
            db.add(a)
        db.commit()
    for m in MACHINES:
        _report(m, first=True)
    # lịch sử hiệu năng 24 giờ (5 phút / điểm) để biểu đồ có dữ liệu ngay
    with SessionLocal() as db:
        now = ag.utcnow()
        for m in MACHINES:
            a = db.query(models.Agent).filter_by(uid=f"demo-{m[0].lower()}").one()
            for i in range(288, 0, -1):
                t = now - timedelta(minutes=5 * i)
                work = 1.0 if 1 <= (t.hour + 7) % 24 - 8 <= 9 else 0.35         # giờ làm việc (UTC+7) bận hơn
                db.add(models.AgentMetric(agent_id=a.id, ts=t, cpu=round(min(99, m[7] * work * random.uniform(0.5, 1.6) + random.uniform(0, 4)), 1),
                                          mem=round(min(99, m[8] * (0.8 + 0.2 * work) + random.uniform(-3, 3)), 1), disk=m[9]))
        db.commit()
    log.warning("Đã tạo %d máy trạm mẫu (DEMO_AGENTS=0 để tắt)", len(MACHINES))


def _report(m, first=False):
    with SessionLocal() as db:
        a = db.query(models.Agent).filter_by(uid=f"demo-{m[0].lower()}").first()
        if not a:
            return []
        aid = a.id
    name, osf = m[0], m[1]
    sw = None
    if first:
        if osf == "windows":
            sw = [ag.Software(name=n, version=v, publisher=p, installed_on="2024-06-12", source="machine") for n, v, p in SOFTWARE_WIN + EXTRA.get(name, [])]
        elif osf == "linux":
            sw = [ag.Software(name=n, version=v, publisher="Ubuntu Developers", source="dpkg") for n, v in
                  [("nginx", "1.24.0-2ubuntu7.1"), ("openssl", "3.0.13-0ubuntu3.4"), ("php8.3-fpm", "8.3.6-0ubuntu0.24.04.2"), ("mysql-server-8.0", "8.0.40-0ubuntu0.24.04.1")]]
        else:
            sw = [ag.Software(name=n, version=v, publisher="Identified Developer", source="app") for n, v in
                  [("Adobe Photoshop 2025", "26.1"), ("Figma", "124.6.5"), ("Google Chrome", "131.0.6778.86"), ("Zalo", "24.10.1")]]
    svcs = [ag.Service(name=n, display=d, state=s, start=st) for n, d, s, st in SERVICES_WIN] if osf == "windows" and first else None
    if svcs and name == "SRV-FILE01":
        svcs.append(ag.Service(name="VeeamEndpointBackupSvc", display="Veeam Agent for Microsoft Windows", state="stopped", start="auto"))
    rep = ag.Report(seq=1, agent_version="1.0.0", system=_system(m), metrics=_metrics(m), software=sw, services=svcs,
                    defender=_defender(name) if osf == "windows" else None,
                    updates={"reboot_pending": name in ("PC-KT02", "SRV-FILE01"), "last_hotfix": {"id": "KB5046617", "installed_on": "2026-11-01"}} if osf == "windows" else None,
                    posture=({"firewall": [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": True}, {"name": "Public", "enabled": name != "PC-LA"}],
                              "bitlocker": {"protection": "On" if name.startswith("LT-") else "Off", "status": "FullyEncrypted" if name.startswith("LT-") else "FullyDecrypted", "percent": 100 if name.startswith("LT-") else 0}}
                             if osf == "windows" else {"filevault": True, "firewall": True, "gatekeeper": True, "sip": True} if osf == "darwin" else {"firewall": True, "firewall_tool": "ufw"}),
                    events=_events(name) if first else [])
    _, notes = ag.process_report(aid, rep, m[4])
    return notes


async def live_loop():
    """Máy mẫu "gửi" hiệu năng mỗi phút để luôn hiện đang kết nối; PC-KD04 coi như đã tắt máy."""
    while True:
        await asyncio.sleep(60)
        try:
            for m in MACHINES:
                if m[0] != "PC-KD04":
                    await asyncio.to_thread(_report, m)
        except Exception:
            log.exception("máy trạm mẫu lỗi")
