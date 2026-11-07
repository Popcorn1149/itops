"""Mô phỏng thiết bị gửi Syslog / SNMP Trap THẬT qua mạng tới IT Ops – kiểm tra đường nhận log mà chưa cần thiết bị.

Gửi gói tin UDP/TCP thật (không đi đường tắt vào app), nên chạy được từ MÁY KHÁC trong LAN:
    python tools/mo_phong_thiet_bi.py --host 192.168.1.50                 # máy IT Ops, cổng 514/162
    python tools/mo_phong_thiet_bi.py --host 127.0.0.1 --syslog-port 6514 --trap-port 6162   # cấu hình dữ liệu mẫu
    python tools/mo_phong_thiet_bi.py --host ... --v3-user itops-v3 --v3-auth MatKhauAuth1 --v3-priv MatKhauPriv1
    python tools/mo_phong_thiet_bi.py --host ... --phuc-hoi 0              # chỉ gửi phần "sự cố", không gửi phục hồi

Tên máy trong log (pfSense-HQ, SW-TANG3, ESXi-02…) trùng tên tài sản của dữ liệu mẫu → log tự gắn vào đúng tài sản.
Trap có kèm agentAddress = IP thiết bị mẫu. Với dữ liệu thật: đổi tên/IP ở bảng THIET_BI cho khớp tài sản của bạn.
Cần thư viện pysnmp (đã có trong backend/requirements.txt) để gửi trap.
"""
import argparse
import asyncio
import socket
import sys
import time
from datetime import datetime

THIET_BI = {   # tên trong log → IP (dùng cho trap agentAddress)
    "pfSense-HQ": "10.0.0.1", "SW-CORE": "10.0.0.2", "SW-TANG3": "10.0.0.3", "ESXi-02": "10.0.10.12",
    "NAS-HN": "10.1.0.50", "UPS-RACK": "10.0.10.60", "AP-HN": "10.1.0.21", "ERP-APP": "10.0.20.30",
}
ENGINE_ID = "8000000001020304"     # Engine ID của "thiết bị" khi gửi trap v3 – khai trong IT Ops: Cài đặt › Nhận Syslog/Trap
OK = 0


def say(ok, msg):
    global OK
    OK += ok
    print(("  ✓ " if ok else "  ✗ ") + msg)


def rfc3164(pri, host, app, msg):
    t = datetime.now()
    return f"<{pri}>{t.strftime('%b')} {t.day:>2} {t.strftime('%H:%M:%S')} {host} {app}: {msg}"


def rfc5424(pri, host, app, msg):
    return f"<{pri}>1 {datetime.now().astimezone().isoformat(timespec='milliseconds')} {host} {app} - - - {msg}"


def udp(args, line):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(line.encode(), (args.host, args.syslog_port))
    s.close()


def tcp(args, lines, octet_counting=False):
    """TCP syslog: mặc định mỗi dòng kết thúc bằng \\n; octet_counting=True theo RFC 6587 ("<độ dài> <log>")."""
    with socket.create_connection((args.host, args.syslog_port), timeout=5) as s:
        for line in lines:
            b = line.encode()
            s.sendall(f"{len(b)} ".encode() + b if octet_counting else b + b"\n")


async def _trap(args, oid, device, varbinds=(), community=None, v3=False):
    from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
                                             NotificationType, ObjectIdentity, ObjectType, Integer, OctetString, IpAddress,
                                             send_notification, usmHMACSHAAuthProtocol, usmAesCfb128Protocol)
    if v3:
        e = SnmpEngine(OctetString(hexValue=args.engine_id))
        auth = UsmUserData(args.v3_user, args.v3_auth, args.v3_priv, authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol)
    else:
        e = SnmpEngine()
        auth = CommunityData(community or args.community, mpModel=1)
    vbs = [ObjectType(ObjectIdentity("1.3.6.1.6.3.18.1.3.0"), IpAddress(THIET_BI[device]))]       # agentAddress
    vbs += [ObjectType(ObjectIdentity(o), Integer(v) if isinstance(v, int) else OctetString(v)) for o, v in varbinds]
    err, *_ = await send_notification(e, auth, await UdpTransportTarget.create((args.host, args.trap_port)), ContextData(), "trap",
                                      NotificationType(ObjectIdentity(oid)).add_varbinds(*vbs))
    e.close_dispatcher()
    return err


def trap(args, oid, device, varbinds=(), **kw):
    return asyncio.run(_trap(args, oid, device, varbinds, **kw))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="IP máy chạy IT Ops")
    ap.add_argument("--syslog-port", type=int, default=514)
    ap.add_argument("--trap-port", type=int, default=162)
    ap.add_argument("--community", default="public", help="community SNMP v2c đã khai trong IT Ops")
    ap.add_argument("--v3-user", default="", help="gửi thêm trap SNMPv3 authPriv (SHA/AES) bằng user này")
    ap.add_argument("--v3-auth", default="")
    ap.add_argument("--v3-priv", default="")
    ap.add_argument("--engine-id", default=ENGINE_ID)
    ap.add_argument("--phuc-hoi", type=float, default=3, help="giây chờ trước khi gửi log/trap phục hồi (0 = không gửi)")
    args = ap.parse_args()
    print(f"Gửi tới {args.host} · syslog {args.syslog_port} (UDP+TCP) · trap {args.trap_port}\n")

    print("[1] Syslog UDP – RFC 3164 (pfSense, Cisco, ESXi, Synology, UPS)")
    sus = [
        (29, "pfSense-HQ", "dpinger[4321]", "MONITOR: WAN_FPT is down, omitting from routing group"),
        (187, "SW-TANG3", "%LINK-3-UPDOWN", "Interface GigabitEthernet1/0/20, changed state to down"),
        (11, "ESXi-02", "Hostd", "error hostd[2099578] Lost access to volume 5f3a1c22-DS-SSD01 (DS-SSD01) due to connectivity issues."),
        (10, "NAS-HN", "System", "Storage Pool 1 has degraded. Please repair it as soon as possible."),
        (10, "UPS-RACK", "UPS", "On battery power in response to an input power problem."),
    ]
    for pri, host, app, msg in sus:
        udp(args, rfc3164(pri, host, app, msg))
        say(1, f"{host}: {msg[:70]}")
    for u in ["admin", "root", "oracle", "test", "support", "guest"]:
        udp(args, rfc3164(36, "pfSense-HQ", "php-fpm[33612]", f"/index.php: webConfigurator authentication error for user '{u}' from: 185.220.101.47"))
    say(1, "pfSense-HQ: 6 lần đăng nhập webGUI sai từ 185.220.101.47")

    print("[2] Syslog UDP – RFC 5424")
    udp(args, rfc5424(86, "ERP-APP", "sshd", "Accepted publickey for deploy from 10.0.20.15 port 51234 ssh2"))
    say(1, "ERP-APP: sshd (định dạng RFC 5424)")

    print("[3] Syslog TCP – xuống dòng và octet-counting (RFC 6587)")
    try:
        tcp(args, [rfc3164(189, "SW-TANG3", "%SYS-5-CONFIG_I", "Configured from console by netadmin on vty0 (10.0.20.15)"),
                   rfc3164(30, "pfSense-HQ", "openvpn[31012]", "user 'ketoan01' authenticated")])
        say(1, "TCP xuống dòng: 2 log")
        tcp(args, [rfc3164(30, "pfSense-HQ", "charon[52001]", "09[IKE] IKE_SA con1000[7] established between 203.0.113.10[HQ]...198.51.100.20[HN]")],
            octet_counting=True)
        say(1, "TCP octet-counting: 1 log")
    except OSError as e:
        say(0, f"TCP {args.syslog_port} không kết nối được: {e}")

    print("[4] SNMP Trap v2c")
    for name, oid, dev, vbs in [
        ("linkDown cổng 1/1/9 SW-CORE", "1.3.6.1.6.3.1.1.5.3", "SW-CORE", [("1.3.6.1.2.1.2.2.1.1", 9), ("1.3.6.1.2.1.31.1.1.1.1", "1/1/9"), ("1.3.6.1.2.1.2.2.1.8", 2)]),
        ("APC onBattery UPS-RACK", "1.3.6.1.4.1.318.0.5", "UPS-RACK", []),
        ("coldStart AP-HN (khởi động lại)", "1.3.6.1.6.3.1.1.5.1", "AP-HN", []),
    ]:
        err = trap(args, oid, dev, vbs)
        say(not err, f"{name}" + (f" – lỗi: {err}" if err else ""))

    if args.v3_user:
        print("[5] SNMP Trap v3 (authPriv SHA/AES)")
        err = trap(args, "1.3.6.1.6.3.1.1.5.3", "SW-TANG3", [("1.3.6.1.2.1.2.2.1.1", 24), ("1.3.6.1.2.1.31.1.1.1.1", "Gi1/0/24")], v3=True)
        say(not err, f"linkDown Gi1/0/24 SW-TANG3 bằng user {args.v3_user}, Engine ID {args.engine_id}" + (f" – lỗi: {err}" if err else ""))

    if args.phuc_hoi > 0:
        print(f"[6] Chờ {args.phuc_hoi:g}s rồi gửi phục hồi")
        time.sleep(args.phuc_hoi)
        for pri, host, app, msg in [
            (29, "pfSense-HQ", "dpinger[4321]", "MONITOR: WAN_FPT is available now, adding to routing group"),
            (187, "SW-TANG3", "%LINK-3-UPDOWN", "Interface GigabitEthernet1/0/20, changed state to up"),
            (14, "ESXi-02", "Hostd", "info hostd[2099578] Successfully restored access to volume 5f3a1c22-DS-SSD01 (DS-SSD01) following connectivity issues."),
            (14, "UPS-RACK", "UPS", "Returned from battery backup power."),
        ]:
            udp(args, rfc3164(pri, host, app, msg))
            say(1, f"{host}: {msg[:70]}")
        err = trap(args, "1.3.6.1.6.3.1.1.5.4", "SW-CORE", [("1.3.6.1.2.1.2.2.1.1", 9), ("1.3.6.1.2.1.31.1.1.1.1", "1/1/9"), ("1.3.6.1.2.1.2.2.1.8", 1)])
        say(not err, "linkUp cổng 1/1/9 SW-CORE")
        err = trap(args, "1.3.6.1.4.1.318.0.9", "UPS-RACK")
        say(not err, "APC powerRestored UPS-RACK")
    print(f"\nĐã gửi {OK} nhóm log/trap. Xem kết quả ở IT Ops: Log thiết bị (tab Log) và Cảnh báo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
