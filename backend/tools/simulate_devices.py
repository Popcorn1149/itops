"""Simulate devices sending REAL Syslog / SNMP Trap packets over the network to IT Ops – test log reception without devices.

Sends real UDP/TCP packets (no shortcut into the app), so it can run from ANOTHER MACHINE on the LAN:
    python tools/simulate_devices.py --host 192.168.1.50                 # IT Ops machine, ports 514/162
    python tools/simulate_devices.py --host 127.0.0.1 --syslog-port 6514 --trap-port 6162   # demo data configuration
    python tools/simulate_devices.py --host ... --v3-user itops-v3 --v3-auth MatKhauAuth1 --v3-priv MatKhauPriv1
    python tools/simulate_devices.py --host ... --recovery 0              # only send the "incident" part, no recovery

Host names in the logs (pfSense-HQ, SW-TANG3, ESXi-02…) match the demo data asset names → logs attach to the right asset.
Traps carry agentAddress = the demo device IP. With real data: change the names/IPs in the DEVICES table to match your assets.
Needs the pysnmp library (already in backend/requirements.txt) to send traps.
"""
import argparse
import asyncio
import socket
import sys
import time
from datetime import datetime

DEVICES = {   # name in the log → IP (used for trap agentAddress)
    "pfSense-HQ": "10.0.0.1", "SW-CORE": "10.0.0.2", "SW-TANG3": "10.0.0.3", "ESXi-02": "10.0.10.12",
    "NAS-HN": "10.1.0.50", "UPS-RACK": "10.0.10.60", "AP-HN": "10.1.0.21", "ERP-APP": "10.0.20.30",
}
ENGINE_ID = "8000000001020304"     # Engine ID of the "device" when sending v3 traps – register it in IT Ops: Settings › Syslog/Trap receivers
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
    """TCP syslog: by default each line ends with \\n; octet_counting=True follows RFC 6587 ("<length> <log>")."""
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
    vbs = [ObjectType(ObjectIdentity("1.3.6.1.6.3.18.1.3.0"), IpAddress(DEVICES[device]))]       # agentAddress
    vbs += [ObjectType(ObjectIdentity(o), Integer(v) if isinstance(v, int) else OctetString(v)) for o, v in varbinds]
    err, *_ = await send_notification(e, auth, await UdpTransportTarget.create((args.host, args.trap_port)), ContextData(), "trap",
                                      NotificationType(ObjectIdentity(oid)).add_varbinds(*vbs))
    e.close_dispatcher()
    return err


def trap(args, oid, device, varbinds=(), **kw):
    return asyncio.run(_trap(args, oid, device, varbinds, **kw))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="IP of the machine running IT Ops")
    ap.add_argument("--syslog-port", type=int, default=514)
    ap.add_argument("--trap-port", type=int, default=162)
    ap.add_argument("--community", default="public", help="SNMP v2c community configured in IT Ops")
    ap.add_argument("--v3-user", default="", help="also send an SNMPv3 authPriv (SHA/AES) trap with this user")
    ap.add_argument("--v3-auth", default="")
    ap.add_argument("--v3-priv", default="")
    ap.add_argument("--engine-id", default=ENGINE_ID)
    ap.add_argument("--recovery", "--phuc-hoi", dest="recovery", type=float, default=3, help="seconds to wait before sending recovery logs/traps (0 = do not send)")
    args = ap.parse_args()
    print(f"Sending to {args.host} · syslog {args.syslog_port} (UDP+TCP) · trap {args.trap_port}\n")

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
    say(1, "pfSense-HQ: 6 failed webGUI logins from 185.220.101.47")

    print("[2] Syslog UDP – RFC 5424")
    udp(args, rfc5424(86, "ERP-APP", "sshd", "Accepted publickey for deploy from 10.0.20.15 port 51234 ssh2"))
    say(1, "ERP-APP: sshd (RFC 5424 format)")

    print("[3] Syslog TCP – newline and octet-counting (RFC 6587)")
    try:
        tcp(args, [rfc3164(189, "SW-TANG3", "%SYS-5-CONFIG_I", "Configured from console by netadmin on vty0 (10.0.20.15)"),
                   rfc3164(30, "pfSense-HQ", "openvpn[31012]", "user 'ketoan01' authenticated")])
        say(1, "TCP newline: 2 logs")
        tcp(args, [rfc3164(30, "pfSense-HQ", "charon[52001]", "09[IKE] IKE_SA con1000[7] established between 203.0.113.10[HQ]...198.51.100.20[HN]")],
            octet_counting=True)
        say(1, "TCP octet-counting: 1 log")
    except OSError as e:
        say(0, f"TCP {args.syslog_port} could not connect: {e}")

    print("[4] SNMP Trap v2c")
    for name, oid, dev, vbs in [
        ("linkDown port 1/1/9 SW-CORE", "1.3.6.1.6.3.1.1.5.3", "SW-CORE", [("1.3.6.1.2.1.2.2.1.1", 9), ("1.3.6.1.2.1.31.1.1.1.1", "1/1/9"), ("1.3.6.1.2.1.2.2.1.8", 2)]),
        ("APC onBattery UPS-RACK", "1.3.6.1.4.1.318.0.5", "UPS-RACK", []),
        ("coldStart AP-HN (restart)", "1.3.6.1.6.3.1.1.5.1", "AP-HN", []),
    ]:
        err = trap(args, oid, dev, vbs)
        say(not err, f"{name}" + (f" – error: {err}" if err else ""))

    if args.v3_user:
        print("[5] SNMP Trap v3 (authPriv SHA/AES)")
        err = trap(args, "1.3.6.1.6.3.1.1.5.3", "SW-TANG3", [("1.3.6.1.2.1.2.2.1.1", 24), ("1.3.6.1.2.1.31.1.1.1.1", "Gi1/0/24")], v3=True)
        say(not err, f"linkDown Gi1/0/24 SW-TANG3 with user {args.v3_user}, Engine ID {args.engine_id}" + (f" – error: {err}" if err else ""))

    if args.recovery > 0:
        print(f"[6] Waiting {args.recovery:g}s, then sending recovery")
        time.sleep(args.recovery)
        for pri, host, app, msg in [
            (29, "pfSense-HQ", "dpinger[4321]", "MONITOR: WAN_FPT is available now, adding to routing group"),
            (187, "SW-TANG3", "%LINK-3-UPDOWN", "Interface GigabitEthernet1/0/20, changed state to up"),
            (14, "ESXi-02", "Hostd", "info hostd[2099578] Successfully restored access to volume 5f3a1c22-DS-SSD01 (DS-SSD01) following connectivity issues."),
            (14, "UPS-RACK", "UPS", "Returned from battery backup power."),
        ]:
            udp(args, rfc3164(pri, host, app, msg))
            say(1, f"{host}: {msg[:70]}")
        err = trap(args, "1.3.6.1.6.3.1.1.5.4", "SW-CORE", [("1.3.6.1.2.1.2.2.1.1", 9), ("1.3.6.1.2.1.31.1.1.1.1", "1/1/9"), ("1.3.6.1.2.1.2.2.1.8", 1)])
        say(not err, "linkUp port 1/1/9 SW-CORE")
        err = trap(args, "1.3.6.1.4.1.318.0.9", "UPS-RACK")
        say(not err, "APC powerRestored UPS-RACK")
    print(f"\nSent {OK} log/trap groups. See the result in IT Ops: Device Logs (Log tab) and Alerts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
