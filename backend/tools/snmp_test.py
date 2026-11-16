"""Quick SNMP reachability test (read-only): asks a device for sysName / sysDescr / sysUpTime.

    python tools/snmp_test.py <ip> <community>                 # SNMP v2c
    python tools/snmp_test.py <ip> <community> --v1            # SNMP v1
    python tools/snmp_test.py <ip> --v3 <user> <auth_key> [priv_key] [--md5] [--aes]   # v3 (default SHA + DES)

Prints which step fails so you can tell "no route / blocked" from "wrong community or version".
"""
import asyncio
import socket
import sys

from pysnmp.hlapi.v3arch.asyncio import (bulk_walk_cmd, CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
                                         UdpTransportTarget, UsmUserData, get_cmd, usmDESPrivProtocol,
                                         usmAesCfb128Protocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
                                         usmNoPrivProtocol)

OIDS = {"sysName": "1.3.6.1.2.1.1.5.0", "sysDescr": "1.3.6.1.2.1.1.1.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0"}
ARUBA = {"APs (aiAccessPointTable)": "1.3.6.1.4.1.14823.2.3.3.1.2.1.1.2", "WLANs (aiWlanTable)": "1.3.6.1.4.1.14823.2.3.3.1.2.3.1.3",
         "Clients (aiClientTable)": "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.3"}


async def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    ip = argv[0]
    if "--v3" in argv:
        rest = [a for a in argv[argv.index("--v3") + 1:] if not a.startswith("--")]
        user, auth = rest[0], rest[1]
        priv = rest[2] if len(rest) > 2 else None
        auth_data = UsmUserData(user, auth, priv,
                                authProtocol=usmHMACMD5AuthProtocol if "--md5" in argv else usmHMACSHAAuthProtocol,
                                privProtocol=(usmAesCfb128Protocol if "--aes" in argv else usmDESPrivProtocol) if priv else usmNoPrivProtocol)
        label = f"v3 user={user}"
    else:
        auth_data = CommunityData(argv[1], mpModel=0 if "--v1" in argv else 1)
        label = "v1" if "--v1" in argv else "v2c"

    try:
        socket.inet_aton(ip)
    except OSError:
        print(f"[FAIL] '{ip}' is not an IPv4 address")
        return 1
    print(f"Testing SNMP {label} → {ip}:161 (timeout 3 s, 1 retry)")
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=3, retries=1)
    err, status, idx, binds = await get_cmd(engine, auth_data, target, ContextData(),
                                            *[ObjectType(ObjectIdentity(o)) for o in OIDS.values()])
    if err:
        print(f"[FAIL] {err}")
        print("  → No answer at all. Check, in order:")
        print("    1. SNMP is enabled on the device and the community / v3 user matches EXACTLY (case-sensitive).")
        print("       A wrong community is silently ignored, so it looks the same as a timeout.")
        print("    2. The SNMP version matches (v2c vs v3).")
        print("    3. UDP 161 is allowed from this machine to the device (VLAN ACL / firewall between subnets).")
        print("    4. Aruba Instant cluster: query the Virtual Controller IP, not a member AP.")
        return 1
    if status:
        print(f"[FAIL] device answered with an error: {status.prettyPrint()}")
        return 1
    print("[OK] SNMP answered:")
    for name, (oid, val) in zip(OIDS, binds):
        print(f"  {name:10} {val.prettyPrint()[:120]}")
    objid = binds[3][1].prettyPrint()
    print(f"  Aruba device: {'yes' if ('14823' in objid.split('.')[:8] or 'enterprises.14823' in objid or objid.startswith('1.3.6.1.4.1.14823')) else 'NO (IT Ops only reads the Wi-Fi client list from Aruba devices)'}")
    for label, oid in ARUBA.items():
        n, sample = 0, []
        async for e, st, _, bs in bulk_walk_cmd(engine, auth_data, target, ContextData(), 0, 30,
                                                ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if e or st:
                print(f"  {label}: error {e or st.prettyPrint()}")
                break
            for _, v in bs:
                n += 1
                if len(sample) < 3:
                    sample.append(v.prettyPrint()[:40])
        print(f"  {label}: {n} rows {sample}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
