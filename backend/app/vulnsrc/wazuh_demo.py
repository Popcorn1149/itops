"""Simulated Wazuh for DEMO DATA only – 5 Wazuh agents with realistic CVEs so the Vulnerabilities screens can be seen
without a Wazuh server. Never created in a real database (see app/vuln.py seed_demo, called only when DEMO_DATA=true).
4 agents match the demo endpoints; WAZUH-LAB-07 does not exist in IT Ops → shows the "unmatched hosts" flow."""
from datetime import timedelta

from . import HostRef, Provider, Record, Snapshot, register

AGENTS = [("001", "PC-KD03", "10.10.6.13", "Windows 11 Pro 23H2"), ("002", "PC-LA", "10.10.9.99", "Windows 11 Pro 23H2"),
          ("003", "SRV-FILE01", "10.10.1.20", "Windows Server 2022"), ("004", "srv-web01", "10.10.1.40", "Ubuntu 22.04.4 LTS"),
          ("005", "WAZUH-LAB-07", "10.10.20.7", "Ubuntu 20.04 LTS")]

# (agent, CVE, package, version, days since first seen, fixed N days ago or None)
RECORDS = [
    ("001", "CVE-2023-38831", "WinRAR", "5.50.0", 20, None),
    ("001", "CVE-2024-11477", "7-Zip", "24.08", 12, None),
    ("001", "CVE-2023-5217", "Google Chrome", "116.0.5845.141", 40, 6),
    ("002", "CVE-2024-21413", "Microsoft Office", "16.0.17126", 9, None),
    ("002", "CVE-2024-11477", "7-Zip", "24.08", 12, None),
    ("002", "CVE-2023-4863", "Google Chrome", "116.0.5845.96", 35, 12),
    ("003", "CVE-2024-38063", "Windows Server 2022", "10.0.20348.2582", 25, None),
    ("003", "CVE-2024-43451", "Windows Server 2022", "10.0.20348.2582", 3, None),
    ("003", "CVE-2024-30088", "Windows Server 2022", "10.0.20348.2340", 60, 20),
    ("004", "CVE-2024-6387", "openssh-server", "1:8.9p1-3ubuntu0.6", 50, None),
    ("004", "CVE-2023-48795", "openssh-server", "1:8.9p1-3ubuntu0.6", 50, None),
    ("004", "CVE-2023-44487", "nginx", "1.18.0-6ubuntu14.4", 15, None),
    ("004", "CVE-2024-2961", "libc6", "2.35-0ubuntu3.6", 1, None),
    ("005", "CVE-2024-6387", "openssh-server", "1:8.2p1-4ubuntu0.11", 10, None),
]

# demo catalogue entries (used only if the CVE is not in the catalogue yet; a real NVD sync replaces them)
CATALOGUE = {
    "CVE-2023-38831": (7.8, "high", True, 0.97, "WinRAR allows code execution when a user opens a crafted ZIP archive."),
    "CVE-2024-11477": (7.8, "high", False, 0.35, "7-Zip Zstandard decompression integer underflow allows remote code execution."),
    "CVE-2023-5217": (8.8, "high", True, 0.90, "Heap buffer overflow in vp8 encoding in libvpx (Google Chrome)."),
    "CVE-2024-21413": (9.8, "critical", True, 0.99, "Microsoft Outlook remote code execution (MonikerLink)."),
    "CVE-2023-4863": (8.8, "high", True, 0.98, "Heap buffer overflow in libwebp (Google Chrome)."),
    "CVE-2024-38063": (9.8, "critical", False, 0.93, "Windows TCP/IP remote code execution via IPv6 packets."),
    "CVE-2024-43451": (6.5, "medium", True, 0.80, "NTLM hash disclosure spoofing vulnerability."),
    "CVE-2024-30088": (7.0, "high", True, 0.95, "Windows kernel elevation of privilege."),
    "CVE-2024-6387": (8.1, "high", False, 0.99, "OpenSSH regreSSHion: signal handler race condition allows unauthenticated RCE."),
    "CVE-2023-48795": (5.9, "medium", False, 0.96, "SSH Terrapin prefix truncation attack."),
    "CVE-2023-44487": (7.5, "high", True, 0.94, "HTTP/2 Rapid Reset denial of service."),
    "CVE-2024-2961": (8.8, "high", False, 0.92, "glibc iconv() ISO-2022-CN-EXT out-of-bounds write."),
}


def snapshot(include_fixed: bool) -> Snapshot:
    hosts = [HostRef(ref=i, name=n, ip=ip, os=os, scanned=True) for i, n, ip, os in AGENTS]
    recs = [Record(ref=a, cve_id=c, package=p, version=v, severity=CATALOGUE[c][1], score=CATALOGUE[c][0])
            for a, c, p, v, _d, fixed in RECORDS if include_fixed or fixed is None]
    return Snapshot(hosts=hosts, records=recs, info={"version": "4.14.5 (simulated)", "tested": True, "agents": len(AGENTS),
                                                    "documents": len(recs)})


@register
class WazuhDemoProvider(Provider):
    kind = "wazuh_demo"
    label = "Wazuh (simulated – demo data)"
    default_confidence = "high"
    singleton = True

    def defaults(self) -> dict:
        return {"interval_hours": 6, "mapping": {}}

    async def test(self, cfg, db) -> dict:
        return {"version": "4.14.5 (simulated)", "tested": True, "agents": len(AGENTS), "vulnerability_documents": len(RECORDS)}

    async def collect(self, cfg, db, payload=None) -> Snapshot:
        return snapshot(include_fixed=False)
