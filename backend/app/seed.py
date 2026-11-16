"""Demo data (DEMO_DATA=true) for previewing the interface. Sample checks run in simulation mode."""
import random

from . import models
from .collectors.base import Result, apply_resources, worst
from .models import now


def _jit(v, sd, lo=0, hi=100):
    return None if v is None else round(max(lo, min(hi, random.gauss(v, sd))), 1)


def simulate(cfg: dict) -> Result:
    st = cfg.get("demo_status", "ok")
    if cfg.get("demo_res"):
        r = cfg["demo_res"]
        data, statuses, notes = dict(cfg.get("demo_data") or {}), [st], []
        m = apply_resources(data, cfg, statuses, notes, cpu=_jit(r.get("cpu"), 6, 1), mem=_jit(r.get("mem"), 0.7, 1),
                            disks=[{**d, "pct": _jit(d["pct"], 0.15)} for d in r.get("disks", [])],
                            mem_total_gb=r.get("mem_total_gb"), cores=r.get("cores"))
        base = float(cfg.get("demo_latency", 5))
        lat = round(max(0.3, random.gauss(base, base * 0.15)), 1)
        msg = " · ".join([cfg.get("demo_message", "OK")] + notes)
        return Result(worst(*statuses), msg, lat, m.get("cpu"), data)
    base = float(cfg.get("demo_latency", 5))
    lat = round(max(0.3, random.gauss(base, base * 0.15)), 1)
    val = cfg.get("demo_value")
    if isinstance(val, (int, float)):
        val = round(max(0, min(100, random.gauss(val, 3))), 1)
    msg = cfg.get("demo_message", "OK")
    if "{lat}" in msg:
        msg = msg.replace("{lat}", f"{lat}")
    if "{val}" in msg and val is not None:
        msg = msg.replace("{val}", f"{val}")
    return Result(st, msg, lat, val, cfg.get("demo_data", {}))


def seed_demo(db):
    S = lambda **k: _add(db, models.Site(**k))  # noqa: E731
    A = lambda **k: _add(db, models.Asset(**k))  # noqa: E731

    hq = S(name="Headquarters", kind="datacenter", location="5th Floor, District 1, Ho Chi Minh City", wan="Two ISP links: FPT + Viettel (static IPs)", vpn="Employee OpenVPN", sort=1)
    br = S(name="Hanoi branch", kind="branch", location="Cau Giay, Hanoi", wan="VNPT dynamic IP", vpn="IPsec site-to-site to HQ", sort=2)
    vps = S(name="VPS / Cloud", kind="vps", location="Viettel IDC", wan="IP public", sort=3)

    fw = A(name="pfSense-HQ", type="firewall", site_id=hq.id, ip="10.0.0.1", vendor="Netgate", model="pfSense CE 2.7.2", status="up",
           meta={"live": {"cpu": 12, "mem": 34, "version": "2.7.2", "uptime": "41d 3h"}})
    core = A(name="SW-CORE", type="switch", site_id=hq.id, parent_id=fw.id, ip="10.0.0.2", vendor="Aruba", model="2930F-48G", status="up")
    sw2 = A(name="SW-TANG3", type="switch", site_id=hq.id, parent_id=core.id, ip="10.0.0.3", vendor="Cisco", model="CBS350-24P", status="up")
    esx1 = A(name="ESXi-01", type="host", site_id=hq.id, parent_id=core.id, ip="10.0.10.11", vendor="HPE", model="ProLiant DL380 Gen10", os="ESXi 8.0.2", status="up",
             meta={"cpu_pct": 37, "mem_pct": 71, "cores": 32, "mem_gb": 256})
    esx2 = A(name="ESXi-02", type="host", site_id=hq.id, parent_id=core.id, ip="10.0.10.12", vendor="Dell", model="PowerEdge R740", os="ESXi 7.0.3", status="warning",
             meta={"cpu_pct": 64, "mem_pct": 88, "cores": 24, "mem_gb": 192})
    vm = {}
    for name, host, ip, os_, status, backup, extra in [
        ("DC01", esx1, "10.0.20.10", "Windows Server 2022", "up", True, {}),
        ("DC02", esx2, "10.0.20.11", "Windows Server 2022", "up", True, {}),
        ("FILE-SRV", esx1, "10.0.20.20", "Windows Server 2019", "up", True, {}),
        ("ERP-APP", esx1, "10.0.20.30", "Ubuntu 22.04", "up", False, {"oldest_snapshot_days": 23, "snapshots": 2}),
        ("ERP-DB", esx2, "10.0.20.31", "Windows Server 2019 + SQL 2019", "up", False, {}),
        ("WEB-INTRANET", esx2, "10.0.20.40", "Ubuntu 24.04", "up", True, {}),
        ("VEEAM-BR", esx1, "10.0.20.50", "Windows Server 2022", "up", False, {}),
        ("MONITOR", esx1, "10.0.20.60", "Debian 12", "up", True, {}),
        ("TEST-OLD", esx2, "", "CentOS 7", "off", False, {"power": "poweredOff"}),
    ]:
        spec = {"DC01": (4, 8192), "DC02": (4, 8192), "FILE-SRV": (4, 16384), "ERP-APP": (8, 32768), "ERP-DB": (8, 65536),
                "WEB-INTRANET": (2, 4096), "VEEAM-BR": (8, 16384), "MONITOR": (4, 8192), "TEST-OLD": (2, 4096)}[name]
        vm[name] = A(name=name, type="vm", site_id=hq.id, parent_id=host.id, ip=ip, os=os_, status=status, backup=backup,
                     backup_note="Nightly Veeam job" if backup else "",
                     meta={"platform": "esxi", "kind": "vm", "power": "poweredOn" if status == "up" else "poweredOff",
                           "vcpu": spec[0], "mem_mb": spec[1], "uptime_s": 86400 * 37 if status == "up" else None,
                           "tools": "guestToolsRunning" if status == "up" else "", "snapshots": 0, **extra})
    for c in ["nginx", "uptime-kuma", "grafana"]:
        A(name=c, type="container", site_id=hq.id, parent_id=vm["MONITOR"].id, status="up", os=f"{c}:latest",
          meta={"platform": "docker", "kind": "docker", "power": "running", "status": "Up 3 weeks"})
    # Proxmox demo: 1 node, 2 VM (QEMU) + 2 container (LXC)
    pve = A(name="PVE-01", type="host", site_id=hq.id, parent_id=core.id, ip="10.0.10.21", vendor="Supermicro", model="AMD EPYC 7302P",
            os="pve-manager/8.2.4", status="up", meta={"platform": "proxmox", "cpu_pct": 22, "mem_pct": 58, "cores": 32, "mem_gb": 128,
                                                       "res": {"cpu": 22, "mem": 58, "mem_total_gb": 128, "cores": 32, "disk": 41, "disk_name": "rootfs"}})
    for vid, (name, kind, run, vcpu, mem_mb, cpu, mem, disk, ip) in enumerate([
        ("gitlab", "qemu", True, 8, 16384, 34, 71, 63, "10.0.21.10"), ("k8s-node1", "qemu", True, 8, 32768, 58, 77, None, "10.0.21.11"),
        ("pihole", "lxc", True, 1, 512, 2, 38, 22, "10.0.21.53"), ("backup-test", "lxc", False, 2, 2048, None, None, None, "")], start=100):
        dsize = 100 if kind == "qemu" else 8
        res = ({"cpu": cpu, "mem": mem, **({"disk": disk, "disk_name": "/" if kind == "qemu" else "rootfs",
                                            "disks": [{"name": "/" if kind == "qemu" else "rootfs", "pct": disk, "size_gb": dsize,
                                                       "used_gb": round(disk * dsize / 100, 1)}]} if disk else {}),
                "mem_total_gb": round(mem_mb / 1024, 1)} if run else None)
        A(name=name, type="vm" if kind == "qemu" else "container", site_id=hq.id, parent_id=pve.id, ip=ip, status="up" if run else "off",
          os="QEMU/KVM" if kind == "qemu" else "LXC", source="demo", external_id=f"pve:PVE-01:{vid}",
          meta={"platform": "proxmox", "kind": kind, "vmid": vid, "power": "running" if run else "stopped", "vcpu": vcpu, "mem_mb": mem_mb,
                "uptime_s": 86400 * 12 if run else None, "snapshots": 1 if name == "gitlab" else 0,
                "oldest_snapshot_days": 15 if name == "gitlab" else None, "res": res})
    nas = A(name="NAS-Synology", type="nas", site_id=hq.id, parent_id=core.id, ip="10.0.10.50", vendor="Synology", model="DS923+", status="up", backup=True)
    A(name="UPS-RACK", type="ups", site_id=hq.id, parent_id=core.id, ip="10.0.10.60", vendor="APC", model="SMT3000", status="up")
    A(name="AP-Tang3", type="ap", site_id=hq.id, parent_id=sw2.id, ip="10.0.30.21", vendor="Aruba", model="AP-505", status="up")
    A(name="AP-Tang5", type="ap", site_id=hq.id, parent_id=sw2.id, ip="10.0.30.22", vendor="Aruba", model="AP-505", status="down")
    A(name="3rd-floor printer", type="printer", site_id=hq.id, parent_id=sw2.id, ip="10.0.40.13", vendor="HP", model="M428fdw", status="up")
    A(name="Camera NVR", type="camera", site_id=hq.id, parent_id=sw2.id, ip="10.0.50.2", vendor="Hikvision", status="up")

    fw2 = A(name="pfSense-HN", type="firewall", site_id=br.id, ip="10.1.0.1", vendor="Netgate", model="SG-2100", status="up", meta={"live": {"cpu": 7}})
    sw_hn = A(name="SW-HN", type="switch", site_id=br.id, parent_id=fw2.id, ip="10.1.0.2", vendor="TP-Link", model="TL-SG3428", status="up")
    A(name="NAS-HN", type="nas", site_id=br.id, parent_id=sw_hn.id, ip="10.1.0.50", vendor="Synology", model="DS220+", status="up")
    A(name="AP-HN", type="ap", site_id=br.id, parent_id=sw_hn.id, ip="10.1.0.21", vendor="UniFi", model="U6-Lite", status="up")

    vps1 = A(name="VPS-Web", type="server", site_id=vps.id, ip="203.0.113.25", os="Ubuntu 22.04", status="up", backup=True, backup_note="Provider snapshot")
    npm = A(name="nginx-proxy-manager", type="container", site_id=vps.id, parent_id=vps1.id, status="up")
    web = A(name="website-congty", type="container", site_id=vps.id, parent_id=vps1.id, status="up")
    db.flush()

    C = lambda **k: _add(db, models.Check(**k))  # noqa: E731
    def demo(st, msg, lat=5, val=None, data=None, res=None, **cfg):
        return {"demo": True, "demo_status": st, "demo_message": msg, "demo_latency": lat, "demo_value": val, "demo_data": data or {},
                "alert_after": 1, **({"demo_res": res} if res else {}), **cfg}

    def D(name, pct, size):
        return {"name": name, "pct": pct, "size_gb": size, "used_gb": round(size * pct / 100, 1)}

    c_fw = C(name="pfSense HQ (API)", type="pfsense", site_id=hq.id, asset_id=fw.id, target="10.0.0.1", interval=60,
             config=demo("ok", "2/2 WAN online · IPsec 1/1 · 14 OpenVPN client", 3, 12, res={"cpu": 14, "mem": 34, "disks": [D("/", 22, 110)], "mem_total_gb": 8, "cores": 4},
                         data={"gateways": [{"name": "WAN_FPT", "status": "online", "loss": "0%", "delay": "3.1ms"}, {"name": "WAN_VIETTEL", "status": "online", "loss": "0%", "delay": "4.5ms"}]}))
    C(name="pfSense HN (API)", type="pfsense", site_id=br.id, asset_id=fw2.id, target="10.1.0.1", interval=60,
      config=demo("ok", "1/1 WAN online · IPsec 1/1", 18, 7, res={"cpu": 9, "mem": 47, "disks": [D("/", 31, 14)], "mem_total_gb": 4, "cores": 2}))
    C(name="SW-CORE (SNMP)", type="snmp", site_id=hq.id, asset_id=core.id, target="10.0.0.2", interval=60,
      config=demo("ok", "SW-CORE · uptime 120d 4h · 31/52 ports up", 2, 9, res={"cpu": 11, "mem": 38, "mem_total_gb": 1}))
    C(name="SW-TANG3 (SNMP)", type="snmp", site_id=hq.id, asset_id=sw2.id, target="10.0.0.3", interval=60, config=demo("ok", "SW-TANG3 · 18/28 ports up", 2, 5, res={"cpu": 6, "mem": 61, "mem_total_gb": 0.5}))
    C(name="SW-HN (SNMP)", type="snmp", site_id=br.id, asset_id=sw_hn.id, target="10.1.0.2", interval=60, config=demo("ok", "SW-HN · 12/28 ports up", 19, 4, res={"cpu": 4, "mem": 44}))
    c_esx1 = C(name="ESXi-01", type="esxi", site_id=hq.id, asset_id=esx1.id, target="10.0.10.11", interval=120,
               config=demo("ok", "1 host · 6/6 VMs running", 40, 37, {"datastores": [{"name": "datastore1", "used_pct": 72, "free_gb": 980}]},
                           res={"cpu": 37, "mem": 71, "disks": [D("datastore1", 72, 3500)], "mem_total_gb": 256, "cores": 32}))
    C(name="ESXi-02", type="esxi", site_id=hq.id, asset_id=esx2.id, target="10.0.10.12", interval=120,
      config=demo("ok", "1 host · 3/4 VMs running", 45, 64, {"datastores": [{"name": "ds-ssd", "used_pct": 91, "free_gb": 85}]},
                res={"cpu": 64, "mem": 88, "disks": [D("ds-ssd", 91, 960), D("ds-hdd", 58, 7400)], "mem_total_gb": 192, "cores": 24}))
    C(name="NAS Synology (SNMP)", type="snmp", site_id=hq.id, asset_id=nas.id, target="10.0.10.50", interval=120, config=demo("ok", "NAS-Synology · 41°C", 2, 6, res={"cpu": 8, "mem": 29, "disks": [D("/volume1", 81, 21800), D("/volume2", 43, 7200)], "mem_total_gb": 8}))
    C(name="UPS (SNMP)", type="snmp", site_id=hq.id, asset_id=db.query(models.Asset).filter_by(name="UPS-RACK").first().id, target="10.0.10.60", interval=120,
      config=demo("ok", "UPS-RACK · Battery {val}% · utility power", 3, 100))
    C(name="AP-Tang5 (Ping)", type="ping", site_id=hq.id, asset_id=db.query(models.Asset).filter_by(name="AP-Tang5").first().id, target="10.0.30.22", interval=60,
      config=demo("fail", "No response", 0))
    for n in ["DC01", "DC02", "FILE-SRV", "ERP-DB", "VEEAM-BR"]:
        C(name=f"{n} (Ping)", type="ping", site_id=hq.id, asset_id=vm[n].id, target=vm[n].ip, interval=60, config=demo("ok", "{lat} ms · 0% packet loss", 1))
    C(name="FILE-SRV (Windows)", type="ssh", site_id=hq.id, asset_id=vm["FILE-SRV"].id, target="10.0.20.20", interval=120,
      config=demo("ok", "FILE-SRV · up 34d", 40, None, res={"cpu": 12, "mem": 58, "disks": [D("C:", 61, 120), D("D:", 89, 4000)], "mem_total_gb": 16, "cores": 8}, platform="windows"))
    C(name="ERP-DB (Windows)", type="ssh", site_id=hq.id, asset_id=vm["ERP-DB"].id, target="10.0.20.31", interval=120,
      config=demo("ok", "ERP-DB · up 12d", 40, None, res={"cpu": 46, "mem": 93, "disks": [D("C:", 54, 100), D("E:", 77, 1000)], "mem_total_gb": 64, "cores": 16}, platform="windows"))
    C(name="Internet HQ", type="internet", site_id=hq.id, target="1.1.1.1, 8.8.8.8, 208.67.222.222", interval=30,
      config=demo("ok", "{lat} ms · 0% packet loss · jitter 1.4 ms · DNS 11 ms · IP 113.161.20.5", 9, 0,
                  {"latency_ms": 9.2, "loss": 0, "jitter_ms": 1.4, "public_ip": "113.161.20.5", "reachable": 3, "total": 3,
                   "targets": [{"target": "1.1.1.1", "loss": 0, "rtt": 9.2, "jitter": 1.1}, {"target": "8.8.8.8", "loss": 0, "rtt": 31.5, "jitter": 1.9},
                               {"target": "208.67.222.222", "loss": 0, "rtt": 36.0, "jitter": 1.2}],
                   "dns": {"name": "google.com", "ok": True, "ms": 11, "addr": "142.250.66.46"}, "http": {"url": "http://www.gstatic.com/generate_204", "ok": True, "code": 204, "ms": 48}}))
    C(name="Internet HN", type="internet", site_id=br.id, target="1.1.1.1, 8.8.8.8, 208.67.222.222", interval=30,
      config=demo("warn", "{lat} ms · 13% packet loss · jitter 41 ms · DNS 35 ms · IP 14.232.8.71", 44, 13,
                  {"latency_ms": 44, "loss": 13.3, "jitter_ms": 41, "public_ip": "14.232.8.71", "reachable": 3, "total": 3}))
    c_ldap = C(name="AD LDAP 389", type="tcp", site_id=hq.id, asset_id=vm["DC01"].id, target="10.0.20.10", interval=60, config=demo("ok", "Port 389 open · {lat} ms", 1))
    c_erp = C(name="ERP web", type="http", site_id=hq.id, asset_id=vm["ERP-APP"].id, target="https://erp.congty.local", interval=60,
              config=demo("warn", "HTTP 200 · {lat} ms · slow", 3400, 3400))
    C(name="MONITOR (SSH)", type="ssh", site_id=hq.id, asset_id=vm["MONITOR"].id, target="10.0.20.60", interval=120,
      config=demo("ok", "monitor · up 63d · 3/3 containers running", 30, 58, res={"cpu": 18, "mem": 41, "disks": [D("/", 58, 80), D("/var/lib/docker", 66, 200)], "mem_total_gb": 8, "cores": 4}))
    c_web = C(name="Company website", type="http", site_id=vps.id, asset_id=web.id, target="https://congty.vn", interval=60,
              config=demo("ok", "HTTP 200 · {lat} ms · SSL expires in 12 days", 180, None, {"cert_days": 12, "code": 200}))
    C(name="VPS-Web (SSH)", type="ssh", site_id=vps.id, asset_id=vps1.id, target="203.0.113.25", interval=120, config=demo("ok", "vps-web · up 120d", 35, 47, res={"cpu": 23, "mem": 52, "disks": [D("/", 47, 160)], "mem_total_gb": 4, "cores": 2}))
    c_npm = C(name="NPM admin", type="tcp", site_id=vps.id, asset_id=npm.id, target="203.0.113.25", interval=60, config=demo("ok", "Port 81 open · {lat} ms", 35))
    ts = now().isoformat() + "Z"
    for n, cpu, mem, dk in [("DC01", 7, 46, [("C:\\", 48, 100)]), ("DC02", 5, 41, [("C:\\", 44, 100)]), ("VEEAM-BR", 31, 72, [("C:\\", 69, 120)]),
                            ("ERP-APP", 72, 81, [("/", 74, 60), ("/opt/erp", 68, 200)]), ("WEB-INTRANET", 9, 35, [("/", 39, 40)])]:
        host_chk = c_esx1.id
        vm[n].meta = {**vm[n].meta, "res": {"cpu": cpu, "mem": mem, "disks": [D(a, b, c) for a, b, c in dk], "disk": max(x[1] for x in dk),
                                            "disk_name": max(dk, key=lambda x: x[1])[0], "via_check": host_chk, "ts": ts}}
    db.flush()

    K = lambda **k: _add(db, models.CriticalSystem(**k))  # noqa: E731
    K(name="pfSense HQ", description="Headquarters Internet gateway + VPN", layer="Access & Authentication", level="High", asset_id=fw.id, backup=True, backup_note="Auto Config Backup", check_ids=[c_fw.id])
    k_ad = K(name="Active Directory", description="Authentication, internal DNS, and Group Policy", layer="Access & Authentication", level="High", asset_id=vm["DC01"].id, check_ids=[c_ldap.id], owner="IT")
    K(name="File server", description="Shared departmental storage", layer="Data", level="High", asset_id=vm["FILE-SRV"].id, depends_on=[k_ad.id])
    k_erpdb = K(name="ERP – Database", description="SQL Server for ERP", layer="Data", level="High", asset_id=vm["ERP-DB"].id)
    K(name="ERP – Application", description="Accounting / inventory application", layer="Application", level="High", asset_id=vm["ERP-APP"].id, depends_on=[k_erpdb.id, k_ad.id], check_ids=[c_erp.id], url="https://erp.congty.local")
    K(name="Email (Microsoft 365)", description="Company-wide email", layer="Application", level="High", hosted_externally=True, external_note="Microsoft 365", depends_on=[k_ad.id])
    K(name="Company website", description="congty.vn qua Nginx Proxy Manager", layer="Application", level="Medium", asset_id=web.id, check_ids=[c_web.id, c_npm.id])
    K(name="Backup Veeam", description="Nightly VM backups to NAS", layer="Data", level="High", asset_id=vm["VEEAM-BR"].id, backup_note="Veeam configuration exported to NAS")
    K(name="Virtualization infrastructure", description="ESXi cluster hosting all VMs", layer="Infrastructure", level="High", asset_id=esx1.id, backup=True, check_ids=[c_esx1.id])
    K(name="Office Wi-Fi", description="Aruba AP + employee/guest SSIDs", layer="Infrastructure", level="Medium", asset_id=sw2.id, backup=True)
    K(name="Time attendance software", description="Time attendance terminal + server", layer="Application", level="Low")
    db.commit()


def _add(db, obj):
    db.add(obj)
    db.flush()
    return obj
