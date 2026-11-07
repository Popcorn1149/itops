"""Thiết bị giả lập dùng cho QA: pfSense REST API v2, OPNsense, Telegram Bot API, webhook, ESXi (pyVmomi)."""
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import uvicorn
from fastapi import FastAPI, Request, HTTPException

# ------------------------------------------------------------------ HTTP device simulator
STATE = {
    "pf_gateways": [
        {"name": "WAN_FPT", "status": "online", "loss": "0.0%", "delay": "3.2ms", "monitorip": "8.8.8.8"},
        {"name": "WAN_VT", "status": "online", "loss": "0.0%", "delay": "4.1ms", "monitorip": "1.1.1.1"},
    ],
    "pf_cpu": 12, "pf_disk": 40,
    "pf_interfaces": [{"name": "wan", "descr": "WAN", "hwif": "igb0", "status": "up", "ipaddr": "113.1.1.2"},
                      {"name": "lan", "descr": "LAN", "hwif": "igb1", "status": "up", "ipaddr": "10.0.0.1"}],
    "pf_leases": [{"ip": "10.0.0.50", "mac": "aa:bb:cc:00:00:01", "hostname": "laptop-ketoan", "online_status": "online"},
                  {"ip": "10.0.0.51", "mac": "aa:bb:cc:00:00:02", "hostname": "<img src=x onerror=alert(1)>", "online_status": "offline"}],
    "api_key": "PFKEY123",
    "opn_key": ("OPNKEY", "OPNSECRET"),
    "telegram": [], "webhook": [],
    "telegram_fail": False,
}

sim = FastAPI()


def _pf_auth(req: Request):
    if req.headers.get("X-API-Key") != STATE["api_key"]:
        raise HTTPException(401, "unauthorized")


@sim.get("/api/v2/status/system")
def pf_system(req: Request):
    _pf_auth(req)
    return {"code": 200, "status": "ok", "data": {"system_platform": "Netgate 4200", "cpu_usage": STATE["pf_cpu"], "mem_usage": 33,
                                                   "disk_usage": STATE["pf_disk"], "temp_c": 45.0, "uptime": 3600 * 24 * 12}}


@sim.get("/api/v2/system/version")
def pf_version(req: Request):
    _pf_auth(req)
    return {"data": {"version": "2.7.2-RELEASE"}}


@sim.get("/api/v2/status/gateways")
def pf_gw(req: Request):
    _pf_auth(req)
    return {"data": STATE["pf_gateways"]}


@sim.get("/api/v2/status/interfaces")
def pf_if(req: Request):
    _pf_auth(req)
    return {"data": STATE["pf_interfaces"]}


@sim.get("/api/v2/status/ipsec/sas")
def pf_ipsec(req: Request):
    _pf_auth(req)
    return {"data": [{"con_id": "con1", "state": "ESTABLISHED", "remote_host": "203.0.113.10"}]}


@sim.get("/api/v2/status/openvpn/servers")
def pf_ovpn(req: Request):
    _pf_auth(req)
    return {"data": [{"name": "RemoteAccess", "conns": [{"common_name": "a"}, {"common_name": "b"}]}]}


@sim.get("/api/v2/status/dhcp_server/leases")
def pf_leases(req: Request):
    _pf_auth(req)
    return {"data": STATE["pf_leases"]}


@sim.get("/api/core/system/status")
def opn_status(req: Request):
    import base64
    exp = "Basic " + base64.b64encode(f"{STATE['opn_key'][0]}:{STATE['opn_key'][1]}".encode()).decode()
    if req.headers.get("Authorization") != exp:
        raise HTTPException(401)
    return {"metadata": {"system": {"status": "OK"}}}


@sim.get("/api/routes/gateway/status")
def opn_gw():
    return {"items": [{"name": "WAN_GW", "status_translated": "Online", "loss": "0.0 %", "delay": "2.1 ms"}]}


@sim.post("/bot{token}/sendMessage")
async def tg(token: str, req: Request):
    if STATE["telegram_fail"]:
        raise HTTPException(400, "chat not found")
    STATE["telegram"].append({"token": token, **(await req.json())})
    return {"ok": True}


@sim.post("/hook")
async def hook(req: Request):
    STATE["webhook"].append(await req.json())
    return {"ok": True}


@sim.get("/web/ok")
def web_ok():
    return {"status": "healthy", "app": "erp"}


@sim.get("/web/slow")
def web_slow():
    time.sleep(1.2)
    return {"status": "healthy"}


@sim.get("/web/500")
def web_500():
    raise HTTPException(500, "boom")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_sim() -> int:
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(sim, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return port
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("simulator did not start")


# ------------------------------------------------------------------ ESXi / vCenter simulator (pyVmomi objects)
class FakeView:
    def __init__(self, items):
        self.view = items

    def Destroy(self):
        pass


def make_vm(moid, name, power="poweredOn", ip="10.0.20.10", os_="Windows Server 2022", snap_days=None, template=False):
    snapshot = None
    if snap_days is not None:
        snapshot = NS(rootSnapshotList=[NS(createTime=datetime.now(timezone.utc) - timedelta(days=snap_days), childSnapshotList=[])])
    return NS(_moId=moid, snapshot=snapshot, summary=NS(
        config=NS(name=name, template=template, guestFullName=os_, numCpu=4, memorySizeMB=8192, annotation="VM giả lập"),
        guest=NS(ipAddress=ip if power == "poweredOn" else None, toolsRunningStatus="guestToolsRunning"),
        runtime=NS(powerState=power), overallStatus="green",
        quickStats=NS(overallCpuUsage=500, guestMemoryUsage=4096)))


def make_host(moid, name, vms, connection="connected", overall="green", cpu_used=8000):
    return NS(_moId=moid, vm=vms, summary=NS(
        config=NS(name=name, product=NS(version="8.0.2")),
        hardware=NS(cpuMhz=2500, numCpuCores=16, memorySize=256 * 1024 ** 3, vendor="HPE", model="ProLiant DL380 Gen10"),
        quickStats=NS(overallCpuUsage=cpu_used, overallMemoryUsage=180 * 1024, uptime=86400 * 30),
        runtime=NS(connectionState=connection), overallStatus=overall))


def make_ds(name, cap_gb, free_gb):
    return NS(summary=NS(name=name, capacity=cap_gb * 1024 ** 3, freeSpace=free_gb * 1024 ** 3))


ESXI = {"hosts": [], "datastores": [], "password": "VMwarePass1!", "fail_connect": False}


def esxi_default():
    ESXI["hosts"] = [
        make_host("host-1", "esx01.lab", [make_vm("vm-1", "DC01"), make_vm("vm-2", "ERP-DB", snap_days=20),
                                         make_vm("vm-3", "OLD-CENTOS", power="poweredOff"), make_vm("vm-t", "TEMPLATE-W22", template=True)]),
        make_host("host-2", "esx02.lab", [make_vm("vm-4", "FILE-SRV", ip="10.0.20.20")], overall="yellow"),
    ]
    ESXI["datastores"] = [make_ds("ds-ssd", 2000, 160), make_ds("ds-hdd", 8000, 5000)]


def patch_pyvmomi(monkeypatch):
    import pyVim.connect as pc
    from pyVmomi import vim

    def smart_connect(host, user, pwd, **kw):
        if ESXI["fail_connect"]:
            raise ConnectionRefusedError("Connection refused")
        if pwd != ESXI["password"]:
            raise vim.fault.InvalidLogin(msg="Cannot complete login due to an incorrect user name or password.")
        content = NS(about=NS(fullName="VMware vCenter Server 8.0.2 (simulated)"),
                     rootFolder=object(),
                     viewManager=NS(CreateContainerView=lambda root, types, rec: FakeView(ESXI["hosts"] if types[0] is vim.HostSystem else ESXI["datastores"])))
        return NS(RetrieveContent=lambda: content)

    monkeypatch.setattr(pc, "SmartConnect", smart_connect)
    monkeypatch.setattr(pc, "Disconnect", lambda si: None)
