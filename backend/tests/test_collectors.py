"""Collector thập: chạy với thiết bị giả lập (pfSense/OPNsense/ESXi) và dịch vụ thật trong máy (HTTP, TCP, ping)."""
import asyncio
import socket

import pytest

from app.collectors import COLLECTORS
from tests import simulators as S

run = lambda t, target, cfg: asyncio.run(COLLECTORS[t](target, cfg))  # noqa: E731


# ---------------- pfSense REST API v2 ----------------
def test_pfsense_api_ok(sim_port):
    r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": S.STATE["api_key"]})
    assert r.status == "ok", r.message
    assert "2/2 WAN online" in r.message and "IPsec 1/1" in r.message and "2 OpenVPN client" in r.message
    assert r.data["version"] == "2.7.2-RELEASE" and r.value == 12
    assert len(r.data["interfaces"]) == 2


def test_pfsense_gateway_down_is_fail(sim_port):
    S.STATE["pf_gateways"][1]["status"] = "down"
    try:
        r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": S.STATE["api_key"]})
        assert r.status == "fail" and "WAN_VT DOWN" in r.message and "1/2 WAN online" in r.message
    finally:
        S.STATE["pf_gateways"][1]["status"] = "online"


def test_pfsense_gateway_loss_is_warn(sim_port):
    S.STATE["pf_gateways"][0]["status"] = "loss"
    try:
        assert run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": S.STATE["api_key"]}).status == "warn"
    finally:
        S.STATE["pf_gateways"][0]["status"] = "online"


def test_pfsense_watch_interface_and_disk(sim_port):
    S.STATE["pf_interfaces"][1]["status"] = "no carrier"
    S.STATE["pf_disk"] = 91
    try:
        r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": S.STATE["api_key"], "watch_interfaces": "LAN"})
        assert r.status == "fail" and "Interface LAN no carrier" in r.message and "Disk 91%" in r.message
    finally:
        S.STATE["pf_interfaces"][1]["status"] = "up"
        S.STATE["pf_disk"] = 40


def test_pfsense_wrong_key_and_missing_package(sim_port):
    r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": "sai"})
    assert r.status == "fail" and "401" in r.message and "API key" in r.message
    r = run("pfsense", f"http://127.0.0.1:{sim_port}/khong-co-api", {"api_key": "x"})
    assert r.status == "fail" and "404" in r.message and "REST API" in r.message


def test_pfsense_unreachable():
    r = run("pfsense", "https://127.0.0.1:1", {"api_key": "x", "timeout": 3})
    assert r.status == "fail" and "Không kết nối" in r.message


def test_pfsense_dhcp_discovery(sim_port):
    r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"api_key": S.STATE["api_key"], "discover_dhcp": True})
    keys = {d["key"] for d in r.discovered}
    assert keys == {"mac:aa:bb:cc:00:00:01", "mac:aa:bb:cc:00:00:02"}
    assert next(d for d in r.discovered if d["name"] == "laptop-ketoan")["status"] == "up"


def test_opnsense(sim_port):
    k, s = S.STATE["opn_key"]
    r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"flavor": "opnsense", "api_key": k, "client_secret": s})
    assert r.status == "ok", r.message
    r = run("pfsense", f"http://127.0.0.1:{sim_port}", {"flavor": "opnsense", "api_key": k, "client_secret": "sai"})
    assert r.status == "fail"


# ---------------- ESXi / vCenter ----------------
def test_esxi_inventory(monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.esxi_default()
    r = run("esxi", "vcenter.lab", {"username": "ro", "password": S.ESXI["password"]})
    assert r.status == "warn", r.message  # host vàng + snapshot 20 ngày + datastore 92%
    assert "2 host" in r.message and "3/4 VM chạy" in r.message
    assert "Datastore ds-ssd 92% (Trouble ≥ 90%)" in r.message and "snapshot 20 ngày" in r.message
    types = [d["type"] for d in r.discovered]
    assert types.count("host") == 2 and types.count("vm") == 4  # template bị bỏ qua
    vm = next(d for d in r.discovered if d["name"] == "OLD-CENTOS")
    assert vm["status"] == "off" and vm["parent_key"] == "host:host-1"
    assert next(d for d in r.discovered if d["name"] == "esx02.lab")["status"] == "warning"
    assert r.value == pytest.approx(20.0)


def test_esxi_datastore_full_and_host_down(monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.esxi_default()
    S.ESXI["datastores"] = [S.make_ds("ds", 1000, 20)]
    S.ESXI["hosts"][1] = S.make_host("host-2", "esx02.lab", [], connection="notResponding")
    r = run("esxi", "vc", {"password": S.ESXI["password"]})
    assert r.status == "fail" and "notResponding" in r.message and "Datastore ds 98% (Critical ≥ 95%)" in r.message


def test_esxi_bad_login_and_unreachable(monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.esxi_default()
    r = run("esxi", "vc", {"password": "sai"})
    assert r.status == "fail" and "InvalidLogin" in r.message
    S.ESXI["fail_connect"] = True
    try:
        r = run("esxi", "vc", {"password": S.ESXI["password"]})
        assert r.status == "fail" and "ConnectionRefused" in r.message
    finally:
        S.ESXI["fail_connect"] = False


def test_esxi_empty_vcenter(monkeypatch):
    S.patch_pyvmomi(monkeypatch)
    S.ESXI["hosts"], S.ESXI["datastores"] = [], []
    r = run("esxi", "vc", {"password": S.ESXI["password"]})
    assert r.status == "ok" and "0 host" in r.message and r.discovered == []


# ---------------- HTTP / TCP / ping ----------------
def test_http_variants(sim_port):
    base = f"http://127.0.0.1:{sim_port}"
    assert run("http", base + "/web/ok", {"keyword": "healthy"}).status == "ok"
    r = run("http", base + "/web/ok", {"keyword": "KHONG-CO"})
    assert r.status == "fail" and "không thấy" in r.message
    r = run("http", base + "/web/500", {})
    assert r.status == "fail" and "HTTP 500" in r.message
    assert run("http", base + "/web/500", {"expected_status": "500"}).status == "ok"
    assert run("http", base + "/web/slow", {"warn_ms": 500}).status == "warn"
    r = run("http", "http://127.0.0.1:1/", {"timeout": 2})
    assert r.status == "fail" and "Không truy cập được" in r.message
    assert run("http", base + "/web/ok", {"expected_status": "200,204"}).status == "ok"


def test_tcp_open_closed():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert run("tcp", "127.0.0.1", {"port": port}).status == "ok"
    finally:
        srv.close()
    assert run("tcp", "127.0.0.1", {"port": port, "timeout": 2}).status == "fail"


def test_ping_local_and_unreachable():
    assert run("ping", "127.0.0.1", {"count": 2}).status == "ok"
    r = run("ping", "192.0.2.123", {"count": 1, "timeout": 1})  # TEST-NET-1: không bao giờ phản hồi
    assert r.status == "fail"
    r = run("ping", "khong-ton-tai.invalid", {"count": 1, "timeout": 1})
    assert r.status == "fail"


def test_snmp_no_agent_fails_fast():
    r = run("snmp", "127.0.0.1", {"community": "public", "port": 9, "timeout": 1, "retries": 0})
    assert r.status == "fail" and "SNMP" in r.message


def test_ssh_refused():
    r = run("ssh", "127.0.0.1", {"port": 1, "username": "x", "password": "y", "timeout": 3})
    assert r.status == "fail" and "SSH lỗi" in r.message


# ---------------- Ping trên Windows (đầu ra tiếng Anh / tiếng Việt) ----------------
WIN_EN_OK = """Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=3ms TTL=64
Reply from 10.0.0.1: bytes=32 time<1ms TTL=64
Reply from 10.0.0.1: bytes=32 time=2ms TTL=64

Ping statistics for 10.0.0.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 3ms, Average = 2ms"""
WIN_VI_PARTIAL = """Đang ping 10.0.0.1 với 32 byte dữ liệu:
Trả lời từ 10.0.0.1: byte=32 thời gian=15ms TTL=64
Hết thời gian chờ yêu cầu.

Thống kê ping cho 10.0.0.1:
    Gói: Đã gửi = 2, Đã nhận = 1, Mất = 1 (mất 50%),
Thời gian khứ hồi xấp xỉ theo mili giây:
    Tối thiểu = 15ms, Tối đa = 15ms, Trung bình = 15ms"""
WIN_EN_DOWN = """Pinging 192.0.2.1 with 32 bytes of data:
Request timed out.
Request timed out.

Ping statistics for 192.0.2.1:
    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),"""
WIN_NOHOST = "Ping request could not find host khong-co.local. Please check the name and try again."
LINUX_OK = "3 packets transmitted, 3 received, 0% packet loss, time 602ms\nrtt min/avg/max/mdev = 0.031/0.045/0.060/0.012 ms"


@pytest.mark.parametrize("text,loss,rtt,parsed", [
    (WIN_EN_OK, 0, 2, True), (WIN_VI_PARTIAL, 50, 15, True), (WIN_EN_DOWN, 100, None, True),
    (WIN_NOHOST, 100, None, False), (LINUX_OK, 0, 0.045, True),
])
def test_parse_ping_windows_and_linux(text, loss, rtt, parsed):
    from app.collectors.network import parse_ping
    assert parse_ping(text) == (loss, rtt, parsed)


def test_ping_command_flags(monkeypatch):
    from app.collectors import network
    monkeypatch.setattr(network, "IS_WINDOWS", True)
    assert network._ping_cmd("1.1.1.1", 3, 2) == ["ping", "-n", "3", "-w", "2000", "1.1.1.1"]
    monkeypatch.setattr(network, "IS_WINDOWS", False)
    assert network._ping_cmd("1.1.1.1", 3, 2)[:3] == ["ping", "-n", "-c"]


def test_snmp_rate_math_wrap_and_reset():
    import importlib
    S = importlib.import_module("app.collectors.snmp")
    S._COUNTERS.clear()
    assert S.compute_rates("fw", 100.0, {"1": (1_000_000, 2_000_000)}) == {}
    r = S.compute_rates("fw", 110.0, {"1": (1_000_000 + 12_500_000, 2_000_000 + 1_250_000)})
    assert r["1"] == (10.0, 1.0), r                                   # 12.5 MB/10 s = 10 Mbps
    S._COUNTERS.clear()
    S.compute_rates("fw", 0.0, {"2": (2**32 - 1000, 0)}, bits=32)
    r = S.compute_rates("fw", 1.0, {"2": (124_000, 0)}, bits=32)      # tràn 32-bit
    assert r["2"][0] == round(125_000 * 8 / 1e6, 3)
    S._COUNTERS.clear()
    S.compute_rates("fw", 0.0, {"3": (9_000_000, 9_000_000)})
    assert S.compute_rates("fw", 5.0, {"3": (10, 10)}) == {}            # bộ đếm 64-bit reset (khởi động lại) → bỏ qua


def test_wan_and_virtual_detection():
    from app.collectors.snmp import WAN_HINT, VIRTUAL_IF
    for n in ["pppoe0", "FPT_IOT", "VNPT_EU", "WAN", "wan2", "Viettel"]:
        assert WAN_HINT.search(n), n
    for n in ["em0.11", "Server_Vlan11", "LAN_VLAN01", "bge0"]:
        assert not WAN_HINT.search(n), n
    for n in ["lo0", "pflog0", "pfsync0", "enc0", "lo"]:
        assert VIRTUAL_IF.match(n), n
    assert not VIRTUAL_IF.match("ovpns1") and not VIRTUAL_IF.match("em0")
