"""SNMP và SSH với agent thật (net-snmp snmpd, OpenSSH sshd) chạy cục bộ. Tự bỏ qua nếu máy test không có."""
import asyncio
import os
import shutil
import subprocess
import tempfile
import time

import pytest

from app.collectors import COLLECTORS
from tests.simulators import free_port

run = lambda t, target, cfg: asyncio.run(COLLECTORS[t](target, cfg))  # noqa: E731


@pytest.fixture(scope="module")
def snmpd():
    if not shutil.which("snmpd"):
        pytest.skip("snmpd không có")
    port = free_port()
    d = tempfile.mkdtemp()
    conf = os.path.join(d, "snmpd.conf")
    open(conf, "w").write(f"agentaddress udp:127.0.0.1:{port}\nrocommunity qa-community 127.0.0.1\n"
                          "createUser qauser SHA QaAuthPass123 AES QaPrivPass123\nrouser qauser priv\n")
    p = subprocess.Popen(["snmpd", "-f", "-C", "-c", conf, "-Ln", "-p", os.path.join(d, "pid")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    yield port
    p.terminate()


NO_RES_LIMIT = {"cpu_warn": "", "cpu_fail": "", "mem_warn": "", "mem_fail": "", "disk_warn": "", "disk_fail": ""}


def test_snmp_v2c(snmpd):
    r = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd, **NO_RES_LIMIT})
    assert r.status == "ok", r.message
    assert r.data["ports_total"] >= 1 and "lo" in [p["name"] for p in r.data["ports"]]
    assert "Linux" in r.data["sys_descr"]


def test_snmp_wrong_community(snmpd):
    r = run("snmp", "127.0.0.1", {"community": "sai", "port": snmpd, "timeout": 1, "retries": 0})
    assert r.status == "fail"


def test_snmp_v3(snmpd):
    r = run("snmp", "127.0.0.1", {"version": "3", "username": "qauser", "password": "QaAuthPass123", "auth_protocol": "SHA",
                                   "priv_key": "QaPrivPass123", "priv_protocol": "AES", "port": snmpd, **NO_RES_LIMIT})
    assert r.status == "ok", r.message


def test_snmp_watch_port_down(snmpd):
    r = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd})
    down = [p["name"] for p in r.data["ports"] if p["oper"] != "up"]
    if not down:
        pytest.skip("không có interface nào down để thử")
    r = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd, "watch_ports": down[0]})
    assert r.status == "fail" and down[0] in r.message


def test_snmp_custom_oid_threshold(snmpd):
    r = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd, "interfaces": False,
                                   "extra_oids": [{"name": "if_count", "oid": "1.3.6.1.2.1.2.1.0", "warn_above": 0}]})
    assert r.status == "warn" and "if_count" in r.message


@pytest.fixture(scope="module")
def sshd():
    if not os.path.exists("/usr/sbin/sshd"):
        pytest.skip("sshd không có")
    d = tempfile.mkdtemp()
    key = os.path.join(d, "id")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    hostkey = os.path.join(d, "host")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostkey], check=True)
    authk = os.path.join(d, "authorized_keys")
    shutil.copy(key + ".pub", authk)
    os.chmod(authk, 0o600)
    os.makedirs("/run/sshd", exist_ok=True)
    port = free_port()
    p = subprocess.Popen(["/usr/sbin/sshd", "-D", "-p", str(port), "-h", hostkey, "-o", f"AuthorizedKeysFile={authk}",
                          "-o", "PermitRootLogin=prohibit-password", "-o", "StrictModes=no", "-o", "PidFile=none"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    yield port, open(key).read()
    p.terminate()


def test_ssh_default_metrics(sshd):
    port, key = sshd
    r = run("ssh", "127.0.0.1", {"port": port, "username": "root", "private_key": key})
    assert r.status in ("ok", "warn"), r.message
    assert r.data["hostname"] and r.data["os"] and r.data["disks"] and r.data["mem_pct"] is not None


def test_ssh_disk_threshold(sshd):
    port, key = sshd
    # threshold cũ (disk_warn/disk_fail) vẫn đọc được = Trouble/Critical; vượt threshold KHÔNG làm check lỗi kết nối
    r = run("ssh", "127.0.0.1", {"port": port, "username": "root", "private_key": key, "disk_warn": 1, "disk_fail": 100})
    assert r.status == "ok" and r.data["res"]["levels"]["disk"] == "trouble"
    r = run("ssh", "127.0.0.1", {"port": port, "username": "root", "private_key": key, "disk_warn": 0, "disk_fail": 1})
    assert r.status == "ok" and r.data["res"]["levels"]["disk"] == "critical" and "Critical" in r.message


def test_ssh_custom_command_exit_codes(sshd):
    port, key = sshd
    base = {"port": port, "username": "root", "private_key": key}
    assert run("ssh", "127.0.0.1", {**base, "command": "echo 42"}).status == "ok"
    r = run("ssh", "127.0.0.1", {**base, "command": "echo backup cu; exit 1"})
    assert r.status == "warn" and "backup cu" in r.message
    assert run("ssh", "127.0.0.1", {**base, "command": "exit 2"}).status == "fail"


def test_ssh_wrong_key(sshd):
    port, _ = sshd
    r = run("ssh", "127.0.0.1", {"port": port, "username": "root", "password": "sai", "timeout": 5})
    assert r.status == "fail" and "SSH lỗi" in r.message


def test_snmp_traffic_rates_two_polls(snmpd):
    """Lần 1 chưa có Mbps; lần 2 (sau khi có lưu lượng) tính ra Mbps cho cổng lo."""
    import importlib
    import subprocess as sp
    importlib.import_module("app.collectors.snmp")._COUNTERS.clear()
    cfg = {"community": "qa-community", "port": snmpd, **NO_RES_LIMIT}
    r1 = run("snmp", "127.0.0.1", cfg)
    assert r1.status == "ok" and "đang đo lưu lượng" in r1.message
    sp.run(["ping", "-c", "40", "-i", "0.05", "-s", "1400", "127.0.0.1"], capture_output=True)
    time.sleep(5)  # net-snmp cache bộ đếm interface vài giây
    r2 = run("snmp", "127.0.0.1", cfg)
    lo = next(p for p in r2.data["ports"] if p["name"] == "lo")
    assert lo["in_mbps"] is not None and lo["in_mbps"] > 0, lo
    assert lo["virtual"] is True and lo not in [p for p in r2.data["ports"] if not p["virtual"]], "lo là cổng ảo, không tính vào tổng"
    assert r2.data["traffic_ready"] is True
    assert r2.data.get("uptime")


def test_snmp_resources_from_host_mib(snmpd):
    """snmpd thật: đọc RAM (đã trừ buffer/cache) và ổ đĩa qua hrStorage; threshold thấp → cảnh báo."""
    r = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd, **NO_RES_LIMIT})
    res = r.data["res"]
    assert 0 < res["mem"] < 100 and res["mem_total_gb"] > 0
    assert res["disks"] and all(not d["name"].startswith(("/proc", "/sys", "/dev")) for d in res["disks"])
    r2 = run("snmp", "127.0.0.1", {"community": "qa-community", "port": snmpd, **NO_RES_LIMIT, "mem_warn": 0.1})
    assert r2.data["res"]["levels"]["mem"] == "trouble" and "RAM" in r2.message and "≥ 0.1%" in r2.message
