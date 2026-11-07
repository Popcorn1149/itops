"""Bộ nhận Syslog (UDP + TCP) và SNMP Trap (v1/v2c/v3)."""
import asyncio
import logging
import os

from .events import submit, STATS
from .syslog_parser import parse

log = logging.getLogger("receivers")
SYSLOG_UDP_PORT = int(os.environ.get("SYSLOG_UDP_PORT", "514"))
SYSLOG_TCP_PORT = int(os.environ.get("SYSLOG_TCP_PORT", "514"))
TRAP_PORT = int(os.environ.get("TRAP_PORT", "162"))
BIND = os.environ.get("RECEIVER_BIND", "0.0.0.0")
MAX_LINE = 16384


def syslog_event(raw: str, ip: str) -> dict:
    p = parse(raw)
    return {"kind": "syslog", "source_ip": ip, "severity": p["severity"], "facility": p["facility"], "host": p["host"],
            "app": p["app"], "message": p["message"] or raw[:500], "device_ts": p["device_ts"],
            "data": {"sd": p["sd"]} if p.get("sd") else {}}


class SyslogUDP(asyncio.DatagramProtocol):
    """Vòng nhận chỉ đẩy dữ liệu thô vào hàng đợi; phân tích làm ở luồng nền để không làm tràn bộ đệm UDP."""
    def connection_made(self, transport):
        sock = transport.get_extra_info("socket")
        try:
            import socket as _s
            sock.setsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF, int(os.environ.get("SYSLOG_RCVBUF", str(16 << 20))))
            STATS["listeners"].setdefault("syslog_udp", {})["rcvbuf"] = sock.getsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF)
        except OSError:
            pass

    def datagram_received(self, data, addr):
        submit({"kind": "syslog", "raw": data[:MAX_LINE], "source_ip": addr[0]})


async def _tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Hỗ trợ cả 2 kiểu đóng gói RFC6587: octet-counting ('123 <34>...') và xuống dòng."""
    ip = (writer.get_extra_info("peername") or ("?",))[0]
    buf = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=600)
            if not chunk:
                break
            buf += chunk
            while buf:
                if buf[:1].isdigit():
                    sp = buf.find(b" ")
                    if 0 < sp <= 6 and buf[:sp].isdigit():
                        n = int(buf[:sp])
                        if len(buf) < sp + 1 + n:
                            break
                        msg, buf = buf[sp + 1: sp + 1 + n], buf[sp + 1 + n:]
                        submit(syslog_event(msg.decode("utf-8", "replace"), ip))
                        continue
                nl = buf.find(b"\n")
                if nl < 0:
                    if len(buf) > MAX_LINE:
                        submit(syslog_event(buf[:MAX_LINE].decode("utf-8", "replace"), ip))
                        buf = b""
                    break
                line, buf = buf[:nl], buf[nl + 1:]
                if line.strip():
                    submit(syslog_event(line.decode("utf-8", "replace"), ip))
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        if buf.strip():
            submit(syslog_event(buf.decode("utf-8", "replace"), ip))
        writer.close()


# ---------------------------------------------------------------- SNMP trap
TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp", "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.2.1.33.2.0.1": "upsTrapOnBattery", "1.3.6.1.2.1.33.2.0.3": "upsTrapAlarmEntryAdded",
    "1.3.6.1.4.1.318.0.5": "APC onBattery", "1.3.6.1.4.1.318.0.9": "APC powerRestored",
    "1.3.6.1.4.1.6574.0": "Synology", "1.3.6.1.4.1.8072.9999.1": "itopsSelfTest",
}
TRAP_SEV = {"coldStart": 4, "warmStart": 5, "linkDown": 3, "linkUp": 5, "authenticationFailure": 4,
            "upsTrapOnBattery": 2, "APC onBattery": 2, "APC powerRestored": 5}
VB_NAMES = {"1.3.6.1.2.1.2.2.1.1": "ifIndex", "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.31.1.1.1.1": "ifName",
            "1.3.6.1.2.1.31.1.1.1.18": "ifAlias", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus", "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
            "1.3.6.1.2.1.1.3.0": "sysUpTime", "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID", "1.3.6.1.6.3.18.1.3.0": "agentAddress",
            "1.3.6.1.6.3.18.1.4.0": "community", "1.3.6.1.6.3.1.1.4.3.0": "enterprise"}


def trap_event(varbinds: list[tuple[str, str]], ip: str) -> dict:
    trap_oid, fields, extra = "", {}, []
    for oid, val in varbinds:
        oid = oid.lstrip(".")
        if oid == "1.3.6.1.6.3.1.1.4.1.0":
            trap_oid = val.lstrip(".")
            continue
        base = next((b for b in VB_NAMES if oid == b or oid.startswith(b + ".")), None)
        if base:
            fields[VB_NAMES[base]] = val
        else:
            extra.append(f"{oid}={val}"[:200])
    name = TRAP_NAMES.get(trap_oid) or next((n for o, n in TRAP_NAMES.items() if trap_oid.startswith(o + ".")), "") or trap_oid
    if_key = fields.get("ifName") or fields.get("ifDescr") or fields.get("ifIndex") or ""
    parts = [name] + [f"{k}={v}" for k, v in fields.items() if k not in ("sysUpTime", "community", "agentAddress")] + extra[:8]
    src = fields.get("agentAddress") if fields.get("agentAddress") not in (None, "", "0.0.0.0") else ip
    return {"kind": "trap", "source_ip": src, "severity": TRAP_SEV.get(name, 5), "facility": None, "host": "", "app": name[:64],
            "message": " · ".join(parts), "device_ts": "",
            "data": {"trap_oid": trap_oid, "trap_name": name, "if_key": str(if_key), "fields": fields, "varbinds": [list(v) for v in varbinds][:40], "via": ip}}


class TrapReceiver:
    def __init__(self, port: int, communities: list[str], v3_users: list[dict]):
        self.port, self.communities, self.v3_users = port, communities, v3_users
        self.engine = None

    def start(self):
        from pysnmp.entity import engine, config
        from pysnmp.entity.rfc3413 import ntfrcv
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.proto.api import v2c  # noqa: F401
        e = engine.SnmpEngine()
        config.add_transport(e, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((BIND, self.port)))
        for i, c in enumerate(self.communities or ["public"]):
            config.add_v1_system(e, f"area-{i}", c)
        A = {"SHA": config.USM_AUTH_HMAC96_SHA, "MD5": config.USM_AUTH_HMAC96_MD5, "SHA256": config.USM_AUTH_HMAC192_SHA256}
        P = {"AES": config.USM_PRIV_CFB128_AES, "DES": config.USM_PRIV_CBC56_DES}
        for u in self.v3_users or []:
            if not u.get("username"):
                continue
            kw = {}
            if u.get("auth_key"):
                kw.update(authProtocol=A.get(u.get("auth_protocol", "SHA"), config.USM_AUTH_HMAC96_SHA), authKey=u["auth_key"])
            if u.get("priv_key"):
                kw.update(privProtocol=P.get(u.get("priv_protocol", "AES"), config.USM_PRIV_CFB128_AES), privKey=u["priv_key"])
            if u.get("engine_id"):
                from pysnmp.proto import rfc1902
                kw["securityEngineId"] = rfc1902.OctetString(hexValue=u["engine_id"].replace(":", ""))
            config.add_v3_user(e, u["username"], **kw)

        def cb(snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, cb_ctx):
            try:
                _, addr = snmp_engine.message_dispatcher.get_transport_info(state_ref)
                ip = addr[0]
            except Exception:
                ip = "?"
            vbs = [(str(n), v.prettyPrint()) for n, v in var_binds]
            submit(trap_event(vbs, ip))

        ntfrcv.NotificationReceiver(e, cb)
        e.transport_dispatcher.job_started(1)
        self.engine = e
        log.info("SNMP trap đang nghe UDP %s", self.port)

    def stop(self):
        if self.engine:
            try:
                self.engine.transport_dispatcher.close_dispatcher()
            except Exception:
                pass
            self.engine = None


_state = {"udp": None, "tcp": None, "trap": None}


async def start_all(trap_cfg: dict):
    loop = asyncio.get_running_loop()
    L = STATS["listeners"]
    try:
        _state["udp"], _ = await loop.create_datagram_endpoint(SyslogUDP, local_addr=(BIND, SYSLOG_UDP_PORT))
        L["syslog_udp"] = {**L.get("syslog_udp", {}), "port": SYSLOG_UDP_PORT, "ok": True}
    except OSError as e:
        L["syslog_udp"] = {"port": SYSLOG_UDP_PORT, "ok": False, "error": str(e)}
        log.error("Không mở được syslog UDP %s: %s", SYSLOG_UDP_PORT, e)
    try:
        _state["tcp"] = await asyncio.start_server(_tcp_client, BIND, SYSLOG_TCP_PORT)
        L["syslog_tcp"] = {"port": SYSLOG_TCP_PORT, "ok": True}
    except OSError as e:
        L["syslog_tcp"] = {"port": SYSLOG_TCP_PORT, "ok": False, "error": str(e)}
        log.error("Không mở được syslog TCP %s: %s", SYSLOG_TCP_PORT, e)
    restart_trap(trap_cfg)


def restart_trap(trap_cfg: dict):
    L = STATS["listeners"]
    if _state["trap"]:
        _state["trap"].stop()
    try:
        r = TrapReceiver(TRAP_PORT, trap_cfg.get("communities") or ["public"], trap_cfg.get("v3_users") or [])
        r.start()
        _state["trap"] = r
        L["snmp_trap"] = {"port": TRAP_PORT, "ok": True}
    except Exception as e:
        _state["trap"] = None
        L["snmp_trap"] = {"port": TRAP_PORT, "ok": False, "error": f"{type(e).__name__}: {e}"}
        log.error("Không mở được SNMP trap %s: %s", TRAP_PORT, e)


async def stop_all():
    if _state["udp"]:
        _state["udp"].close()
    if _state["tcp"]:
        _state["tcp"].close()
    if _state["trap"]:
        _state["trap"].stop()
