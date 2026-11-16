"""Network traffic (NetFlow v5/v9 / IPFIX / sFlow) – 2.10.0.

How it works
  pfSense (softflowd) ──UDP 2055──► GoFlow2 (child process started by IT Ops) ──JSON lines on stdout──► this module
  → keep only traffic with a local address (drops WAN / post-NAT copies) → sum per minute in memory
  → write flow_1m every few seconds → roll up to flow_1h every hour → delete old rows.

GoFlow2 is an external, replaceable collector (BSD licence, github.com/netsampler/goflow2): IT Ops never decodes
NetFlow itself. Point FLOW_COLLECTOR at the binary, or put it in backend/tools/goflow2/ (Windows: goflow2*.exe).
FLOW_COLLECTOR_CMD replaces the whole command (used by the tests). DISABLE_FLOW=1 turns the collector off.

softflowd numbers interfaces itself ("-i 15:em0.15"), not with SNMP ifIndex, and reports the same number as input
and output. Interface names are therefore set per exporter (Traffic → Settings, or paste `ps aux | grep softflowd`).
"""
from __future__ import annotations

import asyncio
import glob
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import models
from .db import SessionLocal, engine, get_db
from .models import now
from .security import admin_user, current_user

log = logging.getLogger("itops.flows")
router = APIRouter()

SETTING_KEY = "flow"
DEFAULT_LOCAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]
DEFAULTS = {
    "enabled": False,
    "port": 2055,              # NetFlow v5/v9 + IPFIX
    "sflow_port": 0,           # 0 = off; 6343 to receive sFlow from switches
    "local_networks": DEFAULT_LOCAL,
    "silent_minutes": 15,      # alert when an exporter that was sending stops for this long
    "keep_minute_days": 7,
    "keep_hour_days": 60,
}
PROTO_NUM = {"HOPOPT": 0, "ICMP": 1, "IGMP": 2, "TCP": 6, "UDP": 17, "GRE": 47, "ESP": 50, "AH": 51, "ICMPv6": 58,
             "IPv6-ICMP": 58, "SCTP": 132, "OSPF": 89, "VRRP": 112, "PIM": 103}
FLUSH_EVERY = 5            # seconds between writes of finished minutes
MAX_KEYS = int(os.environ.get("FLOW_MAX_KEYS", "400000"))     # memory guard for one minute of conversations


# ---------------------------------------------------------------- settings
def _clean(v: dict) -> dict:
    out = {**DEFAULTS, **{k: v[k] for k in DEFAULTS if k in (v or {})}}
    out["enabled"] = bool(out["enabled"])
    for k, lo, hi in (("port", 1, 65535), ("sflow_port", 0, 65535), ("silent_minutes", 2, 1440),
                      ("keep_minute_days", 1, 90), ("keep_hour_days", 1, 800)):
        try:
            out[k] = min(hi, max(lo, int(out[k])))
        except (TypeError, ValueError):
            out[k] = DEFAULTS[k]
    nets = []
    for c in out["local_networks"] if isinstance(out["local_networks"], list) else str(out["local_networks"]).replace(";", ",").replace("\n", ",").split(","):
        c = str(c).strip()
        if not c:
            continue
        try:
            nets.append(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            raise ValueError(f"Not a network: {c}") from None
    out["local_networks"] = nets or list(DEFAULT_LOCAL)
    if out["sflow_port"] and out["sflow_port"] == out["port"]:
        raise ValueError("NetFlow and sFlow ports must differ")
    return out


def get_settings(db: Session | None = None) -> dict:
    own = db is None
    db = db or SessionLocal()
    try:
        s = db.get(models.Setting, SETTING_KEY)
        try:
            return _clean((s.value if s else {}) or {})
        except ValueError:
            return dict(DEFAULTS)
    finally:
        if own:
            db.close()


def save_settings(db: Session, value: dict) -> dict:
    v = _clean({**get_settings(db), **(value or {})})
    st = db.get(models.Setting, SETTING_KEY)
    if st:
        st.value = v
    else:
        db.add(models.Setting(key=SETTING_KEY, value=v))
    return v


# ---------------------------------------------------------------- normalising one flow
class Nets:
    def __init__(self, cidrs: list[str]):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self.cache: dict[str, bool] = {}

    def local(self, ip: str) -> bool:
        r = self.cache.get(ip)
        if r is None:
            try:
                a = ipaddress.ip_address(ip)
                if a.version == 6 and a.ipv4_mapped:
                    a = a.ipv4_mapped
                r = any(a in n for n in self.nets)
            except ValueError:
                r = False
            if len(self.cache) > 100000:
                self.cache.clear()
            self.cache[ip] = r
        return r


def _proto(p) -> int:
    if isinstance(p, int):
        return p
    if isinstance(p, str):
        if p in PROTO_NUM:
            return PROTO_NUM[p]
        try:
            return int(p)
        except ValueError:
            return 255
    return 0


def _ip(s: str) -> str:
    return s[7:] if s.startswith("::ffff:") and "." in s else s


def normalise(f: dict, nets: Nets):
    """One GoFlow2 JSON record → (minute, exporter, if_index, local, remote, proto, port, dir, b_out, b_in, p_out, p_in)
    or a short string saying why it was skipped ("transit", "bad")."""
    src, dst = _ip(str(f.get("src_addr") or "")), _ip(str(f.get("dst_addr") or ""))
    if not src or not dst:
        return "bad"
    ls, ld = nets.local(src), nets.local(dst)
    if not ls and not ld:
        return "transit"          # neither side is ours: WAN copy after NAT, or traffic just passing through
    rate = int(f.get("sampling_rate") or 0) or 1
    b = int(f.get("bytes") or 0) * rate
    pk = int(f.get("packets") or 0) * rate
    sp, dp = int(f.get("src_port") or 0), int(f.get("dst_port") or 0)
    nz = [p for p in (sp, dp) if p]
    port = min(nz) if nz else 0       # the service port is normally the lower one (443 vs 51234)
    t_ns = int(f.get("time_received_ns") or 0) or int(time.time() * 1e9)
    minute = int(t_ns // 60_000_000_000) * 60
    exp = _ip(str(f.get("sampler_address") or "?"))
    ifx = int(f.get("in_if") or f.get("out_if") or 0)
    pr = _proto(f.get("proto"))
    if ls and ld:
        a, z = (src, dst) if src <= dst else (dst, src)       # one row per pair, whichever way the packets went
        fwd = a == src
        return (minute, exp, ifx, a, z, pr, port, "l", b if fwd else 0, 0 if fwd else b, pk if fwd else 0, 0 if fwd else pk)
    if ls:
        return (minute, exp, ifx, src, dst, pr, port, "o", b, 0, pk, 0)
    return (minute, exp, ifx, dst, src, pr, port, "o", 0, b, 0, pk)


# ---------------------------------------------------------------- per-minute aggregation (thread safe)
class Aggregator:
    """Sums records by (minute, exporter, if, local, remote, proto, port, direction).
    Local ↔ local traffic routed between two VLANs is seen on both interfaces – it is counted once per minute."""

    def __init__(self):
        self.lock = threading.Lock()
        self.buckets: dict[int, dict] = {}
        self.local_seen: dict[int, dict] = {}
        self.exporters: dict[str, dict] = {}
        self.stats = {"lines": 0, "stored": 0, "transit": 0, "bad": 0, "dup_local": 0, "overflow": 0,
                      "transit_bytes": 0, "kept_bytes": 0}
        self.recent = deque(maxlen=120)      # (second, flows) for the live rate

    _dec = json.JSONDecoder()

    def add_line(self, line: str, nets: Nets):
        """GoFlow2 writes from several workers at once: two records can end up on one line ("{…}{…}") and a lone
        newline on the next. Decode every object on the line instead of dropping it."""
        line = line.strip()
        if not line or line[0] != "{":
            return
        i, n = 0, len(line)
        while i < n:
            try:
                f, i = self._dec.raw_decode(line, i)
            except ValueError:
                with self.lock:
                    self.stats["bad"] += 1
                return
            if isinstance(f, dict):
                self.add(f, nets)
            while i < n and line[i] in " \t\r\n":
                i += 1

    def add(self, f: dict, nets: Nets):
        r = normalise(f, nets)
        exp = _ip(str(f.get("sampler_address") or "?"))
        sec = int(time.time())
        with self.lock:
            self.stats["lines"] += 1
            e = self.exporters.setdefault(exp, {"flows": 0, "last": 0.0, "ifs": {}})
            e["flows"] += 1
            e["last"] = time.time()
            if self.recent and self.recent[-1][0] == sec:
                self.recent[-1][1] += 1
            else:
                self.recent.append([sec, 1])
            if isinstance(r, str):
                self.stats[r] += 1
                if r == "transit":
                    self.stats["transit_bytes"] += int(f.get("bytes") or 0)
                return
            minute, exp, ifx, lo, rm, pr, port, d, bo, bi, po, pi = r
            e["ifs"][ifx] = e["ifs"].get(ifx, 0) + bo + bi
            self.stats["kept_bytes"] += bo + bi
            if d == "l":
                seen = self.local_seen.setdefault(minute, {})
                k5 = (lo, rm, pr, port)
                first_if = seen.setdefault(k5, ifx)
                if first_if != ifx:
                    self.stats["dup_local"] += 1
                    return
            b = self.buckets.setdefault(minute, {})
            key = (exp, ifx, lo, rm, pr, port, d)
            v = b.get(key)
            if v is None:
                if len(b) >= MAX_KEYS:
                    self.stats["overflow"] += 1
                    return
                b[key] = [bo, bi, po, pi, 1]
            else:
                v[0] += bo; v[1] += bi; v[2] += po; v[3] += pi; v[4] += 1

    def rate(self) -> float:
        with self.lock:
            cut = time.time() - 60
            n = sum(c for s, c in self.recent if s >= cut)
        return round(n / 60, 1)

    def pop_finished(self, before_minute: int | None = None) -> list[tuple]:
        """Rows for every minute that has ended (with a small grace period for late records)."""
        if before_minute is None:
            before_minute = int((time.time() - 15) // 60) * 60
        out = []
        with self.lock:
            for m in [m for m in self.buckets if m < before_minute]:
                ts = datetime.fromtimestamp(m, timezone.utc).replace(tzinfo=None)
                for (exp, ifx, lo, rm, pr, port, d), v in self.buckets.pop(m).items():
                    out.append((ts, exp, ifx, lo, rm, pr, port, d, *v))
            for m in [m for m in self.local_seen if m < before_minute]:
                self.local_seen.pop(m, None)
            self.stats["stored"] += len(out)
        return out

    def take_exporters(self) -> dict:
        with self.lock:
            snap = {k: {"flows": v["flows"], "last": v["last"], "ifs": dict(v["ifs"])} for k, v in self.exporters.items()}
            for v in self.exporters.values():
                v["flows"], v["ifs"] = 0, {}
        return snap


AGG = Aggregator()
COLS = ("ts", "exporter", "if_index", "local_ip", "remote_ip", "proto", "port", "direction",
        "bytes_out", "bytes_in", "pkts_out", "pkts_in", "flows")


def write_rows(rows: list[tuple]):
    if not rows:
        return 0
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        with cur.copy(f"COPY flow_1m ({', '.join(COLS)}) FROM STDIN") as cp:
            for r in rows:
                cp.write_row(r)
        raw.commit()
    finally:
        raw.close()
    return len(rows)


def save_exporters(snap: dict):
    if not snap:
        return
    db = SessionLocal()
    try:
        for ip, v in snap.items():
            e = db.get(models.FlowExporter, ip)
            if not e:
                e = models.FlowExporter(ip=ip, first_seen=now(), interfaces={}, if_names={}, flows_total=0)
                a = db.query(models.Asset).filter(models.Asset.ip == ip).first()
                if a:
                    e.asset_id, e.name = a.id, a.name
                db.add(e)
            if v["last"]:
                e.last_seen = datetime.fromtimestamp(v["last"], timezone.utc).replace(tzinfo=None)
            e.flows_total = (e.flows_total or 0) + v["flows"]
            ifs = dict(e.interfaces or {})
            for idx, by in v["ifs"].items():
                cur = dict(ifs.get(str(idx)) or {})
                cur["last_seen"] = e.last_seen.isoformat() if e.last_seen else None
                cur["bytes"] = int(cur.get("bytes") or 0) + int(by)
                ifs[str(idx)] = cur
            e.interfaces = ifs
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- GoFlow2 child process
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def find_collector() -> str | None:
    p = os.environ.get("FLOW_COLLECTOR", "").strip()
    if p:
        return p if os.path.exists(p) else None
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools"))
    pats = ["goflow2/goflow2*.exe", "goflow2*.exe"] if os.name == "nt" else ["goflow2/goflow2*", "goflow2*"]
    for pat in pats:
        for f in sorted(glob.glob(os.path.join(base, pat)), reverse=True):
            if os.path.isfile(f) and not f.endswith((".txt", ".md", ".gz", ".zip")):
                return f
    return shutil.which("goflow2")


def build_command(cfg: dict) -> list[str] | None:
    custom = os.environ.get("FLOW_COLLECTOR_CMD", "").strip()
    if custom:
        return shlex.split(custom, posix=os.name != "nt")
    exe = find_collector()
    if not exe:
        return None
    listen = f"netflow://:{cfg['port']}"
    if cfg.get("sflow_port"):
        listen += f",sflow://:{cfg['sflow_port']}"
    # arguments are passed as a list – no shell, no PowerShell quoting problems with "-transport.file"
    return [exe, "-listen", listen, "-format", "json", "-transport", "file", "-addr", f"127.0.0.1:{_free_port()}"]


def _pid_file() -> str:
    from .db import DATA_DIR
    return os.path.join(DATA_DIR, "goflow2.pid")


def _is_goflow(pid: int) -> bool:
    """True only if that PID is still a GoFlow2 process (never kill a PID that was reused by something else)."""
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                                 timeout=10, creationflags=0x08000000).stdout
            return "goflow2" in out.lower()
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return b"goflow2" in fh.read().lower()
    except (OSError, subprocess.SubprocessError):
        return False


def reap_stale():
    """VS Code Shift+F5 kills Python at once: the GoFlow2 child of the previous run may still hold UDP 2055. Stop it."""
    try:
        pid = int(open(_pid_file()).read().strip())
    except (OSError, ValueError):
        return
    if pid > 0 and _is_goflow(pid):
        log.warning("Stopping GoFlow2 left over from the previous run (pid %s)", pid)
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=10, creationflags=0x08000000)
            else:
                os.kill(pid, 15)
            time.sleep(1)
        except (OSError, subprocess.SubprocessError):
            log.warning("Could not stop the old GoFlow2 (pid %s)", pid, exc_info=True)
    try:
        os.remove(_pid_file())
    except OSError:
        pass


class Collector:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.cmd: list[str] | None = None
        self.started_at: float | None = None
        self.stopped_at: float | None = time.time()
        self.stderr = deque(maxlen=30)
        self.restarts = 0
        self.next_try = 0.0
        self.backoff = 5.0
        self.last_error = ""
        self.cfg_sig = None
        self.nets = Nets(DEFAULT_LOCAL)

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, cfg: dict):
        cmd = build_command(cfg)
        if not cmd:
            self.last_error = ("GoFlow2 not found. Put goflow2-<version>-windows-amd64.exe in backend\\tools\\goflow2\\ "
                               "(Linux: goflow2 on PATH) or set FLOW_COLLECTOR.")
            return False
        self.nets = Nets(cfg["local_networks"])
        if not os.environ.get("FLOW_COLLECTOR_CMD"):
            reap_stale()
        flags = 0x08000000 if os.name == "nt" else 0     # CREATE_NO_WINDOW
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                         text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=flags)
        except OSError as e:
            self.last_error = f"Could not start GoFlow2: {e}"
            self.proc = None
            return False
        self.cmd, self.started_at, self.last_error = cmd, time.time(), ""
        try:
            with open(_pid_file(), "w") as fh:
                fh.write(str(self.proc.pid))
        except OSError:
            pass
        self.cfg_sig = (cfg["port"], cfg["sflow_port"], tuple(cfg["local_networks"]))
        proc = self.proc
        threading.Thread(target=self._read_out, args=(proc,), daemon=True, name="goflow2-stdout").start()
        threading.Thread(target=self._read_err, args=(proc,), daemon=True, name="goflow2-stderr").start()
        log.info("GoFlow2 started (pid %s): %s", proc.pid, " ".join(cmd))
        return True

    def _read_out(self, proc):
        for line in proc.stdout:
            try:
                AGG.add_line(line, self.nets)
            except Exception:       # one bad record must never stop the reader
                log.debug("flow record skipped", exc_info=True)

    def _read_err(self, proc):
        for line in proc.stderr:
            line = line.strip()
            if line:
                self.stderr.append(f"{time.strftime('%H:%M:%S')} {line[:400]}")
                # GoFlow2 logs "template error" at WARN level while waiting for the IPFIX template (normal for a
                # minute after start) – only real errors are shown as the collector's last error
                if "level=ERROR" in line or ("level=" not in line and "error" in line.lower()):
                    self.last_error = line[:400]

    def stop(self):
        p = self.proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
            try:
                os.remove(_pid_file())
            except OSError:
                pass
        self.proc = None
        self.stopped_at = time.time()

    def supervise(self, cfg: dict):
        want = cfg["enabled"] and os.environ.get("DISABLE_FLOW", "").lower() not in ("1", "true")
        sig = (cfg["port"], cfg["sflow_port"], tuple(cfg["local_networks"]))
        if not want:
            if self.proc:
                self.stop()
                log.info("GoFlow2 stopped (traffic collection disabled)")
            return
        if self.running() and sig != self.cfg_sig:
            log.info("Traffic settings changed – restarting GoFlow2")
            self.stop()
            self.next_try = 0
        if self.running():
            if time.time() - (self.started_at or 0) > 120:
                self.backoff = 5.0
            return
        if self.proc is not None:              # it was running and exited
            code = self.proc.poll()
            self.last_error = self.last_error or f"GoFlow2 exited (code {code})"
            self.proc, self.stopped_at = None, time.time()
            self.restarts += 1
            self.next_try = time.time() + self.backoff
            self.backoff = min(300.0, self.backoff * 2)
            log.warning("GoFlow2 exited (code %s) – retry in %.0f s. %s", code, self.next_try - time.time(), self.last_error)
            return
        if time.time() >= self.next_try:
            if not self.start(cfg):
                self.next_try = time.time() + 60


COLLECTOR = Collector()


# ---------------------------------------------------------------- housekeeping: roll-up, retention, alerts
def rollup(db: Session) -> int:
    """Roll finished hours of flow_1m into flow_1h exactly once (watermark in settings 'flow_rollup')."""
    st = db.get(models.Setting, "flow_rollup")
    upto = (now() - timedelta(minutes=5)).replace(minute=0, second=0, microsecond=0)
    if st and (st.value or {}).get("hour"):
        start = datetime.fromisoformat(st.value["hour"])
    else:
        first = db.execute(text("select min(ts) from flow_1m")).scalar()
        if not first:
            return 0
        start = first.replace(minute=0, second=0, microsecond=0)
    if start >= upto:
        return 0
    n = db.execute(text("""
        insert into flow_1h (ts, exporter, if_index, local_ip, proto, port, direction,
                             bytes_out, bytes_in, pkts_out, pkts_in, flows, remotes)
        select date_trunc('hour', ts), exporter, if_index, local_ip, proto, port, direction,
               sum(bytes_out), sum(bytes_in), sum(pkts_out), sum(pkts_in), sum(flows), count(distinct remote_ip)
        from flow_1m where ts >= :a and ts < :b
        group by 1, exporter, if_index, local_ip, proto, port, direction"""), {"a": start, "b": upto}).rowcount
    if st:
        st.value = {"hour": upto.isoformat()}
    else:
        db.add(models.Setting(key="flow_rollup", value={"hour": upto.isoformat()}))
    return n or 0


def retention(db: Session, cfg: dict) -> tuple[int, int]:
    a = db.execute(text("delete from flow_1m where ts < :t"), {"t": now() - timedelta(days=cfg["keep_minute_days"])}).rowcount
    b = db.execute(text("delete from flow_1h where ts < :t"), {"t": now() - timedelta(days=cfg["keep_hour_days"])}).rowcount
    return a or 0, b or 0


def check_alerts(db: Session, cfg: dict) -> list:
    """Exporter silent for silent_minutes → alert; collector not running while enabled → alert. Both auto-resolve."""
    notes = []
    open_ = {a.dedupe_key: a for a in db.query(models.Alert).filter(models.Alert.source == "flow", models.Alert.status != "resolved")}

    def resolve(key, why):
        a = open_.get(key)
        if a:
            a.status, a.resolved_at = "resolved", now()
            a.message = f"{a.message} · {why}"[:2000]
            notes.append((f"{a.title} – {why}", "", "resolved", {"kind": "resolve", "alert_id": a.id, "asset_id": a.asset_id}))

    def open_alert(key, title, msg, asset_id=None, site_id=None):
        if key in open_:
            return
        a = models.Alert(source="flow", dedupe_key=key, asset_id=asset_id, site_id=site_id, severity="trouble",
                         title=title[:255], message=msg, last_seen=now(), count=1)
        db.add(a)
        db.flush()
        notes.append((a.title, msg, "trouble", {"kind": "open", "alert_id": a.id, "asset_id": asset_id, "site_id": site_id}))

    if not cfg["enabled"] or os.environ.get("DISABLE_FLOW", "").lower() in ("1", "true"):
        for k in list(open_):
            resolve(k, "traffic collection turned off")
        return notes
    down_for = time.time() - (COLLECTOR.stopped_at or time.time()) if not COLLECTOR.running() else 0
    if not COLLECTOR.running() and down_for > 300:
        open_alert("flow-collector", "Traffic collector (GoFlow2) is not running",
                   (COLLECTOR.last_error or "GoFlow2 is not running.") + " No traffic data is being recorded.")
    elif COLLECTOR.running():
        resolve("flow-collector", "collector running again")
    limit = timedelta(minutes=cfg["silent_minutes"])
    for e in db.query(models.FlowExporter).all():
        key = f"flow-silent:{e.ip}"
        if not e.last_seen:
            continue
        if now() - e.last_seen > limit and COLLECTOR.running() and now() - e.last_seen < timedelta(days=7):
            asset = db.get(models.Asset, e.asset_id) if e.asset_id else None
            mins = int((now() - e.last_seen).total_seconds() // 60)
            open_alert(key, f"No traffic data from {e.name or e.ip}",
                       f"{e.name or e.ip} ({e.ip}) has sent no flow records for {mins} minutes (threshold {cfg['silent_minutes']}). "
                       "Check softflowd on the firewall (Status → Services) and that its target is this server, port "
                       f"{cfg['port']}.", e.asset_id, asset.site_id if asset else None)
        elif now() - e.last_seen <= limit:
            resolve(key, "flow records are arriving again")
    return notes


_state = {"hourly": 0.0, "minute": 0.0}


async def loop():
    from .automation.engine import dispatch
    while True:
        try:
            cfg = await asyncio.to_thread(get_settings)
            COLLECTOR.supervise(cfg)
            rows = AGG.pop_finished()
            if rows:
                await asyncio.to_thread(write_rows, rows)
            if time.time() - _state["minute"] >= 60:
                _state["minute"] = time.time()
                await asyncio.to_thread(save_exporters, AGG.take_exporters())

                def work(cfg=cfg):
                    db = SessionLocal()
                    try:
                        notes = check_alerts(db, cfg)
                        if time.time() - _state["hourly"] >= 3600:
                            _state["hourly"] = time.time()
                            rollup(db)
                            retention(db, cfg)
                        db.commit()
                        return notes
                    finally:
                        db.close()
                notes = await asyncio.to_thread(work)
                if notes:
                    await dispatch(notes)
        except asyncio.CancelledError:
            COLLECTOR.stop()
            raise
        except Exception:
            log.exception("Traffic loop failed")
        await asyncio.sleep(FLUSH_EVERY)


def shutdown():
    COLLECTOR.stop()
    try:
        write_rows(AGG.pop_finished(before_minute=int(time.time() // 60) * 60 + 60))
    except Exception:
        log.warning("Could not write the last traffic minute on shutdown", exc_info=True)


# ---------------------------------------------------------------- interface names
PS_RE = re.compile(r"-i\s+(\d+):(\S+)")


def snmp_aliases(db: Session, exporter_ip: str, asset_id: int | None = None) -> dict:
    """Interface name → description from the SNMP / pfSense check of the firewall (e.g. em0.15 → TTS_Vlan15).
    The firewall is the asset linked to the exporter, or the asset with the exporter's IP. pfSense often sends flows
    from a VLAN address (172.17.15.1) while the asset is registered with another one (172.17.11.1) – link it once."""
    from sqlalchemy import or_
    out = {}
    cond = or_(models.Asset.ip == exporter_ip, models.Asset.id == asset_id) if asset_id else models.Asset.ip == exporter_ip
    for c in db.query(models.Check).join(models.Asset, models.Asset.id == models.Check.asset_id).filter(cond):
        for p in ((c.last_data or {}).get("ports") or []):
            if p.get("name") and p.get("alias"):
                out[p["name"]] = p["alias"]
    return out


def parse_softflowd(textv: str, aliases: dict | None = None) -> dict:
    """`ps aux | grep softflowd` output → {"15": "em0.15 TTS_Vlan15"}."""
    aliases = aliases or {}
    return {n: f"{name} {aliases.get(name, '')}".strip() for n, name in PS_RE.findall(textv or "")}


# ---------------------------------------------------------------- API
PERIODS = {1: ("flow_1m", 60), 6: ("flow_1m", 300), 24: ("flow_1m", 900), 168: ("flow_1h", 3600), 720: ("flow_1h", 21600)}


def _iso(d) -> str | None:
    """UTC timestamps go to the UI with a trailing Z, like the rest of IT Ops (main.to_dict)."""
    if not d:
        return None
    return (d if isinstance(d, str) else d.isoformat()).rstrip("Z") + "Z"


def _names(db: Session, ips: set[str]) -> dict:
    """Local IP → (name, source). Assets first, then endpoint agents (hostname / last user)."""
    out = {}
    if not ips:
        return out
    for a in db.query(models.Asset).filter(models.Asset.ip.in_(list(ips))):
        out[a.ip] = {"name": a.name, "src": "asset", "asset_id": a.id}
    for g in db.query(models.Agent).all():
        for ip in set((g.ips or []) + [g.ip or ""]):
            if ip in ips and ip not in out:
                out[ip] = {"name": g.hostname, "src": "agent", "agent_id": g.id,
                           "user": g.logged_user or g.last_user or ""}
    return out


def _if_label(db: Session) -> dict:
    lab = {}
    for e in db.query(models.FlowExporter).all():
        for k, v in (e.if_names or {}).items():
            lab[(e.ip, int(k))] = v
    return lab


def _where(exporter: str, if_index: int | None, host: str, direction: str):
    w, p = [], {}
    if exporter:
        w.append("exporter = :exp"); p["exp"] = exporter
    if if_index is not None:
        w.append("if_index = :ifx"); p["ifx"] = if_index
    if host:
        w.append("local_ip = :host"); p["host"] = host
    if direction in ("o", "l"):
        w.append("direction = :dir"); p["dir"] = direction
    return (" and " + " and ".join(w)) if w else "", p


@router.get("/api/traffic/summary")
def summary(hours: int = Query(1), exporter: str = "", if_index: int | None = None, host: str = "", direction: str = "",
            user=Depends(current_user), db: Session = Depends(get_db)):
    if hours not in PERIODS:
        raise HTTPException(400, f"hours must be one of {sorted(PERIODS)}")
    table, step = PERIODS[hours]
    since = now() - timedelta(hours=hours)
    w, p = _where(exporter, if_index, host, direction)
    p["since"] = since
    q = lambda sql: db.execute(text(sql), p).mappings().all()   # noqa: E731
    by_dir = {r["direction"]: r for r in q(f"""select direction, coalesce(sum(bytes_out),0) b_out, coalesce(sum(bytes_in),0) b_in,
                       coalesce(sum(flows),0) flows, count(distinct local_ip) hosts from {table} where ts >= :since{w} group by direction""")}
    p["step"] = step
    # chart and top hosts: Internet traffic (direction o) unless the user asked for local ↔ local
    sd = "l" if direction == "l" else "o"
    p["sd"] = sd
    series = q(f"""select to_timestamp(floor(extract(epoch from ts) / :step) * :step) at time zone 'UTC' t,
                          sum(bytes_out) b_out, sum(bytes_in) b_in from {table} where ts >= :since and direction = :sd{w}
                   group by 1 order by 1""")
    hosts = q(f"""select local_ip ip, sum(bytes_out) b_out, sum(bytes_in) b_in, sum(flows) flows from {table}
                  where ts >= :since and direction = :sd{w} group by local_ip order by sum(bytes_out + bytes_in) desc limit 25""")
    services = q(f"""select proto, port, sum(bytes_out) b_out, sum(bytes_in) b_in, sum(flows) flows from {table}
                     where ts >= :since{w} group by proto, port order by sum(bytes_out + bytes_in) desc limit 20""")
    ifs = q(f"""select exporter, if_index, sum(bytes_out) b_out, sum(bytes_in) b_in from {table}
                where ts >= :since{w} group by exporter, if_index order by sum(bytes_out + bytes_in) desc limit 30""")
    keep_m = get_settings(db)["keep_minute_days"] * 24
    p["since_m"] = now() - timedelta(hours=min(hours, keep_m))
    remotes = q(f"""select remote_ip ip, sum(bytes_out) b_out, sum(bytes_in) b_in, count(distinct local_ip) hosts,
                           array_agg(distinct proto * 100000 + port) svc from flow_1m
                    where ts >= :since_m and direction = 'o'{w} group by remote_ip order by sum(bytes_out + bytes_in) desc limit 20""")
    convs = q(f"""select local_ip, remote_ip, proto, port, direction, sum(bytes_out) b_out, sum(bytes_in) b_in, sum(flows) flows,
                         min(ts) first, max(ts) last from flow_1m where ts >= :since_m{w}
                  group by local_ip, remote_ip, proto, port, direction order by sum(bytes_out + bytes_in) desc limit 50""")
    lab = _if_label(db)
    names = _names(db, {h["ip"] for h in hosts} | {c["local_ip"] for c in convs} | {c["remote_ip"] for c in convs if c["direction"] == "l"})
    i = lambda v: int(v or 0)   # noqa: E731
    return {
        "hours": hours, "step": step, "table": table, "since": _iso(since),
        "totals": {"b_out": i(by_dir.get("o", {}).get("b_out")), "b_in": i(by_dir.get("o", {}).get("b_in")),
                   "flows": sum(i(r["flows"]) for r in by_dir.values()), "hosts": i(by_dir.get("o", {}).get("hosts")),
                   "local_bytes": i(by_dir.get("l", {}).get("b_out")) + i(by_dir.get("l", {}).get("b_in"))},
        "series": [{"t": _iso(r["t"]), "b_out": i(r["b_out"]), "b_in": i(r["b_in"])} for r in series],
        "hosts": [{"ip": r["ip"], **names.get(r["ip"], {}), "b_out": i(r["b_out"]), "b_in": i(r["b_in"]), "flows": i(r["flows"])} for r in hosts],
        "services": [{"proto": r["proto"], "port": r["port"], "b_out": i(r["b_out"]), "b_in": i(r["b_in"]), "flows": i(r["flows"])} for r in services],
        "interfaces": [{"exporter": r["exporter"], "if_index": r["if_index"], "name": lab.get((r["exporter"], r["if_index"]), ""),
                        "b_out": i(r["b_out"]), "b_in": i(r["b_in"])} for r in ifs],
        "remotes": [{"ip": r["ip"], "b_out": i(r["b_out"]), "b_in": i(r["b_in"]), "hosts": i(r["hosts"]),
                     "services": [[s // 100000, s % 100000] for s in (r["svc"] or [])[:6]]} for r in remotes],
        "conversations": [{"local": r["local_ip"], "local_name": names.get(r["local_ip"], {}).get("name", ""),
                           "remote": r["remote_ip"], "remote_name": names.get(r["remote_ip"], {}).get("name", "") if r["direction"] == "l" else "",
                           "proto": r["proto"], "port": r["port"], "direction": r["direction"],
                           "b_out": i(r["b_out"]), "b_in": i(r["b_in"]), "flows": i(r["flows"]),
                           "first": _iso(r["first"]), "last": _iso(r["last"])} for r in convs],
    }


def status_dict(db: Session) -> dict:
    cfg = get_settings(db)
    st = AGG.stats
    kept, tr = st["kept_bytes"], st["transit_bytes"]
    exps = []
    for e in db.query(models.FlowExporter).order_by(models.FlowExporter.ip):
        ifs = [{"if_index": int(k), "name": (e.if_names or {}).get(k, ""), "last_seen": _iso(v.get("last_seen")), "bytes": v.get("bytes", 0)}
               for k, v in sorted((e.interfaces or {}).items(), key=lambda kv: int(kv[0]))]
        for k, n in (e.if_names or {}).items():
            if k not in (e.interfaces or {}):
                ifs.append({"if_index": int(k), "name": n, "last_seen": None, "bytes": 0})
        exps.append({"ip": e.ip, "name": e.name, "asset_id": e.asset_id, "first_seen": _iso(e.first_seen),
                     "last_seen": _iso(e.last_seen), "flows_total": e.flows_total, "interfaces": ifs})
    return {
        "settings": cfg,
        "disabled_by_env": os.environ.get("DISABLE_FLOW", "").lower() in ("1", "true"),
        "collector": {"running": COLLECTOR.running(), "pid": COLLECTOR.proc.pid if COLLECTOR.running() else None,
                      "binary": find_collector() or ("custom command" if os.environ.get("FLOW_COLLECTOR_CMD") else None),
                      "command": " ".join(COLLECTOR.cmd or []), "started_at": COLLECTOR.started_at,
                      "restarts": COLLECTOR.restarts, "last_error": COLLECTOR.last_error, "log": list(COLLECTOR.stderr)[-12:]},
        "stats": {**st, "rate": AGG.rate(),
                  "transit_pct": round(100 * st["transit"] / st["lines"], 1) if st["lines"] else 0,          # share of records
                  "transit_bytes_pct": round(100 * tr / (tr + kept), 1) if tr + kept else 0},
        "exporters": exps,
        "assets": [{"id": a.id, "name": a.name, "ip": a.ip, "type": a.type} for a in db.query(models.Asset)
                   .filter(models.Asset.type.in_(["firewall", "router", "switch"])).order_by(models.Asset.name)],
        "platform": sys.platform,
    }


@router.get("/api/traffic/status")
def status(user=Depends(current_user), db: Session = Depends(get_db)):
    return status_dict(db)


@router.put("/api/traffic/settings")
def put_settings(body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    from .main import audit
    before = get_settings(db)
    try:
        v = save_settings(db, body)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    changed = {k: [before.get(k), v[k]] for k in v if before.get(k) != v[k]}
    audit(db, user.username, "update", "traffic_settings", None, "Traffic collection settings", changes=changed or None)
    db.commit()
    return status_dict(db)


@router.put("/api/traffic/exporters/{ip}")
def put_exporter(ip: str, body: dict = Body(...), user=Depends(admin_user), db: Session = Depends(get_db)):
    """Body: {name?, asset_id?, if_names?: {"15": "VLAN 15"}, softflowd_ps?: "<ps aux output>"}."""
    from .main import audit
    e = db.get(models.FlowExporter, ip)
    if not e:
        raise HTTPException(404, "Unknown exporter")
    if "name" in body:
        e.name = str(body["name"] or "")[:128]
    if "asset_id" in body:
        aid = body["asset_id"]
        if aid and not db.get(models.Asset, int(aid)):
            raise HTTPException(400, "Unknown asset")
        e.asset_id = int(aid) if aid else None
        if aid and not body.get("name") and not e.name:
            e.name = db.get(models.Asset, int(aid)).name
    names = dict(e.if_names or {})
    if body.get("softflowd_ps"):
        parsed = parse_softflowd(body["softflowd_ps"], snmp_aliases(db, ip, e.asset_id))
        if not parsed:
            raise HTTPException(400, "No '-i <number>:<interface>' found – paste the output of: ps aux | grep softflowd")
        names.update(parsed)
    for k, v in (body.get("if_names") or {}).items():
        if not str(k).isdigit():
            raise HTTPException(400, f"Interface number must be a number: {k}")
        v = str(v or "").strip()[:80]
        if v:
            names[str(int(k))] = v
        else:
            names.pop(str(int(k)), None)
    e.if_names = names
    audit(db, user.username, "update", "flow_exporter", None, f"Traffic exporter {ip}: names / asset updated")
    db.commit()
    return status_dict(db)
