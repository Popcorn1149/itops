"""Ping (ICMP), TCP ports, and HTTP(S) + SSL certificate expiry."""
import asyncio
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .base import Result


IS_WINDOWS = os.name == "nt"


def _ping_cmd(target: str, count: int, timeout: int) -> list[str]:
    if IS_WINDOWS:
        return ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    return ["ping", "-n", "-c", str(count), "-W", str(timeout), "-i", "0.3", target]


def parse_ping(text: str) -> tuple[float, float | None, bool]:
    """Trả (loss %, rtt trung bình ms, có đọc được thống kê không). Hỗ trợ Linux/macOS and Windows (tiếng Anh/Việt)."""
    m = re.search(r"([\d.]+)% packet loss", text)                      # Linux / macOS
    if m:
        rtt = re.search(r"= [\d.]+/([\d.]+)/", text)
        return float(m.group(1)), float(rtt.group(1)) if rtt else None, True
    m = re.search(r"\(\D{0,12}?(\d+)%", text)                          # Windows: "(0% loss)" / "(mất 0%)"
    if m:
        times = re.findall(r"[=<]\s?(\d+)\s?ms", text)                 # Average/Trung bình là số ms cuối cùng
        loss = float(m.group(1))
        return loss, (float(times[-1]) if times and loss < 100 else None), True
    return 100.0, None, False


async def ping(target: str, cfg: dict) -> Result:
    count = int(cfg.get("count", 3))
    timeout = int(cfg.get("timeout", 2))
    import subprocess
    try:
        # chạy trong thread: hoạt động với mọi loại event loop (Windows SelectorEventLoop is not supported subprocess)
        cp = await asyncio.to_thread(subprocess.run, _ping_cmd(target, count, timeout), capture_output=True,
                                     timeout=count * (timeout + 1) + 5,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        return Result("fail", "The server is missing the ping command (install iputils-ping)")
    except subprocess.TimeoutExpired:
        return Result("fail", "Ping timed out")
    raw = cp.stdout + cp.stderr
    text = raw.decode("utf-8", errors="ignore") if not IS_WINDOWS else raw.decode("mbcs", errors="ignore")
    loss, rtt, parsed = parse_ping(text)
    if loss >= 100:
        msg = "No response" if parsed else (text.strip().splitlines() or ["Ping failed"])[-1]
        return Result("fail", msg, None, loss, {"loss": loss}, down=True)
    status = "warn" if loss > float(cfg.get("warn_loss", 20)) or (rtt and rtt > float(cfg.get("warn_ms", 200))) else "ok"
    return Result(status, f"{rtt:.1f} ms · {loss:.0f}% packet loss" if rtt is not None else f"{loss:.0f}% packet loss", rtt, loss, {"loss": loss})


async def tcp(target: str, cfg: dict) -> Result:
    port = int(cfg.get("port", 443))
    t0 = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=float(cfg.get("timeout", 5)))
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
    except Exception as e:
        return Result("fail", f"Port {port} is closed: {type(e).__name__} {e}".strip())
    ms = (time.perf_counter() - t0) * 1000
    return Result("ok", f"Port {port} is open · {ms:.0f} ms", ms)


def _cert_days_left(host: str, port: int, timeout: float = 5) -> int | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    if not der:
        return None
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    exp = cert.not_valid_after_utc
    return (exp - datetime.now(timezone.utc)).days


async def http(target: str, cfg: dict) -> Result:
    url = target if "://" in target else f"https://{target}"
    expected = [int(x) for x in str(cfg.get("expected_status", "200-399")).replace(" ", "").split(",") if x and "-" not in x]
    rng = str(cfg.get("expected_status", "200-399"))
    keyword = cfg.get("keyword", "")
    verify = bool(cfg.get("verify_ssl", False))
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(verify=verify, timeout=float(cfg.get("timeout", 10)), follow_redirects=True) as c:
            r = await c.request(cfg.get("method", "GET"), url)
    except Exception as e:
        return Result("fail", f"Unable to access: {type(e).__name__} {e}"[:300])
    ms = (time.perf_counter() - t0) * 1000

    ok_code = r.status_code in expected
    if not expected and "-" in rng:
        lo, hi = [int(x) for x in rng.split("-")[:2]]
        ok_code = lo <= r.status_code <= hi
    data = {"code": r.status_code}
    status, parts = "ok", [f"HTTP {r.status_code} · {ms:.0f} ms"]
    down = False
    if not ok_code:
        status, down = "fail", True          # web trả mã error = trang không dùng được (giống Uptime Kuma)
    if keyword and keyword not in r.text:
        status, down = "fail", True
        parts.append(f"Expected keyword '{keyword}' was not found")
    if ms > float(cfg.get("warn_ms", 3000)) and status == "ok":
        status = "warn"

    u = urlparse(str(r.url))
    if u.scheme == "https" and cfg.get("check_cert", True):
        try:
            days = await asyncio.to_thread(_cert_days_left, u.hostname, u.port or 443)
            if days is not None:
                data["cert_days"] = days
                parts.append(f"SSL certificate expires in {days} days")
                if days < 0:
                    status = "fail"
                elif days < int(cfg.get("cert_warn_days", 14)) and status == "ok":
                    status = "warn"
        except Exception:
            pass
    return Result(status, " · ".join(parts), ms, ms, data, down=down)


# ---------------------------------------------------------------- Đường Internet (kiểu Uptime Kuma / UptimeRobot)
DEFAULT_INET_TARGETS = "1.1.1.1, 8.8.8.8, 208.67.222.222"


def inet_targets(target: str) -> list[str]:
    return [t.strip() for t in (target or DEFAULT_INET_TARGETS).replace(";", ",").split(",") if t.strip()][:8]


# Well-known public resolvers: if ALL of them stay silent while DNS / HTTP work, ICMP is probably blocked → warning only.
PUBLIC_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220", "9.9.9.9", "149.112.112.112"}


def is_custom_inet(target: str) -> bool:
    """True when the check pings at least one address of IT's own (a WAN public IP, a gateway…), not only public resolvers."""
    return not set(inet_targets(target)) <= PUBLIC_RESOLVERS
_LAST_PUBLIC_IP: dict = {}     # {check key: ip} – phát hiện đổi đường WAN (failover)


def ping_samples(text: str) -> list[float]:
    """Thời gian fromng gói (ms). Linux 'time=12.3 ms'; Windows 'time=12ms' / 'time<1ms' / '\u0074h\u1eddi gian=12ms'."""
    return [float(x) for x in re.findall(r"(?:time|\u0074h\u1eddi gian|thoi gian)\s?[=<]\s?([\d.]+)\s?ms", text, re.I)]


def jitter(samples: list[float]) -> float | None:
    """Jitter = trung bình chênh lệch giữa 2 gói liên tiếp (RFC 3550, dạng đơn giản)."""
    if len(samples) < 2:
        return None
    return round(sum(abs(b - a) for a, b in zip(samples, samples[1:], strict=False)) / (len(samples) - 1), 1)


async def _ping_one(target: str, count: int, timeout: int) -> dict:
    import subprocess
    try:
        cp = await asyncio.to_thread(subprocess.run, _ping_cmd(target, count, timeout), capture_output=True,
                                     timeout=count * (timeout + 1) + 5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        raw = cp.stdout + cp.stderr
        text = raw.decode("utf-8", errors="ignore") if not IS_WINDOWS else raw.decode("mbcs", errors="ignore")
    except FileNotFoundError:
        return {"target": target, "loss": 100.0, "rtt": None, "error": "ping command is missing"}
    except subprocess.TimeoutExpired:
        return {"target": target, "loss": 100.0, "rtt": None, "error": "timed out"}
    loss, rtt, _ = parse_ping(text)
    smp = ping_samples(text)
    return {"target": target, "loss": loss, "rtt": round(rtt, 1) if rtt is not None else None, "jitter": jitter(smp),
            "min": min(smp) if smp else None, "max": max(smp) if smp else None}


async def _dns(name: str, timeout: float) -> dict:
    t0 = time.perf_counter()
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(name, 443, type=socket.SOCK_STREAM), timeout)
        return {"name": name, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "addr": infos[0][4][0] if infos else None}
    except Exception as e:
        return {"name": name, "ok": False, "error": type(e).__name__}


async def _http_probe(url: str, timeout: float) -> dict:
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
            r = await c.get(url)
        return {"url": url, "ok": r.status_code < 400, "code": r.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as e:
        return {"url": url, "ok": False, "error": type(e).__name__}


async def _public_ip(timeout: float) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get("https://api.ipify.org")
        ip = r.text.strip()
        return ip if re.fullmatch(r"[\d.]{7,15}|[0-9a-fA-F:]{3,45}", ip) else None
    except Exception:
        return None


async def internet(target: str, cfg: dict) -> Result:
    """Kiểm tra đường Internet: ping nhiều đích công cộng + DNS + HTTP (+ IP public để biết đang ra bằng đường WAN nào).

    - Error (mất Internet): mọi đích ping, DNS and HTTP đều không được.
    - Warning: một phần đích not responding, mất gói/độ trễ/jitter vượt threshold, DNS hoặc HTTP failure, IP public đổi.
    """
    targets = inet_targets(target)
    custom = is_custom_inet(target)
    count, timeout = int(cfg.get("count", 5)), int(cfg.get("timeout", 2))
    jobs = [_ping_one(t, count, timeout) for t in targets]
    dns_name = str(cfg.get("dns_name", "google.com")).strip()
    http_url = str(cfg.get("http_url", "http://www.gstatic.com/generate_204")).strip()
    extra = []
    if dns_name:
        extra.append(_dns(dns_name, float(cfg.get("dns_timeout", 3))))
    if http_url:
        extra.append(_http_probe(http_url, float(cfg.get("http_timeout", 5))))
    want_ip = cfg.get("public_ip", True)
    if want_ip:
        extra.append(_public_ip(4))
    out = await asyncio.gather(*jobs, *extra)
    pings = out[: len(targets)]
    rest = list(out[len(targets):])
    dns = rest.pop(0) if dns_name else None
    web = rest.pop(0) if http_url else None
    pub = rest.pop(0) if want_ip else None

    alive = [p for p in pings if p["loss"] < 100]
    statuses, notes = ["ok"], []
    data = {"targets": pings, "dns": dns, "http": web, "public_ip": pub}
    best = min((p["rtt"] for p in alive if p["rtt"] is not None), default=None)
    loss = round(sum(p["loss"] for p in pings) / len(pings), 1) if pings else 100.0
    jit = [p["jitter"] for p in alive if p.get("jitter") is not None]
    jit_v = round(sum(jit) / len(jit), 1) if jit else None
    data.update({"latency_ms": best, "loss": loss, "jitter_ms": jit_v, "reachable": len(alive), "total": len(pings)})

    any_ok = bool(alive) or (dns and dns["ok"]) or (web and web["ok"])
    if not any_ok:
        return Result("fail", f"Internet outage · 0/{len(pings)} targets responding" + (" · DNS failure" if dns else "") + (" · HTTP failure" if web else ""),
                      None, 100.0, data, down=True)
    if not alive and custom:
        # Your own targets (e.g. one WAN's public IP / gateway): none answering = that line is DOWN.
        # DNS / HTTP below go out through the server's own default route, so they say nothing about that line.
        return Result("fail", f"No response from {', '.join(targets)} · 100% packet loss", None, 100.0, data, down=True)
    if not alive:
        statuses.append("warn"); notes.append("no ping targets responded (is ICMP blocked?)")
    elif len(alive) < len(pings):
        statuses.append("warn"); notes.append(f"{len(pings) - len(alive)}/{len(pings)} targets did not respond: " + ", ".join(p["target"] for p in pings if p["loss"] >= 100))
    if best is not None:
        notes.insert(0, f"{best:g} ms")
        if best > float(cfg.get("warn_ms", 150)):
            statuses.append("warn"); notes.append(f"high latency (> {cfg.get('warn_ms', 150)} ms)")
    notes.insert(1 if best is not None else 0, f"{loss:g}% packet loss")
    if alive and loss > float(cfg.get("warn_loss", 10)):
        statuses.append("warn")
    if jit_v is not None:
        notes.append(f"jitter {jit_v:g} ms")
        if jit_v > float(cfg.get("warn_jitter", 30)):
            statuses.append("warn")
    if dns:
        if dns["ok"]:
            notes.append(f"DNS {dns['ms']:g} ms")
            if dns["ms"] > float(cfg.get("warn_dns_ms", 500)):
                statuses.append("warn")
        else:
            statuses.append("warn"); notes.append("DNS failure")
    if web and not web["ok"]:
        statuses.append("warn"); notes.append(f"HTTP failure ({web.get('code') or web.get('error')})")
    if pub:
        key = ",".join(targets)
        prev = _LAST_PUBLIC_IP.get(key)
        _LAST_PUBLIC_IP[key] = pub
        notes.append(f"IP {pub}")
        if prev and prev != pub:
            data["public_ip_prev"] = prev
            notes.append(f"WAN egress path changed: {prev} → {pub}")
            if cfg.get("warn_ip_change", True):
                statuses.append("warn")
    from .base import worst
    # latency = best ping RTT only; without any ping reply there is no latency (not the probe's total run time)
    return Result(worst(*statuses), " · ".join(notes), best, loss, data)
