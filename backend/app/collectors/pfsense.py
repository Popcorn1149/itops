"""pfSense / OPNsense.

- pfSense: dùng gói REST API (pfrest.org, API v2) → CPU/RAM/disk, gateway WAN (loss/latency),
  status interface, VPN (IPsec/OpenVPN), tuỳ chọn lấy DHCP lease để đưa thiết bị lên bản đồ.
- OPNsense: API có sẵn (key + secret).
- Không cài API được thì chọn mode "snmp" (bật SNMP trong pfSense: Services > SNMP).
"""
import time

import httpx

from .base import Result, apply_resources, fmt_uptime, worst
from .snmp import snmp as snmp_collect
from .ssh import freebsd_resources


async def _pf_get(c: httpx.AsyncClient, path: str, required: bool = False):
    r = await c.get(path)
    if r.status_code == 404 and not required:
        return None  # endpoint tuỳ chọn (VPN, DHCP...) có thể không có ở bản cũ
    r.raise_for_status()
    j = r.json()
    return j.get("data", j)


async def pfsense(target: str, cfg: dict) -> Result:
    mode = cfg.get("mode", "api")
    if mode == "snmp":
        if not cfg.get("cli_enabled"):
            return await snmp_collect(target, cfg)
        # SNMP (cổng, WAN, lưu lượng) + SSH/CLI (CPU/RAM/Disk chính xác như Dashboard pfSense)
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        res = await snmp_collect(target, {**cfg, "resources": False})
        try:
            b = await freebsd_resources(host, cfg, prefix="cli_")
        except Exception as e:
            r2 = await snmp_collect(target, cfg)     # CLI lỗi → quay về số liệu SNMP
            r2.message += f" · CLI lỗi: {type(e).__name__} {e}"[:200]
            r2.status = worst(r2.status, "warn")
            return r2
        statuses, notes = [res.status], []
        data = res.data or {}
        data["disks"] = b["disks"]
        metrics = apply_resources(data, cfg, statuses, notes, cpu=b.get("cpu"), mem=b.get("mem"), disks=b["disks"],
                                  mem_total_gb=b.get("mem_total_gb"), swap=b.get("swap"), cores=b.get("nproc"))
        data["res"]["source"] = "CLI (SSH)"
        if b.get("uptime_s"):
            data["uptime"] = fmt_uptime(b["uptime_s"])
        if metrics.get("cpu") is not None:
            data["cpu"] = metrics["cpu"]
        res.message = " · ".join([res.message] + notes)
        res.status, res.value, res.data = worst(*statuses), metrics.get("cpu"), data
        return res
    base = target if "://" in target else f"https://{target}"
    headers, auth = {}, None
    flavor = cfg.get("flavor", "pfsense")
    if flavor == "opnsense":
        auth = (cfg.get("api_key", ""), cfg.get("client_secret", ""))
    elif cfg.get("api_key"):
        headers["X-API-Key"] = cfg["api_key"]
    else:
        auth = (cfg.get("username", "admin"), cfg.get("password", ""))

    t0 = time.perf_counter()
    statuses, notes, data, discovered = ["ok"], [], {}, []
    value = None
    try:
        async with httpx.AsyncClient(base_url=base, headers=headers, auth=auth, verify=bool(cfg.get("verify_ssl", False)),
                                     timeout=float(cfg.get("timeout", 15))) as c:
            if flavor == "opnsense":
                sysr = await c.get("/api/core/system/status")
                sysr.raise_for_status()
                data["system"] = sysr.json()
                try:
                    act = await c.get("/api/diagnostics/system/systemResources")
                    mem = act.json().get("memory", {}) if act.status_code == 200 else {}
                    tot, used = float(mem.get("total") or 0), float(mem.get("used") or 0)
                    dk = await c.get("/api/diagnostics/system/systemDisk")
                    devs = dk.json().get("devices", []) if dk.status_code == 200 else []
                    disks = [{"name": d.get("mountpoint"), "pct": str(d.get("used_pct", "")).rstrip("%")} for d in devs if d.get("mountpoint")]
                    value = apply_resources(data, cfg, statuses, notes, mem=(used / tot * 100) if tot else None, disks=disks,
                                            mem_total_gb=tot / 1073741824 if tot else None).get("cpu")
                except Exception:
                    pass
                gw = await c.get("/api/routes/gateway/status")
                gws = gw.json().get("items", []) if gw.status_code == 200 else []
                for g in gws:
                    st = str(g.get("status_translated") or g.get("status", "")).lower()
                    data.setdefault("gateways", []).append({"name": g.get("name"), "status": st, "loss": g.get("loss"), "delay": g.get("delay")})
                    if st not in ("online", "none", ""):
                        statuses.append("fail" if "down" in st or "offline" in st else "warn")
                        notes.append(f"GW {g.get('name')} {st}")
            else:
                sysinfo = await _pf_get(c, "/api/v2/status/system", required=True) or {}
                ms = (time.perf_counter() - t0) * 1000
                data["cpu"] = sysinfo.get("cpu_usage")
                data["mem"] = sysinfo.get("mem_usage")
                data["disk"] = sysinfo.get("disk_usage")
                data["temp"] = sysinfo.get("temp_c")
                data["platform"] = sysinfo.get("system_platform")
                data["uptime"] = fmt_uptime(sysinfo.get("uptime")) if isinstance(sysinfo.get("uptime"), (int, float)) else sysinfo.get("uptime")
                mem_mb = sysinfo.get("mem_total") or sysinfo.get("memory_total")
                metrics = apply_resources(data, cfg, statuses, notes, cpu=data["cpu"], mem=data["mem"],
                                          disks=[{"name": "/", "pct": data["disk"]}] if data["disk"] is not None else [],
                                          swap=sysinfo.get("swap_usage"), cores=sysinfo.get("cpu_count"),
                                          mem_total_gb=(mem_mb / 1024) if isinstance(mem_mb, (int, float)) else None)
                value = metrics.get("cpu")
                try:
                    ver = await _pf_get(c, "/api/v2/system/version") or {}
                    data["version"] = ver.get("version")
                except Exception:
                    pass

                gws = await _pf_get(c, "/api/v2/status/gateways") or []
                data["gateways"] = []
                for g in gws:
                    st = str(g.get("status", "")).lower()
                    data["gateways"].append({"name": g.get("name"), "status": st, "loss": g.get("loss"), "delay": g.get("delay"), "monitor": g.get("monitorip")})
                    if st in ("down", "offline"):
                        statuses.append("fail"); notes.append(f"Gateway {g.get('name')} DOWN")
                    elif st not in ("online", "none", ""):
                        statuses.append("warn"); notes.append(f"Gateway {g.get('name')} {st}")
                if gws:
                    online = sum(1 for g in data["gateways"] if g["status"] in ("online", "none"))
                    notes.insert(0, f"{online}/{len(gws)} WAN online")

                ifs = await _pf_get(c, "/api/v2/status/interfaces") or []
                data["interfaces"] = [{"name": i.get("descr") or i.get("name"), "if": i.get("hwif"), "status": i.get("status"),
                                       "ip": i.get("ipaddr"), "subnet": i.get("subnet")} for i in ifs]
                watch = [w.strip().lower() for w in str(cfg.get("watch_interfaces", "")).split(",") if w.strip()]
                for i in data["interfaces"]:
                    if watch and str(i["name"]).lower() in watch and str(i["status"]).lower() not in ("up", "associated"):
                        statuses.append("fail"); notes.append(f"Interface {i['name']} {i['status']}")

                if cfg.get("check_vpn", True):
                    try:
                        sas = await _pf_get(c, "/api/v2/status/ipsec/sas") or []
                        data["ipsec"] = [{"name": s.get("con_id") or s.get("name"), "state": s.get("state"), "remote": s.get("remote_host")} for s in sas]
                        if sas:
                            up = sum(1 for s in data["ipsec"] if str(s["state"]).upper() == "ESTABLISHED")
                            notes.append(f"IPsec {up}/{len(sas)}")
                    except Exception:
                        pass
                    try:
                        ovpn = await _pf_get(c, "/api/v2/status/openvpn/servers") or []
                        clients = sum(len(s.get("conns") or []) for s in ovpn)
                        data["openvpn_clients"] = clients
                        if ovpn:
                            notes.append(f"{clients} OpenVPN client")
                    except Exception:
                        pass

                if cfg.get("discover_dhcp", False):
                    leases = await _pf_get(c, "/api/v2/status/dhcp_server/leases") or []
                    for l in leases[: int(cfg.get("dhcp_limit", 200))]:
                        if not l.get("mac"):
                            continue
                        online = str(l.get("online_status", "")).lower().startswith("online") or l.get("active_status") == "active"
                        discovered.append({"key": f"mac:{l['mac']}", "type": "device", "name": l.get("hostname") or l.get("ip") or l["mac"],
                                           "status": "up" if online else "unknown", "ip": l.get("ip", ""), "meta": {"mac": l["mac"], "dhcp": True}})
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = " (sai API key/mật khẩu?)" if code in (401, 403) else " (chưa cài gói REST API?)" if code == 404 else ""
        return Result("fail", f"pfSense API trả về {code}{hint}")
    except Exception as e:
        return Result("fail", f"Không kết nối pfSense: {type(e).__name__} {e}"[:300])

    ms = (time.perf_counter() - t0) * 1000
    return Result(worst(*statuses), " · ".join(notes) or "OK", ms, value, data, discovered)
