"""Test tải: 1.000 tài sản, 300 check (chu kỳ 30s) chạy liên tục ~90s; đo độ trễ API and độ đúng hạn of scheduler."""
import json
import os
import statistics
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_ui as E  # noqa: E402

DURATION = int(os.environ.get("LOAD_SECONDS", "90"))


def timed(path, tok):
    t = time.perf_counter()
    req = urllib.request.Request(E.BASE + path, headers={"Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
    return (time.perf_counter() - t) * 1000, len(body)


def main():
    proc, data_dir = E.start_server(demo=False)
    try:
        tok = E.api("POST", "/api/auth/login", {"username": "admin", "password": "Admin@12345"})["token"]
        t0 = time.time()
        site = E.api("POST", "/api/sites", {"name": "LOAD"}, tok)
        fw = E.api("POST", "/api/assets", {"name": "fw", "type": "firewall", "site_id": site["id"]}, tok)
        n_assets = 1
        for s in range(10):
            sw = E.api("POST", "/api/assets", {"name": f"sw{s}", "type": "switch", "site_id": site["id"], "parent_id": fw["id"]}, tok)
            n_assets += 1
            for h in range(2):
                host = E.api("POST", "/api/assets", {"name": f"esx{s}-{h}", "type": "host", "site_id": site["id"], "parent_id": sw["id"]}, tok)
                n_assets += 1
                for v in range(45):
                    vm = E.api("POST", "/api/assets", {"name": f"vm{s}-{h}-{v}", "type": "vm", "site_id": site["id"], "parent_id": host["id"]}, tok)
                    n_assets += 1
                    if v < 3:
                        E.api("POST", "/api/critical", {"name": f"svc{s}-{h}-{v}", "asset_id": vm["id"], "level": "High"}, tok)
        assets = E.api("GET", "/api/assets?type=vm", token=tok)
        ids = [a["id"] for a in assets]
        for i in range(300):
            if i < 200:
                body = {"name": f"ping{i}", "type": "ping", "target": "127.0.0.1", "config": {"count": 1}}
            elif i < 250:
                body = {"name": f"tcp{i}", "type": "tcp", "target": "127.0.0.1", "config": {"port": 1, "timeout": 1, "alert_after": 1}}
            else:
                body = {"name": f"http{i}", "type": "http", "target": f"{E.BASE}/api/health"}
            E.api("POST", "/api/checks", {**body, "interval": 30, "asset_id": ids[i % len(ids)]}, tok)
        print(f"Tạo {n_assets} tài sản, 300 check, 60 hệ thống trọng yếu trong {time.time() - t0:.1f}s")

        lat = {p: [] for p in ["/api/dashboard", "/api/topology", "/api/assets", "/api/checks", "/api/critical", "/api/risks", "/api/sites"]}
        stop = time.time() + DURATION
        errs = []

        def hammer():
            while time.time() < stop:
                for p in lat:
                    try:
                        ms, _ = timed(p, tok)
                        lat[p].append(ms)
                    except Exception as e:  # noqa: BLE001
                        errs.append(f"{p}: {e}")
                time.sleep(0.5)
        threads = [threading.Thread(target=hammer) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]

        checks = E.api("GET", "/api/checks", token=tok)
        runs = []
        for c in checks:
            h = E.api("GET", f"/api/checks/{c['id']}/history?hours=1", token=tok)
            runs.append(len(h))
        alerts = E.api("GET", "/api/alerts", token=tok)
        log = open(os.path.join(data_dir, "server.log")).read()
        try:
            rss = int(open(f"/proc/{proc.pid}/status").read().split("VmRSS:")[1].split()[0]) // 1024
        except Exception:
            rss = -1

        expect = DURATION // 30 + 1
        print(f"\nKết quả sau {DURATION}s:")
        for p, v in lat.items():
            v.sort()
            print(f"  {p:16} n={len(v):4}  p50={statistics.median(v):7.1f} ms  p95={v[int(len(v) * .95)]:7.1f} ms  max={v[-1]:7.1f} ms")
        print(f"  Số lần chạy every check: min={min(runs)} median={statistics.median(runs)} max={max(runs)} (kỳ vọng ≈{expect})")
        print(f"  Check chưa chạy lần nào: {sum(1 for r in runs if r == 0)}")
        print(f"  Open alerts: {len(alerts)} (kỳ vọng 50 từ check TCP cổng đóng)")
        print(f"  Error request: {len(errs)} {errs[:3]}")
        print(f"  'database is locked' trong log: {log.count('database is locked')}, Traceback: {log.count('Traceback')}")
        print(f"  RAM server: {rss} MB")
        E.check("Mọi check đều chạy", min(runs) >= 1)
        E.check("Scheduler đúng hạn (median ≥ kỳ vọng-1)", statistics.median(runs) >= expect - 1)
        E.check("Không check nào chạy quá dày", max(runs) <= expect + 1)
        E.check("50 cảnh báo đúng (không trùng)", len(alerts) == 50, str(len(alerts)))
        E.check("Không error request", not errs)
        E.check("Không khoá DB / Traceback", "database is locked" not in log and "Traceback" not in log, log[-600:])
        E.check("Bảng điều khiển p95 < 1s", sorted(lat["/api/dashboard"])[int(len(lat["/api/dashboard"]) * .95)] < 1000)
        E.check("Bản đồ (1.000 node) p95 < 1.5s", sorted(lat["/api/topology"])[int(len(lat["/api/topology"]) * .95)] < 1500)
    finally:
        proc.terminate()
    ok = all(r[1] for r in E.RESULTS)
    print(f"\nLoad: {sum(r[1] for r in E.RESULTS)}/{len(E.RESULTS)} PASS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
