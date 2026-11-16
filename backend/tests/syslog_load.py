"""Tải syslog: 20 nguồn (IP 127.0.0.x) every nguồn ~150 log/giây trong 20 giây (~60.000 log); đo ghi nhận & độ trễ API."""
import os, socket, statistics, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_ui as E  # noqa: E402

SECONDS, SOURCES, RATE = 20, 20, 150


def main():
    proc, d = E.start_server(demo=False)
    try:
        tok = E.api("POST", "/api/auth/login", {"username": "admin", "password": "Admin@12345"})["token"]
        port = E.RX_UDP
        stop = time.time() + SECONDS
        sent = [0] * SOURCES

        def sender(i):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((f"127.0.0.{i + 2}", 0))
            n = 0
            while time.time() < stop:
                t = time.time()
                for _ in range(RATE // 10):
                    sev = 3 if n % 50 == 0 else 6
                    s.sendto(f"<{8 + sev}>Nov  2 21:00:00 dev{i} app: message {n} from device {i} interface Gi1/0/{n % 48}".encode(), ("127.0.0.1", port))
                    n += 1
                time.sleep(max(0, 0.1 - (time.time() - t)))
            sent[i] = n
        lat = []
        def poller():
            while time.time() < stop:
                for p in ["/api/events?limit=150", "/api/events/stats?hours=24", "/api/dashboard"]:
                    t = time.perf_counter()
                    urlreq = E.urllib.request.Request(E.BASE + p, headers={"Authorization": f"Bearer {tok}"})
                    E.urllib.request.urlopen(urlreq, timeout=30).read()
                    lat.append((time.perf_counter() - t) * 1000)
                time.sleep(0.3)
        th = [threading.Thread(target=sender, args=(i,)) for i in range(SOURCES)] + [threading.Thread(target=poller)]
        [t.start() for t in th]; [t.join() for t in th]
        time.sleep(3)
        st = E.api("GET", "/api/events/stats?hours=1", token=tok)
        total_sent = sum(sent)
        r = st["receiver"]
        lat.sort()
        rss = int(open(f"/proc/{proc.pid}/status").read().split("VmRSS:")[1].split()[0]) // 1024
        print(f"Đã gửi {total_sent:,} log trong {SECONDS}s (~{total_sent // SECONDS:,} log/s) từ {SOURCES} nguồn")
        print(f"Server nhận {r['received']:,} · lưu {r['stored']:,} · bỏ do flood {r['dropped_rate']:,} · bỏ do đầy hàng đợi {r['dropped_queue']:,}")
        print(f"API trong lúc tải: p50={statistics.median(lat):.0f} ms p95={lat[int(len(lat) * .95)]:.0f} ms max={lat[-1]:.0f} ms · RAM {rss} MB")
        loss = 1 - r["stored"] / max(1, total_sent)
        E.check("Ghi nhận ≥ 98% log (UDP cục bộ)", loss <= 0.02, f"mất {loss:.1%}")
        E.check("Không bỏ log do đầy hàng đợi", r["dropped_queue"] == 0)
        E.check("API p95 < 1.5s trong lúc tải", lat[int(len(lat) * .95)] < 1500)
        log = open(os.path.join(d, "server.log")).read()
        E.check("Không error/khóa DB", "Traceback" not in log and "database is locked" not in log, log[-500:])
    finally:
        proc.terminate()
    print(f"Syslog load: {sum(r[1] for r in E.RESULTS)}/{len(E.RESULTS)} PASS")


if __name__ == "__main__":
    main()
