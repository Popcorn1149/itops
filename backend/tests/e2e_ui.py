"""E2E giao diện bằng Playwright, chạy với server thật (uvicorn) + dữ liệu mẫu.

Chạy:  python3 tests/e2e_ui.py   (cần đã build frontend vào backend/static)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
RESULTS = []
E2E_DB_URL = ""   # đặt bởi start_server


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("  PASS " if cond else "  FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


def api(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"null")


class _Server:
    """Tiến trình uvicorn + CSDL PostgreSQL riêng cho lần chạy E2E; terminate() dừng app rồi dọn CSDL."""

    def __init__(self, proc, cleanup):
        self.proc, self._cleanup = proc, cleanup

    def __getattr__(self, k):
        return getattr(self.proc, k)

    def terminate(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._cleanup()


def _e2e_database(data_dir):
    """Giống tests/pgtest.py: TEST_DATABASE_URL → tạo CSDL riêng rồi xoá; không có → PostgreSQL kèm theo (PG_LOCAL) trong data_dir."""
    import secrets
    import socket as _so
    admin = os.environ.get("TEST_DATABASE_URL", "").strip().replace("postgresql+psycopg://", "postgresql://")
    if admin:
        import psycopg
        name = f"itops_e2e_{secrets.token_hex(4)}"
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{name}" ENCODING \'UTF8\' TEMPLATE template0')
        url = admin.rsplit("/", 1)[0].replace("postgresql://", "postgresql+psycopg://") + "/" + name

        def cleanup():
            with psycopg.connect(admin, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        return {"DATABASE_URL": url}, cleanup
    x = _so.socket(); x.bind(("127.0.0.1", 0)); port = x.getsockname()[1]; x.close()

    def cleanup():
        subprocess.run([sys.executable, "-m", "app.pg_local", "stop"], cwd=ROOT, env={**os.environ, "DATA_DIR": data_dir},
                       capture_output=True)
    return {"PG_LOCAL": "1", "PG_LOCAL_PORT": str(port)}, cleanup


def db_url(data_dir):
    """URL psycopg tới CSDL của server E2E đang chạy (dùng cho bước cần sửa dữ liệu trực tiếp)."""
    return E2E_DB_URL


def start_server(demo=True):
    d = tempfile.mkdtemp(prefix="itops-e2e-")
    dbenv, cleanup = _e2e_database(d)
    import socket as _so
    def _fp():
        x = _so.socket(); x.bind(("127.0.0.1", 0)); p_ = x.getsockname()[1]; x.close(); return p_
    globals()["RX_UDP"], globals()["RX_TRAP"] = _fp(), _fp()
    env = {**os.environ, "SYSLOG_UDP_PORT": str(RX_UDP), "SYSLOG_TCP_PORT": str(RX_UDP), "TRAP_PORT": str(RX_TRAP), "DATA_DIR": d, "DEMO_DATA": "true" if demo else "false", "ADMIN_PASSWORD": "Admin@12345", "LOG_LEVEL": "WARNING",
           "REQUIRE_2FA_ADMIN": os.environ.get("E2E_REQUIRE_2FA", "0"),
           "DEMO_LOGS": "0",   # E2E cần dữ liệu cố định: tắt bộ phát log mẫu
           **dbenv}
    if "DATABASE_URL" not in dbenv:
        env.pop("DATABASE_URL", None)
    log = open(os.path.join(d, "server.log"), "w")
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT)], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            urllib.request.urlopen(BASE + "/api/health")
            if "DATABASE_URL" in dbenv:
                url = dbenv["DATABASE_URL"]
            else:
                pw = open(os.path.join(d, ".pg_password"), encoding="utf-8").read().strip()
                url = f"postgresql://itops:{pw}@127.0.0.1:{dbenv['PG_LOCAL_PORT']}/itops"
            globals()["E2E_DB_URL"] = url.replace("postgresql+psycopg://", "postgresql://")
            return _Server(p, cleanup), d
        except Exception:
            if p.poll() is not None:
                break
            time.sleep(0.25)
    cleanup()
    raise RuntimeError("server không lên – xem " + os.path.join(d, "server.log"))


def login(page, user="admin", pw="Admin@12345"):
    page.goto(BASE + "/")
    page.fill("input[autocomplete=username]", user)
    page.fill("input[type=password]", pw)
    page.click("button.primary")
    page.wait_for_selector(".topbar", timeout=5000)


def main():
    proc, data_dir = start_server(demo=True)
    errors = []
    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch(channel=os.environ.get("E2E_CHANNEL") or None)
            ctx = b.new_context(viewport={"width": 1440, "height": 950}, accept_downloads=True)
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            page.on("console", lambda m: m.type == "error" and errors.append(f"console: {m.text}"))
            page.on("dialog", lambda d: d.accept("XOA" if d.type == "prompt" else None))

            print("[1] Đăng nhập")
            page.goto(BASE + "/")
            page.fill("input[autocomplete=username]", "admin")
            page.fill("input[type=password]", "sai-mat-khau")
            page.click("button.primary")
            page.wait_for_selector(".alert-box.fail")
            check("Sai mật khẩu hiện thông báo lỗi", "Sai tài khoản" in page.inner_text(".alert-box.fail"))
            login(page)
            page.wait_for_selector("h1:has-text('Bảng điều khiển')", timeout=5000)
            check("Đăng nhập thành công vào bảng điều khiển", True)
            errors.clear()  # 401 từ bước cố ý nhập sai mật khẩu là hợp lệ
            token = api("POST", "/api/auth/login", {"username": "admin", "password": "Admin@12345"})["token"]   # token cho gọi API trong test
            check("Giao diện không lưu token trong localStorage", page.evaluate("Object.keys(localStorage).filter(k => /token/i.test(k)).length") == 0)
            check("Cookie phiên là HttpOnly (JS không đọc được)", "itops_session" not in page.evaluate("document.cookie"))

            print("[2] Duyệt mọi trang")
            pages = {"dashboard": "Bảng điều khiển", "map": "Bản đồ hệ thống", "sites": "Sites", "assets": "Tất cả tài sản",
                     "assets?type=firewall": "Firewall", "assets?type=vm,container": "Máy ảo & container", "critical": "Hệ thống trọng yếu",
                     "checks": "Giám sát", "alerts": "Cảnh báo", "audit": "Audit log", "settings": "Cài đặt"}
            for path, title in pages.items():
                page.goto(f"{BASE}/#/{path}")
                page.wait_for_selector(f"h1:has-text('{title}')", timeout=5000)
                check(f"Trang {path} hiển thị", True)
            page.goto(BASE + "/#/assets?type=vm,container")
            page.wait_for_selector("table.tbl tbody tr")
            check("Lọc VM chỉ hiện VM/container", all(t in ("Máy ảo (VM)", "Container") or "tự đồng bộ" in t
                  for t in page.locator("table.tbl tbody tr td:nth-child(2) .cell-sub").all_inner_texts()))
            check("Menu bên trái tô sáng đúng mục", "Máy ảo & container" in page.inner_text(".nav-item.active"))

            print("[3] Tìm kiếm toàn cục")
            page.fill(".topbar .search input", "10.0.20.31")
            page.wait_for_selector(".search-item")
            page.click(".search-item >> nth=0")
            page.wait_for_selector(".drawer .modal-head:has-text('ERP-DB')", timeout=5000)
            check("Tìm theo IP mở đúng tài sản ERP-DB", "ERP-DB" in page.inner_text(".drawer .modal-head"))
            check("Drawer hiện đường dẫn pfSense-HQ › SW-CORE › ESXi-02", all(x in page.inner_text(".drawer-body") for x in ["pfSense-HQ", "SW-CORE", "ESXi-02"]))
            page.keyboard.press("Escape")

            print("[4] Thêm site → tài sản → check qua giao diện")
            page.goto(BASE + "/#/sites")
            page.click("button:has-text('Thêm site')")
            page.fill(".modal input >> nth=0", "Kho Bình Dương")
            page.select_option(".modal select", "branch")
            page.click(".modal button:has-text('Lưu')")
            page.wait_for_selector("h3:has-text('Kho Bình Dương')")
            check("Tạo site mới", True)
            page.goto(BASE + "/#/assets?type=firewall")
            page.click("button:has-text('Thêm tài sản')")
            m = page.locator(".modal")
            m.locator("input").nth(0).fill("pfSense-KHO")
            m.locator("select").nth(1).select_option(label="Kho Bình Dương")
            m.locator("input").nth(1).fill("127.0.0.1")
            m.locator("button:has-text('Lưu')").click()
            page.wait_for_selector("td:has-text('pfSense-KHO')")
            check("Tạo firewall mới, hiện trong danh sách Firewall", True)
            page.click("td:has-text('pfSense-KHO')")
            page.wait_for_selector(".drawer")
            page.click(".drawer button:has-text('Thêm check')")
            page.wait_for_selector(".modal:has-text('Thêm check giám sát')")
            md = page.locator(".modal")
            check("Form check được điền sẵn loại pfSense + IP", md.locator("select").first.input_value() == "pfsense" and md.locator("input").nth(1).input_value() == "127.0.0.1")
            md.locator("select").first.select_option("ping")
            md.locator("button:has-text('Chạy thử')").click()
            page.wait_for_selector(".modal .alert-box.ok, .modal .alert-box.fail", timeout=15000)
            check("Chạy thử ping 127.0.0.1 thành công", "Thành công" in page.inner_text(".modal .alert-box.ok") if page.is_visible(".modal .alert-box.ok") else False)
            md.locator("button:has-text('Lưu')").click()
            page.wait_for_selector(".toast:has-text('Đã lưu check')")
            time.sleep(2.5)
            fw = [a for a in api("GET", "/api/assets?type=firewall", token=token) if a["name"] == "pfSense-KHO"][0]
            check("Check mới chạy ngay và cập nhật status firewall = up", fw["status"] == "up", fw["status"])
            page.keyboard.press("Escape")

            print("[5] Form pfSense hiển thị đúng trường theo lựa chọn")
            page.goto(BASE + "/#/checks")
            page.click("button:has-text('Thêm check')")
            md = page.locator(".modal")
            md.locator("select").first.select_option("pfsense")
            check("pfSense/API: có ô API key + hướng dẫn cài REST API", md.locator("label:text-is('API key')").count() == 1 and "REST API" in md.inner_text())
            md.locator("label:has-text('Cách lấy dữ liệu') + select").select_option("snmp")
            check("pfSense/SNMP: hiện Community, ẩn API key", md.locator("label:has-text('Community')").count() == 1 and md.locator("label:text-is('API key')").count() == 0)
            md.locator("select").first.select_option("snmp")
            md.locator("label:has-text('Phiên bản SNMP') + select").select_option("3")
            check("SNMPv3: hiện user/auth/privacy", md.locator("label:has-text('SNMPv3 user')").count() == 1 and md.locator("label:has-text('Privacy password')").count() == 1)
            page.keyboard.press("Escape")

            print("[6] Mật khẩu thiết bị không lộ ra giao diện")
            page.click("button:has-text('Thêm check')")
            md = page.locator(".modal")
            md.locator("select").first.select_option("esxi")
            md.locator("input").nth(0).fill("ESXi lab")
            md.locator("input").nth(1).fill("10.9.9.9")
            md.locator("label:has-text('Mật khẩu') + input").fill("PassBiMat#1")
            md.locator("label:has-text('Đang bật') input").uncheck()
            md.locator("button:has-text('Lưu')").click()
            page.wait_for_selector(".toast:has-text('Đã lưu check')")
            page.click("td:has-text('ESXi lab')")
            page.wait_for_selector(".modal")
            pw_input = page.locator(".modal label:has-text('Mật khẩu') + input")
            check("Mật khẩu đã lưu hiện dạng ••••• (không trả về)", pw_input.input_value() == "" and "đã lưu" in pw_input.get_attribute("placeholder"))
            check("Không có mật khẩu trong HTML trang", "PassBiMat" not in page.content())
            page.keyboard.press("Escape")

            print("[7] Hệ thống trọng yếu")
            page.goto(BASE + "/#/critical")
            page.wait_for_selector("table.tbl tbody tr")
            before = page.locator(".tab:has-text('Chưa ghép') .n").inner_text()
            page.click("button:has-text('Tạo mới hệ thống')")
            md = page.locator(".modal")
            md.locator("input").nth(0).fill("Phần mềm HR")
            md.locator("button:has-text('Lưu')").click()
            page.wait_for_selector("td:has-text('Phần mềm HR')")
            after = page.locator(".tab:has-text('Chưa ghép') .n").inner_text()
            check("Hệ thống mới chưa gán máy → tăng bộ đếm 'Chưa ghép'", int(after) == int(before) + 1, f"{before}->{after}")
            page.click(".tab:has-text('Chưa backup')")
            check("Tab 'Chưa backup' lọc đúng", all("Chưa" in t for t in page.locator("table.tbl tbody tr td:nth-child(6)").all_inner_texts()))

            print("[8] Bản đồ: các chế độ xem + xuất ảnh")
            page.goto(BASE + "/#/map")
            page.wait_for_selector(".map-wrap canvas", timeout=8000)
            check("Mindmap tỏa tròn vẽ ra canvas", page.locator(".map-wrap canvas").count() >= 1)
            page.click(".tab:has-text('Dạng cây')"); time.sleep(0.8)
            check("Dạng cây vẽ ra canvas", page.locator(".map-wrap canvas").count() >= 1)
            page.click(".tab:has-text('Theo luồng')"); time.sleep(1.5)
            check("Theo luồng vẽ ra canvas", page.locator(".map-wrap canvas").count() >= 1)
            with page.expect_download() as dl:
                page.click("button:has-text('Xuất ảnh')")
            f = dl.value.path()
            check("Xuất ảnh PNG bản đồ", f and os.path.getsize(f) > 20000 and open(f, "rb").read(4) == b"\x89PNG")
            page.click(".tab:has-text('Điểm rủi ro')")
            page.wait_for_selector(".risk-item")
            check("Danh sách điểm rủi ro có dữ liệu", page.locator(".risk-item").count() >= 5)

            print("[9] Cảnh báo: nhận xử lý / đóng")
            time.sleep(3)  # chờ check mẫu chạy
            page.goto(BASE + "/#/alerts")
            page.wait_for_selector("table.tbl tbody tr")
            n0 = page.locator("table.tbl tbody tr").count()
            page.locator("table.tbl button:has-text('Nhận')").first.click()
            page.wait_for_selector(".toast:has-text('Đã xác nhận')")
            try:
                page.wait_for_selector("td .badge.info:has-text('admin')", timeout=8000)
            except Exception:
                pass
            check("Nhận xử lý cảnh báo → hiện người nhận", page.locator("td .badge.info:has-text('admin')").count() >= 1)
            page.locator("table.tbl button:has-text('Đóng')").first.click()
            page.wait_for_selector(".toast:has-text('Đã đóng')")
            time.sleep(0.5)
            check("Đóng cảnh báo → giảm 1 dòng", page.locator("table.tbl tbody tr").count() == n0 - 1 or n0 == 1)

            print("[9a] Tài nguyên CPU/RAM/Disk")
            page.goto(BASE + "/#/resources")
            page.wait_for_selector("h1:has-text('Tài nguyên CPU / RAM / Disk')")
            page.wait_for_selector("#res-uncovered")
            check("Trang Tài nguyên hiện thống kê CPU/RAM/Disk", page.locator(".stat:has-text('RAM cao')").count() == 1)
            nrow = page.locator("table.tbl tbody tr").count()
            check("Bảng tài nguyên có dữ liệu hoặc hướng dẫn", nrow >= 1 or page.locator("text=Chưa có số liệu tài nguyên").count() == 1)
            if nrow:
                page.locator("table.tbl tbody tr").first.click()
                page.wait_for_selector(".drawer .res-grid")
                check("Chi tiết thiết bị hiện CPU/RAM/Disk", page.locator(".drawer .res-cell").count() == 3)
                page.keyboard.press("Escape")

            print("[9a2] Tự động hoá")
            page.goto(BASE + "/#/automation")
            page.wait_for_selector("h1:has-text('Tự động hoá')")
            check("Thư viện có đủ 18 template theo 4 nhóm", page.locator(".auto-card").count() == 18)
            page.locator(".auto-card").filter(has_text="RPT-01").locator("button:has-text('Dùng template này')").click()
            page.wait_for_selector(".modal :text('Bản tin sáng')")
            page.click("button:has-text('Chạy thử (không gửi)')")
            page.wait_for_selector(".auto-out")
            check("Chạy thử RPT-01 ra bản tin", "Bản tin IT" in page.locator(".auto-out").inner_text())
            page.click(".modal button:has-text('YAML')")
            page.wait_for_function("document.querySelector('.modal textarea.mono') && document.querySelector('.modal textarea.mono').value.includes('id: RPT-01')")
            check("Chuyển sang YAML", True)
            page.click(".modal-foot button:has-text('Lưu'), .modal button.primary:has-text('Lưu')")
            page.wait_for_selector("text=Đã thêm kịch bản")
            check("Lưu kịch bản từ YAML", page.locator("td :text('Bản tin sáng')").count() >= 1)

            print("[9b] Log thiết bị (syslog/trap)")
            page.goto(BASE + "/#/logs")
            page.wait_for_selector("h1:has-text('Log thiết bị')")
            page.wait_for_selector(".chip.green >> nth=2", timeout=8000)
            check("Bộ nhận syslog/trap đang nghe", page.locator(".chip.green").count() == 3)
            page.click("button:has-text('Gửi thử syslog')")
            page.wait_for_selector(".toast:has-text('Đã nhận lại'), .toast.err", timeout=15000)
            check("Gửi thử syslog quay về", page.locator(".toast:has-text('Đã nhận lại')").count() >= 1, page.inner_text(".toast-wrap"))
            page.click("button:has-text('Gửi thử trap')")
            page.wait_for_selector(".toast:has-text('trap thử'), .toast.err", timeout=15000)
            check("Gửi thử trap quay về", page.locator(".toast:has-text('trap thử')").count() >= 1, page.inner_text(".toast-wrap"))
            time.sleep(1)
            check("Log thử hiện trong bảng", page.locator("td:has-text('Tin thử syslog')").count() >= 1)
            import socket as _so
            sk = _so.socket(_so.AF_INET, _so.SOCK_DGRAM)
            sk.sendto(b"<189>88: *Nov  2 21:10:09: %LINK-3-UPDOWN: Interface Gi1/0/48, changed state to down", ("127.0.0.1", RX_UDP))
            sk.close()
            time.sleep(6.5)
            check("Log mới tự hiện (live)", page.locator("td:has-text('Gi1/0/48')").count() == 1)
            page.locator("td:has-text('Gi1/0/48')").click()
            page.wait_for_selector(".modal:has-text('Nội dung')")
            page.click(".modal button:has-text('Tạo rule cảnh báo')")
            page.wait_for_selector(".modal:has-text('Tạo rule')")
            page.click(".modal button:has-text('Thử rule')")
            page.wait_for_selector(".modal .alert-box:has-text('khớp')")
            check("Tạo rule từ log: dòng mẫu khớp", "Dòng mẫu khớp" in page.inner_text(".modal").replace("\n", " ") or "khớp" in page.inner_text(".modal .alert-box"))
            page.keyboard.press("Escape")
            page.click(".tab:has-text('Rule cảnh báo')")
            page.wait_for_selector("td:has-text('Cổng switch down')")
            check("Danh sách rule mặc định", page.locator("table.tbl tbody tr").count() >= 10)
            page.click(".tab:has-text('Nguồn lạ')")
            page.wait_for_selector(".main :text('Không có nguồn lạ'), td:has-text('127.0.0.1')")
            check("Tab nguồn lạ: log 127.0.0.1 đã gắn vào firewall pfSense-KHO (tạo ở bước 4) nên không còn là nguồn lạ",
                  page.locator(".main :text('Không có nguồn lạ')").count() == 1)
            page.click(".tab:has-text('Hướng dẫn')")
            page.click("h3:has-text('VMware ESXi')")
            check("Hướng dẫn ESXi có lệnh esxcli", "esxcli system syslog" in page.inner_text(".main"))
            page.goto(BASE + "/#/alerts")
            page.wait_for_selector("td:has-text('Cổng switch down')")
            check("Cảnh báo từ log xuất hiện ở trang Cảnh báo", True)

            print("[9c] Máy ảo trên host ảo hoá")
            page.goto(BASE + "/#/assets?type=host,server")
            page.wait_for_selector("td:has-text('ESXi-01')")
            check("Danh sách host có cột Máy ảo / container", page.locator("th:has-text('Máy ảo / container')").count() == 1)
            page.click("td:has-text('PVE-01')")
            page.wait_for_selector("text=Máy ảo & container trên host")
            check("Host Proxmox hiện bảng máy ảo + LXC", page.locator(".drawer td:has-text('gitlab')").count() == 1 and page.locator(".drawer td:has-text('pihole')").count() == 1)
            check("Tóm tắt vCPU cấp phát so với core host", page.locator(".drawer :text('CPU đã chia cho VM')").count() >= 1)
            page.locator(".drawer .tab:has-text('Đã tắt')").click()
            time.sleep(0.3)
            check("Lọc máy đã tắt chỉ còn backup-test", page.locator(".drawer tbody tr").count() == 1 and page.locator(".drawer td:has-text('backup-test')").count() == 1)
            check("Không còn cột/tab Snapshot", page.locator(".drawer th:has-text('Snapshot')").count() == 0)
            page.screenshot(path="/tmp/guests.png", full_page=False)
            page.keyboard.press("Escape")

            print("[9b] Giám sát an ninh + log source")
            page.goto(BASE + "/#/settings")
            page.click(".tab:has-text('Nhận Syslog / Trap')")
            page.wait_for_selector("text=Nguồn đang gửi tới IT Ops")
            check("Bảng log source hiện IP đã gửi", page.locator("td:has-text('127.0.0.1')").count() >= 1)
            page.click(".tab:has-text('Giám sát an ninh')")
            page.wait_for_selector("text=Business hours và SLA xử lý")
            check("Tab Giám sát an ninh hiển thị 4 khối", all(page.locator(f"h3:has-text('{t}')").count() for t in
                  ["Business hours và SLA", "Cảnh báo thao tác của quản trị viên", "Log source im lặng", "Archive log và chuỗi hash"]))
            page.locator("button:has-text('Lưu ngay các ngày còn thiếu')").click()
            time.sleep(1)
            page.locator("button:has-text('Lưu cấu hình')").click()
            page.wait_for_selector("text=Đã lưu cấu hình giám sát an ninh")
            check("Lưu cấu hình giám sát an ninh", True)
            page.goto(BASE + "/#/alerts")
            page.wait_for_selector("text=thao tác admin", timeout=5000)
            check("Sửa cấu hình an ninh sinh cảnh báo thao tác admin", True)

            print("[10] Cài đặt + người dùng chỉ xem")
            page.goto(BASE + "/#/settings")
            page.click(".tab:has-text('Người dùng')")
            page.click("button:has-text('Thêm')")
            md = page.locator(".modal")
            md.locator("input").nth(0).fill("helpdesk")
            md.locator("input").nth(1).fill("Nhân viên Helpdesk")
            md.locator("input[type=password]").fill("Helpdesk@1")
            md.locator("button:has-text('Lưu')").click()
            page.wait_for_selector("td:has-text('helpdesk')")
            check("Tạo người dùng chỉ xem", True)
            v = b.new_context(viewport={"width": 1440, "height": 950}).new_page()
            v.on("pageerror", lambda e: errors.append(f"viewer pageerror: {e}"))
            login(v, "helpdesk", "Helpdesk@1")
            for path, btn in [("sites", "Thêm site"), ("critical", "Tạo mới hệ thống"), ("checks", "Thêm check"), ("assets", "Thêm tài sản")]:
                v.goto(f"{BASE}/#/{path}"); time.sleep(0.6)
                check(f"Viewer không thấy nút '{btn}'", v.locator(f"button:has-text('{btn}')").count() == 0)
            v.goto(BASE + "/#/settings"); time.sleep(0.5)
            check("Viewer chỉ có tab 'Tài khoản của tôi'", v.locator(".tab").count() == 1)

            print("[11] Đăng xuất")
            page.click(".avatar"); page.click("text=Đăng xuất")
            page.wait_for_selector("h2:has-text('Đăng nhập')")
            check("Đăng xuất: phiên bị vô hiệu ở server", page.context.request.get(BASE + "/api/auth/me").status == 401)
            check("Đăng xuất: xoá cookie gợi ý", "itops_auth=1" not in page.evaluate("document.cookie"))

            print("[12] Giao diện điện thoại")
            mob = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True).new_page()
            login(mob)
            for path in ["dashboard", "critical", "checks"]:
                mob.goto(f"{BASE}/#/{path}"); time.sleep(0.8)
                sw = mob.evaluate("document.querySelector('.main').scrollWidth - document.querySelector('.main').clientWidth")
                check(f"Mobile {path}: trang không tràn ngang (bảng được cuộn trong khung)", sw <= 2, f"tràn {sw}px")
            mob.click(".topbar .icon-btn")
            check("Mobile: nút menu mở thanh điều hướng", mob.is_visible(".sidebar"))
            mob.screenshot(path="/tmp/shots/e2e_mobile_menu.png")
            b.close()
        check("Không có lỗi JavaScript trong suốt phiên test", not errors, "; ".join(errors[:5]))
    finally:
        proc.terminate()
        log = open(os.path.join(data_dir, "server.log")).read()
        check("Log server không có Traceback", "Traceback" not in log, log[-800:])
        shutil.rmtree(data_dir, ignore_errors=True)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\nE2E: {passed}/{len(RESULTS)} PASS")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
