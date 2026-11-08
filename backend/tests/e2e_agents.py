"""E2E trang Máy trạm (chạy trình duyệt thật): máy trạm mẫu + 1 agent Linux THẬT (file build từ agent/) gửi lên server.

    python tests/e2e_agents.py           (cần agent/dist/itops-agent-linux-amd64 – build bằng agent/scripts/build.sh)
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from playwright.sync_api import sync_playwright  # noqa: E402

from tests import e2e_ui as E  # noqa: E402

SHOTS = os.environ.get("E2E_SHOTS", "/tmp/e2e-agents")
AGENT = next((p for p in (os.path.join(os.path.dirname(__file__), "..", "..", "agent", "dist", "itops-agent-linux-amd64"),
                          os.path.join(os.path.dirname(__file__), "..", "agent_dist", "itops-agent-linux-amd64")) if os.path.exists(p)),
             "agent/dist/itops-agent-linux-amd64")


def api(path, token, body=None, method=None):
    req = urllib.request.Request(E.BASE + "/api" + path, method=method or ("POST" if body is not None else "GET"),
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"null")


def main():
    os.makedirs(SHOTS, exist_ok=True)
    proc, data_dir = E.start_server(demo=True, extra_env={"DEMO_AGENTS": "1"})
    errors = []
    agent_proc = None
    try:
        tok = json.loads(urllib.request.urlopen(urllib.request.Request(E.BASE + "/api/auth/login", data=json.dumps(
            {"username": "admin", "password": "Admin@12345"}).encode(), headers={"Content-Type": "application/json"})).read())["token"]
        # ---- agent Linux thật: đăng ký bằng token, gửi báo cáo lên server E2E
        if os.path.exists(AGENT):
            api("/agent-policy", tok, {"report_seconds": 30}, "PUT")
            et = api("/agent-tokens", tok, {"name": "E2E Linux", "days": 1, "max_uses": 1})["token"]
            adir = tempfile.mkdtemp(prefix="agent-e2e-")
            with open(os.path.join(adir, "agent.json"), "w") as f:
                json.dump({"server_url": E.BASE, "allow_http": True, "uid": "", "enroll_token": et}, f)
            agent_proc = subprocess.Popen([AGENT, "run"], env={**os.environ, "ITOPS_AGENT_DIR": adir},
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            real = None
            for _ in range(40):
                time.sleep(0.5)
                real = next((a for a in api("/agents", tok) if not a["hostname"].upper().startswith(("PC-", "LT-", "SRV-", "MBP-")) and a["hostname"] != "srv-web01"), None)
                if real and real.get("cpu") is not None:
                    break
            E.check("agent Linux thật đăng ký + gửi số liệu", real and real["status"] == "online" and real.get("cpu") is not None, str(real)[:200])
            E.check("agent thật: token đã bị xoá khỏi agent.json", "enroll_token" not in open(os.path.join(adir, "agent.json")).read())
        else:
            E.check("có file agent Linux để test", False, AGENT)

        with sync_playwright() as pw:
            b = pw.chromium.launch(channel=os.environ.get("E2E_CHANNEL") or None)
            page = b.new_page(viewport={"width": 1440, "height": 900})
            page.on("console", lambda m: m.type == "error" and errors.append(m.text))
            page.on("pageerror", lambda e: errors.append(str(e)))
            E.login(page)
            page.click(".nav-item:has-text('Máy trạm')")
            page.wait_for_selector("text=Danh sách máy")
            page.wait_for_selector("text=PC-KD03")
            rows = page.locator(".tbl tbody tr").count()
            E.check("danh sách có 12 máy mẫu (+ agent thật)", rows >= 12, f"{rows} dòng")
            E.check("thẻ thống kê: Defender tắt = 1", page.locator(".stat:has-text('Defender tắt') .stat-value").inner_text().strip() == "1")
            E.check("PC-LA hiện 'Defender TẮT'", page.locator("tr:has-text('PC-LA') >> text=Defender TẮT").count() == 1)
            E.check("SRV-FILE01 hiện phần mềm diệt virus khác", page.locator("tr:has-text('SRV-FILE01') >> text=Kaspersky").count() == 1)
            page.screenshot(path=f"{SHOTS}/1-danh-sach.png")
            # ---- chi tiết máy có mã độc
            page.click("tr:has-text('PC-KD03')")
            page.wait_for_selector(".drawer >> text=Tổng quan")
            E.check("chi tiết: người đang dùng", page.locator(".drawer >> text=CTY\\minh.lq").count() >= 1)
            E.check("chi tiết: cảnh báo đang mở 'Phát hiện mã độc'", page.locator(".drawer .alert-box >> text=Phát hiện mã độc").count() >= 1)
            page.wait_for_timeout(600)
            page.screenshot(path=f"{SHOTS}/2-chi-tiet.png")
            page.click(".drawer .tab:has-text('Sự kiện')")
            page.wait_for_selector(".drawer >> text=Chuyện gì")
            txt = page.locator(".drawer .drawer-body").inner_text()
            E.check("sự kiện mã độc dịch tiếng Việt", "Windows Defender PHÁT HIỆN mã độc" in txt and "Trojan:Win32/Wacatac.B!ml" in txt and "Nên làm gì" in txt)
            page.screenshot(path=f"{SHOTS}/3-su-kien.png")
            page.click(".drawer .tab:has-text('Phần mềm')")
            page.wait_for_selector(".drawer >> text=AnyDesk")
            E.check("phần mềm của máy", page.locator(".drawer td >> text=AnyDesk").count() >= 1)
            page.keyboard.press("Escape")
            # ---- sự kiện toàn bộ máy: dò mật khẩu gộp ×14, không có đăng nhập thành công
            page.click(".tab:has-text('Sự kiện')")
            page.wait_for_selector("text=Tài khoản bị khoá")
            body = page.locator(".main").inner_text()
            E.check("sự kiện toàn bộ: khoá tài khoản + thêm nhóm quản trị", "Tài khoản bị khoá" in body and "Thêm vào nhóm QUẢN TRỊ" in body)
            E.check("không có sự kiện đăng nhập thành công", "4624" not in body and "Đăng nhập thành công" not in body)
            page.screenshot(path=f"{SHOTS}/4-su-kien-tat-ca.png", full_page=True)
            # ---- tìm phần mềm
            page.click(".tab:has-text('Phần mềm')")
            page.fill("input[placeholder^='vd. AnyDesk']", "teamviewer")
            page.wait_for_selector("text=TeamViewer")
            page.click("tr:has-text('TeamViewer')")
            E.check("tìm phần mềm → ra máy PC-LA", page.locator(".chip:has-text('PC-LA')").count() == 1)
            # ---- cài đặt agent: tạo token, lệnh cài
            page.click(".tab:has-text('Cài đặt agent')")
            page.wait_for_selector("text=Token đăng ký")
            page.click("button:has-text('Tạo token')")
            page.fill(".modal input >> nth=0", "GPO thử nghiệm")
            page.click(".modal button:has-text('Tạo')")
            page.wait_for_selector("text=Token chỉ hiện MỘT lần")
            cmds = page.locator(".modal").inner_text()
            E.check("lệnh cài Windows/GPO/Linux/macOS có token", "install --server" in cmds and "install-windows.ps1" in cmds and "install-linux.sh" in cmds and "itk_" in cmds)
            E.check("cảnh báo khi server http://", "chỉ dùng để demo" in cmds)
            page.screenshot(path=f"{SHOTS}/5-token.png")
            page.click(".modal button:has-text('Đã lưu')")
            E.check("danh mục sự kiện trong chính sách", page.locator("text=Nhật ký bảo mật bị xoá").count() >= 1)
            # ---- giao diện tối
            page.evaluate("localStorage.setItem('itops_theme','dark')")
            page.goto(E.BASE + "/#/agents")
            page.reload()
            page.wait_for_selector("text=PC-KD03")
            E.check("giao diện tối áp dụng", page.evaluate("document.documentElement.dataset.theme") == "dark")
            page.click("tr:has-text('SRV-FILE01')")
            page.wait_for_timeout(800)
            page.screenshot(path=f"{SHOTS}/6-toi.png")
            # ---- cảnh báo agent xuất hiện ở trang Cảnh báo chung
            page.keyboard.press("Escape")
            page.click(".nav-item:has-text('Cảnh báo')")
            page.wait_for_selector("text=Nghi dò mật khẩu")
            E.check("cảnh báo agent ở trang Cảnh báo", page.locator("text=Nghi dò mật khẩu: SRV-DC01").count() >= 1)
            b.close()
        E.check("không lỗi JavaScript", not errors, "; ".join(errors[:3]))
    finally:
        if agent_proc:
            agent_proc.terminate()
        proc.terminate()
    ok = sum(1 for _, c, _ in E.RESULTS if c)
    for n, c, d in E.RESULTS:
        print(("PASS " if c else "FAIL ") + n + (f" – {d}" if d and not c else ""))
    print(f"E2E máy trạm: {ok}/{len(E.RESULTS)}")
    sys.exit(0 if ok == len(E.RESULTS) else 1)


if __name__ == "__main__":
    main()
