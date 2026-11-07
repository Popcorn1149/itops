import os
"""Kiểm tra bảo mật giao diện: XSS qua tên tài sản (VD hostname DHCP / tên VM do người khác đặt)."""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import e2e_ui as E  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

PAYLOAD = '<img src=x onerror="window.__xss=(window.__xss||0)+1">'


def main():
    proc, _ = E.start_server(demo=False)
    try:
        tok = E.api("POST", "/api/auth/login", {"username": "admin", "password": "Admin@12345"})["token"]
        site = E.api("POST", "/api/sites", {"name": "S" + PAYLOAD}, tok)
        fw = E.api("POST", "/api/assets", {"name": "FW" + PAYLOAD, "type": "firewall", "site_id": site["id"], "ip": PAYLOAD}, tok)
        E.api("POST", "/api/assets", {"name": "VM" + PAYLOAD, "type": "vm", "site_id": site["id"], "parent_id": fw["id"]}, tok)
        E.api("POST", "/api/critical", {"name": "C" + PAYLOAD, "asset_id": fw["id"]}, tok)
        E.api("POST", "/api/checks", {"name": "K" + PAYLOAD, "type": "tcp", "target": "127.0.0.1", "asset_id": fw["id"], "config": {"port": 1, "alert_after": 1}}, tok)
        time.sleep(2)
        with sync_playwright() as pw:
            b = pw.chromium.launch(channel=os.environ.get("E2E_CHANNEL") or None)
            page = b.new_page(viewport={"width": 1440, "height": 950})
            E.login(page)
            for path in ["dashboard", "sites", "assets", "critical", "checks", "alerts"]:
                page.goto(f"{E.BASE}/#/{path}")
                time.sleep(0.8)
            page.fill(".topbar .search input", "img")
            time.sleep(0.8)
            pages_xss = page.evaluate("window.__xss || 0")
            E.check("Bảng/danh sách/tìm kiếm không thực thi HTML trong tên", pages_xss == 0, f"{pages_xss} lần")

            hits = 0
            for view in ["Dạng cây", "Mindmap tỏa tròn", "Theo luồng"]:
                page.goto(f"{E.BASE}/#/map")
                page.wait_for_selector(".map-wrap canvas")
                page.click(f".tab:has-text('{view}')")
                time.sleep(1.5)
                box = page.locator(".map-wrap").bounding_box()
                for y in range(int(box["y"]) + 10, int(box["y"] + box["height"]), 14):
                    for x in range(int(box["x"]) + 10, int(box["x"] + box["width"]), 14):
                        page.mouse.move(x, y)
                        if page.locator("div[style*='z-index: 9999999']:visible").count():
                            hits += 1
                            break
                    if hits:
                        break
                time.sleep(0.5)
            n = page.evaluate("window.__xss || 0")
            E.check("Đã rê chuột trúng node và hiện tooltip", hits > 0)
            E.check("Tooltip bản đồ không thực thi HTML trong tên tài sản (XSS)", n == 0, f"payload chạy {n} lần")
            b.close()
    finally:
        proc.terminate()
    ok = all(r[1] for r in E.RESULTS)
    print(f"\nSecurity UI: {sum(r[1] for r in E.RESULTS)}/{len(E.RESULTS)} PASS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
