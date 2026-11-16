"""E2E luồng bảo mật P1 (bắt buộc 2FA cho admin) bằng trình duyệt thật.
Chạy:  python tests/e2e_security.py        (cần đã build frontend ando backend/static)
       E2E_CHANNEL=chrome python tests/e2e_security.py   (dùng Chrome cài sẵn thay cho Chromium of Playwright)
Ảnh chụp lưu ở thư items E2E_SHOTS (mặc định: thư items tạm)."""
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from playwright.sync_api import sync_playwright  # noqa: E402

from tests import e2e_ui as E  # noqa: E402

SHOTS = os.environ.get("E2E_SHOTS") or tempfile.mkdtemp(prefix="itops-shots-")
os.makedirs(SHOTS, exist_ok=True)


def totp(secret, ahead=0):
    # app.security nạp app.db (cần cấu hình CSDL) → trỏ ando CSDL of server E2E đang chạy
    os.environ.setdefault("DATABASE_URL", E.E2E_DB_URL.replace("postgresql://", "postgresql+psycopg://"))
    os.environ.pop("PG_LOCAL", None)
    from app.security import totp_now   # cùng thuật toán RFC 6238 với server
    return totp_now(secret, time.time() + ahead)


def main():
    os.environ["E2E_REQUIRE_2FA"] = "1"
    proc, data_dir = E.start_server(demo=True)
    errors = []
    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch(channel=os.environ.get("E2E_CHANNEL") or None)
            ctx = b.new_context(viewport={"width": 1440, "height": 950})
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            page.on("console", lambda m: m.type == "error" and errors.append(f"console: {m.text}"))

            print("[1] Admin none 2FA bị buộc bật trước khi ando hệ thống")
            E.login_form = None
            page.goto(E.BASE + "/")
            page.fill("input[autocomplete=username]", "admin")
            page.fill("input[type=password]", "Admin@12345")
            page.click("button.primary")
            page.wait_for_selector("h2:has-text('Enable two-factor authentication')", timeout=5000)
            E.check("Hiện màn hình bắt buộc bật 2FA", page.locator(".topbar").count() == 0)
            E.check("Không có token trong localStorage", page.evaluate("Object.keys(localStorage).length") == 0)
            E.check("Cookie sessions HttpOnly, chỉ thấy cookie gợi ý", page.evaluate("document.cookie") == "itops_auth=1")
            page.click("button:has-text('Tạo mã QR')")
            page.wait_for_selector("img[alt='Mã QR 2FA']")
            secret = page.inner_text("code.mono").replace(" ", "")
            E.check("Có mã QR and khoá nhập tay", len(secret) >= 16)
            page.screenshot(path=os.path.join(SHOTS, "1-bat-2fa.png"))
            page.fill("input[autocomplete=one-time-code]", "000000")
            page.click("button:has-text('Xác nhận and bật 2FA')")
            page.wait_for_selector(".alert-box.fail")
            E.check("Mã sai bị từ chối", "không đúng" in page.inner_text(".alert-box.fail"))
            page.fill("input[autocomplete=one-time-code]", totp(secret))
            page.click("button:has-text('Xác nhận and bật 2FA')")
            page.wait_for_selector("h1:has-text('Bảng điều khiển')", timeout=5000)
            E.check("Bật 2FA xong ando thẳng bảng điều khiển", True)

            print("[2] Đăng xuất → sign-in lại cần mã 6 số")
            page.click(".avatar"); page.click("text=Đăng xuất")
            page.wait_for_selector("h2:has-text('Đăng nhập')")
            page.fill("input[autocomplete=username]", "admin")
            page.fill("input[type=password]", "Admin@12345")
            page.click("button.primary")
            page.wait_for_selector("h2:has-text('Xác thực 2 lớp')")
            E.check("Mật khẩu đúng → chuyển sang step nhập mã", True)
            page.screenshot(path=os.path.join(SHOTS, "2-dang-nhap-otp.png"))
            page.fill("input[autocomplete=one-time-code]", "123456")
            page.click("button:has-text('Xác nhận')")
            page.wait_for_selector(".alert-box.fail")
            E.check("Mã sai báo error, vẫn ở step nhập mã", page.locator("h2:has-text('Xác thực 2 lớp')").count() == 1)
            page.fill("input[autocomplete=one-time-code]", totp(secret, ahead=30))   # step kế tiếp: step hiện tại đã dùng khi bật
            page.click("button:has-text('Xác nhận')")
            page.wait_for_selector("h1:has-text('Bảng điều khiển')", timeout=5000)
            E.check("Mã đúng → ando hệ thống", True)
            errors.clear()     # 401 từ các step cố ý nhập sai là hợp lệ

            print("[3] Tài khoản of tôi: 2FA + sessions sign-in")
            page.goto(E.BASE + "/#/settings?tab=account")
            page.wait_for_selector("text=Xác thực 2 lớp (2FA)")
            E.check("Trạng thái 2FA: Đang bật", page.locator(".badge:has-text('Đang bật')").count() == 1)
            E.check("Admin không có nút tắt 2FA khi bắt buộc", page.locator("button:has-text('Disabled 2FA')").count() == 0)
            page.wait_for_selector("text=Phiên này")
            rows = page.locator(".card:has-text('Phiên sign-in đang hoạt động') tbody tr").count()
            E.check("Danh sách sessions có sessions hiện tại", rows >= 1)
            page.screenshot(path=os.path.join(SHOTS, "3-tai-khoan.png"), full_page=True)

            print("[4] Xoá có lý do → audit ghi đủ 5W1H")
            # gọi API bằng chính sessions of trình duyệt (cookie + header chống CSRF), giống giao diện
            rq = page.context.request
            W = {"X-Requested-With": "itops"}
            E.check("Ghi bằng cookie mà missing header CSRF bị chặn", rq.post(E.BASE + "/api/sites", data={"name": "x"}).status == 403)
            site = rq.post(E.BASE + "/api/sites", data={"name": "Chi nhánh thanh lý", "kind": "branch"}, headers=W).json()
            rq.put(E.BASE + f"/api/sites/{site['id']}", data={"name": "CN-THANH-LY"}, headers=W)
            u = rq.post(E.BASE + "/api/users", data={"username": "kythuat", "password": "Kythuat@123", "role": "viewer"}, headers=W).json()
            E.check("Tạo được người dùng thường (không bắt buộc 2FA)", u["require_2fa"] is False)
            page.goto(E.BASE + "/#/sites")
            page.wait_for_selector("text=CN-THANH-LY")
            card = page.locator(".card, tr").filter(has_text="CN-THANH-LY").last
            card.locator("button.danger, button:has(svg.lucide-trash-2)").first.click()
            page.wait_for_selector(".confirm-box")
            E.check("Hộp xác nhận xoá có ô Lý do", page.locator(".confirm-box input[placeholder*='VD']").count() == 1)
            page.fill(".confirm-box input[placeholder*='VD']", "Đóng chi nhánh theo phiếu CR-77")
            page.click(".confirm-box button.danger-solid")
            time.sleep(1)
            page.goto(E.BASE + "/#/audit")
            page.wait_for_selector("text=Lý do:")
            txt = page.inner_text("table")
            E.check("Audit hiện lý do xoá", "Đóng chi nhánh theo phiếu CR-77" in txt)
            E.check("Audit hiện trước → sau khi sửa", "Chi nhánh thanh lý" in txt and "CN-THANH-LY" in txt)
            E.check("Audit hiện IP nguồn", "127.0.0.1" in txt)
            page.screenshot(path=os.path.join(SHOTS, "4-audit.png"))

            print("[5] Không thao tác quá lâu → tự sign-out, có thông báo")
            import psycopg
            old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
            with psycopg.connect(E.db_url(data_dir), autocommit=True) as c:
                c.execute("update login_sessions set last_seen=%s where revoked_at is null", (old,))
            page.goto(E.BASE + "/#/sites")
            page.reload()
            page.wait_for_selector("h2:has-text('Đăng nhập')", timeout=8000)
            E.check("Về màn hình sign-in", True)
            E.check("Thông báo lý do bị sign-out", "không thao tác" in page.inner_text(".alert-box.warn"))
            page.screenshot(path=os.path.join(SHOTS, "5-het-phien.png"))
            errors.clear()      # 401 do hết sessions là đúng kịch bản
            b.close()
    finally:
        proc.terminate()
    E.check("Không có error JavaScript", not errors, "; ".join(errors[:3]))
    log = open(os.path.join(data_dir, "server.log")).read()
    E.check("Log server không có Traceback", "Traceback" not in log, log[-800:])
    ok = sum(1 for _, c, _ in E.RESULTS if c)
    print(f"\nE2E bảo mật: {ok}/{len(E.RESULTS)} PASS · ảnh: {SHOTS}")
    return 0 if ok == len(E.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
