# ADR 0002 – Đợt bảo mật P1: phiên phía server, 2FA bắt buộc với admin, không tự xây kho mật khẩu

- **Ngày:** 2026-11-08
- **Trạng thái:** Đã áp dụng (bản v2). Chi tiết vận hành: `SECURITY.md`.

## Bối cảnh
Bản v1: JWT nằm trong localStorage (mã độc XSS đọc được), backend nhận token qua `?token=` (lộ qua log, lịch sử trình duyệt), không thu hồi được phiên, không có 2FA, cùng một khoá vừa ký phiên vừa mã hoá mật khẩu thiết bị, audit thiếu "ở đâu / như thế nào / tại sao" và sửa/xoá được trong CSDL, check SSH chạy được lệnh bất kỳ bằng tài khoản thiết bị.

## Quyết định
1. **Phiên phía server** (bảng `login_sessions`) + **cookie HttpOnly / SameSite=Strict** + header chống CSRF; bỏ `?token=`; tự hết hạn khi không thao tác; thu hồi được.
2. **TOTP 2FA**, **bắt buộc với admin**, bật/tắt bắt buộc chỉ qua biến môi trường. Tự cài đặt RFC 6238 bằng thư viện chuẩn (không thêm dependency); mã QR dùng `segno` (Python thuần, không phụ thuộc gì).
3. **Tách khoá**: `.secret_key` chỉ ký phiên, `.enc_key` chỉ mã hoá (AES-256-GCM). Dữ liệu cũ được mã hoá lại khi khởi động.
4. **Audit 5W1H** + trigger chặn UPDATE/DELETE.
5. **Khoá lệnh SSH tuỳ chỉnh** mặc định (`ALLOW_SSH_COMMAND`).
6. **Không xây kho mật khẩu hạ tầng** trong IT Ops.

## Vì sao không xây kho mật khẩu
Kho mật khẩu là "cửa" giá trị nhất của hạ tầng; tự viết nghĩa là tự chịu toàn bộ rủi ro mật mã, phân quyền, khôi phục. Vaultwarden / KeePass / Bitwarden đã được kiểm định rộng rãi. IT Ops chỉ giữ đúng những bí mật nó cần để **đọc** thiết bị, và không bao giờ hiển thị lại.

## Phương án đã cân nhắc
- *Giữ JWT trong localStorage, thêm CSP*: vẫn lộ token nếu có XSS – loại.
- *Bắt buộc 2FA chỉnh trong giao diện*: phiên admin bị chiếm có thể tắt – loại, chỉ cho chỉnh bằng biến môi trường.
- *Thư viện `pyotp`*: tiện nhưng thêm dependency cho ~30 dòng code đã có véc-tơ thử RFC – loại.

## Hệ quả
- Script/API vẫn dùng `Authorization: Bearer` (token chỉ trả về khi đăng nhập không kèm header web).
- Bộ đếm khoá đăng nhập vẫn trong RAM → chưa chạy nhiều instance được (P2).
- Mất `.enc_key` = mất khả năng giải mã mật khẩu thiết bị → sao lưu tự động gồm cả khoá; file sao lưu phải được bảo vệ.
