# SECURITY.md – IT Ops Workspace v2

Tài liệu này chỉ mô tả những gì **code đang làm và có test chứng minh** (tên test ghi trong ngoặc).
Mọi thay đổi về đăng nhập, phân quyền, mã hoá, audit phải cập nhật file này trong cùng commit.

Nguyên tắc: *thêm một tool là thêm một cửa – cửa đó phải chắc hơn những cửa nó trông coi.*

---

## 1. Tài khoản kết nối thiết bị: chỉ đọc

- Các collector (`backend/app/collectors/`) chỉ **đọc**: SNMP GET/WALK (không có SET), REST API dạng GET, SSH chạy bộ lệnh đo cố định.
- Các khối Automation (`automation/blocks.py`) chỉ tạo báo cáo/thông báo, không gửi lệnh tới thiết bị.
- **Lệnh SSH tuỳ chỉnh bị khoá mặc định**: lưu check có ô "Lệnh tuỳ chỉnh" → API trả 400; check cũ đã lưu lệnh → collector trả lỗi, không chạy.
  Chỉ mở khi đặt biến môi trường `ALLOW_SSH_COMMAND=1` (`test_ssh_custom_command_locked_by_default`).

Tạo tài khoản chỉ đọc cho từng loại thiết bị:

| Thiết bị | Cách cấp quyền chỉ đọc |
|---|---|
| Switch / firewall qua SNMP | Dùng **SNMPv3** (authPriv, SHA + AES) với view chỉ đọc; tránh v2c. Nếu buộc dùng v2c: community riêng (không dùng `public`), chỉ cho IP máy IT Ops |
| pfSense (REST API) | User riêng, chỉ gán quyền đọc các trang status/system cần thiết |
| ESXi / vCenter | Tạo user, gán role **Read-only** ở mức host / vCenter |
| Linux (SSH) | User thường, không sudo; đăng nhập bằng khoá SSH |
| Windows (SSH) | User thuộc nhóm **Event Log Readers** (đọc event) – không cần admin |

## 2. Đăng nhập và phiên

| Cơ chế | Chi tiết | Test |
|---|---|---|
| Mật khẩu | bcrypt; tối thiểu 8 ký tự | – |
| Phiên phía server | Bảng `login_sessions`; JWT chỉ mang mã phiên (`jti`), server kiểm tra phiên còn hiệu lực ở mỗi request | `test_logout_revokes_session` |
| Cookie | `itops_session`: **HttpOnly**, **SameSite=Strict**, **Secure** khi chạy HTTPS. Giao diện web **không** nhận và **không** lưu token (không dùng localStorage) | `test_web_login_uses_httponly_cookie_not_token`, E2E |
| Cookie gợi ý | `itops_auth=1` – không chứa bí mật, chỉ để giao diện biết có nên hỏi `/api/auth/me` | E2E |
| Chống CSRF | Request ghi dùng cookie phải có header `X-Requested-With: itops` | `test_web_login…`, E2E |
| Token qua URL | `?token=` **không còn được chấp nhận** | `test_token_in_query_string_rejected` |
| Hết hạn | Tối đa `TOKEN_HOURS` (12 giờ); **không thao tác** quá `SESSION_IDLE_MINUTES` (30 phút) → tự thu hồi. Request nền (tự làm mới số liệu, header `X-Background: 1`) không tính là thao tác | `test_idle_timeout_and_background_requests` |
| Thu hồi | Người dùng xem và thu hồi phiên của mình; admin xem/thu hồi phiên của mọi người. Đổi mật khẩu → thu hồi các phiên khác. Admin đặt lại mật khẩu / đổi quyền / xoá user → thu hồi mọi phiên của người đó | `test_sessions_list_and_revoke`, `test_password_change_revokes_other_sessions` |
| Khoá đăng nhập | 5 lần sai / 5 phút theo **IP + tài khoản**; 20 lần sai / 5 phút theo **IP** (chặn dò nhiều tài khoản). Bộ đếm nằm trong RAM – mất khi khởi động lại; chạy nhiều instance cần chuyển sang nơi lưu chung | `test_lockout_per_ip_across_usernames`, `test_login_lockout_after_5_failures` |
| Script / API | Đăng nhập không kèm header web vẫn nhận `token` trong JSON để dùng `Authorization: Bearer` | – |

## 3. Xác thực 2 lớp (2FA)

- TOTP chuẩn RFC 6238 (30 giây, 6 số, SHA-1) – dùng Google Authenticator, Microsoft Authenticator… Tự cài đặt bằng thư viện chuẩn, kiểm theo véc-tơ thử của RFC (`test_totp_rfc6238_vector`).
- **Bắt buộc với admin** khi `REQUIRE_2FA_ADMIN=1` (mặc định). Admin chưa bật → đăng nhập được nhưng **mọi API khác trả 403** cho tới khi bật xong (`test_admin_must_enroll_2fa`). Cài đặt này chỉ đổi được bằng biến môi trường, không đổi được từ giao diện (phiên bị chiếm quyền không tắt được).
- Chống dùng lại mã: mỗi mã chỉ dùng một lần (`totp_last_step`).
- Bí mật TOTP lưu đã mã hoá (AES-256-GCM), không bao giờ trả ra API sau khi bật (`test_2fa_setup_enable_login_and_replay`).
- Mất điện thoại: admin khác bấm **Đặt lại 2FA** (thu hồi mọi phiên của người đó), hoặc trên máy chủ: `python -m app.admin_tools reset-2fa <user>` (task VS Code số 9). Mọi lần đặt lại đều vào audit.

## 4. Mã hoá bí mật và khoá

| Khoá | File / biến | Dùng để | Mất thì sao |
|---|---|---|---|
| Khoá ký | `data/.secret_key` / `SECRET_KEY` | Ký phiên đăng nhập (JWT HS256) | Mọi người phải đăng nhập lại |
| Khoá mã hoá | `data/.enc_key` / `ENCRYPTION_KEY` (32 byte, base64) | Mã hoá mật khẩu, community, token thiết bị và bí mật TOTP bằng **AES-256-GCM** (tiền tố `enc2:`) | **Không giải mã lại được** – phải nhập lại mọi mật khẩu thiết bị |

- Hai khoá **tách riêng** (`test_signing_and_encryption_keys_are_separate`). Sửa 1 byte dữ liệu mã hoá → GCM phát hiện, trả rỗng.
- Dữ liệu từ bản v1 (`enc:`, Fernet) vẫn đọc được và được **mã hoá lại sang `enc2:` khi khởi động** (`test_legacy_fernet_values_reencrypted`). Cần giữ `.secret_key` cũ cho lần nâng cấp đầu.
- Giao diện và API **không bao giờ** trả bí mật đã lưu (hiện `••••••`); audit che bí mật trong phần trước/sau (`test_secrets_encrypted_and_masked`).

## 5. Nhật ký thao tác (audit) – 5W1H, chỉ ghi thêm

| | Cột | Nguồn |
|---|---|---|
| Ai | `user` | tài khoản đăng nhập (`cli` nếu chạy lệnh trên máy chủ) |
| Cái gì | `action`, `entity`, `entity_id`, `detail` | |
| Khi nào | `ts` (UTC) | |
| Ở đâu | `ip`, `user_agent` | request |
| Như thế nào | `changes` = `{before, after}` – chỉ các trường thực sự đổi, bí mật bị che | |
| Tại sao | `reason` | ô "Lý do" trong hộp xác nhận xoá, hoặc header `X-Audit-Reason` |

- **Chỉ ghi thêm**: trigger SQLite chặn mọi `UPDATE` / `DELETE` trên `audit_logs`, kể cả khi lỗi code hay bị chèn SQL (`test_audit_append_only`). Ứng dụng không có API sửa/xoá audit.
- Mỗi ngày audit + log + cảnh báo được xuất ra file nén có **chuỗi hash SHA-256** (`secmon.archive_day`) – sửa file cũ sẽ bị phát hiện khi kiểm chuỗi.
- Giới hạn: người có quyền ghi trực tiếp file CSDL vẫn có thể xoá trigger. Chuỗi hash của archive là lớp phát hiện cho trường hợp đó; cần cất bản sao archive ở nơi khác (NAS chỉ đọc).

## 6. Sao lưu

- Tự động mỗi ngày sau `BACKUP_HOUR` (mặc định 2 giờ sáng, giờ VN), giữ `BACKUP_KEEP` bản (mặc định 7) tại `BACKUP_DIR` (mặc định `data/backups`). Đặt `BACKUP_KEEP=0` để tắt.
- Thủ công: `python -m app.admin_tools backup [thư_mục]` (task VS Code số 7).
- Nội dung: `itops.db` (sao chụp nhất quán khi app đang chạy) + `.secret_key` + `.enc_key` + `archive/` + hướng dẫn khôi phục (`test_backup_contains_db_and_keys_and_restores`).
- ⚠️ File sao lưu chứa **khoá giải mã** → cất ở nơi chỉ admin truy cập; nên đặt `BACKUP_DIR` sang NAS/ổ khác (cùng ổ với CSDL thì hỏng ổ là mất cả hai).

## 7. HTTPS

- Chứng chỉ tự ký cho mạng nội bộ: `python -m app.admin_tools gen-cert localhost <IP> <tên-máy>` (task VS Code số 8) → `data/tls/`.
- Chạy: cấu hình VS Code **"▶ Chạy IT Ops (HTTPS, dữ liệu mẫu)"** (cổng 8443) – cookie tự bật cờ `Secure`.
- Trình duyệt cảnh báo chứng chỉ tự ký là bình thường. Khi chạy thật nên dùng chứng chỉ do CA nội bộ cấp hoặc đặt sau reverse proxy có TLS.

## 8. Dữ liệu ra ngoài

Không có tính năng gửi dữ liệu lên cloud. **Ngoại lệ**: nội dung cảnh báo / báo cáo gửi qua **Telegram, email, webhook** (do admin cấu hình) – có thể chứa tên máy, IP, nội dung log. Chưa có tuỳ chọn che thông tin trong tin nhắn (xem mục 10).

## 9. Biến môi trường liên quan bảo mật

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `REQUIRE_2FA_ADMIN` | `1` | Bắt buộc 2FA với admin |
| `SESSION_IDLE_MINUTES` | `30` | Tự đăng xuất khi không thao tác (0 = tắt) |
| `TOKEN_HOURS` | `12` | Thời hạn tối đa một phiên |
| `LOGIN_MAX_FAILS` / `LOGIN_MAX_FAILS_PER_IP` / `LOGIN_LOCK_SECONDS` | `5` / `20` / `300` | Khoá đăng nhập |
| `ALLOW_SSH_COMMAND` | `0` | Cho phép lệnh SSH tuỳ chỉnh |
| `COOKIE_SECURE` | `0` (tự bật khi HTTPS) | Ép cờ Secure cho cookie (khi chạy sau reverse proxy TLS) |
| `SECRET_KEY` / `ENCRYPTION_KEY` | sinh tự động trong `data/` | Khoá ký / khoá mã hoá |
| `BACKUP_DIR` / `BACKUP_KEEP` / `BACKUP_HOUR` | `data/backups` / `7` / `2` | Sao lưu tự động |

## 10. Chưa làm (đã biết, có chủ đích)

| Hạng mục | Ưu tiên | Ghi chú |
|---|---|---|
| Phân quyền nhiều vai trò (operator / NOC) | P2 | Hiện chỉ có admin và viewer |
| Che IP / hostname trong tin gửi Telegram / email / webhook | P2 | |
| Bộ đếm khoá đăng nhập dùng chung khi chạy nhiều instance | P2 | Hiện trong RAM |
| Trigger chỉ-ghi-thêm cho PostgreSQL | P3 | Hiện chỉ SQLite |
| Kho mật khẩu hạ tầng | **Không làm** | Dùng Vaultwarden / KeePass đã được kiểm định – tự xây là mở thêm cửa giá trị nhất (xem `DECISIONS/0002`) |

## Báo lỗi bảo mật

Gửi trực tiếp cho người phụ trách IT Ops, không đăng lên nhóm chat chung. Ghi rõ phiên bản (`git log -1`), cách tái hiện và ảnh hưởng.
