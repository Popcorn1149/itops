# IT Ops Workspace – bản v2

Bản tách riêng khỏi bản đang chạy (`Documents\itops`) để làm cấu trúc mới. Tách từ code ngày 07/11/2026, quản lý bằng **Git** (`git log` để xem từng bước).

| Commit | Nội dung |
|---|---|
| 1 | Bản nền: cổng 8100, dữ liệu riêng, mật khẩu admin trong `.env.local` |
| 2 | Alembic – quản lý thay đổi CSDL, tự nâng cấp CSDL bản v1 |
| 3–4 | Bảo mật P1 (backend) |
| 5 | Giao diện bảo mật P1 + E2E |
| 6 | Tài liệu: `SECURITY.md`, `DECISIONS/` |
| 7–8 | Dữ liệu mẫu có log/cảnh báo như thật; sửa lỗi tách tên user trong log đăng nhập sai |
| 9 | Công cụ mô phỏng thiết bị (gói tin thật); vá lỗ hổng trap vượt bộ lọc IP qua agentAddress |

Chi tiết cơ chế bảo mật: **`SECURITY.md`**. Lý do các quyết định: **`DECISIONS/`**.

## Khác với bản đang chạy
| Hạng mục | Bản đang chạy (`itops`) | Bản v2 |
|---|---|---|
| Cổng web | 8000 | **8100** (HTTPS: **8443**) |
| Log/trap (dữ liệu mẫu) | 5514 / 5162 | **6514 / 6162**, chỉ nhận từ 127.0.0.1 |
| Thư mục dữ liệu | `backend/data-dev`, `data-local` | **`backend/data-v2-dev`, `data-v2-local`** |
| Mật khẩu admin ban đầu | `admin12345` ghi trong `launch.json` | Sinh ngẫu nhiên vào `.env.local` |
| Đăng nhập | JWT trong localStorage, nhận cả `?token=` | **Cookie HttpOnly**, phiên phía server, tự đăng xuất sau 30 phút không thao tác |
| 2FA | Không có | **Bắt buộc với admin** (TOTP) |
| Khoá | 1 khoá vừa ký phiên vừa mã hoá | **Tách 2 khoá**, mã hoá **AES-256-GCM** |
| Audit | Ai / làm gì / khi nào | **5W1H** (thêm IP, trình duyệt, trước→sau, lý do), **không sửa/xoá được** |
| Lệnh SSH tuỳ chỉnh | Chạy được lệnh bất kỳ | **Khoá mặc định** |
| Nâng cấp CSDL | `auto_migrate` (chỉ thêm cột) | **Alembic** |
| Sao lưu | Không có | **Tự động mỗi ngày** (CSDL + 2 khoá + archive) |

## Chạy lần đầu (máy Windows)
1. Cài **Python** và **VS Code** (khi cài Python tick "Add python.exe to PATH").
2. Giải nén, bấm đúp **`CAI-DAT.bat`** → cuối cùng in ra tài khoản admin, **lưu lại**.
3. VS Code → Ctrl+Shift+D → **▶ Chạy IT Ops (dữ liệu mẫu)** → F5 → `http://127.0.0.1:8100`.
4. Chuẩn bị **Google Authenticator** hoặc **Microsoft Authenticator** trên điện thoại – lần đăng nhập đầu admin phải bật 2FA.

## Hướng dẫn test nhanh (khoảng 15 phút)
| # | Làm | Kết quả đúng |
|---|---|---|
| 1 | Đăng nhập admin bằng mật khẩu trong `.env.local` | Màn hình **"Bật xác thực 2 lớp"**, chưa vào được menu |
| 2 | Bấm **Tạo mã QR** → quét bằng điện thoại → nhập mã 6 số | Vào thẳng Bảng điều khiển |
| 3 | Thử nhập sai mã ở bước 2 | Báo "Mã không đúng" |
| 4 | Avatar → **Đăng xuất** → đăng nhập lại | Sau mật khẩu có bước **"Xác thực 2 lớp"** |
| 5 | Nhập lại đúng mã vừa dùng (trong cùng 30 giây) | Bị từ chối – mã chỉ dùng 1 lần; đợi mã mới |
| 6 | F12 → Application → Local Storage / Cookies | Local Storage **trống**; cookie `itops_session` có dấu ✓ ở cột **HttpOnly** |
| 7 | Avatar → **Mật khẩu · 2FA · Phiên** | Thấy 2FA "Đang bật", danh sách phiên có "Phiên này" |
| 8 | Mở trình duyệt khác (hoặc ẩn danh) đăng nhập cùng tài khoản → quay lại trình duyệt 1 → **Thu hồi** phiên kia | Trình duyệt kia bị đăng xuất ở thao tác kế tiếp |
| 9 | **Sites** → sửa tên một site → xoá một site, gõ lý do ở ô **"Lý do"** | – |
| 10 | **Audit log** | Thấy IP, tên cũ → tên mới (gạch ngang → in đậm), dòng "Lý do: …" |
| 11 | **Cài đặt → Người dùng** → thêm user *chỉ xem*, đăng nhập user đó | Không bị bắt bật 2FA; tự bật được ở "Tài khoản của tôi" |
| 12 | Admin → Người dùng → **Đặt lại 2FA** của user ở bước 11 | User đó bị đăng xuất; đăng nhập lại không cần mã |
| 13 | **Giám sát → Thêm check → SSH**, điền ô "Lệnh tuỳ chỉnh" → Lưu | Báo lỗi "đang bị khoá (… chỉ để đọc)" |
| 14 | Để yên trình duyệt **> 30 phút**, rồi bấm sang trang khác | Về màn hình đăng nhập với thông báo "hết hạn do không thao tác" |
| 15 | Task VS Code **7. Sao lưu dữ liệu** | File `.zip` trong `backend/data-v2-dev/backups`, có `itops.db`, `.secret_key`, `.enc_key` |
| 16 | Task **8. Tạo chứng chỉ HTTPS** → cấu hình **▶ Chạy IT Ops (HTTPS)** → `https://127.0.0.1:8443` | Trình duyệt cảnh báo chứng chỉ tự ký (bình thường) → Advanced → Proceed → đăng nhập được |
| 17 | Mất điện thoại: dừng app → task **9. Đặt lại 2FA của admin** → chạy lại | Admin đăng nhập lại phải bật 2FA mới |

Muốn thử nhanh bước 14: đặt `"SESSION_IDLE_MINUTES": "2"` trong `env` của cấu hình chạy (`.vscode/launch.json`).

## Dữ liệu mẫu có log "như thật"
Cấu hình **▶ Chạy IT Ops (dữ liệu mẫu)** giờ có sẵn log và cảnh báo để test mà không cần thiết bị:
- **24 giờ lịch sử** (~3.500 log của 20 thiết bị mẫu: pfSense, switch Cisco/Aruba/TP-Link, ESXi, Proxmox, Synology, UPS, AP, Linux, Windows, camera) – tạo **một lần** khi tạo dữ liệu mẫu.
- **Sự cố đã qua và tự đóng**: WAN mất 4–5 phút, cổng switch down/up, ESXi mất datastore, UPS chạy pin, trap linkDown/linkUp.
- **Sự cố còn mở cần xử lý**: RAID NAS-HN degraded, thêm user vào nhóm Administrators trên DC01, tạo tài khoản lạ trên FILE-SRV, cổng switch down chưa lên lại, dò mật khẩu webGUI pfSense từ IP ngoài (đang diễn ra).
- **Sự cố tự đóng theo rule** (không lặp lại sau 30–60 phút): dò mật khẩu cũ, IP tĩnh bị đổi MAC (UC-10 – dữ liệu mẫu đã bật sẵn rule này), AP khởi động lại.
- **Log trực tiếp**: khi app chạy, cứ 8–25 giây có log mới; mỗi 4–12 phút phát sinh một sự cố rồi tự phục hồi sau vài phút.
- Log mẫu đi qua **đúng đường xử lý của log thật** (phân tích syslog → rule → mở/đóng cảnh báo) nên test được cả rule, gom cảnh báo, SLA, bản tin sáng.

| Biến (trong `env` của `.vscode/launch.json`) | Mặc định | Ý nghĩa |
|---|---|---|
| `DEMO_LOGS` | `1` | `0` = tắt log mẫu (cả lịch sử và trực tiếp) |
| `DEMO_INCIDENT_EVERY` | `240,720` | Khoảng cách giữa 2 sự cố (giây). VD `60,120` để có sự cố mỗi 1–2 phút |

Lịch sử chỉ tạo khi **dữ liệu mẫu còn trống** → đã chạy bản trước thì chạy task **6. Xoá dữ liệu chạy thử** rồi F5 (phải bật 2FA lại vì là dữ liệu mới).

## Kiểm tra nhận Syslog / SNMP Trap bằng gói tin thật
`backend/tools/mo_phong_thiet_bi.py` giả làm thiết bị, gửi **gói tin mạng thật** (khác log mẫu – log mẫu đưa thẳng vào app):
syslog UDP (RFC 3164 + 5424), syslog TCP (xuống dòng + octet-counting), trap v2c, trap v3 authPriv, kèm log/trap phục hồi.
- Ngay trên máy chạy v2 (cấu hình dữ liệu mẫu): task VS Code **10. Mô phỏng thiết bị…**
- Từ **máy khác trong LAN** (giống thiết bị thật – cấu hình ▶ Thiết bị thật + `MO-TUONG-LUA.bat`):
  `python tools/mo_phong_thiet_bi.py --host <IP-máy-chạy-v2>`
- Trap v3: khai user ở **Cài đặt → Nhận Syslog/Trap** (SHA/AES, Engine ID `8000000001020304`) rồi thêm `--v3-user … --v3-auth … --v3-priv …`.
- Kết quả đúng: **Log thiết bị** có log gắn vào pfSense-HQ, SW-TANG3, ESXi-02, NAS-HN, UPS-RACK, SW-CORE, AP-HN, ERP-APP; **Cảnh báo** mở rồi tự đóng sau ~3 giây (WAN, cổng switch, datastore, UPS); còn mở: RAID NAS-HN, dò mật khẩu pfSense, AP khởi động lại.
- Không thấy log: xem **Log thiết bị → Nguồn lạ** (IP bị chặn hiện ở đó) và **Cài đặt → Nhận Syslog/Trap → Nguồn được phép**.

## Dùng lại dữ liệu thật của bản đang chạy (tuỳ chọn)
Bản v2 **tự nâng cấp** CSDL bản cũ (đã thử: 3 site / 35 tài sản / 26 check / audit cũ còn nguyên; mật khẩu thiết bị và token Telegram được mã hoá lại và giải mã đúng).
1. **Dừng** bản đang chạy (để CSDL không đang ghi).
2. Chép `itops.db` **và** `.secret_key` từ `itops\backend\data-local` sang `itops-v2\backend\data-v2-local` (thiếu `.secret_key` thì mật khẩu thiết bị cũ không giải mã được).
3. Chạy v2 bằng cấu hình **▶ Thiết bị thật** → đăng nhập bằng mật khẩu admin **cũ** → bật 2FA.
Nâng cấp là **một chiều**: CSDL đã mở bằng v2 không dùng lại cho bản cũ được – luôn làm trên **bản chép**.

## Chạy test
```
cd backend
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --ignore=tests/test_real_agents.py --ignore=tests/load_test.py
.venv\Scripts\python.exe -m playwright install chromium
.venv\Scripts\python.exe tests\e2e_security.py
```

## Kết quả kiểm tra trước khi đóng gói (Linux, Python 3.13, Chrome)
- pytest: **184 đạt**, 3 lỗi do môi trường thử không có lệnh `ping` (Windows có sẵn).
- E2E giao diện cũ: **76/78** (2 bước cần `ping`). E2E bảo mật mới: **22/22**.
- Cài sạch từ `requirements-dev.txt` trên môi trường mới: chạy được.
- Nâng cấp CSDL thật từ code bản v1: đạt.
- Ruff / ESLint: không có lỗi mới (còn 5 / 2 cảnh báo có sẵn từ bản gốc).

## Sau khi `git clone`
`backend/static` (giao diện đã build) không nằm trong Git → chạy task **2** rồi **3** (cần Node.js) để build. File zip đã có sẵn bản build.
