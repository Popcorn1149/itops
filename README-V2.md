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
| 10 | Giao diện Sáng/Tối/Theo hệ thống, ghim/bỏ ghim thanh bên; giữ lý do đăng xuất qua lần tải lại |
| 11 | **PostgreSQL** thay SQLite (tự chạy kèm khi demo), sao lưu/khôi phục mới, chuyển dữ liệu v1, ADR agent + chính sách event log |
| 12 | **Agent máy trạm** (Go, Windows/Linux/macOS) + trang **Máy trạm**: hiệu năng, Defender, dịch vụ, phần mềm, sự kiện đã lọc và dịch tiếng Việt, tự cập nhật có ký số |

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
| CSDL | SQLite (`itops.db`) | **PostgreSQL 17** – demo: tự tải + tự chạy kèm, chỉ nghe 127.0.0.1 (cổng 5433 / 5434) |
| Nâng cấp CSDL | `auto_migrate` (chỉ thêm cột) | **Alembic** |
| Sao lưu | Không có | **Tự động mỗi ngày** (CSDL + 2 khoá + archive), **khôi phục** bằng 1 lệnh |

## Chạy lần đầu (máy Windows)
1. Cài **Python** và **VS Code** (khi cài Python tick "Add python.exe to PATH").
2. Giải nén, bấm đúp **`CAI-DAT.bat`** (cần Internet: thư viện Python + PostgreSQL di động ~30 MB) → cuối cùng in ra tài khoản admin, **lưu lại**.
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
| 15 | Task VS Code **7. Sao lưu dữ liệu** | File `.zip` trong `backend/data-v2-dev/backups`, có thư mục `db/` (mỗi bảng 1 file), `.secret_key`, `.enc_key` |
| 15b | Sửa/xoá vài site → **Shift+F5** dừng app → task **13. Khôi phục…** → dán đường dẫn file `.zip` ở bước 15 → F5 | Dữ liệu quay về lúc sao lưu; Audit có dòng "restore" |
| 16 | Task **8. Tạo chứng chỉ HTTPS** → cấu hình **▶ Chạy IT Ops (HTTPS)** → `https://127.0.0.1:8443` | Trình duyệt cảnh báo chứng chỉ tự ký (bình thường) → Advanced → Proceed → đăng nhập được |
| 17 | Mất điện thoại: dừng app → task **9. Đặt lại 2FA của admin** → chạy lại | Admin đăng nhập lại phải bật 2FA mới |

Muốn thử nhanh bước 14: đặt `"SESSION_IDLE_MINUTES": "2"` trong `env` của cấu hình chạy (`.vscode/launch.json`).

## Giao diện Sáng / Tối, ghim thanh bên
- **Sáng / Tối / Theo hệ thống**: nút 3 biểu tượng ☀ ☾ 🖥 trên thanh trên (điện thoại: trong menu avatar; trang đăng nhập: góc phải). Mặc định *Theo hệ thống* – đổi theo Windows/macOS.
- Chế độ tối: nền than chì, thẻ xám đậm viền mảnh, màu nhấn xanh dương, nhãn trạng thái chữ sáng trên nền màu trong suốt; biểu đồ, bản đồ, thanh cuộn đổi theo. Ảnh xuất từ bản đồ dùng nền của giao diện đang chọn.
- **Ghim / bỏ ghim thanh bên**: nút ▣ góc trái trên thanh trên cùng. Bỏ ghim → chỉ còn cột icon; **rê chuột vào** thì mở đè lên nội dung, không xô lệch trang.
- Cả hai lựa chọn được nhớ trên trình duyệt (mỗi máy / mỗi trình duyệt riêng).

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

## CSDL PostgreSQL (khi chạy bằng VS Code)
- Không cần cài gì: lần đầu app tự tải PostgreSQL 17 "di động" vào `backend/tools/pgsql` (CAI-DAT.bat đã tải sẵn), tự tạo CSDL với **mật khẩu ngẫu nhiên** và tự khởi động.
- Dữ liệu mẫu: `backend/data-v2-dev/pgdata`, cổng **5433** · Thiết bị thật: `backend/data-v2-local/pgdata`, cổng **5434**. Chỉ nghe `127.0.0.1`.
- Tắt app (Shift+F5) **không** tắt PostgreSQL (lần F5 sau nhanh hơn). Tắt hẳn: task **11 / 12. PostgreSQL: dừng**. Task **6. Xoá dữ liệu chạy thử** tự dừng PostgreSQL trước khi xoá.
- Muốn xem bảng bằng DBeaver/pgAdmin: `python -m app.pg_local url` (cùng `DATA_DIR`, `PG_LOCAL=1`) in ra chuỗi kết nối – có mật khẩu, đừng chia sẻ màn hình lúc đó.
- Đã có PostgreSQL riêng: bỏ `PG_LOCAL`, đặt `DATABASE_URL=postgresql+psycopg://user:pass@host:5432/itops`.
- Lỗi "Cổng 5433 đang có chương trình khác dùng": đổi `PG_LOCAL_PORT` trong `.vscode/launch.json` (và trong tasks.json).

## Dùng lại dữ liệu thật của bản đang chạy (tuỳ chọn)
Bản v1 dùng SQLite → v2 **chuyển** sang PostgreSQL bằng lệnh có sẵn. File của v1 chỉ được **đọc**, không bị sửa.
1. **Dừng** bản đang chạy (để CSDL không đang ghi), chép `itops.db`, `.secret_key` (và `.enc_key` nếu có) từ `itops\backend\data-local` sang một thư mục tạm.
2. Ở v2: chạy **▶ Thiết bị thật** một lần cho PostgreSQL được tạo → Shift+F5.
3. Task **14. Chuyển dữ liệu bản v1 (SQLite)…** → dán đường dẫn `itops.db` ở bước 1. Lệnh **xoá dữ liệu v2 đang có trong cấu hình thiết bị thật**, chép dữ liệu + khoá, in số bản ghi từng bảng.
4. F5 **▶ Thiết bị thật** → lần khởi động này tự mã hoá lại mật khẩu thiết bị kiểu cũ sang AES-256-GCM → đăng nhập bằng mật khẩu admin **cũ** → bật 2FA.
Thiếu `.secret_key` của v1 thì mật khẩu thiết bị cũ không giải mã được (phải nhập lại). Phiên đăng nhập cũ không chuyển.

## Chạy thật trên máy chủ Linux (sau này)
`docker-compose.yml` đã có sẵn 2 dịch vụ: `db` (image `postgres:17-alpine` chính thức) và `itops` (host network để thấy đúng IP thiết bị gửi log). Docker Engine trên Linux miễn phí, không cần Docker Desktop.
`cp .env.example .env` → đặt `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `DEMO_DATA=false` → `docker compose up -d --build`. Chuyển dữ liệu từ máy demo: sao lưu ở máy demo → chép `.zip` lên máy chủ → `docker compose exec itops python -m app.admin_tools restore /data/<file>.zip --wipe`.
*(Phần Docker chưa chạy thử được trong môi trường đóng gói – sẽ kiểm khi dựng VM.)*

## Agent máy trạm
Trang **Máy trạm** (menu Vận hành). Với dữ liệu mẫu có sẵn 12 máy mẫu (Windows, Linux, macOS) kèm sự cố "như thật": dò mật khẩu RDP vào DC, khoá tài khoản, thêm người vào nhóm Administrators, mã độc bị Defender chặn, Defender bị tắt, ổ gần đầy, tắt máy đột ngột, dịch vụ backup chết, lỗi ổ đĩa. Tắt máy mẫu: `DEMO_AGENTS=0`.

**Giả lập thêm máy Windows + macOS** (không cần quyền admin, không cài gì): Máy trạm → Cài đặt agent → **Tạo token** (tối đa ≥ 5 máy) → chạy task VS Code **17** và dán token. Sau ~10 giây có thêm SIM-SRV01, SIM-WIN02, SIM-WIN03, SIM-MAC01, SIM-MAC02 với dò mật khẩu, khoá tài khoản, thêm admin, mã độc, Defender tắt, ổ đầy, dò SSH vào Mac… Dữ liệu đi qua đúng code của agent thật (đọc XML Event Log, đọc log macOS, hàng đợi, gửi lên). Ctrl+C để dừng.

Thử agent THẬT trên chính máy demo (Windows):
1. Máy trạm → **Cài đặt agent** → **Tạo token** → chép lệnh "Windows".
2. Tải `itops-agent-windows-amd64.exe` ở cùng trang. Mở PowerShell **Run as administrator** trong thư mục tải về, dán lệnh (có `--allow-http` vì bản demo chạy http://).
3. Sau ~1 phút máy hiện trong danh sách. Kiểm tra: `& "C:\Program Files\ITOpsAgent\itops-agent.exe" status`. Xem thông tin thu được mà không gửi: `itops-agent.exe collect`.
4. Gỡ: `& "C:\Program Files\ITOpsAgent\itops-agent.exe" uninstall --purge`, rồi xoá máy trên giao diện.

Chi tiết cài GPO, HTTPS/`ca_pin` (có hoặc không có AD CS), tự cập nhật: **`agent/README.md`**. Thiết kế + danh sách Event ID: **`DECISIONS/0004`**.
Event log **chỉ lấy sự kiện cần xử lý**, **bỏ đăng nhập/đăng xuất thường ngày** và đăng nhập của dịch vụ/tài khoản máy; mỗi sự kiện hiện theo *Ai · Từ đâu · Chuyện gì · Nên làm gì*, lặp lại thì gộp (×số lần).

## Chạy test
Test tự dựng một PostgreSQL tạm (thư mục tạm, cổng ngẫu nhiên) rồi xoá – **không đụng** dữ liệu mẫu hay dữ liệu thật. Task VS Code **5** làm sẵn các bước dưới.
```
cd backend
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --ignore=tests/test_real_agents.py --ignore=tests/load_test.py
.venv\Scripts\python.exe -m playwright install chromium
.venv\Scripts\python.exe tests\e2e_security.py
.venv\Scripts\python.exe tests\e2e_agents.py     (cần agent Linux đã build – chỉ chạy được trên Linux)
```
Agent (Go ≥ 1.24, không cần Internet): `cd agent && go test ./... && ./scripts/build.sh 1.0.0`.
Đã có PostgreSQL dùng để test: đặt `TEST_DATABASE_URL=postgresql://user:pass@host:5432/postgres` (user có quyền CREATEDB) – mỗi lần chạy tạo một CSDL `itops_test_…` rồi xoá.

## Kết quả kiểm tra trước khi đóng gói (Linux, Python 3.13, PostgreSQL 17.11, Chrome)
- pytest trên PostgreSQL thật: **186 đạt**, 3 lỗi do môi trường thử không có lệnh `ping` (Windows có sẵn). Chế độ PostgreSQL tạm (giống task 5 trên Windows) đạt, không để lại tiến trình.
- E2E giao diện cũ: **76/78** (2 bước cần `ping`). E2E bảo mật: **22/22** (2 lần). XSS: đạt.
- App chạy với `PG_LOCAL=1` từ thư mục trống: tự tải PostgreSQL (khớp sha512) → initdb → migration 0001→0003 → dữ liệu mẫu 24 giờ (~3.500 log); simulator gửi syslog/trap thật được nhận và lưu.
- Sao lưu → khôi phục `--wipe` (3.713 bản ghi) đạt; bản sao lưu hỏng không làm mất dữ liệu đang có.
- Chuyển dữ liệu v1: mật khẩu thiết bị mã hoá kiểu v1 (Fernet) → chuyển → khởi động → mã hoá lại AES-256-GCM, giải mã đúng.
- **Chưa chạy thử trên Windows thật** (môi trường đóng gói là Linux): bộ PostgreSQL bản Windows đã kiểm mã băm và giải nén được; khởi động trên Windows sẽ kiểm ở máy 2. Docker Compose chưa chạy thử.
- Ruff / ESLint: không có lỗi mới (còn 5 / 2 cảnh báo có sẵn từ bản gốc).

## Sau khi `git clone`
`backend/static` (giao diện đã build) không nằm trong Git → chạy task **2** rồi **3** (cần Node.js) để build. File zip đã có sẵn bản build.
