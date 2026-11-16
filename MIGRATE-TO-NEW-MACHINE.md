# Chuyển IT Ops sang máy mới

Dành cho người tiếp quản hoặc khi đổi máy chạy IT Ops (máy Windows chạy VS Code). Làm **theo đúng thứ tự** – bỏ bước 2 hoặc 6
là mất dữ liệu hoặc thiết bị vẫn gửi về máy cũ. Chuyển lên **máy chủ Linux (Docker)**: xem mục cuối.

Thời gian: ~45 phút + thời gian sửa cấu hình thiết bị. Cần: quyền Administrator trên máy mới, tài khoản admin IT Ops (kèm 2FA),
quyền quản trị pfSense.

## ⚡ Cách nhanh (khuyên dùng)

**Máy A (đang chạy thật)**
1. VS Code **Shift+F5** (dừng IT Ops).
2. Nhấp đúp **`PREPARE-MIGRATION.bat`** → ra 1 file `Desktop\itops-migration-<ngày-giờ>.zip`.
   Script tự: sao lưu dữ liệu thật (CSDL + 2 khoá) → dừng PostgreSQL → tạo lại `MANIFEST.sha256` → đóng gói mã nguồn
   + mọi file không có trong Git (`static`, `agent_dist`, GoFlow2, PostgreSQL di động, `.env.local`).
   Không đóng gói `.venv` (gắn với Python máy A), `node_modules`, thư mục `data-*` (dữ liệu đi bằng bản sao lưu), `_backup\` (bản sao lưu file cũ, xem `_backup\README.md`).

**Chép file zip sang máy B** bằng USB / thư mục chỉ IT đọc được (zip **có khoá mã hoá dữ liệu**).

**Máy B** (không cần có sẵn Python, VS Code, Node.js, Git; cần Internet nếu phải cài Python/VS Code)
1. Giải nén zip (ra thư mục `itops-v2`, đặt đâu cũng được).
2. Nhấp đúp **`itops-v2\SETUP-NEW-MACHINE.bat`** (không cần *Run as administrator*). Script tự:
   cài Python 3.12 nếu thiếu → `SETUP.bat` (kiểm tra mã nguồn, `.venv`, thư viện) → khôi phục dữ liệu →
   hỏi quyền admin 1 lần để mở tường lửa → cài VS Code + extension Python nếu thiếu → mở VS Code ở thư mục này.
3. Trong VS Code: **Ctrl+Shift+D** → chọn **▶ Thiết bị thật (cổng 514/162)** → **F5**. Đăng nhập bằng tài khoản admin cũ + 2FA.

**Phần không tự động được** (nằm ngoài máy): trỏ pfSense / SNMP trap / agent về IP máy B (mục 7) – script in IP máy B
ở cuối. Đặt tên DNS cho IT Ops (vd. `itops.<domain>`) thì lần sau đổi máy chỉ sửa DNS, không phải sửa từng thiết bị.

Ghi chú:
- Máy A bản trước 16/11 chưa có các script này: chép 5 file sau vào đúng chỗ trong thư mục `itops-v2` của máy A rồi làm như trên:
  `PREPARE-MIGRATION.bat`, `SETUP-NEW-MACHINE.bat`, `SETUP.bat`, `backend\tools\migrate_machine.py`, `backend\tools\setup_new_machine.ps1`.
- Đã có mã nguồn trên máy B và file sao lưu riêng: `SETUP-NEW-MACHINE.bat "D:\duong-dan\itops-backup-<ngày-giờ>.zip"`.
- Chạy lại `SETUP-NEW-MACHINE.bat` an toàn: bản sao lưu đã khôi phục được đánh dấu `.restored` (không khôi phục đè lần 2);
  thư mục dữ liệu có sẵn được đổi tên `data-v2-local.old-<ngày-giờ>`, không bị xoá.
- Defender xoá file agent `.exe` khi giải nén → bước kiểm tra báo "MISSING files": Windows Security → Protection history →
  Restore, rồi chạy lại.

Các mục dưới đây là quy trình làm tay chi tiết – dùng khi script báo lỗi hoặc cần hiểu từng bước.

---

## 0. Tóm tắt

| Thứ | Có trong Git / file zip? | Làm gì |
|---|---|---|
| Mã nguồn, test, tài liệu (README, `DECISIONS/`, `docs/BACKLOG.md`, file `.md` này) | ✅ Có | `git clone` hoặc giải nén |
| Giao diện đã build `backend\static\` | ❌ **Không** (bị `.gitignore` bỏ) | Chép tay, hoặc build lại (bước 4) |
| Bộ thu flow `backend\tools\goflow2\goflow2-…-windows-amd64.exe` | ❌ Không | Chép tay, hoặc tải lại (bước 4) |
| File cài agent `backend\agent_dist\itops-agent-*` | ❌ Không | **Chép tay** – thiếu thì `SETUP.bat` báo "MISSING files" và dừng |
| `.env.local` (biến môi trường riêng, có thể chứa bí mật) | ❌ Không | Chép tay nếu máy cũ có |
| Python venv, PostgreSQL di động, `node_modules` | ❌ Không | `SETUP.bat` tạo lại |
| **Dữ liệu thật** (CSDL + 2 khoá `.enc_key`, `.secret_key`) | ❌ Không | **Sao lưu → khôi phục** (bước 2 và 5). KHÔNG chép thư mục `pgdata` |
| Rule tường lửa Windows | ❌ Theo máy | Chạy `OPEN-FIREWALL.bat` (bước 6) |
| Cấu hình thiết bị trỏ về IP máy cũ (pfSense syslog, softflowd, trap, agent) | — | Sửa sang IP máy mới (bước 7) |

> ⚠️ Chỉ **một** máy được chạy cấu hình *▶ Thiết bị thật* tại một thời điểm. Hai máy cùng chạy = tranh cổng 514/162/2055,
> cảnh báo Telegram gửi trùng, dữ liệu flow bị chia đôi.

---

## 1. Chuẩn bị máy mới
1. Cài **Python 3.12** (tick *Add python.exe to PATH*) và **VS Code**.
2. (Chỉ khi cần build lại giao diện) cài **Node.js 22 LTS**.
3. (Nên) cài **Git**.
4. Đặt **IP tĩnh** (hoặc DHCP reservation) cho máy mới – thiết bị và agent sẽ gửi về IP này. Tốt nhất tạo thêm tên DNS
   (vd. `itops.<domain>`) trỏ về máy mới để lần sau đổi máy không phải sửa thiết bị.

## 2. Trên máy CŨ: sao lưu và dừng
1. Commit mã nguồn (nếu có Git): `git add -A && git commit -m "truoc khi chuyen may"` rồi `git push`.
2. Tạo bản sao lưu **mới nhất** của dữ liệu thật (app đang chạy cũng được). PowerShell trong thư mục `itops-v2\backend`:
   ```powershell
   $env:DATA_DIR="$PWD\data-v2-local"; $env:PG_LOCAL="1"; $env:PG_LOCAL_PORT="5434"; $env:PYTHONUTF8="1"
   .\.venv\Scripts\python.exe -m app.admin_tools backup
   ```
   File tạo ra: `backend\data-v2-local\backups\itops-backup-<ngày-giờ>.zip` – **có cả 2 khoá mã hoá**: giữ cẩn thận
   (USB / thư mục chỉ IT đọc được), không gửi qua email/chat.
3. Chép sang máy mới (USB / thư mục chia sẻ):
   - file sao lưu `.zip` ở trên,
   - `backend\static\` (cả thư mục),
   - `backend\tools\goflow2\goflow2-2.2.7-windows-amd64.exe`,
   - `backend\agent_dist\` (cả thư mục),
   - `.env.local` (nếu có).
4. Dừng IT Ops trên máy cũ: VS Code **Shift+F5**, rồi task **12. PostgreSQL: dừng (thiết bị thật)**.
   Từ giờ **không** bấm F5 cấu hình *Thiết bị thật* trên máy cũ nữa (giữ máy cũ để quay lại nếu cần – xem mục 9).

## 3. Lấy mã nguồn về máy mới
- Có Git: `git clone <địa chỉ repo> itops-v2` (vd. vào `Documents\itops-v2`).
- Không Git: giải nén file zip phát hành **hoặc** chép cả thư mục `itops-v2` từ máy cũ **trừ** `backend\data-*`,
  `backend\.venv`, `frontend\node_modules`, `backend\tools\pgsql`.

## 4. Đặt lại các file không có trong Git
Chép các file ở bước 2.3 vào đúng chỗ trong `itops-v2`:

| File / thư mục | Đặt vào |
|---|---|
| `static\` | `itops-v2\backend\static\` |
| `goflow2-2.2.7-windows-amd64.exe` | `itops-v2\backend\tools\goflow2\` |
| `agent_dist\` | `itops-v2\backend\agent_dist\` |
| `.env.local` | `itops-v2\.env.local` |

Không có bản `static` / GoFlow2 cũ?
- Giao diện: VS Code → *Terminal → Run Task* → **2. Cài thư viện giao diện**, rồi **3. Build giao diện vào backend/static**.
- GoFlow2: tải `goflow2-2.2.7-windows-amd64.exe` từ <https://github.com/netsampler/goflow2/releases>, kiểm tra mã băm theo
  `backend\tools\goflow2\README.txt` (`Get-FileHash <file>`).

## 5. Cài đặt và khôi phục dữ liệu
1. Chạy **`SETUP.bat`** (nhấp đúp). Nó kiểm tra mã nguồn, chép cấu hình VS Code, tạo Python venv, cài thư viện,
   tải PostgreSQL di động. Báo "MISSING files" → quay lại bước 4.
2. Khôi phục bản sao lưu vào cấu hình *Thiết bị thật* (PowerShell trong `itops-v2\backend`, IT Ops **chưa** chạy):
   ```powershell
   $env:DATA_DIR="$PWD\data-v2-local"; $env:PG_LOCAL="1"; $env:PG_LOCAL_PORT="5434"; $env:PYTHONUTF8="1"
   .\.venv\Scripts\python.exe -m app.admin_tools restore "D:\duong-dan\itops-backup-<ngày-giờ>.zip" --wipe
   ```
   Lệnh tạo CSDL, nạp dữ liệu, chép 2 khoá + archive vào `data-v2-local` rồi nâng cấp CSDL lên bản mới nhất.
   Thiếu `.enc_key` → mật khẩu thiết bị đã lưu (SNMP, ESXi, pfSense, Wazuh, Telegram…) không đọc được, phải nhập lại.

## 6. Chạy lần đầu trên máy mới
1. Chuột phải **`OPEN-FIREWALL.bat` → Run as administrator** (mở 8100, 514, 162, 2055, 6343).
2. VS Code: `Ctrl+Shift+D` → **▶ Thiết bị thật (cổng 514/162)** → **F5**. Mở `http://127.0.0.1:8100`.
3. Đăng nhập bằng tài khoản admin **cũ** (dữ liệu đã khôi phục) + 2FA như trước.
4. Góc dưới menu trái hiện đúng phiên bản (vd. *Version 2.10.0*), chấm xanh *API online*.

## 7. Trỏ thiết bị về máy mới (thay `<IP mới>`)
| Ở đâu | Sửa gì |
|---|---|
| pfSense → *Status › System Logs › Settings › Remote Logging* | Remote log servers: `<IP mới>:514` |
| pfSense → *Services › softflowd* | Host: `<IP mới>`, Port `2055` (giữ nguyên các interface đã chọn) |
| Switch / UPS / thiết bị gửi SNMP trap | Trap host: `<IP mới>` (cổng 162) |
| Thiết bị giới hạn ai được hỏi SNMP (ACL / allowed hosts) | Thêm `<IP mới>` |
| Agent trên máy trạm | Agent cài với `--server http://<IP cũ>:8100` → **cài lại** với `<IP mới>` (hoặc tên DNS). Xem `agent/README.md` |
| Wazuh / hệ thống khác cho phép theo IP | Thêm `<IP mới>` nếu có giới hạn |
| Telegram / email / webhook | Không cần sửa (cấu hình nằm trong CSDL đã khôi phục) |

## 8. Kiểm tra sau khi chuyển (đánh dấu từng dòng)
- [ ] `http://127.0.0.1:8100/api/health` → `"ok": true`, `"db": true`, `"receivers_ok": true`, đúng `"version"`.
- [ ] *Monitoring*: các check chạy lại, trạng thái như trên máy cũ.
- [ ] *Device Logs*: có log mới từ pfSense (sau bước 7).
- [ ] *Network traffic → Settings*: Collector **running**, *Records* tăng dần; exporter pfSense hiện *last record* vài giây trước.
- [ ] *Endpoints*: agent đã cài lại báo về.
- [ ] *Settings → Notifications*: bấm *Send Test* → Telegram nhận được.
- [ ] Task **5. Chạy kiểm thử** → toàn bộ test *passed* (test dùng CSDL tạm, không đụng dữ liệu thật).
- [ ] Task **18. Kiểm tra mã nguồn** → "Source matches the release".
- [ ] Ngày hôm sau: có file sao lưu tự động mới trong `backend\data-v2-local\backups\` (nên chép ra ngoài máy định kỳ).

## Lỗi hay gặp khi cài trên máy mới
| Thông báo | Nguyên nhân | Cách sửa |
|---|---|---|
| `[0/5]` … **CHANGED files (differ from the release)** | File bị sửa sau khi giải nén, hoặc `MANIFEST.sha256` cũ hơn file (đóng gói xong lại sửa tiếp mà không chạy `tools_make_manifest.py`) | Đối chiếu file với máy cũ; nếu file đúng thì tạo lại manifest trên máy cũ (`python tools_make_manifest.py`) rồi đóng gói lại |
| `[0/5]` … **MISSING files** `backend/agent_dist/…` | Chép thiếu file không có trong Git | Dùng `PREPARE-MIGRATION.bat` (tự đóng gói), hoặc chép tay theo bước 4 |
| `did not find executable at 'C:\Users\<tên-máy-cũ>\…\python.exe'` | Chép cả `backend\.venv` từ máy cũ – venv trỏ tới Python của máy cũ | Bản `SETUP.bat` mới tự xoá và tạo lại. Bản cũ: đóng VS Code, xoá `backend\.venv`, chạy lại |
| `Could not delete backend\.venv` | VS Code / terminal đang dùng venv | Đóng VS Code và mọi cửa sổ terminal rồi chạy lại |
| `IT Ops is running (port 8100)` khi khôi phục | App đang chạy trên máy mới | Shift+F5 trong VS Code rồi chạy lại |

## 9. Nếu có sự cố – quay lại máy cũ
1. Máy mới: Shift+F5.
2. Máy cũ: F5 *Thiết bị thật* (dữ liệu trên máy cũ dừng ở lúc sao lưu bước 2).
3. Trả cấu hình thiết bị ở bước 7 về `<IP cũ>`.
Dữ liệu phát sinh trên máy mới trong lúc chạy thử sẽ **không** tự sang máy cũ – nếu cần, sao lưu máy mới rồi khôi phục vào máy cũ như bước 2 + 5.

## 10. Làm việc với Claude trên máy mới
- Lịch sử trao đổi nằm trong tài khoản Claude (claude.ai), mở được từ máy nào cũng được; không có gì của Claude lưu trong mã nguồn.
- Quyền đọc/ghi thư mục và trình duyệt tích hợp **cấp theo từng máy**: trên máy mới mở Claude desktop, mở lại cuộc trò chuyện,
  cấp quyền thư mục `itops-v2` khi được hỏi (đường dẫn có thể khác `C:\Users\<tên>\Documents\itops-v2`).
- Có repo Git (GitHub) thì Claude làm việc thẳng trên repo, không phụ thuộc máy.

## Chuyển lên máy chủ Linux (Docker) thay vì máy Windows
Các bước 2, 5 (dữ liệu), 7, 8 giống hệt. Khác:
- Mã nguồn: `git clone` lên server; `cp .env.example .env` → đặt `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `DEMO_DATA=false`.
- `docker compose up -d --build` (image tự có GoFlow2; `network_mode: host` giữ đúng IP nguồn của syslog/flow).
- Khôi phục: chép file `.zip` vào `./data/` rồi
  `docker compose exec itops python -m app.admin_tools restore /data/itops-backup-<ngày-giờ>.zip --wipe`.
- Tường lửa server: mở TCP 8080 (web, theo `.env`), UDP/TCP 514, UDP 162, UDP 2055.
- Trước khi `docker compose build`, chép `backend/agent_dist/` vào mã nguồn trên server (giống bước 4) để trang *Endpoints* có file cài agent.
- Đường Docker **chưa được chạy thử trên máy chủ thật**: chạy song song (máy Windows ở chế độ *Song song với v1* hoặc tắt nhận log) vài ngày rồi mới tắt máy Windows.

---
*Tạo 2026-11-13 (bản 2.10.0), thêm script chuyển máy 2026-11-16, đổi tên file sang tiếng Anh 2026-11-16. Cập nhật file này khi quy trình cài đặt / sao lưu thay đổi.*
