# Báo cáo QA/QC: IT Ops Workspace 1.0.0

**Ngày:** 31/10/2026
**Phạm vi:** code, tiến trình giám sát, luồng nghiệp vụ, giao diện, bảo mật, tải
**Môi trường:** Python 3.13, Chromium (Playwright), SQLite. Do chưa có thiết bị thật, **pfSense/OPNsense, ESXi/vCenter, Telegram và SMTP được giả lập**; kết quả giả lập được chấp nhận theo yêu cầu.

## 1. Kết quả tổng hợp

| Lớp kiểm thử | Số ca | Kết quả |
|---|---|---|
| Lint backend (ruff) + frontend (eslint, rules-of-hooks) | toàn bộ mã nguồn | ✅ Sạch |
| Unit/integration API (pytest) | 63 | ✅ 63/63 |
| E2E giao diện (Playwright, desktop + mobile) | 49 | ✅ 49/49 |
| Bảo mật giao diện (XSS) | 3 | ✅ 3/3 |
| Tải (1.000 tài sản, 300 check, 90 giây) | 8 | ✅ 8/8 |
| **Tổng** | **123** | **✅ 123/123** |

Chạy lại toàn bộ bằng một lệnh: `bash backend/tests/run_all.sh`

## 2. Lỗi phát hiện và đã sửa

| # | Mức | Lỗi | Ảnh hưởng | Cách sửa |
|---|---|---|---|---|
| 1 | 🔴 Nghiêm trọng | **Path traversal** ở route phục vụ giao diện: `GET /%2e%2e/app/security.py` trả về mã nguồn server | Đọc được file ngoài thư mục web, kể cả `data/.secret_key`, từ đó giả mạo đăng nhập và giải mã mật khẩu thiết bị | Chuẩn hoá đường dẫn bằng `realpath`, chỉ phục vụ file nằm trong thư mục static |
| 2 | 🔴 Nghiêm trọng | **XSS ở tooltip bản đồ**: tên tài sản chứa HTML bị thực thi khi rê chuột | Hostname DHCP (lấy từ pfSense) hoặc tên VM do người khác đặt có thể chạy mã trong phiên admin | Escape mọi dữ liệu đưa vào tooltip ECharts |
| 3 | 🟠 Cao | **Chỉ số live (CPU/RAM...) không cập nhật** từ lần chạy thứ 2 | Bản đồ và trang tài sản hiển thị số liệu cũ | `deepcopy` JSON trước khi sửa để SQLAlchemy nhận ra thay đổi |
| 4 | 🟠 Cao | **pfSense chưa cài REST API vẫn báo "OK"** (lỗi 404 bị bỏ qua) | Tưởng firewall đang được giám sát nhưng thực tế không có | Endpoint `/status/system` bắt buộc phải có; 404 báo rõ "chưa cài gói REST API?" |
| 5 | 🟠 Cao | **Không chống dò mật khẩu** | Có thể brute-force tài khoản admin | Khoá 5 phút sau 5 lần sai (theo IP + tài khoản), ghi nhật ký "Đăng nhập sai" |
| 6 | 🟡 Trung bình | Cảnh báo **treo mãi** khi xoá hoặc tắt check | Danh sách cảnh báo bẩn, số đếm sai | Tự đóng cảnh báo kèm lý do |
| 7 | 🟡 Trung bình | Cho phép đặt cha-con **vòng lặp** (A→B→C→A) | Cả nhánh biến mất khỏi bản đồ | Kiểm tra chuỗi cha khi lưu, báo lỗi rõ |
| 8 | 🟡 Trung bình | "Chạy ngay" một check đang tắt làm tài sản về trạng thái "Chưa rõ" | Hiển thị sai | Luôn tính check vừa chạy |
| 9 | 🟢 Thấp | Không đặt `ADMIN_PASSWORD` thì mật khẩu mặc định là `admin123` | Dễ đoán | Tự sinh mật khẩu ngẫu nhiên và in ra log |
| 10 | 🟢 Thấp | Thiếu security header; trang `/docs` API mở công khai | Lộ cấu trúc API | Thêm `nosniff`, `X-Frame-Options: DENY`, `no-store`; tắt `/docs` |

Ngoài ra trong quá trình kiểm thử còn có 9 lỗi nằm ở chính **kịch bản test** (selector, timing, tham số). Các lỗi này đã được sửa trong bộ test, không phải lỗi của ứng dụng.

## 3. Chi tiết theo luồng

### 3.1 Thu thập dữ liệu (collector)
| Nguồn | Cách test | Kịch bản đã đạt |
|---|---|---|
| pfSense REST API v2 | Server giả lập | OK; 1 WAN down → Lỗi; WAN loss → Cảnh báo; interface quan trọng down; disk ≥85%; sai API key (401); chưa cài gói (404); không kết nối được; IPsec/OpenVPN; DHCP lease đưa lên bản đồ |
| OPNsense | Server giả lập | Key/secret đúng và sai |
| ESXi / vCenter | Giả lập đối tượng pyVmomi | 2 host / 5 VM; bỏ qua template; VM tắt; host vàng; host notResponding; datastore 92% và 98%; snapshot 20 ngày; sai mật khẩu; không kết nối được; vCenter trống |
| SNMP | **snmpd thật** | v2c, **v3 (SHA/AES)**, sai community, cổng quan trọng down, OID tuỳ chỉnh có ngưỡng |
| SSH | **sshd thật** | Đo uptime/RAM/disk; ngưỡng disk cảnh báo/lỗi; lệnh tuỳ chỉnh exit 0/1/2; sai khoá |
| HTTP(S) | Server giả lập | Có/không có từ khoá, HTTP 500, mã HTTP tuỳ chỉnh, phản hồi chậm, không kết nối được |
| TCP / Ping | Thật | Cổng mở/đóng; ping localhost, IP không phản hồi, tên miền không tồn tại |

### 3.2 Luồng giám sát → cảnh báo → thông báo
Kịch bản: dịch vụ sống → chết lần 1 (chưa báo) → chết lần 2 (**mở cảnh báo, gửi Telegram + Email + Webhook**) → chết lần 3 (**không gửi trùng**) → sống lại (**tự đóng, gửi "đã hoạt động lại"**). Lịch sử ghi `ok, fail, fail, fail, ok` và uptime 24h = 40%, đúng như tính toán.

Các kịch bản khác đã đạt:
- Cảnh báo vàng nâng lên đỏ thì gửi lại.
- Kênh đặt "không gửi mức vàng" thì đúng là không nhận tin mức vàng.
- Telegram lỗi không làm hỏng việc giám sát; nút "Gửi thử" báo rõ lỗi.
- Helpdesk (quyền chỉ xem) vẫn được *nhận xử lý* cảnh báo.
- Chạy cùng một check 2 lần đồng thời thì chỉ thực thi 1 lần.
- Scheduler chỉ chạy check đến hạn và đang bật.

### 3.3 Đồng bộ ESXi lên bản đồ
- Lần chạy đầu tạo host và VM đúng cây cha-con, đúng site.
- Chạy lại không nhân bản dữ liệu.
- VM bị xoá được đánh dấu "Không còn thấy".
- **VM vMotion sang host khác thì cây trên bản đồ đổi theo.**
- Nếu chỉ có 1 host và check gắn vào host đã nhập tay thì dùng luôn host đó, không tạo bản trùng.
- Xoá check thì tài sản được giữ lại dưới dạng thủ công.

### 3.4 Giao diện (E2E)
- Đăng nhập đúng và sai; duyệt 11 trang; bộ lọc theo loại tài sản; tìm kiếm theo IP mở đúng tài sản và hiện đường dẫn firewall › switch › host.
- Tạo site → firewall → check từ drawer (form điền sẵn) → "Chạy thử" → lưu → trạng thái tự cập nhật.
- Form pfSense/SNMP hiện đúng các trường theo lựa chọn; mật khẩu đã lưu không xuất hiện trong HTML.
- Hệ thống trọng yếu: bộ đếm và tab lọc đúng.
- Bản đồ: 3 chế độ xem, xuất PNG, danh sách điểm rủi ro.
- Cảnh báo: nhận xử lý và đóng.
- Người dùng chỉ xem không thấy nút thêm/sửa/xoá.
- Đăng xuất.
- **Mobile 390px**: không tràn ngang, menu mở được.
- Không có lỗi JavaScript nào trong toàn bộ phiên test.

### 3.5 Bảo mật
- Mọi API đều yêu cầu đăng nhập; token bị sửa thì bị từ chối; quyền chỉ xem nhận 403 cho mọi thao tác ghi.
- Mật khẩu thiết bị được mã hoá trong DB (`enc:...`), không trả về trong API, file export hay HTML; khi sửa check giữ nguyên mật khẩu cũ.
- Thử SQL injection ở ô tìm kiếm: không có tác dụng.
- Thử 6 biến thể path traversal: đều bị chặn.
- XSS ở bảng, tìm kiếm và tooltip: không thực thi.
- File `.secret_key` có quyền 600; mật khẩu người dùng băm bằng bcrypt và không bao giờ trả về.

### 3.6 Tải (1.000 tài sản, 300 check chu kỳ 30 giây, 4 luồng gọi API liên tục)

| API | p50 | p95 |
|---|---|---|
| Bảng điều khiển | < 100 ms | < 300 ms |
| Bản đồ (1.000 node) | 182 ms | 410 ms |
| Danh sách tài sản | 185 ms | 357 ms |
| Điểm rủi ro | 199 ms | 435 ms |

Toàn bộ 300 check đều chạy đúng chu kỳ, đúng 50 cảnh báo (không trùng), **0 lỗi request, 0 lần khoá DB**, RAM khoảng 125 MB.

## 4. Rủi ro còn lại và giới hạn

| Mục | Ghi chú | Khuyến nghị |
|---|---|---|
| pfSense / ESXi thật | Test bằng giả lập dựng theo tài liệu API. Tên trường thực tế có thể khác giữa các phiên bản (VD gói REST API v2.x) | Khi triển khai: thêm check, bấm **Chạy thử**, xem mục "Dữ liệu thu được". Nếu thiếu trường thì gửi lại nội dung để điều chỉnh |
| Docker image | Chưa build được trong môi trường QA (Docker Hub bị chặn). Ứng dụng đã chạy trực tiếp ngoài Docker | Lần đầu chạy `docker compose up -d --build` trên máy chủ thật |
| Khoá đăng nhập | Lưu trong bộ nhớ, reset khi khởi động lại container | Đủ dùng cho nội bộ; nếu public thì đặt sau VPN hoặc reverse proxy |
| HTTPS | App chạy HTTP | Đặt sau Nginx Proxy Manager hoặc reverse proxy có SSL |
| Quy mô | Đã test ổn ở 1.000 tài sản / 300 check | Trên ~2.000 check nên chuyển sang PostgreSQL (đã hỗ trợ qua `DATABASE_URL`) |

## 5. Cách chạy lại QA

```bash
cd backend
pip install -r requirements-dev.txt && playwright install chromium
# tuỳ chọn để chạy test SNMP/SSH thật: apt install snmpd openssh-server
bash tests/run_all.sh
```


---

# Bổ sung 02/11/2026: Nhận Syslog & SNMP Trap

| Lớp kiểm thử | Số ca | Kết quả |
|---|---|---|
| Pytest mới (parser, nhận UDP/TCP/trap qua mạng thật, quy tắc, flood, lưu trữ, nâng cấp CSDL) | 35 | ✅ 35/35 |
| Toàn bộ pytest (cũ + mới) | 98 | ✅ 98/98 |
| E2E giao diện (thêm luồng trang Log, chạy 3 lần liên tiếp) | 59 | ✅ 59/59 |
| Tải syslog: 20 thiết bị, ~3.000 log/giây, 20 giây | 4 | ✅ 60.000/60.000 log, API p95 ≈ 375 ms, RAM ~136 MB |
| Regression tải giám sát (1.000 tài sản, 300 check), XSS, demo mobile | 8 + 3 + 21 | ✅ |

**Đã kiểm chứng:**
- Định dạng RFC3164 và RFC5424, pfSense (không có hostname), Cisco `%LINK-3-UPDOWN`, ESXi, Synology; log thiếu PRI hoặc PRI sai.
- TCP với cả 2 kiểu đóng gói (xuống dòng và octet-counting), kể cả khi gói bị cắt giữa chừng.
- Trap v2c (sai community thì bị loại) và **trap v3 SHA/AES**.
- Cặp linkDown/linkUp; cổng up chỉ đóng đúng cảnh báo của cổng đó.
- Ngưỡng 5 lần trong 5 phút; quy tắc bỏ qua `filterlog`.
- Kiểm tra không báo nhầm: các log như "backup volume completed", "APDU", "SMART test passed" không sinh cảnh báo.
- Tự đóng cảnh báo khi log im lặng; gửi Telegram khi mở và khi phục hồi.
- Lọc, phân trang, nguồn lạ; xoá log quá hạn và vượt số lượng.
- Nâng cấp CSDL từ phiên bản cũ mà không mất dữ liệu.

**Lỗi tìm thấy và đã sửa:**

| # | Mức | Lỗi | Cách sửa |
|---|---|---|---|
| 11 | 🔴 | Bấm **Lưu** cấu hình trap trong Cài đặt làm **tắt hẳn bộ nhận trap** (khởi động lại trong thread không có event loop). Mọi trap sau đó bị mất | Chạy việc khởi động lại trên event loop chính; báo lỗi rõ nếu không mở lại được cổng |
| 12 | 🟠 | **Cảnh báo bị nhân bản** khi nhiều log giống nhau đến trong cùng một lô; log "cổng up" trong cùng lô không đóng được cảnh báo "down" | Flush ngay sau khi tạo hoặc đóng cảnh báo |
| 13 | 🟠 | Ở ~3.000 log/giây **mất 9% log** do bộ đệm UDP tràn (phân tích log chạy ngay trong vòng nhận gói) | Vòng nhận chỉ đẩy dữ liệu thô vào hàng đợi; phân tích ở luồng nền; tăng SO_RCVBUF. Kết quả: 0% mất |
| 14 | 🟡 | Nút "Gửi thử trap" dùng `warmStart` nên sinh cảnh báo "khởi động lại" giả | Dùng OID riêng cho tin thử |
| 15 | 🟡 | Chưa có cơ chế nâng cấp CSDL: thêm cột mới sẽ làm hỏng DB cũ | Tự thêm cột còn thiếu khi khởi động (có test riêng) |

**Giới hạn:**
- Chưa có syslog qua TLS (6514).
- Trap v3 cần khai báo Engine ID của thiết bị.
- Trong Docker, kernel có thể giới hạn bộ đệm UDP (`net.core.rmem_max`). Với lưu lượng rất lớn (>5.000 log/giây) nên tăng `sysctl -w net.core.rmem_max=16777216` trên máy chủ.

**Cập nhật: giới hạn IP nguồn.** Log/trap chỉ được nhận từ IP/subnet cho phép, mặc định là dải mạng nội bộ; IP lạ bị chặn và đếm số lần. Đã thêm 2 test; tổng pytest 100/100, E2E 59/59.
Đã cân nhắc nhưng không làm, để giữ hệ thống gọn: nạp MIB, tách trường kiểu Wazuh, syslog TLS, ký số file log. Nếu cần tuân thủ hoặc kiểm toán thì chạy kèm Wazuh.

## Bổ sung: Giám sát CPU / RAM / Disk (04/11/2026)
- Bộ đánh giá ngưỡng dùng chung `collectors/base.py: apply_resources` cho SNMP, SSH (Linux + Windows/OpenSSH), ESXi, pfSense/OPNsense API.
- SNMP: HOST-RESOURCES-MIB (hrProcessorLoad, hrStorage: RAM trừ buffer/cache, ổ đĩa, swap; lọc /dev /proc /run tmpfs; gộp dataset ZFS trùng pool; sửa tràn Integer32) → dự phòng UCD (Linux), CISCO-PROCESS/MEMORY-POOL, HP/Aruba.
- ESXi: CPU/RAM host, datastore; VM: CPU (theo MHz host), RAM guest, ổ đĩa guest (VMware Tools).
- Lịch sử: cột `check_results.metrics` (tự thêm khi nâng cấp), API `/api/resources`, `/api/resources/history`, thẻ trên Bảng điều khiển.
- Kiểm thử: pytest 116/116 (thêm `test_resources.py` + hrStorage qua snmpd thật), E2E 62/62.
