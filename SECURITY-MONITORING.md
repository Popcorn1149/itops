# Giám sát an ninh (ISO 27001 · ISO 9001 · SOC 2)

Cấu hình tại **Cài đặt › Giám sát an ninh**. Các giá trị mặc định là đề xuất, cần lãnh đạo IT chốt.

## 1. Chế độ chạy thật (C10)
Thêm vào `.env`:
```
ITOPS_ENV=production
```
Khi bật, nút "Xoá toàn bộ dữ liệu hạ tầng" bị khoá (API trả 403). Mọi lần thử vẫn được ghi audit log và tạo cảnh báo Critical.

## 2. SLA xử lý (B5)
| Mức | Cách tính | Hạn ack mặc định |
|---|---|---|
| Critical / DOWN | 24/7 | 15 phút trong giờ, 30 phút ngoài giờ |
| Trouble | Business hours | 60 phút |
| Attention | Business hours | 540 phút (1 ngày làm việc) |

Business hours mặc định là T2–T7, 07:30–18:30 (theo `APP_TZ_OFFSET`, mặc định +7). Cảnh báo quá hạn ack được đánh dấu "quá hạn SLA" và gửi nhắc 1 lần.

## 3. Cảnh báo thao tác của quản trị viên (B6 / UC-14)
Các thao tác sinh cảnh báo:
- **Critical:** tạo tài khoản admin, đổi vai trò thành admin, xoá dữ liệu (hoặc thử xoá khi chạy thật), sửa cấu hình Giám sát an ninh.
- **Trouble:** đăng nhập IT Ops sai ≥ 5 lần / 5 phút từ cùng IP; tạo/xoá tài khoản; tắt hoặc xoá check, rule log, kịch bản; sửa kênh cảnh báo hoặc cấu hình nhận log; nhập dữ liệu.

Người thực hiện **không tự ack/đóng** được cảnh báo về chính mình; người khác phải xem xét (tách nhiệm vụ). Nên gửi cho trưởng IT / người phụ trách ISMS qua email hoặc chat Telegram riêng.

## 4. Log source im lặng (UC-13 / C13)
Chỉ áp dụng cho thiết bị đã từng gửi log. Threshold theo nhóm: firewall/router 30 phút, server/VM 30 phút, switch/AP 24 giờ, khác 24 giờ.
- Không báo khi thiết bị đang DOWN (check giám sát đã báo).
- Switch: nếu có check SNMP thì chỉ báo khi SNMP vẫn trả lời.
- Server Linux cần nhịp đều đặn để dùng được threshold 30 phút:
  ```
  # crontab -e
  */10 * * * * logger -t itops-heartbeat alive
  ```
  (rsyslog phải đang chuyển log về IT Ops.)

## 5. Archive log + chuỗi hash (B7 / B8)
- Giữ 90 ngày trong CSDL. Mỗi ngày lúc 00:30, log + audit + cảnh báo của ngày hôm trước được nén thành `YYYY/MM/itops-YYYY-MM-DD.jsonl.gz`.
- SHA-256 của từng file được nối thành chuỗi trong `hash-chain.csv`: `chain = SHA256(chain_trước | ngày | sha256_file)`. Sửa, xoá hay chèn bất kỳ file nào đều bị phát hiện ở bảng "Kiểm tra toàn vẹn archive".
- Thư mục mặc định là `archive` trong thư mục dữ liệu. Để lưu ra NAS, nhập đường dẫn tuyệt đối (Windows: `\\NAS01\itops-archive`; Docker: mount NAS vào container rồi nhập `/mnt/nas/itops`). Nên bật snapshot chỉ đọc trên NAS.
- File được giữ 365 ngày. Dòng trong `hash-chain.csv` không bao giờ bị xoá.
- Hash hằng ngày được gửi cho email / chat Telegram khai báo ở mục "Gửi hash hằng ngày cho".

## 6. Đọc Windows Event qua SSH (B9 / C14 / C15)
Trong check SSH (Windows), bật **Đọc Windows Event (bảo mật)**.
- Đọc theo `EventRecordID`. Lần đầu chỉ ghi nhận vị trí; các lần sau chỉ lấy bản ghi mới, không trùng và không sót khi IT Ops khởi động lại.
- Sự kiện đọc: 1102, 104 (xoá log), 1100 (dịch vụ log dừng; bỏ qua nếu có 1074/6006 trong ±15 phút = tắt máy có kế hoạch), 4720 (tạo tài khoản), 4728/4732/4756 vào admin group.
- RecordId giảm hoặc bị hụt so với lần đọc trước → cảnh báo "RecordId bất thường".
- Quyền: tài khoản SSH phải là Administrator hoặc thuộc nhóm **Event Log Readers**.
- Kiểm tra audit policy: `auditpol /get /category:"Account Management"`. User Account Management và Security Group Management phải có Success.

## 7. Rule log mới
| Rule | Ghi chú |
|---|---|
| Đăng nhập sai liên tục (C11) | Gộp theo **IP source**; một IP thử nhiều user = 1 cảnh báo, kèm danh sách user đã thử. Mức Trouble |
| IP đổi MAC (C12 / UC-10) | **Tắt sẵn.** Nhập danh sách IP tĩnh quan trọng vào "Chỉ áp dụng cho khoá" rồi bật |
| Windows: xoá nhật ký / dịch vụ log dừng / tạo tài khoản / thêm vào admin group / RecordId bất thường | Dùng dữ liệu từ mục 6 |

## 8. Kiểm tra log của thiết bị có tới IT Ops không (D)
**Cài đặt › Nhận Syslog / Trap › Nguồn đang gửi tới IT Ops** liệt kê mọi IP đã gửi gói tới kể từ lúc khởi động, kể cả gói bị chặn.
- Không thấy thiết bị trong bảng → gói chưa tới máy IT Ops. Dùng Packet Capture trên firewall (UDP 514, host = IP IT Ops) để biết firewall có gửi không; nếu có gửi, kiểm tra Windows Firewall trên máy IT Ops.
- Thấy nhưng **bị chặn** → thêm IP vào "IP được phép gửi log / trap".
