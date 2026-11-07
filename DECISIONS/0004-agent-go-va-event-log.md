# ADR 0004 – Agent cho máy Windows / Linux / macOS và chính sách thu event log

- **Ngày:** 2026-11-08
- **Trạng thái:** Đã thống nhất, **chưa triển khai** (bước sau PostgreSQL). Windows + Linux trước, macOS ở giai đoạn 2.

## Bối cảnh
50–200 máy. Cần: event log quan trọng, trạng thái Windows Defender, hiệu năng (CPU/RAM/ổ đĩa), dịch vụ đang chạy, phần mềm đã cài. Linux/macOS tương tự. Chưa có chứng chỉ code signing, chưa có tài khoản Apple Developer. Công ty có GPO; chưa rõ có AD CS.

## Quyết định
1. **Agent viết bằng Go** (một file chạy, không cần cài runtime); server giữ **Python + FastAPI**.
2. **Chỉ đẩy lên (push-only), chỉ đọc:** agent tự gửi dữ liệu theo lịch qua HTTPS tới `/api/agent/v1`; **server không có kênh ra lệnh cho máy trạm** (không chạy lệnh từ xa, không cài phần mềm, không bắt gói tin). Bản thiết kế "sensor-agent" tham khảo trên mạng (capture/tshark/commands) **không dùng**: bắt gói tin cần Npcap (bản miễn phí giới hạn 5 máy, không cài im lặng được) và kênh lệnh từ xa biến agent thành công cụ điều khiển 200 máy nếu server bị chiếm.
3. **Đăng ký bằng token một lần** → mỗi máy có khoá riêng, thu hồi được từng máy. Có AD CS thì dùng thêm chứng chỉ máy (mTLS) qua GPO; **không có AD CS vẫn chạy được** (token + HTTPS với chứng chỉ tự ký được ghim trong cấu hình agent).
4. **Chưa có code signing:** triển khai qua GPO / script nội bộ, công bố mã băm SHA-256 của từng bản; SmartScreen/Defender có thể cảnh báo lần đầu. macOS chưa có Apple Developer → giai đoạn 2, cài thủ công (Gatekeeper sẽ chặn bản chưa ký).

## Chính sách event log: chỉ lấy sự kiện thực tế cần xử lý
**Không lấy toàn bộ Event ID** và **không lấy đăng nhập/đăng xuất thường ngày** – các log này chiếm phần lớn khối lượng, gần như luôn là hoạt động bình thường (người dùng, dịch vụ, tài khoản máy) và làm quản trị viên/helpdesk bị nhiễu.

**Bỏ qua mặc định:** 4624 (đăng nhập thành công), 4634 / 4647 (đăng xuất), 4672 (quyền đặc biệt khi đăng nhập), 4648, 4776 thành công, các đăng nhập của dịch vụ / tài khoản máy (`*$`, SYSTEM, LOCAL SERVICE, NETWORK SERVICE), 5156/5158 (Firewall cho phép kết nối), 4688/4689 (tạo/thoát tiến trình).

**Thu mặc định (Windows):**

| Nhóm | Event ID | Ý nghĩa cho helpdesk |
|---|---|---|
| Tài khoản | 4625 | Đăng nhập **sai** (gom theo tài khoản + nguồn; nhiều lần → cảnh báo dò mật khẩu) |
| | 4740 | Tài khoản bị **khoá** |
| | 4720 / 4726 | **Tạo / xoá** tài khoản cục bộ |
| | 4728 / 4732 / 4756 | **Thêm vào nhóm quyền** (Administrators, Domain Admins…) |
| | 1102 | **Nhật ký bảo mật bị xoá** |
| Hệ thống | 41 / 6008 | Máy **tắt đột ngột** (mất điện, treo) |
| | 7031 / 7034 | **Dịch vụ dừng bất thường** |
| | 7045 | Cài **dịch vụ mới** |
| | Disk 7 / 51 / 153, NTFS 55 | **Lỗi ổ đĩa** |
| Defender | 1116 / 1117 | **Phát hiện / đã xử lý mã độc** |
| | 5001 | **Tắt bảo vệ thời gian thực** |
| | 2001 | **Cập nhật mẫu nhận diện lỗi** |

Linux / macOS: tương đương – sudo/su thất bại, thêm user vào sudo/wheel/admin, dịch vụ systemd/launchd chết liên tục, OOM kill, lỗi ổ đĩa (dmesg/SMART), khởi động lại bất thường.

**Hiển thị dễ đọc cho IT helpdesk:** mỗi Event ID có mẫu tiếng Việt cố định **Ai · Từ đâu · Chuyện gì · Nên làm gì** (vd. *"Tài khoản `lan.nt` bị khoá sau 5 lần nhập sai từ máy `KT-PC07` – xác nhận với người dùng rồi mở khoá trong AD"*); sự kiện lặp lại được **gom** (×12 trong 10 phút); ID chưa có mẫu thì hiện câu Windows tự sinh. Danh sách thu/bỏ chỉnh được ở server theo nhóm máy, không cần cài lại agent.

## Hệ quả
- Server: migration mới cho bảng máy/agent (`jsonb` cho inventory), API `/api/agent/v1` có schema Pydantic + test hợp đồng, rule mới dùng chung đường cảnh báo hiện có.
- Agent không bao giờ nhận lệnh → muốn sửa máy trạm vẫn dùng công cụ hiện có (GPO, RDP, SCCM/Intune nếu có).
