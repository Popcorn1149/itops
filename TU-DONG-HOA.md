# Tự động hoá – hướng dẫn nhanh

Menu **Vận hành › Tự động hoá**. Mỗi kịch bản gồm: **Khi nào chạy → Phạm vi → Tham số / Nội dung → Gửi tới → Mức tự động**.
Giờ trong lịch là giờ Việt Nam. Tin gửi qua Telegram / Email / Webhook đã cấu hình ở **Cài đặt** (có thể chỉ định chat/email riêng cho từng kịch bản).

## Dùng template
1. Tab **Thư viện template** → chọn template → **Dùng template này**.
2. Sửa lịch, phạm vi, tham số, người nhận → **Chạy thử (không gửi)** để xem trước nội dung → **Lưu**.
3. Bật/tắt bằng công tắc. **Chạy ngay** (nút ▶) gửi thật ngay lập tức.

| Nhóm | Template có sẵn |
|---|---|
| Báo cáo (RPT) | RPT-01 Bản tin sáng · RPT-02 Báo cáo tuần · RPT-03 SLA tháng · RPT-04 Backup & rủi ro · RPT-06 Biến động tài sản |
| Cảnh báo – Sự cố (INC) | INC-01 Gom theo nguyên nhân gốc · INC-02 Chống chập chờn · INC-03 Leo thang · INC-05 Runbook đính kèm · INC-08 Thông báo người dùng |
| Phòng ngừa (PRE) | PRE-01 Dự báo đầy ổ · PRE-02 SSL hết hạn · PRE-04 Độ trễ tăng bất thường · PRE-08 Log bất thường |
| Bảo trì – Vòng đời (LCM) | LCM-01 Lịch bảo trì · LCM-02 Onboard · LCM-03 Offboard · LCM-06 Rà soát quý |

12 template còn lại trong tài liệu (RPT-05, INC-04/06/07, PRE-03/05/06/07, LCM-04/05/07/08) cần tích hợp hoặc dữ liệu mới nên **chưa đưa vào** – xem mục "Chưa hỗ trợ" trên trang, có ghi lý do.

**Nên bật trước:** RPT-01, INC-01, INC-02, INC-05, PRE-02, LCM-01 – dùng được ngay, giảm tin rác nhiều nhất.

Lưu ý:
- MTTA trong RPT-02 chỉ đúng khi mọi người bấm **Nhận** trên trang Cảnh báo. INC-03 cũng dừng leo thang khi có người bấm Nhận.
- PRE-01, PRE-04 cần ≥ 7 ngày số liệu mới chính xác (chạy được từ 24 giờ, nhưng chỉ là ước lượng).
- RPT-03 tính từ số liệu gộp theo ngày; nếu máy chạy IT Ops tắt nhiều ngày, báo cáo ghi rõ số ngày có dữ liệu.
- Khi máy chạy IT Ops tắt, mọi kịch bản dừng theo.

## Tự tạo kịch bản
**Tự tạo kịch bản** (góc phải) → chọn:
- **Theo lịch / định kỳ** + các **khối nội dung** (tổng quan, cảnh báo mở, Internet/WAN, SSL, tài nguyên, log, uptime, MTTA/MTTR, backup & rủi ro, biến động tài sản). "Chỉ khi có mục cần báo" để không gửi tin trống.
- **Theo sự kiện** (cảnh báo mở / đóng / nặng lên) + mẫu tin có biến `{title} {message} {severity} {asset} {site} {check} {time}`. Kết hợp **Phạm vi** (site, mức) để báo riêng cho từng nhóm.

## YAML
Mỗi kịch bản sửa được dạng YAML (nút **YAML** trong trình sửa), cùng định dạng mẫu trong tài liệu – dán nguyên khối là dùng được:

```yaml
id: RPT-02
name: Báo cáo tuần vận hành
enabled: true
trigger: { type: schedule, cron: "0 8 * * 1" }
scope: { sites: all }
params: { uptime_target: 99.5, top_n: 5 }
actions:
  - { type: email, to: [it-manager@congty.vn] }
  - { type: telegram, chat: "-1001234567890" }
level: L0
```

Cron: `phút giờ ngày tháng thứ` – `30 7 * * *` = 07:30 mỗi ngày · `0 8 * * 1` = 08:00 Thứ Hai · `0 8 1 * *` = ngày 1 hằng tháng.

## An toàn
- Không kịch bản nào xoá dữ liệu hay tắt thiết bị. Cảnh báo bị chặn (bảo trì, nguyên nhân gốc, chập chờn) vẫn được ghi lại, chỉ không gửi tin, và có lý do.
- Mọi lần chạy ghi ở tab **Lịch sử chạy** (giữ 300 lần gần nhất mỗi kịch bản). Thêm/sửa/xoá kịch bản ghi vào Nhật ký.
- Tài khoản *viewer* chỉ xem, không sửa/chạy được.
