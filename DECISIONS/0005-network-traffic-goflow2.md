# ADR 0005 – Lưu lượng mạng: GoFlow2 + PostgreSQL (không ClickHouse, không Kafka)

- **Ngày:** 2026-11-13
- **Trạng thái:** Đã áp dụng (2.10.0)

## Bối cảnh
Cần biết ai dùng đường Internet, cho dịch vụ gì, qua VLAN nào. Firewall là pfSense **CE 2.8.1** (2 nhân), xuất flow bằng gói
**softflowd**. Đo thử trên mạng thật ngày 13/11 (17 interface, 3 phút): ~509 bản ghi/giây, trong đó 54% là bản sao trên WAN sau NAT;
bỏ WAN còn ~250/giây → ~1,5–2 triệu dòng gộp-theo-phút mỗi ngày làm việc (~250–300 MB). Giờ cao điểm WAN 650–744 Mbps.

Phát hiện khi đo: cổng mặc định của softflowd là **9996**; softflowd **tự đánh số interface** (`-i 15:em0.15`), không theo ifIndex SNMP,
và ghi cùng một số cho cả vào/ra; ICMP bị ghi **protocol 0** (lỗi template của softflowd); GoFlow2 chạy 2 worker nên đôi khi
**2 bản ghi JSON nằm chung một dòng**.

## Quyết định
1. **GoFlow2** (BSD-3, Go) là bộ thu, chạy như **tiến trình con của IT Ops** (bật/tắt trong giao diện, tự khởi động lại có back-off).
   IT Ops không tự giải mã NetFlow. GoFlow2 là thành phần **thay được** (đúng Quyết định A): đổi bộ thu chỉ cần cùng định dạng JSON.
2. **PostgreSQL** như phần còn lại (ADR 0003): `flow_1m` (gộp theo phút, 7 ngày) + `flow_1h` (theo giờ, bỏ IP đích, 60 ngày),
   index **BRIN** theo thời gian. Không ClickHouse (không chạy native trên Windows → staging ≠ prod), không Kafka (một người vận hành).
3. **Chỉ giữ traffic có địa chỉ nội bộ** → bản sao WAN sau NAT tự bị bỏ; traffic nội bộ giữa 2 VLAN chỉ đếm một lần mỗi phút.
4. **Một dòng cho mỗi hội thoại** (local, remote, proto, cổng dịch vụ = cổng nhỏ hơn), có `bytes_out` / `bytes_in`.
5. Tên interface đặt **theo exporter** (dán `ps aux | grep softflowd`, lấy mô tả VLAN từ check pfSense/SNMP).
6. Bảng flow **không nằm trong bản sao lưu** hằng ngày (lớn, dữ liệu sống).

## Phương án đã cân nhắc
- *ntopng + nProbe:* nProbe trả phí; ntopng Community không tự nhận NetFlow; khó gắn với tài sản/cảnh báo của IT Ops – loại.
- *ClickHouse:* nén tốt hơn ~10×, nhưng không chạy native trên Windows và thêm một hệ thống phải vận hành; xem lại khi > ~2 000 bản ghi/giây.
- *Bảng phân vùng theo ngày (partition):* xoá nhanh hơn, nhưng làm phức tạp migration/kiểm tra schema; với lượng hiện tại DELETE theo giờ + BRIN là đủ.
- *Giải mã NetFlow bằng Python trong app:* một tiến trình asyncio, GIL – rủi ro làm chậm web và các check – loại.

## Hệ quả
- Cần file `goflow2-…exe` trong `backend\tools\goflow2\` (Docker image có sẵn). Mở UDP 2055 (`OPEN-FIREWALL.bat`).
- Chưa có: tên miền / người dùng cho từng kết nối (cần agent đọc DNS cache – xem BACKLOG), tên tổ chức (ASN) của IP đích, cảnh báo băng thông theo VLAN.
- Theo dõi CPU pfSense khi bật thêm interface cho softflowd (bắt gói ở user space).
