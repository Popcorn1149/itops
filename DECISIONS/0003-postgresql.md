# ADR 0003 – Chuyển CSDL sang PostgreSQL (bỏ SQLite)

- **Ngày:** 2026-11-08
- **Trạng thái:** Đã áp dụng (bản v2). Thay phần "tự nâng cấp CSDL SQLite bản v1" của ADR 0001.

## Bối cảnh
Bước tiếp theo là agent cho 50–200 máy Windows/Linux/macOS. Mỗi máy gửi định kỳ hiệu năng, dịch vụ, phần mềm, event log → nhiều tiến trình ghi đồng thời và bảng lớn. SQLite chỉ cho **một** người ghi tại một thời điểm, không có quyền theo user CSDL, và khó sao lưu nóng/nhân bản khi chạy thật trên máy chủ.

Hiện tại vẫn **demo bằng VS Code trên Windows**, sau này mới chạy thật trên **máy chủ Linux + Docker**. Cả hai phải dùng cùng một loại CSDL để thứ test được trên Windows chính là thứ chạy thật.

## Quyết định
1. **Chỉ dùng PostgreSQL 17** (driver `psycopg` 3). SQLite bị bỏ; app báo lỗi rõ nếu `DATABASE_URL` không phải PostgreSQL.
2. Hai cách chạy:
   - **Demo / dev (Windows, VS Code):** `PG_LOCAL=1` → app tự tải bộ PostgreSQL "di động" (không cần cài, không cần quyền admin), tự `initdb` lần đầu với **mật khẩu ngẫu nhiên** (`DATA_DIR/.pg_password`), xác thực `scram-sha-256`, **chỉ nghe 127.0.0.1**, rồi tự khởi động.
     Nguồn binary: gói npm `@embedded-postgres/<nền tảng>` 17.11; tải thẳng qua HTTPS và **kiểm tra sha512** trước khi giải nén (`backend/tools/get_postgres.py`).
   - **Chạy thật (Linux + Docker):** image `postgres:17-alpine` chính thức trong `docker-compose.yml`, app nối qua `DATABASE_URL`.
3. Cột JSON hiện có **giữ kiểu `json`** (không đổi sang `jsonb`). `jsonb` sắp xếp lại key trong object → thứ tự hiển thị / nội dung thông báo có thể đổi so với bản cũ (đã bắt được trong `test_inc03_escalation`). Bảng mới cần truy vấn bên trong JSON (inventory agent) sẽ dùng `jsonb`.
4. **Audit chỉ ghi thêm** bằng trigger plpgsql: chặn `UPDATE`, `DELETE` **và** `TRUNCATE` trên `audit_logs` (migration 0003).
5. **Sao lưu logic** không phụ thuộc `pg_dump` (bộ PostgreSQL di động không có `pg_dump`): đọc toàn bộ bảng trong **một transaction REPEATABLE READ READ ONLY** (ảnh chụp nhất quán khi app đang ghi) → JSONL trong file `.zip` kèm 2 khoá và archive. Khôi phục: dựng schema đúng revision của bản sao lưu → nạp → `upgrade head`; `--wipe` và nạp nằm trong **cùng một transaction** nên lỗi giữa chừng không làm mất dữ liệu đang có.
6. Chuyển dữ liệu bản v1 / v2-SQLite: `admin_tools import-sqlite` (file SQLite mở **chỉ đọc**, chép cột chung theo thứ tự khoá ngoại, chuyển đúng kiểu bool/JSON/thời gian, chỉnh sequence, chép khoá; phiên đăng nhập cũ không chuyển).
7. Test chạy trên **PostgreSQL thật**: mỗi lần chạy một CSDL mới (`TEST_DATABASE_URL`) hoặc một PostgreSQL di động tạm ở cổng ngẫu nhiên; xong thì xoá.

## Phương án đã cân nhắc
- *Giữ SQLite cho demo, PostgreSQL cho chạy thật:* hai đường code, lỗi chỉ lộ khi lên máy chủ (đã gặp: biểu thức `strftime` của SQLite, `GROUP BY` với tham số) – loại.
- *Cài PostgreSQL bằng bộ cài EDB trên Windows:* cần quyền admin, chạy thành dịch vụ thường trực, mật khẩu `postgres` do người cài tự đặt – nặng cho máy demo. Vẫn dùng được: đặt `DATABASE_URL` thay vì `PG_LOCAL`.
- *Docker Desktop trên Windows để chạy PostgreSQL:* cần trả phí với công ty ≥ 250 nhân viên hoặc doanh thu > 10 triệu USD; chạy thật thì dùng Docker Engine trên Linux (miễn phí) – loại cho bước demo.
- *Thư viện `pgserver` (PostgreSQL nhúng qua pip):* chỉ hỗ trợ Python ≤ 3.12 – loại.

## Hệ quả
- Lần chạy đầu cần Internet để tải ~30 MB (CAI-DAT.bat tải sẵn). PostgreSQL vẫn chạy sau khi tắt app; dừng bằng task VS Code 11/12.
- Không còn file `itops.db` – dữ liệu nằm ở `DATA_DIR/pgdata`. Sao lưu/khôi phục bằng `admin_tools`, không chép thư mục `pgdata` khi đang chạy.
- Chạy app bằng tài khoản **root** trên Linux với `PG_LOCAL=1` bị từ chối (PostgreSQL không cho) – trên máy chủ dùng Docker.
- Người có quyền owner CSDL vẫn tắt được trigger audit; chuỗi hash của archive và log PostgreSQL là lớp phát hiện.
