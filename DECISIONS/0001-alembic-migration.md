# ADR 0001 – Dùng Alembic quản lý thay đổi CSDL

- **Ngày:** 2026-11-08
- **Trạng thái:** Đã áp dụng (bản v2). Phần SQLite (tự nâng cấp CSDL v1, chế độ batch) được thay bằng ADR 0003 – PostgreSQL.

## Bối cảnh
Bản v1 tạo bảng bằng `create_all` và hàm `auto_migrate()` tự viết: chỉ **thêm cột**, không đổi kiểu, không đổi tên, không rollback, không có lịch sử phiên bản schema. Mỗi tính năng mới đụng tới schema đều có rủi ro mất dữ liệu khi nâng cấp.

## Quyết định
- Dùng **Alembic** (công cụ migration của SQLAlchemy). Migration nằm ở `backend/migrations/versions/`.
- `0001` = schema bản v1 (sinh tự động từ models lúc chuyển đổi). App tự chạy `upgrade head` khi khởi động (`app/db.py → run_migrations`).
- CSDL từ bản v1 (chưa có bảng `alembic_version`): chỉ **thêm** bảng/cột còn thiếu cho khớp `0001`, đánh dấu `0001`, rồi nâng cấp tiếp. Không xoá, không sửa dữ liệu.
- Quy định: **không sửa `models.py` mà không có migration** – `tests/test_migrations.py` chặn (so schema do migration tạo với models) và chặn tách nhánh migration.

## Hệ quả
- Thêm dependency `alembic`. Dockerfile phải chép `backend/migrations` và `alembic.ini`.
- Trên SQLite, Alembic dùng chế độ "batch" (dựng lại bảng) khi đổi cột → trigger trên bảng đó bị mất; migration nào batch bảng `audit_logs` phải tạo lại trigger chỉ-ghi-thêm (có test kiểm).
- Lệnh thường dùng (trong `backend`): `alembic revision --autogenerate -m "..."`, `alembic upgrade head`, `alembic downgrade -1`.
