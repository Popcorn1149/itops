# IT Ops Workspace – bản v2 (bản làm việc cho cấu trúc mới)

Bản này tách khỏi bản đang chạy ở `Documents\itops`. Nó được tạo ngày 07/11/2026 từ code mới nhất của bản đó, để làm cấu trúc mới (Git, tài liệu, Alembic, CI…) mà không ảnh hưởng tới tool đang dùng.

## Khác với bản đang chạy
| Hạng mục | Bản đang chạy (`itops`) | Bản v2 (`itops-v2`) |
|---|---|---|
| Cổng web | 8000 | **8100** |
| Log/trap (dữ liệu mẫu) | 5514 / 5162 | **6514 / 6162**, chỉ nhận từ 127.0.0.1 |
| Log/trap (thiết bị thật) | 514 / 162 | 514 / 162 (chỉ dùng khi máy này nhận log thật) |
| Thư mục dữ liệu | `backend/data-dev`, `backend/data-local` | **`backend/data-v2-dev`, `backend/data-v2-local`** (bắt đầu trống, không chép DB thật) |
| Mật khẩu admin | `admin12345` ghi trong `launch.json` | **Sinh ngẫu nhiên** vào `.env.local` khi chạy `CAI-DAT.bat`; `.env.local` không được commit |
| PyYAML | Không khai báo (đi kèm uvicorn) | Khai báo `PyYAML==6.0.3` trong `requirements.txt` |
| Rule Windows Firewall cho web | "ITOps Web" (8000) | "ITOps v2 Web" (8100) |
| Bản build giao diện | 22 bản cũ trong `backend/static/assets` | Chỉ bản đang dùng (`index-BxGq9TUp.js`) |

Code trong `backend/app` và `frontend/src` **giữ nguyên 100%** so với bản đang chạy.

## Chạy trên máy khác
1. Cài **Python** (cùng version với máy đang chạy là tốt nhất) và **VS Code**. Khi cài Python nhớ tick "Add python.exe to PATH".
2. Giải nén, bấm đúp **`CAI-DAT.bat`**. Cuối cùng file sẽ in ra tài khoản admin; **lưu lại**.
3. VS Code → Ctrl+Shift+D → **▶ Chạy IT Ops (dữ liệu mẫu)** → F5 → mở `http://127.0.0.1:8100`.

Muốn đặt lại mật khẩu ban đầu: dừng app, xoá `.env.local` và thư mục `backend/data-v2-dev`, rồi chạy lại `CAI-DAT.bat`.

## Chạy test
```
cd backend
.venv\Scripts\python.exe -m pip install pytest aiosmtpd
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --ignore=tests/test_real_agents.py --ignore=tests/load_test.py
```
`load_test.py` là script đo tải (cần Playwright), không phải test của pytest, nên phải bỏ qua khi chạy pytest.

## Đã kiểm tra trước khi đóng gói (trên Linux, Python 3.13)
- Khởi động ở cổng 8100, `/api/health` báo bình thường; scheduler và receiver chạy.
- Đăng nhập bằng `admin12345` bị từ chối (401); đăng nhập bằng mật khẩu trong `.env.local` thành công.
- Dữ liệu mẫu: 3 site, 35 tài sản. Gửi syslog vào cổng 6514 → ghi nhận được sự kiện.
- Giao diện tải đúng bản build `index-BxGq9TUp.js`.
- pytest: 161 đạt, 3 lỗi do môi trường thử không có lệnh `ping` (trên Windows có sẵn).

## Chưa làm (bước tiếp theo theo đề xuất hoàn thiện codebase)
- Khởi tạo Git và commit đầu tiên.
- AGENTS.md, ARCHITECTURE.md, SECURITY.md, thư mục DECISIONS/.
- Alembic, backup thư mục `data`, CI.
