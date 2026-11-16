# Chạy thử bằng VS Code (Windows) – bản v2

Không cần Docker, không cần cài PostgreSQL. Giao diện đã được build sẵn trong `backend/static`.
CSDL là **PostgreSQL 17 chạy kèm**: SETUP.bat tải sẵn (~30 MB), app tự khởi động khi bấm F5 (chỉ nghe 127.0.0.1).

## Cần cài một lần
1. **Python 3.12** từ python.org. Khi cài, nhớ tick **"Add python.exe to PATH"**.
2. **VS Code**, cài extension **Python** (VS Code sẽ tự gợi ý khi mở thư mục).
3. Node.js LTS: *chỉ cần* khi bạn muốn sửa giao diện.

## Chạy
1. Bấm đúp **`SETUP.bat`** trong thư mục `itops-v2`. File này chép cấu hình VS Code vào `.vscode`, tạo môi trường Python, cài thư viện, tải PostgreSQL di động và **tạo mật khẩu admin ngẫu nhiên trong `.env.local`**, mất 1–3 phút. Xong sẽ hiện "DONE!" và tự mở VS Code.
   (Nếu VS Code không tự mở: **File › Open Folder…** → chọn thư mục `itops-v2`.)
2. VS Code hỏi cài extension Python thì chọn **Install**.
3. Mở **Run and Debug** (Ctrl+Shift+D), chọn **▶ Chạy IT Ops (dữ liệu mẫu)** → bấm **F5**.
4. Trình duyệt tự mở `http://127.0.0.1:8100`. Đăng nhập bằng tài khoản ghi trong file **`.env.local`** (SETUP.bat in ra khi chạy xong). Lần đầu admin phải **bật xác thực 2 lớp**: chuẩn bị Google Authenticator / Microsoft Authenticator trên điện thoại để quét mã QR.

Dừng bằng **Shift+F5** (PostgreSQL vẫn chạy nền cho lần sau; tắt hẳn bằng task **11 / 12**).

## Các chế độ chạy (chọn ở Run and Debug)
| Cấu hình | Dùng khi |
|---|---|
| ▶ Chạy IT Ops (dữ liệu mẫu) | Xem thử, trình diễn. Dữ liệu lưu ở `backend/data-v2-dev` |
| ▶ Thiết bị thật (cổng 514/162) | Dùng với thiết bị thật trong mạng. Dữ liệu riêng ở `backend/data-v2-local`. Xem **ADD-REAL-DEVICES.md** |
| ▶ Sửa code: backend + giao diện | Sửa UI, trang tự tải lại ở `http://localhost:5173` (cần Node.js và đã chạy task 2) |

## Task hữu ích (Ctrl+Shift+P → Tasks: Run Task)
- **4. Gửi thử syslog**: gửi 3 log mẫu (cổng switch down, WAN down, đăng nhập sai) để xem trang *Log thiết bị* và *Cảnh báo*.
- **5. Chạy kiểm thử**: chạy bộ test tự động.
- **6. Xoá dữ liệu chạy thử**: muốn làm lại từ đầu (tự dừng PostgreSQL của dữ liệu mẫu trước khi xoá).
- **7. Sao lưu** · **13. Khôi phục** · **14. Chuyển dữ liệu bản v1 (SQLite)** – xem README-V2.md.
- **11 / 12. PostgreSQL: dừng** – tắt hẳn PostgreSQL chạy kèm (dữ liệu mẫu / thiết bị thật).

## Lưu ý khi chạy trên máy cá nhân
- Chế độ *dữ liệu mẫu* nghe log/trap ở **6514/6162**; chế độ *Thiết bị thật* nghe ở **514/162** như bản Docker.
- Trước khi dùng thiết bị thật, chuột phải **OPEN-FIREWALL.bat** → *Run as administrator* để mở Windows Firewall.
- Máy tính phải nằm cùng mạng với thiết bị cần giám sát (hoặc có VPN), và laptop tắt thì giám sát cũng dừng. Chạy lâu dài thì dùng bản Docker trên VM.
- Lỗi `python không được nhận diện` → cài lại Python và tick "Add to PATH", rồi mở lại VS Code.
- Lỗi cổng 8100 đang bị dùng → sửa `"--port", "8100"` trong `.vscode/launch.json`.
- Lỗi "Cổng 5433 đang có chương trình khác dùng" (máy đã cài PostgreSQL khác) → đổi `PG_LOCAL_PORT` trong `.vscode/launch.json` và `.vscode/tasks.json`.
- Lỗi "Chưa có PostgreSQL di động" (máy không có Internet lúc cài) → khi có mạng chạy task **0. Tải PostgreSQL**.

## Không đăng nhập được
- **Không có mật khẩu / `.env.local` không có**: chạy lại `SETUP.bat` (giữ nguyên mật khẩu nếu đã có). Nếu app **đã từng chạy** khi chưa có `.env.local`, tài khoản admin đã được tạo với mật khẩu ngẫu nhiên (in một lần ở Terminal dòng "ADMIN_PASSWORD chưa đặt…") → dùng task **15. Quên mật khẩu admin – đặt lại (dữ liệu mẫu)** (thiết bị thật: task **16**), mật khẩu mới in ra Terminal.
- **"Không kết nối được máy chủ" / "Failed to fetch"**: app không chạy hoặc lỗi lúc khởi động. Xem cửa sổ **Terminal / Debug Console** trong VS Code – dòng lỗi cuối cùng (vd. "Chưa có PostgreSQL di động", "Cổng 5433 đang có chương trình khác dùng") cho biết cần làm gì. Tab trình duyệt cũ còn mở từ lần chạy trước cũng báo lỗi này → F5 lại app rồi tải lại trang.
