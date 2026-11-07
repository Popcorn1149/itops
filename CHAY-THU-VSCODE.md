# Chạy thử bằng VS Code (Windows) – bản v2

Không cần Docker. Giao diện đã được build sẵn trong `backend/static`.

## Cần cài một lần
1. **Python 3.12** từ python.org. Khi cài, nhớ tick **"Add python.exe to PATH"**.
2. **VS Code**, cài extension **Python** (VS Code sẽ tự gợi ý khi mở thư mục).
3. Node.js LTS: *chỉ cần* khi bạn muốn sửa giao diện.

## Chạy
1. Bấm đúp **`CAI-DAT.bat`** trong thư mục `itops-v2`. File này chép cấu hình VS Code vào `.vscode`, tạo môi trường Python, cài thư viện và **tạo mật khẩu admin ngẫu nhiên trong `.env.local`**, mất 1–3 phút. Xong sẽ hiện "XONG" và tự mở VS Code.
   (Nếu VS Code không tự mở: **File › Open Folder…** → chọn thư mục `itops-v2`.)
2. VS Code hỏi cài extension Python thì chọn **Install**.
3. Mở **Run and Debug** (Ctrl+Shift+D), chọn **▶ Chạy IT Ops (dữ liệu mẫu)** → bấm **F5**.
4. Trình duyệt tự mở `http://127.0.0.1:8100`. Đăng nhập bằng tài khoản ghi trong file **`.env.local`** (CAI-DAT.bat in ra khi chạy xong). Lần đầu admin phải **bật xác thực 2 lớp**: chuẩn bị Google Authenticator / Microsoft Authenticator trên điện thoại để quét mã QR.

Dừng bằng **Shift+F5**.

## Các chế độ chạy (chọn ở Run and Debug)
| Cấu hình | Dùng khi |
|---|---|
| ▶ Chạy IT Ops (dữ liệu mẫu) | Xem thử, trình diễn. Dữ liệu lưu ở `backend/data-v2-dev` |
| ▶ Thiết bị thật (cổng 514/162) | Dùng với thiết bị thật trong mạng. Dữ liệu riêng ở `backend/data-v2-local`. Xem **THEM-THIET-BI-THAT.md** |
| ▶ Sửa code: backend + giao diện | Sửa UI, trang tự tải lại ở `http://localhost:5173` (cần Node.js và đã chạy task 2) |

## Task hữu ích (Ctrl+Shift+P → Tasks: Run Task)
- **4. Gửi thử syslog**: gửi 3 log mẫu (cổng switch down, WAN down, đăng nhập sai) để xem trang *Log thiết bị* và *Cảnh báo*.
- **5. Chạy kiểm thử**: chạy bộ test tự động.
- **6. Xoá dữ liệu chạy thử**: muốn làm lại từ đầu.

## Lưu ý khi chạy trên máy cá nhân
- Chế độ *dữ liệu mẫu* nghe log/trap ở **6514/6162**; chế độ *Thiết bị thật* nghe ở **514/162** như bản Docker.
- Trước khi dùng thiết bị thật, chuột phải **MO-TUONG-LUA.bat** → *Run as administrator* để mở Windows Firewall.
- Máy tính phải nằm cùng mạng với thiết bị cần giám sát (hoặc có VPN), và laptop tắt thì giám sát cũng dừng. Chạy lâu dài thì dùng bản Docker trên VM.
- Lỗi `python không được nhận diện` → cài lại Python và tick "Add to PATH", rồi mở lại VS Code.
- Lỗi cổng 8100 đang bị dùng → sửa `"--port", "8100"` trong `.vscode/launch.json`.
