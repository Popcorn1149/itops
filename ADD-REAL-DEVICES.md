# Thêm thiết bị thật (SNMP + Syslog) khi chạy bằng VS Code

## 0. Chuẩn bị (một lần)
1. Nếu đã chạy `SETUP.bat` từ trước, **chạy lại một lần** để cập nhật cấu hình VS Code mới.
2. Chuột phải **`OPEN-FIREWALL.bat`** → **Run as administrator**. File này mở Windows Firewall cho cổng 514 (syslog), 162 (trap) và 8100 (web), chỉ nhận từ mạng nội bộ. Nó cũng in ra **IP của máy bạn**, ví dụ `192.168.1.50`. Ghi lại IP này.
3. VS Code → Ctrl+Shift+D → chọn **▶ Thiết bị thật (cổng 514/162)** → **F5**. Đăng nhập bằng tài khoản trong `.env.local`, rồi đổi mật khẩu ngay (avatar → Đổi mật khẩu).
4. Vào trang **Log thiết bị**: 3 chip *Syslog UDP :514, Syslog TCP :514, SNMP Trap :162* phải **xanh**. Chip đỏ nghĩa là cổng đang bị chương trình khác dùng (xem mục Sự cố).

> Máy tính phải cùng mạng (hoặc có VPN) với thiết bị. Tắt máy thì giám sát dừng.

## 1. Lấy thông tin bằng SNMP (hệ thống chủ động hỏi thiết bị)
**Trên thiết bị:** bật SNMP v2c, community chỉ đọc (VD `itops-ro`), cho phép IP máy bạn.

| Thiết bị | Lệnh / chỗ cấu hình |
|---|---|
| Cisco | `snmp-server community itops-ro RO` |
| HPE/Aruba | `snmp-server community "itops-ro" operator` |
| pfSense | Services › SNMP › Enable, Read Community = `itops-ro` |
| Synology | Control Panel › Terminal & SNMP › SNMP › bật SNMPv1/v2c |
| UPS APC | Configuration › Network › SNMPv1 › Access |

**Trong IT Ops:**
1. **Sites → Thêm site** (VD "Văn phòng").
2. **Thiết bị mạng → Thêm tài sản**: tên, loại (Switch…), site, **IP thật**.
3. Bấm vào thiết bị vừa tạo → **Thêm check** → loại **SNMP** → điền community `itops-ro`. Với UPS chọn loại thiết bị UPS, với NAS chọn Synology.
4. Bấm **Chạy thử**. Kết quả đúng sẽ hiện tên thiết bị, uptime, số cổng up/down, CPU. Xong thì **Lưu**.
5. Với switch: điền **Cổng quan trọng** (VD `Gi1/0/48`) để cổng uplink down là báo đỏ.

Firewall pfSense: dùng check **pfSense** (cần gói REST API) hoặc check SNMP như trên. ESXi: dùng check **ESXi** với user Read-only, VM sẽ tự hiện lên bản đồ.

## 2. Nhận Syslog (thiết bị tự gửi về)
Trỏ thiết bị gửi log về **`<IP máy bạn>:514`** (UDP):

| Thiết bị | Cấu hình |
|---|---|
| pfSense | Status › System Logs › Settings › Enable Remote Logging → `<IP>:514` |
| Cisco | `logging host <IP>` + `logging trap informational` |
| HPE/Aruba | `logging <IP>` |
| ESXi | `esxcli system syslog config set --loghost='udp://<IP>:514'` rồi `esxcli system syslog reload` |
| Synology | Log Center › Log Sending → `<IP>`, port 514, UDP |
| Linux | thêm `*.info @<IP>:514` vào `/etc/rsyslog.d/90-itops.conf`, restart rsyslog |

Lệnh đầy đủ (điền sẵn IP) có trong **Log thiết bị → tab Hướng dẫn cấu hình thiết bị**.

**Kiểm tra:** trang **Log thiết bị** sẽ hiện log trong vài giây. Log từ IP chưa khai báo hiện ở tab **Nguồn lạ** → bấm **Thêm tài sản** để gắn vào bản đồ.

## 3. Nhận SNMP Trap (tuỳ chọn)
- Trỏ trap về `<IP máy bạn>:162`. Ví dụ Cisco: `snmp-server host <IP> version 2c itops-trap` + `snmp-server enable traps snmp linkdown linkup`.
- Trong IT Ops: **Cài đặt → Nhận Syslog / Trap** → thêm community `itops-trap` → Lưu.

## 4. Giám sát CPU / RAM / Disk (trang **Tài nguyên**)
Không cần cài agent. Mỗi loại thiết bị dùng 1 check có sẵn; số liệu tự gom về trang **Tài nguyên** và cảnh báo khi vượt ngưỡng (mặc định CPU 85/95%, RAM 90/97%, Disk 85/95% – sửa trong từng check, để trống = tắt).

| Thiết bị | Thêm check | Cần bật trên thiết bị |
|---|---|---|
| pfSense | SNMP (đang dùng) hoặc pfSense API | Services › SNMP – đã bật. Tick module **Host Resources** để có RAM/Disk |
| Switch Cisco / HP-Aruba | SNMP | `snmp-server community <chuỗi> RO` – CPU/RAM tự đọc qua MIB riêng của hãng |
| Synology / QNAP | SNMP | Control Panel › Terminal & SNMP › bật SNMPv1/v2c |
| Server Linux | SSH (Hệ điều hành: Linux) | user có quyền đọc, không cần root |
| Server Windows | SSH (Hệ điều hành: Windows) | Settings › Optional features › **OpenSSH Server**, rồi `Start-Service sshd; Set-Service sshd -StartupType Automatic` |
| ESXi / vCenter | ESXi | user Read-only. CPU/RAM host + datastore; VM có số liệu nếu cài VMware Tools |

Thiết bị chưa có số liệu được liệt kê cuối trang **Tài nguyên** kèm nút **Thêm SNMP/SSH/ESXi** điền sẵn IP.

## 5. Sự cố thường gặp
| Hiện tượng | Cách xử lý |
|---|---|
| SNMP "không phản hồi" | Sai community; thiết bị chưa cho phép IP máy bạn; firewall giữa hai bên chặn UDP 161 |
| Không thấy log nào | Đã chạy `OPEN-FIREWALL.bat` chưa; thiết bị đã trỏ đúng IP máy bạn chưa; IP máy có đổi không (DHCP) |
| Chip đỏ "Chặn N log từ IP lạ" | IP thiết bị ngoài dải nội bộ → thêm vào Cài đặt › Nhận Syslog / Trap › IP được phép |
| Chip SNMP Trap :162 đỏ | Dịch vụ SNMP Trap của Windows đang chiếm cổng → chạy lại `OPEN-FIREWALL.bat` (nó tự tắt dịch vụ này) |
| Chip Syslog :514 đỏ | Phần mềm syslog khác (Kiwi, Tftpd64…) đang chạy → tắt nó đi |
| pfSense chỉ có CPU, không có RAM/Disk | Services › SNMP › Modules: tick **Host Resources** → Save |
| Windows: SSH lỗi xác thực | Dùng user `.\tenuser` hoặc `DOMAIN\user`; tài khoản phải được phép đăng nhập SSH |
| Dùng lại dữ liệu mẫu | Chọn cấu hình **▶ Chạy IT Ops (dữ liệu mẫu)**; hai bộ dữ liệu tách riêng |

## Host ảo hoá: xem máy ảo trên từng host

Bấm vào một host ở **Hạ tầng › Host vật lý** để xem khối **Máy ảo & container trên host**:
số lượng (đang chạy / tổng), vCPU và RAM cấp phát so với host (tỉ lệ overcommit), CPU/RAM/Disk từng máy, uptime, snapshot cũ.
Danh sách host có thêm cột **Máy ảo / container**.

| Nền tảng | Cách thêm | Ghi chú |
|---|---|---|
| VMware ESXi / vCenter | Check loại **ESXi**, user role Read-only | CPU/RAM/disk trong VM cần VMware Tools |
| Proxmox VE | Check loại **Proxmox VE**, API token | Xem bên dưới |
| Hyper-V | Check **SSH**, hệ điều hành Windows, bật **Đọc máy ảo Hyper-V** | User SSH thuộc nhóm *Hyper-V Administrators* |
| Docker | Check **SSH** Linux, bật **Đưa container lên bản đồ** | User SSH thuộc nhóm `docker` |

SNMP của ESXi chỉ liệt kê được tên VM và bật/tắt, không có hiệu năng từng VM, nên IT Ops dùng API.

### Proxmox VE: tạo API token chỉ đọc
```bash
pveum user add itops@pve
pveum aclmod / -user itops@pve -role PVEAuditor
pveum user token add itops@pve monitor --privsep 0     # ghi lại secret hiển thị 1 lần
# (tùy chọn) đọc IP/disk qua QEMU guest agent:
#   PVE 9: thêm quyền VM.GuestAgent.Audit · PVE 8: thêm VM.Monitor
```
Trong IT Ops: **Thêm check › Proxmox VE**, target = IP node, Token ID `itops@pve!monitor`, Token secret, cổng 8006.
Một check đọc được cả cluster: mọi node, VM (QEMU), container (LXC), storage. Template bị bỏ qua.

## pfSense: gửi flow cho trang *Lưu lượng mạng* (2.10.0)

1. IT Ops: chép `goflow2-2.2.7-windows-amd64.exe` vào `backend\tools\goflow2\`, chạy lại `OPEN-FIREWALL.bat`,
   rồi **Network traffic → Settings → Collect traffic** → Save (ô Collector phải hiện *running*).
2. pfSense CE: **System › Package Manager** → cài **softflowd** → **Services › softflowd**:

| Ô | Giá trị |
|---|---|
| Interface | chỉ các **LAN / VLAN** (`em0.11`, `em0.15`…). **Không** chọn WAN/PPPoE (đếm trùng sau NAT), **không** chọn `em0` (trunk) |
| Host | IP máy IT Ops (vd. `172.17.15.29`) |
| Port | **2055** (mặc định của gói là 9996 – phải đổi) |
| NetFlow version | **IPFIX** · Flow tracking level: **Full** |
| Timeout general / TCP / UDP / ICMP | **60** · Maximum lifetime **120** |

3. Kiểm tra trên pfSense (**Diagnostics › Command Prompt**): `ps aux | grep [s]oftflowd` – mỗi interface một dòng,
   có `-n <IP IT Ops>:2055`. Khi IT Ops đã nhận flow (khoảng 1 phút), mở **Network traffic → Settings**: chọn
   **Firewall asset = FW-Core** (pfSense gửi từ IP VLAN, vd. 172.17.15.1, khác IP khai báo 172.17.11.1), rồi dán kết quả
   `ps aux` → **Read names from ps output** → interface có tên dạng `em0.14 IOT_LAB_VLAN14`.
4. Bật thêm interface từng ít một và xem CPU của firewall trên IT Ops (softflowd bắt gói ở user space).

Không thấy dữ liệu? Ô *Collector* trong Settings hiện lệnh, log và số bản ghi/giây. 0 bản ghi → kiểm tra Host/Port của softflowd
và tường lửa Windows; có bản ghi nhưng "ignored" cao → đang xuất cả WAN, hoặc thiếu dải IP trong *Local networks*.

