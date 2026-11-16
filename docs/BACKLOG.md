# Backlog – tính năng cân nhắc làm sau

Danh sách các việc **đã bàn nhưng chưa làm**, để rà lại định kỳ (gợi ý: mỗi quý, hoặc khi chuẩn bị audit).
Mỗi mục ghi: vì sao cần, cỡ việc, điều kiện trước, tín hiệu "đến lúc làm", nguồn gốc.
Làm xong mục nào thì chuyển sang Changelog trong `README.md` và xoá khỏi đây.

Cỡ việc: **S** = vài giờ · **M** = 1–2 ngày · **L** = nhiều ngày / nhiều đợt.

---

## 1. Nguồn dữ liệu CVE

| # | Việc | Vì sao | Cỡ | Đến lúc làm khi… |
|---|---|---|---|---|
| 1.1 | **Cảnh báo nguồn quá hạn**: NVD / KEV / EPSS / MSRC quá 48 giờ không đồng bộ được → cảnh báo email/Telegram | Hiện chỉ có dòng "updated … ago", không ai để ý thì nguồn chết âm thầm | S | làm sớm – rẻ, giảm rủi ro "mù" |
| 1.2 | **Chỉ số độ phủ NVD** trên trang CVEs: "% CVE mới (30 ngày) chưa có CPE/CVSS" | Từ 15/4/2026 NIST chỉ bổ sung dữ liệu cho CVE ưu tiên → ITOps bỏ sót lỗ hổng mà không báo lỗi | S | làm sớm – là "đèn báo" cho 1.3 |
| 1.3 | **Bản ghi CVE gốc (CNA, cvelistV5)**: ✅ *một phần trong 2.9.0* – đã dùng cho Remediation và để thêm CVE còn thiếu vào kho. Còn lại: dùng làm nguồn chính cho *mọi* CVE (CPE matching cho thiết bị không agent, CVSS khi NVD khác CNA) | Giảm phụ thuộc NVD | M | chỉ số 1.2 vượt ~30–40% |
| 1.4 | **KEV của EUVD (ENISA)** làm nguồn "đang bị khai thác" thứ hai | CISA cắt giảm nhân sự → KEV có thể chậm | S–M | KEV chậm rõ rệt, hoặc khi cần đối chiếu NIS2/CRA |
| 1.5 | Wazuh CTI: chỉ dùng làm **link tham khảo** (✅ đã làm trong 2.9.0); *không* làm kho CVE chính (trái Quyết định A) | — | — | xem lại nếu Wazuh công bố điều khoản cho dùng API |

## 2. Remediation Mapping (khắc phục lỗ hổng)

| # | Việc | Vì sao | Cỡ | Điều kiện / tín hiệu |
|---|---|---|---|---|
| 2.1 | **Advisory Linux**: Ubuntu USN/OVAL, Red Hat CSAF, Debian tracker → gói + phiên bản đã vá + lệnh `apt`/`dnf` | Chính xác hơn NVD cho máy chủ Linux | M | khi số finding Linux đáng kể (hiện Wazuh đã cho `fixed_version` cho Linux) |
| 2.2 | **OSV.dev** cho thư viện mã nguồn mở (npm, PyPI, Maven, Go) | log4j/openssl trong ứng dụng tự phát triển | M | khi quét phần mềm tự viết / container |
| 2.3 | **CSAF của các vendor khác** (Cisco, Fortinet, VMware/Broadcom, Veeam nếu có) | Thiết bị mạng/ảo hoá không có agent | M–L | theo vendor có nhiều finding nhất |
| 2.4 | **Ma trận quy tắc (Rule-Based Matrix)** dịch dữ liệu advisory → hành động | Cần **người kiểm chứng và bảo trì** quy tắc; hiện chưa có → HOÃN | L | khi có người phụ trách review quy tắc định kỳ |
| 2.5 | **Lưu tiến độ checklist** theo từng finding (ai tick bước nào, khi nào) + đính kèm bằng chứng | Bằng chứng ISO 27001 A.8.8 | M | khi bắt đầu dùng checklist hằng ngày |
| 2.6 | **Tự đóng finding** khi agent báo đã đạt phiên bản/build đã vá | Hiện chỉ *hiển thị* "đã đạt bản vá"; tự đóng là đổi chính sách (nguồn quét mới là bên đóng finding) | S–M | sau vài tuần đối chiếu thấy tín hiệu "đã vá" luôn đúng |
| 2.7 | Tạo **phiếu thay đổi / ticket Jira** từ playbook | Nối quy trình change management | M | khi có Jira connector / quy trình CAB |
| 2.8 | ~~Cào web (scrape) hướng dẫn sửa lỗi~~ | **Loại bỏ** – dễ vỡ, không kiểm chứng, có thể bị cài lệnh độc, vướng điều khoản | — | không làm |

## 3. Agent

| # | Việc | Vì sao | Cỡ | Điều kiện |
|---|---|---|---|---|
| 3.1 | **Khoá ký bản cập nhật** (keygen một lần, cất khoá riêng ngoài server) | Bắt buộc trước 3.2 | S (IT làm) | — |
| 3.2 | **Nút "Update" trên Endpoints** (chọn máy/site/tag, xem tiến trình) – vẫn giữ chữ ký số | IT chủ động cập nhật | M–L | cần 3.1 + khoá công khai trên agent |
| 3.3 | **Gửi sự kiện gần như tức thì** (nghe Event Log, gửi trong vài giây); hiệu năng giữ 30–60 s | Cảnh báo nhanh hơn | M–L | khi cần phản ứng sự cố nhanh hơn ~1 phút |

## 4. Khác

| # | Việc | Ghi chú |
|---|---|---|
| 4.1 | Wazuh: nút mở thẳng dashboard Wazuh (SCA, FIM, malware, MITRE) cho từng máy | đã có trong Roadmap README |
| 4.2 | Báo cáo bằng chứng TSC (SOC 2) | khi có lịch audit |

## 5. Lưu lượng mạng (sau 2.10.0)

| # | Việc | Vì sao | Cỡ | Đến lúc làm khi… |
|---|---|---|---|---|
| 5.1 | **Domain cho từng kết nối**: agent đọc DNS cache / nhật ký DNS-Client của Windows; ghép theo IP + thời gian, ghi rõ nguồn tên | DNS do AD xử lý; log Unbound của pfSense không có IP trả lời | M–L | khi agent đã cài trên phần lớn máy trạm |
| 5.2 | **IP → máy/người theo thời gian** (`ip_identity`): agent, Aruba, DHCP (syslog pfSense) – có lịch sử, không chỉ ảnh chụp hiện tại | IP DHCP đổi chủ → flow cũ bị gán sai tên | M | cùng lúc 5.1 |
| 5.3 | **Tiến trình cho từng kết nối** (kiểu TCPView) do agent chụp – theo yêu cầu / khi có cảnh báo | Biết "rclone.exe" chứ không chỉ IP | M | sau 5.1 |
| 5.4 | **ASN / quốc gia** cho IP đích (DB-IP lite hoặc GeoLite2, tải hằng tháng) | Đích hiện chỉ là IP | S | sớm – rẻ |
| 5.5 | **Cảnh báo băng thông** theo VLAN / máy, baseline, đích mới | Phát hiện upload bất thường | M | sau 2–4 tuần dữ liệu |
| 5.6 | **Danh sách đen IP** (FireHOL) dùng khung đồng bộ feed của CVE | Phát hiện kết nối tới IP xấu | S–M | sau 5.4 |
| 5.7 | Dữ liệu traffic mẫu cho chế độ **dữ liệu mẫu** (demo) | Xem thử không cần pfSense | S | khi cần demo |
| 5.8 | Bảng phân vùng theo ngày / ClickHouse | Chỉ khi > ~2 000 bản ghi/giây | L | đo thấy chậm |

## 6. Vận hành chính ITOps (thêm 2026-11-14)

| # | Việc | Vì sao | Cỡ | Đến lúc làm khi… |
|---|---|---|---|---|
| 6.1 | **Watchdog bên ngoài**: máy/dịch vụ khác gọi `/api/health` mỗi 1–5 phút, báo Telegram khi không trả lời hoặc `ok=false` | ITOps chết thì không ai cảnh báo (điểm hỏng duy nhất) | S | làm sớm |
| 6.2 | **Chạy thử Docker trên máy chủ Linux thật** song song máy Windows: build, khôi phục bản sao lưu, nhận syslog/flow (`network_mode: host`), backup | Đường Docker chưa từng chạy trên máy chủ thật | M | trước khi chuyển khỏi máy Windows |
| 6.3 | **Đối chiếu thời gian lưu** (event 30 ngày, flow 7/60 ngày, archive log) với chính sách ISO 27001 / hợp đồng; ghi thành quyết định | Audit hỏi "giữ log bao lâu" | S | trước audit |
| 6.4 | **Bản sao lưu ra ngoài máy** (NAS/ổ khác) tự động + **diễn tập khôi phục** mỗi quý theo `MIGRATE-TO-NEW-MACHINE.md` | Backup hiện nằm cùng máy với CSDL | S–M | làm sớm |
| 6.5 | **Triển khai agent** cho phần lớn máy trạm/server (GPO / Intune / script) | Điều kiện của 3.x, 5.1–5.3 và độ phủ lỗ hổng; hiện mới 1 agent | M (IT làm) | sau 3.1 |
| 6.6 | **Tên DNS cố định** cho ITOps (vd. `itops.<domain>`), agent/pfSense trỏ theo tên | Đổi máy/IP không phải sửa thiết bị | S | lần đổi máy tới |
| 6.7 | **HTTPS mặc định** cho máy thật (chứng chỉ nội bộ AD CS) thay cho HTTP 8100 | Mật khẩu/agent token đi rõ trong LAN | S–M | khi lên máy chủ |
| 6.8 | Trang **"Tình trạng ITOps"**: backup gần nhất, dung lượng CSDL, tốc độ syslog/flow, lỗi đồng bộ feed, nguồn im lặng – một chỗ | Phát hiện sớm ITOps đang yếu | S–M | tuỳ |

## 7. Ý tưởng chờ xem xét (chưa đánh giá kỹ)

| # | Ý tưởng | Ghi chú |
|---|---|---|
| 7.1 | **Sao lưu cấu hình thiết bị** (pfSense `config.xml`, switch running-config) theo phiên bản + so sánh thay đổi | Gần với audit log thay đổi; cần quyền đọc cấu hình |
| 7.2 | **Theo dõi hạn**: bảo hành, license, tên miền, gia hạn hợp đồng ISP – cảnh báo trước 30/7 ngày | Mở rộng từ cảnh báo hạn SSL đã có |
| 7.3 | **Băng thông interface qua SNMP** (ifHCInOctets) làm nguồn dự phòng khi không có NetFlow | Không cần softflowd; chỉ có tổng, không có máy/đích |
| 7.4 | **Báo cáo tháng tự động** (uptime, sự cố, lỗ hổng, top traffic) gửi PDF/email cho quản lý | Tái dùng digest + SLA report |
| 7.5 | **Nhận diện máy lạ**: MAC/IP mới xuất hiện (Aruba, DHCP, flow) chưa có trong tài sản → cảnh báo | Hữu ích cho ISO 27001 A.5.9 (kiểm kê tài sản) |
| 7.6 | **Tách bộ thu** syslog/flow thành tiến trình riêng ghi thẳng PostgreSQL | Chỉ khi đo thấy nghẽn (xem 5.8) |
| 7.7 | **Phân quyền chỉ xem** theo site/nhóm (helpdesk xem, không sửa) | Khi có thêm người dùng ngoài IT |
| 7.8 | **Nút "đang xử lý / ai nhận"** trên cảnh báo + ghi chú, để nhiều người không làm trùng | Khi đội IT > 1–2 người trực |

## 8. Bảo mật: Wazuh alerts, IDS/IPS, Active Response (thêm 2026-11-16)

**Đã chốt khi bàn:**
- ITOps **không phát hiện, không chặn**. Suricata phát hiện, Wazuh lưu và tự chặn (Active Response trên pfSense). ITOps gắn ngữ cảnh (máy/người, CVE, traffic), quản lý case, giám sát cả chuỗi.
- ITOps **chỉ đọc** Wazuh (indexer 9200, API 55000), hỏi trực tiếp mỗi lần xem, **không sao chép** toàn bộ alert vào CSDL (Quyết định A). ITOps chỉ lưu case, ghi chú, trạng thái.
- Việc hằng ngày làm trên ITOps; truy vấn tự do, dashboard tự vẽ, log thô, sửa rule/decoder vẫn làm trên Wazuh (mỗi alert có nút mở đúng alert đó bên Wazuh – nối với 4.1).
- **Có dữ liệu thật trước, rồi mới chốt thiết kế và code.** Mockup Network IDS (bản nháp, dữ liệu mẫu): https://claude.ai/artifact/WjwdPqNVUg3XGDWh25Qqqv

| # | Việc | Vì sao | Cỡ | Đến lúc làm khi… |
|---|---|---|---|---|
| 8.1 | **Sức khoẻ và độ phủ Wazuh agent**: cảnh báo agent mất kết nối / chưa từng kết nối / bản cũ; danh sách máy trong ITOps chưa có Wazuh agent | Hiện chỉ đọc danh sách agent để ghép máy cho CVE; máy không có agent thì CVE/malware "mù" mà không ai biết | S–M | làm sớm – dữ liệu API đã có |
| 8.2 | **Bộ đọc Wazuh alerts dùng chung** (`wazuh-alerts-*`): lọc theo nhóm, mức, máy, thời gian; ghép `agent`/IP → máy ITOps | Nền chung cho 8.3–8.5 và 8.7; làm một lần | M | sau 8.1 |
| 8.3 | **Trang Security events**: danh sách alert mức cao, dòng thời gian theo máy (đặt cạnh CVE + traffic), chi tiết alert (JSON + giải thích), nút mở Wazuh | Người vận hành không phải mở Wazuh hằng ngày | M | sau 8.2 |
| 8.4 | **~15 hunt soạn sẵn** bấm một lần: đăng nhập sai nhiều lần, thêm vào Administrators, dịch vụ mới, PowerShell mã hoá, file lạ ở Startup, USB… | Người không rành Wazuh vẫn "săn" được | M | sau 8.3; kiểm module nào đang bật |
| 8.5 | **Malware**: hiển thị alert FIM/syscheck, rootcheck, VirusTotal, YARA/ClamAV; gộp với sự kiện Defender từ agent ITOps | Hiện ITOps chỉ thấy Defender, chưa thấy malware từ Wazuh | M | khi các module này bật trên Wazuh (cần kiểm) |
| 8.6 | **Cài Suricata** trên VM Proxmox: 2 NIC (NIC bắt gói không IP, nhận SPAN), ET Open, `suricata-update`; **Wazuh agent** đọc `eve.json` chỉ gửi `alert` + `stats`, `dns`/`tls`/`flow` để lại trên sensor | Chưa có dữ liệu IDS thì 8.7 chỉ là giả định | M (IT làm) | làm trước 8.7 |
| 8.7 | **Trang Network IDS** (Overview · Cases · Case detail): case = SID + máy nội bộ, tự đóng sau 7 ngày im, tái diễn; **alert khớp CVE đang mở trên máy → P1**; link sang Network traffic | Một chỗ xem IDS kèm ngữ cảnh | L | sau 1–2 tuần dữ liệu 8.6 + tune rule nhiễu; dùng lại 8.2 |
| 8.8 | **Active Response cài tay trên lab**: 1 rule → chặn tại pfSense (Wazuh agent trên pfSense, `location: defined-agent`, script `pf`), **có timeout**, whitelist `HOME_NET`/DNS/gateway/hệ thống trọng yếu; không dùng `location: local` (VM Suricata không nằm trên đường đi) | Chặn sau khi phát hiện; chỉ hiệu quả với tấn công kéo dài (dò quét, brute-force, C2) | M (IT làm) | sau 8.6 + 2–4 tuần IDS không báo nhầm (rule "tốt nghiệp") |
| 8.9 | **Tab Auto-block (chỉ đọc)**: IP đang chặn, lý do, giờ gỡ; nghi chặn nhầm (đối chiếu NetFlow); rule được phép chặn + whitelist đọc từ Wazuh; cảnh báo khi agent pfSense/VM Suricata mất kết nối | Active Response chạy âm thầm, cần nơi kiểm soát | M | sau 8.8 |
| 8.10 | **Bộ kiểm tra bắt buộc cho trang mới** (ghi `docs/TESTING.md`): sort mọi cột tăng/giảm với số, rỗng, trùng, mức độ; lọc kết hợp; số ô tổng = số dòng; dữ liệu thật; sáng/tối; màn hẹp; 5 000 dòng; toàn bộ test cũ đạt; nhãn Beta 1–2 tuần | Tránh lỗi cơ bản kiểu sort CVE | S | commit đầu tiên khi code 8.3 / 8.7 |
| 8.11 | **Sửa nhỏ tab By CVE**: cờ KEV lấy từ danh mục CVE, không từ finding đầu tiên (`vuln_policy.by_cve`) + test | Finding mới chưa tính lại có thể làm CVE hiện "không KEV", sort sai cột KEV | S | làm sớm |
| 8.12 | **Đối chiếu CVE/Vulnerabilities với dữ liệu thật**: export CSV theo từng kiểu sort + chụp trang CVEs → script kiểm thứ tự, số khớp, dữ liệu lạ | Code đã rà (sort server-side, padding IP/CVE, scroll Wazuh) nhưng chưa kiểm trên dữ liệu thật | S | làm sớm |

**Đã cân nhắc, chưa làm:**
- ~~ITOps soạn "policy" rồi đẩy rule/CDB list sang Wazuh qua API~~ – số rule tự chặn ít (5–20), ít khi sửa; thêm rủi ro ITOps ghi vào hệ thống khác (cần ADR mới, RBAC, duyệt 2 người). Xem lại khi: rule phải sửa hằng tuần, có nhiều người không rành Linux phải tự sửa, hoặc có nhiều sensor/manager. Nếu làm: ITOps chỉ quản file rule + list riêng, **không bao giờ sửa `ossec.conf`**, có chế độ chạy thử "would_block".
- ~~Agent ITOps đọc thẳng `eve.json` thay Wazuh agent~~ – Active Response cần alert nằm trong Wazuh; hai đường dữ liệu song song dễ lệch.
- ~~Quản lý rule/policy Suricata trong ITOps (kiểu IDSTower)~~ – cần đẩy cấu hình xuống sensor, trái nguyên tắc agent chỉ gửi lên. Xem lại khi có nhiều sensor.

---
*Tạo 2026-11-11. Thêm mục 6–7: 2026-11-14 (chưa rà). Thêm mục 8: 2026-11-16 (chưa rà). Rà lại lần tới: ________ (người rà: ________)*
