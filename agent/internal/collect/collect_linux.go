//go:build linux

package collect

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"itops/agent/pkg/protocol"
)

type linux struct{ prevIdle, prevTotal uint64 }

func New() Collector { return &linux{} }

func (l *linux) OSFamily() string { return "linux" }

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func osRelease() map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(readFile("/etc/os-release"), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func (l *linux) System() protocol.SystemInfo {
	h, _ := os.Hostname()
	host, dom, _ := strings.Cut(h, ".")
	rel := osRelease()
	s := protocol.SystemInfo{Hostname: host, Domain: dom, OSName: rel["PRETTY_NAME"], OSVersion: rel["VERSION_ID"],
		Arch: runtime.GOARCH, Manufacturer: readFile("/sys/class/dmi/id/sys_vendor"), Model: readFile("/sys/class/dmi/id/product_name"),
		Serial: readFile("/sys/class/dmi/id/product_serial"), MachineID: strings.TrimSpace(readFile("/etc/machine-id")), CPUCores: runtime.NumCPU(), IPs: LocalIPs(), MACs: LocalMACs(), OSKind: "server"}
	if out, err := run(5*time.Second, "systemctl", "get-default"); err == nil && strings.Contains(string(out), "graphical") {
		s.OSKind = "client"
	}
	for _, line := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
			s.CPUModel = strings.TrimSpace(v)
			break
		}
	}
	if kb := meminfo()["MemTotal"]; kb > 0 {
		s.RAMMB = int(kb / 1024)
	}
	for _, line := range strings.Split(readFile("/proc/stat"), "\n") {
		if strings.HasPrefix(line, "btime ") {
			if sec, err := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64); err == nil {
				t := time.Unix(sec, 0).UTC()
				s.BootTime = &t
			}
		}
	}
	if out, err := run(5*time.Second, "who"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				s.LoggedUser, s.UserSource = f[0], "console"
				if strings.Contains(line, "pts/") && !strings.Contains(line, "(:") {
					s.UserSource = "ssh"
				}
				if strings.Contains(line, "(:0") || strings.Contains(line, "tty7") || strings.Contains(line, "seat") {
					break // ưu tiên người đang ngồi máy (phiên đồ hoạ)
				}
			}
		}
	}
	return s
}

func meminfo() map[string]uint64 {
	m := map[string]uint64{}
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			m[strings.TrimSuffix(f[0], ":")] = v
		}
	}
	return m
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true,
	"exfat": true, "ntfs": true, "ntfs3": true, "f2fs": true, "jfs": true, "reiserfs": true}

func (l *linux) Metrics() protocol.Metrics {
	m := protocol.Metrics{Disks: []protocol.Disk{}}
	sample := func() (idle, total uint64, ok bool) {
		f := strings.Fields(strings.SplitN(readFile("/proc/stat"), "\n", 2)[0])
		if len(f) <= 4 || f[0] != "cpu" {
			return 0, 0, false
		}
		for i, x := range f[1:] {
			v, _ := strconv.ParseUint(x, 10, 64)
			total += v
			if i == 3 || i == 4 { // idle + iowait
				idle += v
			}
		}
		return idle, total, true
	}
	if idle, total, ok := sample(); ok {
		if l.prevTotal == 0 { // lần đầu: thêm một mẫu sau 0,5 giây (chỉ một lần)
			l.prevIdle, l.prevTotal = idle, total
			time.Sleep(500 * time.Millisecond)
			idle, total, _ = sample()
		}
		if total > l.prevTotal {
			m.CPU = f64(round1(100 * (1 - float64(idle-l.prevIdle)/float64(total-l.prevTotal))))
		}
		l.prevIdle, l.prevTotal = idle, total
	}
	mi := meminfo()
	if mi["MemTotal"] > 0 {
		m.Mem = f64(round1(100 * (1 - float64(mi["MemAvailable"])/float64(mi["MemTotal"]))))
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(readFile("/proc/mounts"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] || strings.HasPrefix(f[1], "/snap/") {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(f[1], &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[f[0]] = true
		total := float64(st.Blocks) * float64(st.Bsize)
		if total < 1<<30 {
			continue // phân vùng nhỏ (/boot/efi, ảnh snap, ổ gắn tạm) đầy là bình thường – không đưa vào cảnh báo ổ đầy
		}
		used := total - float64(st.Bfree)*float64(st.Bsize)
		avail := float64(st.Bavail) * float64(st.Bsize)
		pct := 0.0
		if used+avail > 0 {
			pct = 100 * used / (used + avail) // như lệnh df (phần dành riêng cho root không tính là trống)
		}
		m.Disks = append(m.Disks, protocol.Disk{Mount: strings.ReplaceAll(f[1], `\040`, " "), FS: f[2], TotalGB: round1(total / (1 << 30)), UsedPct: round1(pct)})
	}
	if up := strings.Fields(readFile("/proc/uptime")); len(up) > 0 {
		v, _ := strconv.ParseFloat(up[0], 64)
		m.UptimeS = int64(v)
	}
	return m
}

func (l *linux) Services() ([]protocol.Service, error) {
	start := map[string]string{}
	if out, err := run(20*time.Second, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 2 {
				st := f[1]
				if st == "enabled" {
					st = "auto"
				}
				start[f[0]] = st
			}
		}
	}
	out, err := run(20*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, err
	}
	var res []protocol.Service
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] == "not-found" {
			continue
		}
		state := map[string]string{"running": "running", "exited": "exited", "dead": "stopped", "failed": "failed"}[f[3]]
		if state == "" {
			state = f[3]
		}
		res = append(res, protocol.Service{Name: f[0], Display: strings.Join(f[4:], " "), State: state, Start: start[f[0]]})
	}
	return res, nil
}

func (l *linux) Software() ([]protocol.Software, error) {
	var res []protocol.Software
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := run(60*time.Second, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${db:Status-Abbrev}\t${source:Package}\n")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Split(line, "\t")
			if len(f) >= 4 && strings.HasPrefix(f[3], "ii") {
				sw := protocol.Software{Name: f[0], Version: f[1], Publisher: trunc(f[2], 255), Source: "dpkg"}
				if len(f) >= 5 {
					sw.SourcePkg = trunc(f[4], 255)
				}
				res = append(res, sw)
			}
		}
	} else if _, err := exec.LookPath("rpm"); err == nil {
		out, err := run(60*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\t%{SOURCERPM}\n")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Split(line, "\t"); len(f) >= 3 && f[0] != "" && !strings.HasPrefix(f[0], "gpg-pubkey") {
				sw := protocol.Software{Name: f[0], Version: f[1], Publisher: trunc(f[2], 255), Source: "rpm"}
				if len(f) >= 5 {
					sw.SourcePkg = trunc(srpmName(f[4]), 255)
				}
				res = append(res, sw)
			}
		}
	}
	if _, err := exec.LookPath("snap"); err == nil {
		if out, err := run(30*time.Second, "snap", "list"); err == nil {
			for i, line := range strings.Split(string(out), "\n") {
				if f := strings.Fields(line); i > 0 && len(f) >= 2 {
					res = append(res, protocol.Software{Name: f[0], Version: f[1], Source: "snap"})
				}
			}
		}
	}
	sort.Slice(res, func(a, b int) bool { return res[a].Name < res[b].Name })
	return res, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (l *linux) Defender() (map[string]any, error) { return nil, nil }

func (l *linux) Updates() (map[string]any, error) {
	_, err := os.Stat("/var/run/reboot-required")
	return map[string]any{"reboot_pending": err == nil}, nil
}

func (l *linux) Posture() (map[string]any, error) {
	p := map[string]any{}
	if out, err := run(10*time.Second, "ufw", "status"); err == nil {
		p["firewall"] = strings.Contains(string(out), "Status: active")
		p["firewall_tool"] = "ufw"
	} else if out, err := run(10*time.Second, "systemctl", "is-active", "firewalld"); err == nil || len(out) > 0 {
		p["firewall"] = strings.TrimSpace(string(out)) == "active"
		p["firewall_tool"] = "firewalld"
	}
	return p, nil
}

// ---------------------------------------------------------------- sự kiện: journald
// Chỉ đọc các nguồn có thể sinh sự kiện trong danh mục – giảm khối lượng phải duyệt.
var journalMatches = []string{"SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "SYSLOG_IDENTIFIER=sudo", "+",
	"SYSLOG_IDENTIFIER=useradd", "+", "SYSLOG_IDENTIFIER=usermod", "+", "SYSLOG_IDENTIFIER=gpasswd", "+", "SYSLOG_IDENTIFIER=login",
	"+", "SYSLOG_IDENTIFIER=su", "+", "_TRANSPORT=kernel", "+", "SYSLOG_IDENTIFIER=systemd"}

func jstr(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte // journald trả mảng byte khi nội dung không phải UTF-8
	if json.Unmarshal(raw, &b) == nil {
		return strings.ToValidUTF8(string(b), "?")
	}
	return ""
}

func (l *linux) Events(cfg protocol.Config, st *EventState, max int) ([]protocol.Event, error) {
	want := map[string]bool{}
	for _, k := range cfg.UnixEvents {
		want[k] = true
	}
	var out []protocol.Event
	if want["unclean_shutdown"] {
		if ev := uncleanShutdown(st); ev != nil {
			out = append(out, *ev)
		}
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return out, nil
	}
	args := []string{"-o", "json", "--no-pager", "-q"}
	if st.Cursor != "" {
		args = append(args, "--after-cursor="+st.Cursor)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(time.Now().Add(-time.Duration(cfg.BackfillHours)*time.Hour).Unix(), 10))
	}
	cmd := exec.Command("journalctl", append(args, journalMatches...)...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return out, err
	}
	if err := cmd.Start(); err != nil {
		return out, err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	scanned := 0
	for sc.Scan() && len(out) < max && scanned < 200000 {
		scanned++
		var e map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		st.Cursor = jstr(e["__CURSOR"])
		ident := jstr(e["SYSLOG_IDENTIFIER"])
		if jstr(e["_TRANSPORT"]) == "kernel" {
			ident = "kernel"
		}
		if ident == "sshd-session" {
			ident = "sshd"
		}
		msg := jstr(e["MESSAGE"])
		kind, data := classify(ident, msg)
		if kind == "" || !want[kind] {
			continue
		}
		us, _ := strconv.ParseInt(jstr(e["__REALTIME_TIMESTAMP"]), 10, 64)
		out = append(out, protocol.Event{Channel: "journal", Provider: ident, Kind: kind, RecordID: us,
			TS: time.UnixMicro(us).UTC(), Data: data, Message: trunc(msg, 2000)})
	}
	return out, nil
}

// uncleanShutdown: mỗi lần khởi động kiểm tra 1 lần xem lần chạy trước có tắt đúng cách không
// (chỉ khi agent đã chạy ở lần khởi động trước – tránh báo nhầm lúc mới cài).
func uncleanShutdown(st *EventState) *protocol.Event {
	boot := readFile("/proc/sys/kernel/random/boot_id")
	if boot == "" || boot == st.BootID {
		return nil
	}
	first := st.BootID == ""
	st.BootID = boot
	if first {
		return nil
	}
	out, err := run(20*time.Second, "journalctl", "-b", "-1", "-n", "40", "-o", "cat", "--no-pager", "-q")
	if err != nil || len(out) == 0 {
		return nil // không có journal lưu lâu dài → không kết luận
	}
	s := string(out)
	for _, ok := range []string{"Journal stopped", "systemd-shutdown", "Reached target System Power Off", "Reached target System Reboot",
		"Reached target Power-Off", "Reached target Reboot", "Shutting down."} {
		if strings.Contains(s, ok) {
			return nil
		}
	}
	return &protocol.Event{Channel: "journal", Provider: "agent", Kind: "unclean_shutdown", TS: time.Now().UTC(),
		Data: map[string]string{}, Message: "The previous boot ended without a clean shutdown"}
}

// srpmName: "openssl-3.0.7-25.el9.src.rpm" → "openssl" (bỏ phiên bản-bản phát hành).
func srpmName(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".src.rpm")
	if s == "(none)" {
		return ""
	}
	for i := 0; i < 2; i++ {
		if j := strings.LastIndex(s, "-"); j > 0 {
			s = s[:j]
		}
	}
	return s
}
