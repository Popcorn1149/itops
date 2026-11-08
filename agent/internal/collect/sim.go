package collect

// Máy GIẢ LẬP cho lệnh `itops-agent simulate` – để thử trên máy demo (vd. Windows) như thể có máy Windows/macOS thật.
// Dữ liệu thô dựng đúng định dạng hệ điều hành trả về (XML Event Log của Windows; launchctl, system_profiler,
// log show của macOS) rồi đi qua CÙNG hàm đọc mà agent thật dùng (ParseEventXML, macLaunchctl, macApps, macLogLine).

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"itops/agent/pkg/protocol"
)

type Sim struct {
	OS, Host, User, IP string
	Server             bool
	cpu, mem, disk     float64
	tick               int
	defenderOff        bool
}

func NewSim(os string, i int) *Sim {
	s := &Sim{OS: os, cpu: 5 + rand.Float64()*20, mem: 40 + rand.Float64()*30, disk: 40 + rand.Float64()*45}
	switch os {
	case "windows":
		s.Host = fmt.Sprintf("SIM-WIN%02d", i)
		s.User = fmt.Sprintf(`CTY\nv.gialap%02d`, i)
		s.IP = fmt.Sprintf("10.20.1.%d", 10+i)
		s.Server = i == 1 // máy đầu là máy chủ (để thử cảnh báo mất kết nối)
		s.defenderOff = i == 2
		if s.Server {
			s.Host, s.User = fmt.Sprintf("SIM-SRV%02d", i), ""
		}
	default:
		s.Host = fmt.Sprintf("SIM-MAC%02d", i)
		s.User = fmt.Sprintf("thietke%02d", i)
		s.IP = fmt.Sprintf("10.20.2.%d", 10+i)
	}
	return s
}

func (s *Sim) OSFamily() string { return s.OS }

func (s *Sim) System() protocol.SystemInfo {
	boot := time.Now().Add(-time.Duration(30+len(s.Host)) * time.Hour).UTC().Truncate(time.Minute)
	if s.OS == "windows" {
		name, kind, ver := "Windows 11 Pro", "client", "24H2 (build 26100.2314)"
		if s.Server {
			name, kind, ver = "Windows Server 2022 Standard", "server", "21H2 (build 20348.2849)"
		}
		return protocol.SystemInfo{Hostname: s.Host, Domain: "cty.local", OSName: name, OSVersion: ver, OSKind: kind, Arch: "amd64",
			Manufacturer: "Dell Inc.", Model: "OptiPlex 7010 (giả lập)", Serial: "SIM" + s.Host, CPUModel: "Intel(R) Core(TM) i5-13500",
			CPUCores: 14, RAMMB: 16384, BootTime: &boot, IPs: []string{s.IP}, LoggedUser: s.User}
	}
	return protocol.SystemInfo{Hostname: s.Host, OSName: "macOS 15.1", OSVersion: "24B83", OSKind: "client", Arch: "arm64",
		Manufacturer: "Apple", Model: "Mac14,9 (giả lập)", Serial: macSerial(`"IOPlatformSerialNumber" = "SIMC02` + s.Host[len(s.Host)-2:] + `"`),
		CPUModel: "Apple M2 Pro", CPUCores: 10, RAMMB: 16384, BootTime: macBoot(fmt.Sprintf("{ sec = %d, usec = 0 }", boot.Unix())),
		IPs: []string{s.IP}, LoggedUser: s.User}
}

func jit(v, d float64) float64 { return max(0.5, min(99, v+(rand.Float64()*2-1)*d)) }

func (s *Sim) Metrics() protocol.Metrics {
	s.tick++
	s.disk = min(99, s.disk+0.01)
	if s.OS == "darwin" { // đi qua hàm đọc top / vm_stat của macOS
		top := fmt.Sprintf("CPU usage: 50.00%% user, 10.00%% sys, 40.00%% idle\nCPU usage: 3.00%% user, 2.00%% sys, %.2f%% idle\n", 100-jit(s.cpu, 6))
		used := jit(s.mem, 3) / 100
		total := float64(16 << 30)
		vm := fmt.Sprintf("Pages free: %d.\nPages inactive: 0.\nPages speculative: 0.\n", int(total*(1-used)/16384))
		return protocol.Metrics{CPU: macCPU(top), Mem: macMem(vm, total, 16384), UptimeS: int64(30 * 3600),
			Disks: []protocol.Disk{{Mount: "Macintosh HD", FS: "APFS", TotalGB: 460, UsedPct: round1(s.disk)}}}
	}
	d := []protocol.Disk{{Mount: "C:", FS: "NTFS", TotalGB: 237, UsedPct: round1(s.disk)}}
	if s.Server {
		d = append(d, protocol.Disk{Mount: "D:", FS: "NTFS", TotalGB: 2000, UsedPct: 91.5}) // ổ dữ liệu gần đầy → cảnh báo
	}
	return protocol.Metrics{CPU: f64(round1(jit(s.cpu, 8))), Mem: f64(round1(jit(s.mem, 4))), Disks: d, UptimeS: int64(30 * 3600)}
}

func (s *Sim) Services() ([]protocol.Service, error) {
	if s.OS == "darwin" {
		return macLaunchctl("PID\tStatus\tLabel\n512\t0\tcom.apple.Finder\n743\t0\tcom.google.keystone.agent\n-\t78\tcom.microsoft.update.agent\n1201\t0\tvn.itops.agent\n"), nil
	}
	return []protocol.Service{{Name: "Spooler", Display: "Print Spooler", State: "running", Start: "auto"},
		{Name: "WinDefend", Display: "Microsoft Defender Antivirus Service", State: "running", Start: "auto"},
		{Name: "wuauserv", Display: "Windows Update", State: "stopped", Start: "manual"},
		{Name: "ITOpsAgent", Display: "IT Ops Agent", State: "running", Start: "auto-delayed"},
		{Name: "VeeamEndpointBackupSvc", Display: "Veeam Agent for Microsoft Windows", State: "stopped", Start: "auto"}}, nil
}

func (s *Sim) Software() ([]protocol.Software, error) {
	if s.OS == "darwin" {
		return macApps([]byte(`{"SPApplicationsDataType":[
 {"_name":"Safari","version":"18.1","obtained_from":"apple","path":"/System/Applications/Safari.app"},
 {"_name":"Google Chrome","version":"131.0.6778.86","obtained_from":"identified_developer","path":"/Applications/Google Chrome.app","lastModified":"2026-11-02T03:12:44Z"},
 {"_name":"Adobe Photoshop 2025","version":"26.1","obtained_from":"identified_developer","path":"/Applications/Adobe Photoshop 2025/Adobe Photoshop 2025.app"},
 {"_name":"Zalo","version":"24.10.1","obtained_from":"identified_developer","path":"/Applications/Zalo.app"}]}`))
	}
	sw := []protocol.Software{{Name: "Google Chrome", Version: "131.0.6778.86", Publisher: "Google LLC", Source: "machine"},
		{Name: "Microsoft 365 Apps for business - vi-vn", Version: "16.0.18129.20158", Publisher: "Microsoft Corporation", Source: "machine"},
		{Name: "Zalo", Version: "24.10.1", Publisher: "VNG Corp.", Source: "user"}, {Name: "7-Zip 24.08 (x64)", Version: "24.08", Publisher: "Igor Pavlov", Source: "machine"}}
	if strings.HasSuffix(s.Host, "03") {
		sw = append(sw, protocol.Software{Name: "AnyDesk", Version: "8.1.0", Publisher: "AnyDesk Software GmbH", Source: "user"})
	}
	return sw, nil
}

func (s *Sim) Defender() (map[string]any, error) {
	if s.OS != "windows" {
		return nil, nil
	}
	return map[string]any{"realtime": !s.defenderOff, "antivirus_enabled": true, "signature_age_days": 0, "signature_version": "1.421.15.0",
		"running_mode": "Normal", "quick_scan_age_days": 1, "full_scan_age_days": 12, "tamper_protection": !s.defenderOff}, nil
}

func (s *Sim) Updates() (map[string]any, error) {
	if s.OS != "windows" {
		return map[string]any{}, nil
	}
	return map[string]any{"reboot_pending": s.Server, "last_hotfix": map[string]any{"id": "KB5046617", "installed_on": "2026-11-01"}}, nil
}

func (s *Sim) Posture() (map[string]any, error) {
	if s.OS == "darwin" {
		return map[string]any{"filevault": true, "firewall": !strings.HasSuffix(s.Host, "02"), "gatekeeper": true, "sip": true}, nil
	}
	return map[string]any{"firewall": []map[string]any{{"name": "Domain", "enabled": true}, {"name": "Private", "enabled": true},
		{"name": "Public", "enabled": !s.defenderOff}}, "bitlocker": map[string]any{"protection": "Off", "status": "FullyDecrypted", "percent": 0}}, nil
}

// ---- sự kiện: dựng XML Event Log thật / dòng unified log thật rồi đọc bằng hàm của agent
const simXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='%s'/><EventID>%d</EventID><Level>%d</Level><TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID><Channel>%s</Channel><Computer>%s.cty.local</Computer></System><EventData>%s</EventData></Event>`

func dataXML(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, "<Data Name='%s'>%s</Data>", kv[i], kv[i+1])
	}
	return b.String()
}

func (s *Sim) Events(cfg protocol.Config, st *EventState, max int) ([]protocol.Event, error) {
	now := time.Now().UTC()
	var out []protocol.Event
	if s.OS == "darwin" {
		want := map[string]bool{}
		for _, k := range cfg.UnixEvents {
			want[k] = true
		}
		var lines []string
		if s.tick%4 == 1 { // dò mật khẩu SSH vào Mac (cả lần đầu)
			for i := 0; i < 12; i++ {
				lines = append(lines, fmt.Sprintf(`{"timestamp":"%s","eventMessage":"error: PAM: authentication error for illegal user %s from 198.51.100.%d","processImagePath":"/usr/sbin/sshd"}`,
					now.Add(time.Duration(i)*time.Second).In(time.FixedZone("", 7*3600)).Format("2006-01-02 15:04:05.000000-0700"), []string{"admin", "root", "test"}[i%3], 20+s.tick%5))
			}
		}
		if s.tick%6 == 3 || s.tick == 1 {
			lines = append(lines, fmt.Sprintf(`{"timestamp":"%s","eventMessage":"  %s : 3 incorrect password attempts ; TTY=ttys000 ; USER=root ; COMMAND=/bin/ls","processImagePath":"/usr/bin/sudo"}`,
				now.In(time.FixedZone("", 7*3600)).Format("2006-01-02 15:04:05.000000-0700"), s.User))
		}
		for _, l := range lines {
			if ev, _, ok := macLogLine([]byte(l), want); ok && len(out) < max {
				out = append(out, ev)
			}
		}
		return out, nil
	}
	if st.Bookmarks == nil {
		st.Bookmarks = map[string]int64{}
	}
	add := func(channel, provider string, id, level int, data string, at time.Time) {
		st.Bookmarks[channel]++
		if st.Bookmarks[channel] < 1000 {
			st.Bookmarks[channel] = 1000
		}
		x := fmt.Sprintf(simXML, provider, id, level, at.Format("2006-01-02T15:04:05.0000000Z"), st.Bookmarks[channel], channel, s.Host, data)
		if ev, ok := ParseEventXML(x); ok && len(out) < max {
			out = append(out, ev)
		}
	}
	sec := "Microsoft-Windows-Security-Auditing"
	phases := []int{s.tick % 6}
	if s.tick == 1 {
		phases = []int{1, 2, 3, 4, 5} // lần đầu: chạy mọi tình huống để thấy ngay trên giao diện
	}
	for _, ph := range phases {
		s.winPhase(ph, add, sec, now)
	}
	return out, nil
}

func (s *Sim) winPhase(ph int, add func(string, string, int, int, string, time.Time), sec string, now time.Time) {
	switch ph {
	case 1: // người dùng gõ sai mật khẩu mở khoá màn hình (bình thường, chỉ ghi nhận)
		add("Security", sec, 4625, 0, dataXML("TargetUserName", strings.TrimPrefix(s.User, `CTY\`), "TargetDomainName", "CTY",
			"WorkstationName", s.Host, "IpAddress", "127.0.0.1", "LogonType", "7", "SubStatus", "0xc000006a"), now)
	case 2:
		if s.Server { // dò mật khẩu RDP vào máy chủ → cảnh báo "Nghi dò mật khẩu"
			for i := 0; i < 12; i++ {
				add("Security", sec, 4625, 0, dataXML("TargetUserName", []string{"administrator", "admin", "ketoan", "backup"}[i%4],
					"TargetDomainName", "CTY", "WorkstationName", "SIM-WIN03", "IpAddress", "10.20.1.13", "LogonType", "10",
					"SubStatus", "0xc000006a"), now.Add(time.Duration(i)*time.Second))
			}
			add("Security", sec, 4740, 0, dataXML("TargetUserName", "ketoan", "TargetDomainName", "SIM-WIN03"), now.Add(15*time.Second))
		}
	case 3:
		if strings.HasSuffix(s.Host, "03") {
			add("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, 3, dataXML(
				"Threat Name", "Trojan:Win32/Wacatac.B!ml", "Severity Name", "Severe", "Category Name", "Trojan",
				"Path", `file:_C:\Users\`+strings.TrimPrefix(s.User, `CTY\`)+`\Downloads\HoaDon.pdf.exe`, "Detection User", s.User), now)
			add("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1117, 4, dataXML(
				"Threat Name", "Trojan:Win32/Wacatac.B!ml", "Action Name", "Quarantine", "Detection User", s.User), now.Add(time.Second))
		}
		if s.Server {
			add("System", "Service Control Manager", 7031, 2, dataXML("param1", "Veeam Agent for Microsoft Windows", "param2", "1"), now)
		}
	case 4:
		if s.Server {
			add("Security", sec, 4732, 0, dataXML("TargetUserName", "Administrators", "MemberName", "CN=Nhan Vien Gia Lap,OU=Users,DC=cty,DC=local",
				"SubjectUserName", "it.admin", "SubjectDomainName", "CTY"), now)
		}
	case 5: // các ID KHÔNG nằm trong chính sách – agent thật không lấy, gửi lên để thấy server cũng bỏ
		add("Security", sec, 4624, 0, dataXML("TargetUserName", "nv.gialap"), now)
	}
}
