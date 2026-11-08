//go:build darwin

package collect

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"itops/agent/pkg/protocol"
)

type mac struct{}

func New() Collector { return &mac{} }

func (m *mac) OSFamily() string { return "darwin" }

func out(name string, args ...string) string {
	b, _ := run(20*time.Second, name, args...)
	return strings.TrimSpace(string(b))
}

var reSerial = regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)
var reBoot = regexp.MustCompile(`sec = (\d+)`)

func (m *mac) System() protocol.SystemInfo {
	h, _ := os.Hostname()
	host, dom, _ := strings.Cut(h, ".")
	if dom == "local" {
		dom = ""
	}
	s := protocol.SystemInfo{Hostname: host, Domain: dom, OSName: out("sw_vers", "-productName") + " " + out("sw_vers", "-productVersion"),
		OSVersion: out("sw_vers", "-buildVersion"), OSKind: "client", Arch: runtime.GOARCH, Manufacturer: "Apple",
		Model: out("sysctl", "-n", "hw.model"), CPUModel: out("sysctl", "-n", "machdep.cpu.brand_string"), CPUCores: runtime.NumCPU(),
		IPs: LocalIPs(), LoggedUser: out("stat", "-f", "%Su", "/dev/console")}
	if s.LoggedUser == "root" {
		s.LoggedUser = "" // màn hình đăng nhập, chưa ai dùng
	}
	if mm := reSerial.FindStringSubmatch(out("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")); mm != nil {
		s.Serial = mm[1]
	}
	if b, err := strconv.ParseUint(out("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
		s.RAMMB = int(b >> 20)
	}
	if mm := reBoot.FindStringSubmatch(out("sysctl", "-n", "kern.boottime")); mm != nil {
		sec, _ := strconv.ParseInt(mm[1], 10, 64)
		t := time.Unix(sec, 0).UTC()
		s.BootTime = &t
	}
	return s
}

var reCPU = regexp.MustCompile(`CPU usage: [\d.]+% user, [\d.]+% sys, ([\d.]+)% idle`)
var reVM = regexp.MustCompile(`^(.+):\s+(\d+)\.`)

func (m *mac) Metrics() protocol.Metrics {
	res := protocol.Metrics{Disks: []protocol.Disk{}}
	if all := reCPU.FindAllStringSubmatch(out("top", "-l", "2", "-n", "0", "-s", "1"), -1); len(all) > 0 {
		idle, _ := strconv.ParseFloat(all[len(all)-1][1], 64)
		res.CPU = f64(round1(100 - idle))
	}
	total, _ := strconv.ParseFloat(out("sysctl", "-n", "hw.memsize"), 64)
	page, _ := strconv.ParseFloat(out("pagesize"), 64)
	pages := map[string]float64{}
	for _, line := range strings.Split(out("vm_stat"), "\n") {
		if mm := reVM.FindStringSubmatch(line); mm != nil {
			pages[mm[1]], _ = strconv.ParseFloat(mm[2], 64)
		}
	}
	if total > 0 && page > 0 {
		free := (pages["Pages free"] + pages["Pages inactive"] + pages["Pages speculative"]) * page
		res.Mem = f64(round1(100 * (1 - free/total)))
	}
	for _, p := range []string{"/System/Volumes/Data", "/"} {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) != nil || st.Blocks == 0 {
			continue
		}
		tot := float64(st.Blocks) * float64(st.Bsize)
		avail := float64(st.Bavail) * float64(st.Bsize)
		res.Disks = append(res.Disks, protocol.Disk{Mount: "Macintosh HD", FS: "APFS", TotalGB: round1(tot / (1 << 30)), UsedPct: round1(100 * (1 - avail/tot))})
		break // các volume APFS dùng chung dung lượng – một dòng là đủ
	}
	if bt := m.System().BootTime; bt != nil {
		res.UptimeS = int64(time.Since(*bt).Seconds())
	}
	return res
}

func (m *mac) Services() ([]protocol.Service, error) {
	b, err := run(20*time.Second, "launchctl", "list")
	if err != nil {
		return nil, err
	}
	var res []protocol.Service
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || strings.HasPrefix(f[2], "com.apple.") {
			continue // bỏ dịch vụ của chính macOS – quá nhiều, không cần cho helpdesk
		}
		st := "running"
		if f[0] == "-" {
			st = "stopped"
		}
		res = append(res, protocol.Service{Name: f[2], State: st})
	}
	return res, nil
}

func (m *mac) Software() ([]protocol.Software, error) {
	b, err := run(180*time.Second, "system_profiler", "SPApplicationsDataType", "-json", "-detailLevel", "mini")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Apps []struct {
			Name     string `json:"_name"`
			Version  string `json:"version"`
			Obtained string `json:"obtained_from"`
			Path     string `json:"path"`
			Modified string `json:"lastModified"`
			Info     string `json:"info"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var res []protocol.Software
	for _, a := range doc.Apps {
		if strings.HasPrefix(a.Path, "/System/") || seen[a.Name+a.Version] {
			continue
		}
		seen[a.Name+a.Version] = true
		res = append(res, protocol.Software{Name: trunc(a.Name, 255), Version: trunc(a.Version, 128), Publisher: trunc(a.Obtained, 255),
			InstalledOn: trunc(a.Modified, 10), Source: "app"})
	}
	sort.Slice(res, func(x, y int) bool { return strings.ToLower(res[x].Name) < strings.ToLower(res[y].Name) })
	return res, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m *mac) Defender() (map[string]any, error) { return nil, nil }

func (m *mac) Updates() (map[string]any, error) { return map[string]any{}, nil }

func (m *mac) Posture() (map[string]any, error) {
	return map[string]any{
		"filevault":  strings.Contains(out("fdesetup", "status"), "On"),
		"firewall":   strings.Contains(out("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), "enabled"),
		"gatekeeper": strings.Contains(out("spctl", "--status"), "enabled"),
		"sip":        strings.Contains(out("csrutil", "status"), "enabled"),
	}, nil
}

// Sự kiện: unified log (log show) – chỉ lọc đăng nhập SSH sai và sudo sai mật khẩu.
const logPredicate = `(process == "sshd" AND (eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "authentication error")) OR (process == "sudo" AND eventMessage CONTAINS "incorrect password")`

func (m *mac) Events(cfg protocol.Config, st *EventState, max int) ([]protocol.Event, error) {
	want := map[string]bool{}
	for _, k := range cfg.UnixEvents {
		want[k] = true
	}
	start := time.Unix(st.SinceUnix, 0)
	if st.SinceUnix == 0 {
		start = time.Now().Add(-time.Duration(cfg.BackfillHours) * time.Hour)
	}
	now := time.Now()
	cmd := exec.Command("log", "show", "--style", "ndjson", "--start", start.Format("2006-01-02 15:04:05"), "--predicate", logPredicate)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var res []protocol.Event
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() && len(res) < max {
		var e struct {
			TS   string `json:"timestamp"`
			Msg  string `json:"eventMessage"`
			Proc string `json:"processImagePath"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Msg == "" {
			continue
		}
		ts, err := time.Parse("2006-01-02 15:04:05.000000-0700", e.TS)
		if err != nil {
			continue
		}
		kind, data := classify(filepath.Base(e.Proc), e.Msg)
		if kind == "" || !want[kind] {
			continue
		}
		res = append(res, protocol.Event{Channel: "unifiedlog", Provider: filepath.Base(e.Proc), Kind: kind,
			RecordID: ts.UnixMicro(), TS: ts.UTC(), Data: data, Message: trunc(e.Msg, 2000)})
		now = ts.Add(time.Second)
	}
	st.SinceUnix = now.Unix()
	return res, nil
}
