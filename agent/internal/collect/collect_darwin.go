//go:build darwin

package collect

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
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
	s.Serial = macSerial(out("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
	if b, err := strconv.ParseUint(out("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
		s.RAMMB = int(b >> 20)
	}
	s.BootTime = macBoot(out("sysctl", "-n", "kern.boottime"))
	return s
}

func (m *mac) Metrics() protocol.Metrics {
	res := protocol.Metrics{Disks: []protocol.Disk{}}
	res.CPU = macCPU(out("top", "-l", "2", "-n", "0", "-s", "1"))
	total, _ := strconv.ParseFloat(out("sysctl", "-n", "hw.memsize"), 64)
	page, _ := strconv.ParseFloat(out("pagesize"), 64)
	res.Mem = macMem(out("vm_stat"), total, page)
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
	return macLaunchctl(string(b)), nil
}

func (m *mac) Software() ([]protocol.Software, error) {
	b, err := run(180*time.Second, "system_profiler", "SPApplicationsDataType", "-json", "-detailLevel", "mini")
	if err != nil {
		return nil, err
	}
	return macApps(b)
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
		ev, ts, ok := macLogLine(sc.Bytes(), want)
		if !ts.IsZero() {
			now = ts.Add(time.Second)
		}
		if ok {
			res = append(res, ev)
		}
	}
	st.SinceUnix = now.Unix()
	return res, nil
}
