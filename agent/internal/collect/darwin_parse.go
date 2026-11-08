package collect

// Đọc kết quả lệnh của macOS – tách khỏi collect_darwin.go để kiểm thử được trên mọi hệ điều hành.

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"itops/agent/pkg/protocol"
)

var (
	reSerial = regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)
	reBoot   = regexp.MustCompile(`sec = (\d+)`)
	reCPU    = regexp.MustCompile(`CPU usage: [\d.]+% user, [\d.]+% sys, ([\d.]+)% idle`)
	reVM     = regexp.MustCompile(`^(.+):\s+(\d+)\.`)
)

// macCPU: lấy mẫu CUỐI của `top -l 2 -n 0` (mẫu đầu là trung bình từ lúc khởi động).
func macCPU(top string) *float64 {
	all := reCPU.FindAllStringSubmatch(top, -1)
	if len(all) == 0 {
		return nil
	}
	idle, _ := strconv.ParseFloat(all[len(all)-1][1], 64)
	return f64(round1(100 - idle))
}

// macMem: % RAM đang dùng từ `vm_stat` (trống = free + inactive + speculative).
func macMem(vmstat string, total, page float64) *float64 {
	pages := map[string]float64{}
	for _, line := range strings.Split(vmstat, "\n") {
		if mm := reVM.FindStringSubmatch(strings.TrimSpace(line)); mm != nil {
			pages[mm[1]], _ = strconv.ParseFloat(mm[2], 64)
		}
	}
	if total <= 0 || page <= 0 || len(pages) == 0 {
		return nil
	}
	free := (pages["Pages free"] + pages["Pages inactive"] + pages["Pages speculative"]) * page
	return f64(round1(100 * (1 - free/total)))
}

func macSerial(ioreg string) string {
	if mm := reSerial.FindStringSubmatch(ioreg); mm != nil {
		return mm[1]
	}
	return ""
}

func macBoot(kern string) *time.Time {
	mm := reBoot.FindStringSubmatch(kern)
	if mm == nil {
		return nil
	}
	sec, _ := strconv.ParseInt(mm[1], 10, 64)
	t := time.Unix(sec, 0).UTC()
	return &t
}

// macLaunchctl: `launchctl list` → dịch vụ (bỏ com.apple.* – của chính macOS, quá nhiều).
func macLaunchctl(out string) []protocol.Service {
	var res []protocol.Service
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || strings.HasPrefix(f[2], "com.apple.") {
			continue
		}
		st := "running"
		if f[0] == "-" {
			st = "stopped"
		}
		res = append(res, protocol.Service{Name: f[2], State: st})
	}
	return res
}

// macApps: `system_profiler SPApplicationsDataType -json` → phần mềm (bỏ app hệ thống trong /System).
func macApps(js []byte) ([]protocol.Software, error) {
	var doc struct {
		Apps []struct {
			Name     string `json:"_name"`
			Version  string `json:"version"`
			Obtained string `json:"obtained_from"`
			Path     string `json:"path"`
			Modified string `json:"lastModified"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var res []protocol.Software
	for _, a := range doc.Apps {
		if strings.HasPrefix(a.Path, "/System/") || seen[a.Name+a.Version] {
			continue
		}
		seen[a.Name+a.Version] = true
		res = append(res, protocol.Software{Name: truncS(a.Name, 255), Version: truncS(a.Version, 128), Publisher: truncS(a.Obtained, 255),
			InstalledOn: truncS(a.Modified, 10), Source: "app"})
	}
	sort.Slice(res, func(x, y int) bool { return strings.ToLower(res[x].Name) < strings.ToLower(res[y].Name) })
	return res, nil
}

// macLogLine: một dòng `log show --style ndjson` → sự kiện (nếu là loại cần thu).
func macLogLine(line []byte, want map[string]bool) (protocol.Event, time.Time, bool) {
	var e struct {
		TS   string `json:"timestamp"`
		Msg  string `json:"eventMessage"`
		Proc string `json:"processImagePath"`
	}
	if json.Unmarshal(line, &e) != nil || e.Msg == "" {
		return protocol.Event{}, time.Time{}, false
	}
	ts, err := time.Parse("2006-01-02 15:04:05.000000-0700", e.TS)
	if err != nil {
		return protocol.Event{}, time.Time{}, false
	}
	kind, data := classify(filepath.Base(e.Proc), e.Msg)
	if kind == "" || !want[kind] {
		return protocol.Event{}, ts, false
	}
	return protocol.Event{Channel: "unifiedlog", Provider: filepath.Base(e.Proc), Kind: kind, RecordID: ts.UnixMicro(), TS: ts.UTC(),
		Data: data, Message: truncS(e.Msg, 2000)}, ts, true
}

func truncS(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
