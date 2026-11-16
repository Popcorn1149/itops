// Package collect: thu thập thông tin máy – CHỈ ĐỌC. Mỗi hệ điều hành một file (collect_windows.go, _linux.go, _darwin.go).
package collect

import (
	"net"
	"sort"
	"strings"

	"itops/agent/pkg/protocol"
)

// EventState: vị trí đã đọc tới trong nhật ký hệ thống (lưu xuống đĩa sau mỗi lần gửi vào hàng đợi).
type EventState struct {
	Bookmarks map[string]int64 `json:"bookmarks,omitempty"` // Windows: kênh → EventRecordID đã lấy
	Cursor    string           `json:"cursor,omitempty"`    // Linux: con trỏ journald
	SinceUnix int64            `json:"since_unix,omitempty"`
	BootID    string           `json:"boot_id,omitempty"` // đã kiểm tra "tắt máy đột ngột" cho lần khởi động này
}

type Collector interface {
	System() protocol.SystemInfo
	Metrics() protocol.Metrics
	Services() ([]protocol.Service, error)
	Software() ([]protocol.Software, error)
	Defender() (map[string]any, error) // Windows Defender; nil ở hệ điều hành khác
	Updates() (map[string]any, error)  // chờ khởi động lại, bản cập nhật gần nhất
	Posture() (map[string]any, error)  // tường lửa, mã hoá ổ đĩa...
	Events(cfg protocol.Config, st *EventState, max int) ([]protocol.Event, error)
	OSFamily() string
}

// LocalIPs: IPv4/IPv6 toàn cục của các card mạng đang bật (bỏ loopback, link-local).
func LocalIPs() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return strings.Contains(out[a], ".") && !strings.Contains(out[b], ".") })
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}

// LocalMACs: địa chỉ MAC (AA:BB:CC:DD:EE:FF) của các card mạng đang bật VÀ có IP toàn cục
// (bỏ loopback, card ảo chưa nối mạng, Bluetooth chưa dùng…). Card có IPv4 xếp trước.
func LocalMACs() []string {
	type nic struct {
		mac  string
		ipv4 bool
	}
	var list []nic
	seen := map[string]bool{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		mac := strings.ToUpper(i.HardwareAddr.String())
		if mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		addrs, _ := i.Addrs()
		has, v4 := false, false
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			has = true
			v4 = v4 || ipn.IP.To4() != nil
		}
		if has {
			seen[mac] = true
			list = append(list, nic{mac, v4})
		}
	}
	sort.SliceStable(list, func(a, b int) bool { return list[a].ipv4 && !list[b].ipv4 })
	out := make([]string, 0, len(list))
	for _, n := range list {
		out = append(out, n.mac)
	}
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}

func f64(v float64) *float64 { return &v }

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
