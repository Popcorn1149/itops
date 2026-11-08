//go:build windows

package collect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"itops/agent/pkg/protocol"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	pGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	pGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	pGetTickCount64       = kernel32.NewProc("GetTickCount64")
	wtsapi32              = windows.NewLazySystemDLL("wtsapi32.dll")
	pWTSQuerySessionInfoW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

type win struct {
	prevIdle, prevTotal uint64
	mu                  sync.Mutex
	ps                  map[string]any // kết quả PowerShell gần nhất (Defender, BitLocker, tường lửa, serial)
	psAt                time.Time
	pubs                map[string]windows.Handle
}

func New() Collector { return &win{pubs: map[string]windows.Handle{}} }

func (w *win) OSFamily() string { return "windows" }

// ---------------------------------------------------------------- thông tin máy
func regStr(k registry.Key, path, name string) string {
	key, err := registry.OpenKey(k, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	s, _, err := key.GetStringValue(name)
	if err != nil {
		if n, _, err2 := key.GetIntegerValue(name); err2 == nil {
			return strconv.FormatUint(n, 10)
		}
		return ""
	}
	return strings.TrimSpace(s)
}

type memStatusEx struct {
	Length, MemoryLoad                                 uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
	TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
}

func memStatus() (memStatusEx, bool) {
	var m memStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	return m, r != 0
}

func consoleUser() string {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return ""
	}
	q := func(class uintptr) string {
		var buf *uint16
		var n uint32
		r, _, _ := pWTSQuerySessionInfoW.Call(0, uintptr(sid), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
		if r == 0 || buf == nil {
			return ""
		}
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
		return windows.UTF16PtrToString(buf)
	}
	u, d := q(5), q(7) // WTSUserName, WTSDomainName
	if u == "" {
		return ""
	}
	if d != "" {
		return d + `\` + u
	}
	return u
}

func (w *win) System() protocol.SystemInfo {
	h, _ := os.Hostname()
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	name := regStr(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regStr(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	if b, _ := strconv.Atoi(build); b >= 22000 && strings.Contains(name, "Windows 10") {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1) // registry vẫn ghi "Windows 10" trên Windows 11
	}
	ver := regStr(registry.LOCAL_MACHINE, cv, "DisplayVersion")
	if ubr := regStr(registry.LOCAL_MACHINE, cv, "UBR"); build != "" {
		ver = strings.TrimSpace(fmt.Sprintf("%s (build %s.%s)", ver, build, ubr))
	}
	kind := "client"
	if strings.HasPrefix(regStr(registry.LOCAL_MACHINE, cv, "InstallationType"), "Server") {
		kind = "server"
	}
	s := protocol.SystemInfo{Hostname: h, OSName: name, OSVersion: ver, OSKind: kind, Arch: runtime.GOARCH,
		Manufacturer: regStr(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"),
		Model:        regStr(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"),
		CPUModel:     regStr(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"),
		CPUCores:     runtime.NumCPU(), IPs: LocalIPs(), LoggedUser: consoleUser()}
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	if windows.GetComputerNameEx(windows.ComputerNameDnsDomain, &buf[0], &n) == nil {
		s.Domain = windows.UTF16ToString(buf[:n])
	}
	if m, ok := memStatus(); ok {
		s.RAMMB = int(m.TotalPhys >> 20)
	}
	if r, _, _ := pGetTickCount64.Call(); r != 0 {
		t := time.Now().Add(-time.Duration(r) * time.Millisecond).UTC().Truncate(time.Minute)
		s.BootTime = &t
	}
	w.mu.Lock()
	if v, ok := w.ps["serial"].(string); ok {
		s.Serial = v
	}
	w.mu.Unlock()
	return s
}

// ---------------------------------------------------------------- hiệu năng
func ft(lo, hi uint32) uint64 { return uint64(hi)<<32 | uint64(lo) }

func (w *win) Metrics() protocol.Metrics {
	m := protocol.Metrics{Disks: []protocol.Disk{}}
	var idle, kern, user windows.Filetime
	if r, _, _ := pGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&user))); r != 0 {
		i := ft(idle.LowDateTime, idle.HighDateTime)
		total := ft(kern.LowDateTime, kern.HighDateTime) + ft(user.LowDateTime, user.HighDateTime) // kernel đã gồm idle
		if w.prevTotal > 0 && total > w.prevTotal {
			m.CPU = f64(round1(100 * (1 - float64(i-w.prevIdle)/float64(total-w.prevTotal))))
			w.prevIdle, w.prevTotal = i, total
		} else {
			w.prevIdle, w.prevTotal = i, total
			time.Sleep(500 * time.Millisecond)
			return w.Metrics()
		}
	}
	if ms, ok := memStatus(); ok && ms.TotalPhys > 0 {
		m.Mem = f64(round1(100 * (1 - float64(ms.AvailPhys)/float64(ms.TotalPhys))))
	}
	mask, _ := windows.GetLogicalDrives()
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree) != nil || total == 0 {
			continue
		}
		m.Disks = append(m.Disks, protocol.Disk{Mount: root[:2], FS: "NTFS", TotalGB: round1(float64(total) / (1 << 30)),
			UsedPct: round1(100 * (1 - float64(totalFree)/float64(total)))})
	}
	if r, _, _ := pGetTickCount64.Call(); r != 0 {
		m.UptimeS = int64(r / 1000)
	}
	return m
}

// ---------------------------------------------------------------- dịch vụ
var stateName = map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
	svc.Running: "running", svc.ContinuePending: "continuing", svc.PausePending: "pausing", svc.Paused: "paused"}

func (w *win) Services() ([]protocol.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var out []protocol.Service
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		item := protocol.Service{Name: n}
		if st, err := s.Query(); err == nil {
			item.State = stateName[st.State]
		}
		if c, err := s.Config(); err == nil {
			item.Display = c.DisplayName
			switch c.StartType {
			case mgr.StartAutomatic:
				item.Start = "auto"
				if c.DelayedAutoStart {
					item.Start = "auto-delayed"
				}
			case mgr.StartManual:
				item.Start = "manual"
			case mgr.StartDisabled:
				item.Start = "disabled"
			default:
				item.Start = "system"
			}
		}
		s.Close()
		out = append(out, item)
	}
	sort.Slice(out, func(a, b int) bool { return strings.ToLower(out[a].Display) < strings.ToLower(out[b].Display) })
	return out, nil
}

// ---------------------------------------------------------------- phần mềm (khoá Uninstall: máy + từng người dùng)
func (w *win) Software() ([]protocol.Software, error) {
	seen := map[string]bool{}
	var out []protocol.Software
	scan := func(root registry.Key, path string, access uint32, src string) {
		k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|access)
		if err != nil {
			return
		}
		defer k.Close()
		subs, _ := k.ReadSubKeyNames(-1)
		for _, sub := range subs {
			sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE|access)
			if err != nil {
				continue
			}
			get := func(n string) string { s, _, _ := sk.GetStringValue(n); return strings.TrimSpace(s) }
			name := get("DisplayName")
			sysComp, _, _ := sk.GetIntegerValue("SystemComponent")
			rt := get("ReleaseType")
			if name == "" || sysComp == 1 || get("ParentKeyName") != "" || strings.Contains(rt, "Update") || rt == "Hotfix" {
				sk.Close()
				continue
			}
			ver := get("DisplayVersion")
			if key := strings.ToLower(name + "|" + ver); !seen[key] {
				seen[key] = true
				inst := get("InstallDate")
				if len(inst) == 8 {
					inst = inst[:4] + "-" + inst[4:6] + "-" + inst[6:]
				}
				out = append(out, protocol.Software{Name: trunc(name, 255), Version: trunc(ver, 128), Publisher: trunc(get("Publisher"), 255),
					InstalledOn: trunc(inst, 32), Source: src})
			}
			sk.Close()
		}
	}
	const u = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	scan(registry.LOCAL_MACHINE, u, registry.WOW64_64KEY, "machine")
	scan(registry.LOCAL_MACHINE, u, registry.WOW64_32KEY, "machine-x86")
	if users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := users.ReadSubKeyNames(-1)
		users.Close()
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				scan(registry.USERS, sid+`\`+u, 0, "user") // chỉ hồ sơ người dùng đang đăng nhập (hive đã nạp)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return strings.ToLower(out[a].Name) < strings.ToLower(out[b].Name) })
	return out, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- Defender, BitLocker, tường lửa (PowerShell, chỉ đọc)
const psScript = `[Console]::OutputEncoding=[Text.Encoding]::UTF8
$ErrorActionPreference='SilentlyContinue'
$o=@{}
$mp=Get-MpComputerStatus
if($mp){ $o.defender=@{realtime=[bool]$mp.RealTimeProtectionEnabled; antivirus_enabled=[bool]$mp.AntivirusEnabled;
  am_service=[bool]$mp.AMServiceEnabled; signature_age_days=[int]$mp.AntivirusSignatureAge;
  signature_version=[string]$mp.AntivirusSignatureVersion;
  signature_updated=$(if($mp.AntivirusSignatureLastUpdated){$mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')});
  quick_scan_age_days=[int]$mp.QuickScanAge; full_scan_age_days=[int]$mp.FullScanAge; tamper_protection=[bool]$mp.IsTamperProtected;
  running_mode=[string]$mp.AMRunningMode; product_version=[string]$mp.AMProductVersion; engine_version=[string]$mp.AMEngineVersion} }
$av=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
if($av){ $o.av_products=@($av | ForEach-Object { [string]$_.displayName }) }
$fw=Get-NetFirewallProfile
if($fw){ $o.firewall=@($fw | ForEach-Object { @{name=[string]$_.Name; enabled=[bool]$_.Enabled} }) }
$bl=Get-BitLockerVolume -MountPoint $env:SystemDrive
if($bl){ $o.bitlocker=@{protection=[string]$bl.ProtectionStatus; status=[string]$bl.VolumeStatus; percent=[int]$bl.EncryptionPercentage} }
$hf=Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if($hf){ $o.last_hotfix=@{id=[string]$hf.HotFixID; installed_on=$hf.InstalledOn.ToString('yyyy-MM-dd')} }
$b=Get-CimInstance Win32_BIOS
if($b){ $o.serial=[string]$b.SerialNumber }
$o | ConvertTo-Json -Depth 4 -Compress`

func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (w *win) powershell() map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ps != nil && time.Since(w.psAt) < time.Minute {
		return w.ps
	}
	out, err := run(120*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePS(psScript))
	res := map[string]any{}
	if err == nil {
		_ = json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(string(out)), "\uFEFF")), &res)
	}
	w.ps, w.psAt = res, time.Now()
	return res
}

func (w *win) Defender() (map[string]any, error) {
	ps := w.powershell()
	d, _ := ps["defender"].(map[string]any)
	if d == nil {
		d = map[string]any{"available": false}
	}
	var other []string
	if list, ok := ps["av_products"].([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok && !strings.Contains(strings.ToLower(s), "defender") {
				other = append(other, s)
			}
		}
	}
	if len(other) > 0 {
		d["other_av"] = strings.Join(other, ", ")
	}
	return d, nil
}

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (w *win) Updates() (map[string]any, error) {
	u := map[string]any{"reboot_pending": keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) ||
		keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`)}
	if hf, ok := w.powershell()["last_hotfix"]; ok {
		u["last_hotfix"] = hf
	}
	return u, nil
}

func (w *win) Posture() (map[string]any, error) {
	ps := w.powershell()
	p := map[string]any{}
	for _, k := range []string{"firewall", "bitlocker"} {
		if v, ok := ps[k]; ok {
			p[k] = v
		}
	}
	return p, nil
}

// ---------------------------------------------------------------- nhật ký sự kiện (wevtapi)
var (
	wevtapi           = windows.NewLazySystemDLL("wevtapi.dll")
	pEvtQuery         = wevtapi.NewProc("EvtQuery")
	pEvtNext          = wevtapi.NewProc("EvtNext")
	pEvtRender        = wevtapi.NewProc("EvtRender")
	pEvtClose         = wevtapi.NewProc("EvtClose")
	pEvtOpenPublisher = wevtapi.NewProc("EvtOpenPublisherMetadata")
	pEvtFormatMessage = wevtapi.NewProc("EvtFormatMessage")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtRenderEventXml        = 1
	evtFormatMessageEvent    = 1
	errNoMoreItems           = 259
	errInsufficientBuffer    = 122
	errChannelNotFound       = 15007
)

func evtClose(h uintptr) {
	if h != 0 {
		pEvtClose.Call(h)
	}
}

func renderXML(h uintptr) (string, error) {
	buf := make([]uint16, 4096)
	for {
		var used, props uint32
		r, _, err := pEvtRender.Call(0, h, evtRenderEventXml, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		if en, ok := err.(syscall.Errno); ok && en == errInsufficientBuffer && used/2 > uint32(len(buf)) {
			buf = make([]uint16, used/2+16)
			continue
		}
		return "", err
	}
}

// formatMessage: câu mô tả Windows tự sinh (dự phòng khi server chưa có mẫu tiếng Việt).
func (w *win) formatMessage(provider string, h uintptr) string {
	pub, ok := w.pubs[provider]
	if !ok {
		p, _ := windows.UTF16PtrFromString(provider)
		r, _, _ := pEvtOpenPublisher.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 0)
		pub = windows.Handle(r)
		w.pubs[provider] = pub
	}
	if pub == 0 {
		return ""
	}
	buf := make([]uint16, 2048)
	var used uint32
	r, _, err := pEvtFormatMessage.Call(uintptr(pub), h, 0, 0, 0, evtFormatMessageEvent, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
	if r == 0 {
		if en, ok := err.(syscall.Errno); ok && en == errInsufficientBuffer && used > 0 && used < 1<<16 {
			buf = make([]uint16, used)
			r, _, _ = pEvtFormatMessage.Call(uintptr(pub), h, 0, 0, 0, evtFormatMessageEvent, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		}
		if r == 0 {
			return ""
		}
	}
	return windows.UTF16ToString(buf)
}

func (w *win) Events(cfg protocol.Config, st *EventState, max int) ([]protocol.Event, error) {
	var out []protocol.Event
	for _, q := range cfg.WindowsEvents {
		if len(q.IDs) == 0 || len(out) >= max {
			continue
		}
		evs, last, err := w.queryChannel(q.Channel, buildXPath(q.IDs, st.Bookmarks[q.Channel], cfg.BackfillHours), max-len(out))
		if err != nil {
			continue // kênh không tồn tại (vd. không có Defender) hoặc không đủ quyền – bỏ qua kênh đó
		}
		out = append(out, evs...)
		if last > st.Bookmarks[q.Channel] {
			st.Bookmarks[q.Channel] = last
		}
	}
	return out, nil
}

func (w *win) queryChannel(channel, xpath string, max int) ([]protocol.Event, int64, error) {
	ch, _ := windows.UTF16PtrFromString(channel)
	xp, _ := windows.UTF16PtrFromString(xpath)
	rs, _, err := pEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(xp)), evtQueryChannelPath|evtQueryForwardDirection)
	if rs == 0 {
		return nil, 0, err
	}
	defer evtClose(rs)
	var out []protocol.Event
	var last int64
	handles := make([]uintptr, 64)
	for len(out) < max {
		var n uint32
		r, _, err := pEvtNext.Call(rs, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 5000, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			if en, ok := err.(syscall.Errno); ok && en == errNoMoreItems {
				break
			}
			return out, last, err
		}
		for i := uint32(0); i < n; i++ {
			h := handles[i]
			if len(out) < max {
				if x, err := renderXML(h); err == nil {
					if ev, ok := ParseEventXML(x); ok {
						ev.Message = trunc(w.formatMessage(ev.Provider, h), 2000)
						out = append(out, ev)
						if ev.RecordID > last {
							last = ev.RecordID
						}
					}
				}
			}
			evtClose(h)
		}
	}
	return out, last, nil
}
