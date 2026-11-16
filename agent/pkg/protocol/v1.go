// Package protocol: dữ liệu agent gửi lên server (/api/agent/v1). Phải khớp với app/agents.py (Pydantic).
// Agent CHỈ gửi lên – không có kiểu dữ liệu nào cho lệnh từ server xuống.
package protocol

import "time"

const Version = 1

type SystemInfo struct {
	Hostname     string     `json:"hostname"`
	Domain       string     `json:"domain,omitempty"`
	OSName       string     `json:"os_name,omitempty"`
	OSVersion    string     `json:"os_version,omitempty"`
	OSKind       string     `json:"os_kind,omitempty"` // client | server
	Arch         string     `json:"arch,omitempty"`
	Manufacturer string     `json:"manufacturer,omitempty"`
	Model        string     `json:"model,omitempty"`
	Serial       string     `json:"serial,omitempty"`
	CPUModel     string     `json:"cpu_model,omitempty"`
	CPUCores     int        `json:"cpu_cores,omitempty"`
	RAMMB        int        `json:"ram_mb,omitempty"`
	BootTime     *time.Time `json:"boot_time,omitempty"`
	IPs          []string   `json:"ips,omitempty"`
	LoggedUser   string     `json:"logged_user"`
	UserSource   string     `json:"user_source,omitempty"` // console | rdp | ssh
	MachineID    string     `json:"machine_id,omitempty"`  // MachineGuid / /etc/machine-id: nhận ra máy khi cài lại agent
	MACs         []string   `json:"macs,omitempty"`        // MAC các card mạng đang có IP (agent ≥ 1.0.4)
}

type Disk struct {
	Mount   string  `json:"mount"`
	FS      string  `json:"fs,omitempty"`
	TotalGB float64 `json:"total_gb"`
	UsedPct float64 `json:"used_pct"`
}

type Metrics struct {
	CPU     *float64 `json:"cpu,omitempty"`
	Mem     *float64 `json:"mem,omitempty"`
	Disks   []Disk   `json:"disks"`
	UptimeS int64    `json:"uptime_s,omitempty"`
}

type Service struct {
	Name    string `json:"name"`
	Display string `json:"display,omitempty"`
	State   string `json:"state,omitempty"`
	Start   string `json:"start,omitempty"`
}

type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
	Source      string `json:"source,omitempty"`
	SourcePkg   string `json:"source_pkg,omitempty"` // gói nguồn Linux (dpkg Source / SRPM) để khớp OVAL/USN
}

type Event struct {
	Channel  string            `json:"channel,omitempty"`
	Provider string            `json:"provider,omitempty"`
	EventID  int               `json:"event_id,omitempty"`
	Kind     string            `json:"kind,omitempty"` // Linux/macOS: loại agent đã nhận diện (auth_fail, oom...)
	Level    string            `json:"level,omitempty"`
	RecordID int64             `json:"record_id,omitempty"`
	TS       time.Time         `json:"ts"`
	Data     map[string]string `json:"data,omitempty"`
	Message  string            `json:"message,omitempty"`
}

type Report struct {
	Seq          int64          `json:"seq"`
	AgentVersion string         `json:"agent_version"`
	System       *SystemInfo    `json:"system,omitempty"`
	Metrics      *Metrics       `json:"metrics,omitempty"`
	Defender     map[string]any `json:"defender,omitempty"`
	Services     []Service      `json:"services,omitempty"`
	Software     []Software     `json:"software,omitempty"`
	Updates      map[string]any `json:"updates,omitempty"`
	Posture      map[string]any `json:"posture,omitempty"`
	Events       []Event        `json:"events"`
}

type EnrollRequest struct {
	UID          string     `json:"uid"`
	OSFamily     string     `json:"os_family"`
	AgentVersion string     `json:"agent_version"`
	Site         string     `json:"site,omitempty"` // tên site trong IT Ops (tuỳ chọn) – server gắn máy vào site trùng tên
	Tags         string     `json:"tags,omitempty"`
	System       SystemInfo `json:"system"`
}

type WindowsQuery struct {
	Channel string `json:"channel"`
	IDs     []int  `json:"ids"`
}

type UpdateCfg struct {
	Enabled    bool `json:"enabled"`
	CheckHours int  `json:"check_hours"`
}

// Config: tham số thu thập do server gửi xuống. Không phải lệnh – agent chỉ đổi chu kỳ và danh sách sự kiện cần lấy.
type Config struct {
	Version            string         `json:"version"`
	ReportSeconds      int            `json:"report_seconds"`
	ServicesMinutes    int            `json:"services_minutes"`
	SoftwareHours      int            `json:"software_hours"`
	DefenderMinutes    int            `json:"defender_minutes"`
	BackfillHours      int            `json:"backfill_hours"`
	MaxEventsPerReport int            `json:"max_events_per_report"`
	WindowsEvents      []WindowsQuery `json:"windows_events,omitempty"`
	UnixEvents         []string       `json:"unix_events,omitempty"`
	Update             UpdateCfg      `json:"update"`
}

type EnrollResponse struct {
	AgentID int64  `json:"agent_id"`
	Key     string `json:"key"`
	Config  Config `json:"config"`
}

type ReportResponse struct {
	OK            bool   `json:"ok"`
	EventsStored  int    `json:"events_stored"`
	EventsDropped int    `json:"events_dropped"`
	ConfigVersion string `json:"config_version"`
	ReportSeconds int    `json:"report_seconds"`
}

// DefaultConfig dùng khi chưa nhận được cấu hình từ server.
func DefaultConfig() Config {
	return Config{ReportSeconds: 60, ServicesMinutes: 30, SoftwareHours: 6, DefenderMinutes: 15, BackfillHours: 24,
		MaxEventsPerReport: 500, Update: UpdateCfg{CheckHours: 6}}
}
