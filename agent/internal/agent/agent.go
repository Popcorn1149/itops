// Package agent: vòng chạy chính – thu thập → ghi hàng đợi trên đĩa → gửi lên server. Không nhận lệnh từ server.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"itops/agent/internal/collect"
	"itops/agent/internal/config"
	"itops/agent/internal/logx"
	"itops/agent/internal/spool"
	"itops/agent/internal/transport"
	"itops/agent/internal/update"
	"itops/agent/pkg/protocol"
)

type State struct {
	Seq          int64              `json:"seq"`
	Config       protocol.Config    `json:"config"`
	Ev           collect.EventState `json:"events"`
	SystemHash   string             `json:"system_hash"`
	LastSystem   time.Time          `json:"last_system"`
	LastServices time.Time          `json:"last_services"`
	LastSoftware time.Time          `json:"last_software"`
	LastDefender time.Time          `json:"last_defender"`
	LastUpdate   time.Time          `json:"last_update_check"`
	Revoked      bool               `json:"revoked"`
}

type Agent struct {
	Version string
	cfg     *config.File
	col     collect.Collector
	cli     *transport.Client
	sp      *spool.Spool
	st      State
	dir     string
	// Restart: được gọi sau khi đã thay file chạy bằng bản cập nhật (dịch vụ tự khởi động lại bản mới).
	Restart func()
}

func (a *Agent) statePath() string { return filepath.Join(a.dir, "state.json") }

func New(version string, cfg *config.File) (*Agent, error) {
	return NewWith(version, cfg, collect.New(), config.Dir())
}

// NewWith: bộ thu thập + thư mục dữ liệu tuỳ chọn (lệnh simulate chạy nhiều máy giả lập trong một tiến trình).
func NewWith(version string, cfg *config.File, col collect.Collector, dir string) (*Agent, error) {
	sp, err := spool.Open(filepath.Join(dir, "spool"))
	if err != nil {
		return nil, err
	}
	a := &Agent{Version: version, cfg: cfg, col: col, cli: transport.New(cfg, version), sp: sp, dir: dir}
	if b, err := os.ReadFile(a.statePath()); err == nil {
		_ = json.Unmarshal(b, &a.st)
	}
	if a.st.Config.ReportSeconds == 0 {
		a.st.Config = protocol.DefaultConfig()
	}
	return a, nil
}

func (a *Agent) saveState() {
	b, _ := json.Marshal(a.st)
	tmp := a.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.statePath())
	}
}

// Enroll: dùng token đăng ký 1 lần để lấy khoá riêng của máy. Token bị xoá khỏi file ngay sau đó.
func (a *Agent) Enroll() error {
	if a.cfg.UID == "" {
		a.cfg.UID = config.NewUID()
	}
	sys := a.col.System()
	res, err := a.cli.Enroll(protocol.EnrollRequest{Token: a.cfg.EnrollToken, UID: a.cfg.UID, OSFamily: a.col.OSFamily(),
		AgentVersion: a.Version, System: sys})
	if err != nil {
		return err
	}
	a.cfg.AgentID, a.cfg.Key, a.cfg.EnrollToken = res.AgentID, res.Key, ""
	if err := a.cfg.Save(); err != nil {
		return err
	}
	a.st.Config = res.Config
	a.st.Revoked = false
	a.saveState()
	logx.Infof("đã đăng ký với server, mã máy %d", res.AgentID)
	return nil
}

func due(last time.Time, every time.Duration) bool { return every > 0 && time.Since(last) >= every }

// Collect: dựng một báo cáo. Vị trí đọc nhật ký chỉ được lưu khi báo cáo đã nằm an toàn trong hàng đợi.
func (a *Agent) Collect() (*protocol.Report, collect.EventState) {
	c := a.st.Config
	r := &protocol.Report{Seq: a.st.Seq + 1, AgentVersion: a.Version, Events: []protocol.Event{}}
	m := a.col.Metrics()
	r.Metrics = &m
	sys := a.col.System()
	sb, _ := json.Marshal(sys)
	h := sha256.Sum256(sb)
	if hs := hex.EncodeToString(h[:]); hs != a.st.SystemHash || due(a.st.LastSystem, 6*time.Hour) {
		r.System = &sys
	} else if sys.LoggedUser != "" || a.st.SystemHash != "" {
		r.System = &protocol.SystemInfo{Hostname: sys.Hostname, LoggedUser: sys.LoggedUser, IPs: sys.IPs}
	}
	if due(a.st.LastServices, time.Duration(c.ServicesMinutes)*time.Minute) {
		if s, err := a.col.Services(); err == nil {
			r.Services = s
		} else {
			logx.Warnf("đọc danh sách dịch vụ lỗi: %v", err)
		}
	}
	if due(a.st.LastSoftware, time.Duration(c.SoftwareHours)*time.Hour) {
		if s, err := a.col.Software(); err == nil {
			r.Software = s
		} else {
			logx.Warnf("đọc phần mềm lỗi: %v", err)
		}
	}
	if due(a.st.LastDefender, time.Duration(c.DefenderMinutes)*time.Minute) {
		if d, err := a.col.Defender(); err == nil {
			r.Defender = d
		} else {
			logx.Warnf("đọc Defender lỗi: %v", err)
		}
		if u, err := a.col.Updates(); err == nil {
			r.Updates = u
		}
		if p, err := a.col.Posture(); err == nil {
			r.Posture = p
		}
	}
	ev := a.st.Ev
	if ev.Bookmarks == nil {
		ev.Bookmarks = map[string]int64{}
	}
	max := c.MaxEventsPerReport
	if max <= 0 {
		max = 500
	}
	if evs, err := a.col.Events(c, &ev, max); err == nil {
		if evs != nil {
			r.Events = evs // giữ [] thay vì null khi không có sự kiện
		}
	} else {
		logx.Warnf("đọc nhật ký sự kiện lỗi: %v", err)
	}
	return r, ev
}

// Tick: thu thập → hàng đợi → gửi.
func (a *Agent) Tick() {
	r, ev := a.Collect()
	gz, err := transport.Gzip(r)
	if err != nil {
		logx.Errorf("nén báo cáo lỗi: %v", err)
		return
	}
	if err := a.sp.Put(r.Seq, gz); err != nil {
		logx.Errorf("ghi hàng đợi lỗi: %v", err)
		return
	}
	// đã nằm trong hàng đợi → cập nhật mốc
	a.st.Seq, a.st.Ev = r.Seq, ev
	now := time.Now()
	if r.System != nil && r.System.OSName != "" {
		b, _ := json.Marshal(r.System)
		h := sha256.Sum256(b)
		a.st.SystemHash, a.st.LastSystem = hex.EncodeToString(h[:]), now
	}
	if r.Services != nil {
		a.st.LastServices = now
	}
	if r.Software != nil {
		a.st.LastSoftware = now
	}
	if r.Defender != nil || r.Updates != nil {
		a.st.LastDefender = now
	}
	a.saveState()
	a.flush()
}

func (a *Agent) flush() {
	if a.st.Revoked {
		return
	}
	cfgVer := ""
	n, err := a.sp.Flush(func(body []byte) (bool, error) {
		res, err := a.cli.SendReport(body)
		var rej *transport.ErrRejected
		switch {
		case err == nil:
			cfgVer = res.ConfigVersion
			return false, nil
		case errors.As(err, &rej):
			logx.Errorf("server từ chối 1 báo cáo, bỏ qua: %v", err)
			// báo cáo bị bỏ có thể chứa danh sách phần mềm/dịch vụ (gửi thưa) → lần sau gửi lại đủ
			a.st.LastSystem, a.st.LastServices, a.st.LastSoftware, a.st.LastDefender = time.Time{}, time.Time{}, time.Time{}, time.Time{}
			a.st.SystemHash = ""
			return true, err
		default:
			return false, err
		}
	})
	if errors.Is(err, transport.ErrRevoked) {
		logx.Errorf("%v – ngừng gửi. Cài lại agent với token mới nếu cần.", err)
		a.st.Revoked = true
		a.saveState()
		return
	}
	if err != nil {
		logx.Warnf("chưa gửi được (%d báo cáo chờ trong hàng đợi): %v", a.sp.Len(), err)
	} else if n > 1 {
		logx.Infof("đã gửi bù %d báo cáo", n)
	}
	if cfgVer != "" && cfgVer != a.st.Config.Version {
		if c, err := a.cli.Config(); err == nil {
			a.st.Config = *c
			a.saveState()
			logx.Infof("nhận cấu hình mới %s (gửi mỗi %ds)", c.Version, c.ReportSeconds)
		}
	}
}

func (a *Agent) maybeUpdate() {
	u := a.st.Config.Update
	if !u.Enabled || a.cfg.UpdatePubKey == "" || a.st.Revoked {
		return
	}
	if !due(a.st.LastUpdate, time.Duration(max(1, u.CheckHours))*time.Hour) {
		return
	}
	a.st.LastUpdate = time.Now()
	a.saveState()
	applied, err := update.Check(a.cli, a.cfg.UpdatePubKey, a.Version, runtime.GOOS+"-"+runtime.GOARCH)
	if err != nil {
		logx.Warnf("kiểm tra cập nhật: %v", err)
		return
	}
	if applied != "" && a.Restart != nil {
		logx.Infof("đã cài bản %s – khởi động lại agent", applied)
		a.Restart()
	}
}

// Run: chạy tới khi ctx bị huỷ (dịch vụ dừng).
func (a *Agent) Run(ctx context.Context) error {
	backoff := 30 * time.Second
	for a.cfg.AgentID == 0 {
		if a.cfg.EnrollToken == "" {
			return errors.New("chưa đăng ký và không có token – chạy lại lệnh cài với --token")
		}
		err := a.Enroll()
		if err == nil {
			break
		}
		var rej *transport.ErrRejected
		if errors.As(err, &rej) && rej.Status == 403 {
			return err // token sai/hết hạn: thử lại vô ích
		}
		logx.Warnf("đăng ký chưa được: %v – thử lại sau %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Minute)
	}
	logx.Infof("agent %s chạy – server %s, mã máy %d", a.Version, a.cfg.ServerURL, a.cfg.AgentID)
	// lệch pha ngẫu nhiên vài giây: 200 máy khởi động cùng lúc (GPO) không dồn vào server cùng một giây
	time.Sleep(time.Duration(rand.IntN(10)) * time.Second)
	for {
		if a.st.Revoked {
			select { // bị thu hồi: chỉ kiểm tra lại mỗi giờ (admin có thể xoá máy để đăng ký lại)
			case <-ctx.Done():
				return nil
			case <-time.After(time.Hour):
			}
			if _, err := a.cli.Config(); err == nil {
				a.st.Revoked = false
			}
			continue
		}
		a.Tick()
		a.maybeUpdate()
		every := time.Duration(max(30, a.st.Config.ReportSeconds)) * time.Second
		select {
		case <-ctx.Done():
			a.saveState()
			return nil
		case <-time.After(every):
		}
	}
}
