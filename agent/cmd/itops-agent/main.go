// itops-agent: agent máy trạm của IT Ops Workspace – CHỈ ĐỌC, CHỈ GỬI LÊN (ADR 0004).
//
//	itops-agent install --server https://itops.cty.local:8443 [--site TÊN] [--ca-pin <sha256>] [--update-pubkey <base64>]
//	itops-agent uninstall [--purge]
//	itops-agent status | collect | pin --server URL | version
//	itops-agent run            (dịch vụ gọi; chạy tay để xem log trực tiếp)
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"itops/agent/internal/agent"
	"itops/agent/internal/collect"
	"itops/agent/internal/config"
	"itops/agent/internal/logx"
	"itops/agent/internal/spool"
	"itops/agent/internal/transport"
	"itops/agent/pkg/protocol"
)

// Version: gắn lúc build (-ldflags "-X main.Version=1.0.0").
var Version = "1.0.0-dev"

const serviceName = "ITOpsAgent"

func usage() {
	fmt.Fprintf(os.Stderr, `IT Ops Agent %s – chỉ đọc thông tin máy và gửi lên server, không nhận lệnh từ xa.

Cài đặt (quyền Administrator/root):
  itops-agent install --server https://itops.cty.local:8443 [--site TÊN] [--tags a,b] [--ca-pin SHA256] [--update-pubkey KHOA]
      đăng ký mở: chỉ cần địa chỉ server. Máy trùng một máy đã có sẽ chờ IT duyệt (Endpoints → Pending approvals).
      --re-enroll: máy đã cài đăng ký lại (vd. server chuyển đi); server không nhận thì giữ nguyên như cũ
  itops-agent uninstall [--purge]       gỡ dịch vụ (--purge: xoá cả cấu hình, khoá máy, hàng đợi)

Kiểm tra:
  itops-agent status                    cấu hình + hàng đợi
  itops-agent collect                   in thông tin thu được (không gửi) – để kiểm tra trên máy
  itops-agent pin --server URL          in ca_pin của chứng chỉ server (dùng khi server dùng chứng chỉ tự ký)
  itops-agent version

Chạy thử (không cần quyền admin, không cài gì):
  itops-agent simulate --server URL [--windows 3] [--macos 2] [--allow-http]
      giả lập nhiều máy Windows/macOS gửi dữ liệu thật lên server (Ctrl+C để dừng)
`, Version)
}

func main() {
	if len(os.Args) < 2 {
		if isService() { // Windows SCM khởi động không kèm tham số
			runService()
			return
		}
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		// dịch vụ Windows được tạo với "run --service": gọi thẳng SCM, không dựa vào việc tự đoán
		if (len(args) > 0 && args[0] == "--service") || isService() {
			if runService() {
				return
			}
		}
		err = runForeground()
	case "install":
		err = install(args)
	case "uninstall":
		err = uninstall(args)
	case "status":
		err = status()
	case "collect":
		err = collectOnce()
	case "pin":
		err = pin(args)
	case "simulate":
		err = simulate(args)
	case "version", "--version", "-v":
		fmt.Println(Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "LỖI:", err)
		os.Exit(1)
	}
}

func newAgent() (*agent.Agent, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("chưa cài/cấu hình (%s): %w", config.Path(), err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	a, err := agent.New(Version, cfg)
	if err != nil {
		return nil, err
	}
	a.Restart = func() { os.Exit(3) } // trình quản lý dịch vụ (SCM / systemd / launchd) tự chạy lại bản mới
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old") // bản cũ còn lại sau lần tự cập nhật trước
	}
	return a, nil
}

func runForeground() error {
	logx.Setup(config.Dir(), true)
	a, err := newAgent()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "địa chỉ server, vd. https://itops.cty.local:8443")
	site := fs.String("site", "", "tên site trong IT Ops để gắn máy vào (tuỳ chọn)")
	tags := fs.String("tags", "", "nhãn cho máy, phân cách bằng dấu phẩy (tuỳ chọn)")
	reenroll := fs.Bool("re-enroll", false, "máy đã cài: đăng ký lại với server (vd. server chuyển sang máy khác)")
	pinV := fs.String("ca-pin", "", "SHA-256 khoá công khai chứng chỉ server (chứng chỉ tự ký)")
	pub := fs.String("update-pubkey", "", "khoá công khai Ed25519 (base64) để kiểm chữ ký bản cập nhật")
	allowHTTP := fs.Bool("allow-http", false, "CHỈ DEMO: cho phép server http://")
	_ = fs.Parse(args)
	if err := requireAdmin(); err != nil {
		return err
	}
	cfg, _ := config.Load()
	if cfg == nil {
		cfg = &config.File{}
	}
	if *server != "" {
		cfg.ServerURL = strings.TrimRight(*server, "/")
	}
	if *pinV != "" {
		cfg.CAPin = strings.ToLower(strings.ReplaceAll(*pinV, ":", ""))
	}
	if *pub != "" {
		cfg.UpdatePubKey = *pub
	}
	cfg.AllowHTTP = *allowHTTP
	if *site != "" {
		cfg.Site = *site
	}
	if *tags != "" {
		cfg.Tags = *tags
	}
	if cfg.UID == "" {
		cfg.UID = config.NewUID()
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	logx.Setup(config.Dir(), true)
	if *reenroll && cfg.AgentID != 0 {
		// máy ĐÃ đăng ký, muốn đăng ký lại (vd. đổi server): thử TRƯỚC, chỉ lưu khi server nhận.
		// Server không nhận → giữ nguyên khoá cũ, agent vẫn chạy như trước.
		trial := *cfg
		trial.AgentID, trial.Key = 0, ""
		a, err := agent.New(Version, &trial)
		if err != nil {
			return err
		}
		if err := a.Enroll(); err != nil {
			return fmt.Errorf("đăng ký lại không được (%v) – GIỮ NGUYÊN cấu hình cũ, agent vẫn chạy như trước", errText(err))
		}
		cfg = &trial
	}
	exe, err := installBinary()
	if err != nil {
		return fmt.Errorf("chép file chạy: %w", err)
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	if cfg.AgentID == 0 { // máy mới: đăng ký ngay để admin thấy lỗi (sai địa chỉ, bị chặn...) thay vì dịch vụ âm thầm thử lại
		a, err := agent.New(Version, cfg)
		if err != nil {
			return err
		}
		if err := a.Enroll(); err != nil {
			var rej *transport.ErrRejected
			if errors.As(err, &rej) {
				return fmt.Errorf("server từ chối đăng ký: %s", errText(err))
			}
			var pend *transport.ErrPending
			if errors.As(err, &pend) {
				fmt.Fprintf(os.Stderr, "CHỜ DUYỆT: %s\nMáy này trùng một máy đã có trong IT Ops nên IT phải duyệt (trang Endpoints → Pending approvals). "+
					"Dịch vụ sẽ tự hỏi lại; duyệt xong agent tự chạy, không cần cài lại.\n", pend.Msg)
			} else {
				fmt.Fprintf(os.Stderr, "CẢNH BÁO: chưa kết nối được server (%v) – dịch vụ sẽ tự thử lại.\n", err)
			}
		}
	}
	if err := installService(exe); err != nil {
		return fmt.Errorf("tạo dịch vụ: %w", err)
	}
	fmt.Printf("Đã cài IT Ops Agent %s → %s\nCấu hình: %s\n", Version, exe, config.Path())
	return nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "xoá cả cấu hình, khoá máy, hàng đợi")
	_ = fs.Parse(args)
	if err := requireAdmin(); err != nil {
		return err
	}
	if err := removeService(); err != nil {
		fmt.Fprintln(os.Stderr, "gỡ dịch vụ:", err)
	}
	if *purge {
		_ = os.RemoveAll(config.Dir())
	}
	fmt.Println("Đã gỡ IT Ops Agent. (Xoá máy trên giao diện Máy trạm nếu không dùng nữa.)")
	return nil
}

func status() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("chưa cài: %w", err)
	}
	sp, _ := spool.Open(filepath.Join(config.Dir(), "spool"))
	st := map[string]any{}
	if b, err := os.ReadFile(filepath.Join(config.Dir(), "state.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	fmt.Printf("Phiên bản:   %s\nServer:      %s\nMã máy:      %d (đã đăng ký: %v)\nca_pin:      %v\nTự cập nhật: %v\nBáo cáo chờ: %d\nĐã gửi tới:  #%v\nThu hồi:     %v\nThư mục:     %s\n",
		Version, cfg.ServerURL, cfg.AgentID, cfg.AgentID != 0, cfg.CAPin != "", cfg.UpdatePubKey != "", sp.Len(), st["seq"], st["revoked"], config.Dir())
	return nil
}

func collectOnce() error {
	c := collect.New()
	cfg := protocol.DefaultConfig()
	cfg.BackfillHours = 24
	cfg.UnixEvents = []string{"auth_fail", "sudo_fail", "user_added", "group_admin", "oom", "service_failed", "disk_error"}
	cfg.WindowsEvents = []protocol.WindowsQuery{
		{Channel: "Security", IDs: []int{1102, 4625, 4720, 4726, 4728, 4732, 4740, 4756}},
		{Channel: "System", IDs: []int{7, 20, 41, 51, 55, 153, 6008, 7031, 7034, 7045}},
		{Channel: "Microsoft-Windows-Windows Defender/Operational", IDs: []int{1006, 1007, 1116, 1117, 2001, 5001}}}
	sys := c.System()
	m := c.Metrics()
	svcs, _ := c.Services()
	sw, _ := c.Software()
	def, _ := c.Defender()
	upd, _ := c.Updates()
	pos, _ := c.Posture()
	evs, err := c.Events(cfg, &collect.EventState{Bookmarks: map[string]int64{}}, 50)
	out := map[string]any{"system": sys, "metrics": m, "services_count": len(svcs), "software_count": len(sw),
		"software_first_10": sw[:min(10, len(sw))], "defender": def, "updates": upd, "posture": pos, "events_24h_first_50": evs}
	if err != nil {
		out["events_error"] = err.Error()
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func pin(args []string) error {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	server := fs.String("server", "", "https://host:port")
	_ = fs.Parse(args)
	u, err := url.Parse(*server)
	if err != nil || u.Scheme != "https" {
		return errors.New("--server phải là https://host:port")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer conn.Close()
	c := conn.ConnectionState().PeerCertificates[0]
	fmt.Printf("Chứng chỉ: %s (hết hạn %s)\nca_pin:    %s\n\nĐỐI CHIẾU chuỗi này với lệnh in trên chính server trước khi dùng.\n",
		c.Subject.CommonName, c.NotAfter.Format("2006-01-02"), transport.SPKIPin(c))
	return nil
}

func errText(err error) string {
	var rej *transport.ErrRejected
	if errors.As(err, &rej) {
		return rej.Body
	}
	var pend *transport.ErrPending
	if errors.As(err, &pend) {
		return "đang chờ IT duyệt – " + pend.Msg
	}
	return err.Error()
}

// simulate: chạy N máy GIẢ LẬP trong một tiến trình, mỗi máy đi qua đúng đường của agent thật
// (đăng ký, hàng đợi trên đĩa, gửi HTTPS/ca_pin, đọc XML Event Log / log macOS). Không cần quyền admin, không cài dịch vụ.
func simulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	server := fs.String("server", "", "địa chỉ server")
	pinV := fs.String("ca-pin", "", "ca_pin (server HTTPS chứng chỉ tự ký)")
	allowHTTP := fs.Bool("allow-http", false, "cho phép http:// (demo)")
	nWin := fs.Int("windows", 3, "số máy Windows giả lập")
	nMac := fs.Int("macos", 2, "số máy macOS giả lập")
	dir := fs.String("dir", filepath.Join(os.TempDir(), "itops-agent-simulate"), "thư mục trạng thái (giữ lại để chạy lại không tạo máy trùng)")
	_ = fs.Parse(args)
	if *server == "" {
		return errors.New("thiếu --server")
	}
	logx.Setup(*dir, true)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	type m struct {
		os string
		i  int
	}
	var list []m
	for i := 1; i <= *nWin; i++ {
		list = append(list, m{"windows", i})
	}
	for i := 1; i <= *nMac; i++ {
		list = append(list, m{"darwin", i})
	}
	errs := make(chan error, len(list))
	for _, x := range list {
		sim := collect.NewSim(x.os, x.i)
		d := filepath.Join(*dir, sim.Host)
		cfg := (&config.File{}).WithPath(d)
		if b, err := os.ReadFile(filepath.Join(d, "agent.json")); err == nil {
			_ = json.Unmarshal(b, cfg)
		}
		cfg.ServerURL, cfg.AllowHTTP = strings.TrimRight(*server, "/"), *allowHTTP
		if *pinV != "" {
			cfg.CAPin = *pinV
		}
		if cfg.UID == "" {
			cfg.UID = "sim-" + strings.ToLower(sim.Host) + "-" + config.NewUID()[:8]
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		a, err := agent.NewWith(Version, cfg, sim, d)
		if err != nil {
			return err
		}
		fmt.Printf("  %-11s %-8s %s\n", sim.Host, map[string]string{"windows": "Windows", "darwin": "macOS"}[x.os], sim.IP)
		go func() { errs <- a.Run(ctx) }()
	}
	fmt.Printf("Đang giả lập %d máy → %s (Ctrl+C để dừng). Log: %s\n", len(list), *server, filepath.Join(*dir, "agent.log"))
	for range list {
		if err := <-errs; err != nil {
			stop()
			return err
		}
	}
	return nil
}
