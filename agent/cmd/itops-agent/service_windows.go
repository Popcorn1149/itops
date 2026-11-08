//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"itops/agent/internal/config"
	"itops/agent/internal/logx"
)

func isService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

type handler struct{}

func (handler) Execute(_ []string, req <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	logx.Setup(config.Dir(), false)
	a, err := newAgent()
	if err != nil {
		logx.Errorf("không chạy được: %v", err)
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case err := <-done:
			if err != nil {
				logx.Errorf("agent dừng: %v", err)
				return true, 1
			}
			return false, 0
		}
	}
}

// runService: false = không phải do SCM khởi động (chạy tay "run --service") → chạy như tiến trình thường.
func runService() bool {
	if err := svc.Run(serviceName, handler{}); err != nil {
		logx.Errorf("dịch vụ: %v", err)
		return false
	}
	return true
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("cần chạy bằng quyền Administrator (Run as administrator)")
	}
	return nil
}

func installBinary() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	dir := filepath.Join(pf, "ITOpsAgent")
	dst := filepath.Join(dir, "itops-agent.exe")
	if filepath.Clean(src) == filepath.Clean(dst) {
		return dst, nil
	}
	_ = stopService()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	out.Close()
	_ = os.Remove(dst + ".old")
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, dst+".old"); err != nil {
			return "", err
		}
	}
	return dst, os.Rename(tmp, dst)
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 40; i++ {
		time.Sleep(500 * time.Millisecond)
		st, err = s.Query()
	}
	return nil
}

// Chỉ đổi đúng phần cần đổi bằng API gốc: không đọc–ghi lại toàn bộ cấu hình (mgr.UpdateConfig) vì
// một số bản Windows rút gọn / Wine không hỗ trợ đọc cấu hình mở rộng → ghi đè cấu hình rỗng.
func setBinPath(h windows.Handle, cmd string) error {
	p, _ := windows.UTF16PtrFromString(cmd)
	n := uint32(windows.SERVICE_NO_CHANGE)
	return windows.ChangeServiceConfig(h, n, n, n, p, nil, nil, nil, nil, nil, nil)
}

func setExtras(h windows.Handle) {
	d, _ := windows.UTF16PtrFromString("Gửi thông tin máy (hiệu năng, dịch vụ, phần mềm, Defender, sự kiện quan trọng) lên " +
		"IT Ops Workspace. Chỉ đọc, không nhận lệnh từ xa.")
	desc := windows.SERVICE_DESCRIPTION{Description: d}
	_ = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&desc)))
	delayed := windows.SERVICE_DELAYED_AUTO_START_INFO{IsDelayedAutoStartUp: 1} // khởi động sau các dịch vụ hệ thống
	_ = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&delayed)))
}

func installService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	cmd := fmt.Sprintf(`"%s" run --service`, exe)
	s, err := m.OpenService(serviceName)
	if err == nil { // đã có (cài lại / nâng cấp)
		if err := setBinPath(s.Handle, cmd); err != nil {
			s.Close()
			return fmt.Errorf("cập nhật đường dẫn dịch vụ: %w", err)
		}
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{DisplayName: "IT Ops Agent", StartType: mgr.StartAutomatic}, "run", "--service")
		if err != nil {
			return err
		}
	}
	defer s.Close()
	setExtras(s.Handle)
	// dừng bất thường / sau khi tự cập nhật → SCM chạy lại
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Minute}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	return s.Start()
}

func removeService() error {
	_ = stopService()
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}
