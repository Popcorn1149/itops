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

func runService() {
	if err := svc.Run(serviceName, handler{}); err != nil {
		logx.Errorf("dịch vụ: %v", err)
	}
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

func installService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil { // đã có (cài lại / nâng cấp): cập nhật đường dẫn rồi chạy
		c, _ := s.Config()
		c.BinaryPathName = fmt.Sprintf(`"%s" run`, exe)
		_ = s.UpdateConfig(c)
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{DisplayName: "IT Ops Agent", StartType: mgr.StartAutomatic,
			DelayedAutoStart: true, Description: "Gửi thông tin máy (hiệu năng, dịch vụ, phần mềm, Defender, sự kiện quan trọng) " +
				"lên IT Ops Workspace. Chỉ đọc, không nhận lệnh từ xa."}, "run")
		if err != nil {
			return err
		}
	}
	defer s.Close()
	// dừng bất thường / sau khi tự cập nhật → SCM chạy lại sau 30 giây
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
