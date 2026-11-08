//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

func isService() bool { return false } // systemd / launchd chạy "itops-agent run" như tiến trình thường

func runService() bool { return false }

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("cần quyền root (sudo)")
	}
	return nil
}

const binPath = "/usr/local/bin/itops-agent"

func installBinary() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	if src == binPath {
		return binPath, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp := binPath + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	out.Close()
	return binPath, os.Rename(tmp, binPath) // đổi tên đè file đang chạy là an toàn trên Linux/macOS
}

const systemdUnit = `[Unit]
Description=IT Ops Agent (chỉ đọc, chỉ gửi lên server)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/itops-agent run
Restart=always
RestartSec=30
# chạy root để đọc journal/dmidecode; hạn chế phần còn lại
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=/var/lib/itops-agent /usr/local/bin
PrivateTmp=yes
Nice=10

[Install]
WantedBy=multi-user.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>vn.itops.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/itops-agent</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
`

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v %s", name, args, err, out)
	}
	return nil
}

func installService(string) error {
	if runtime.GOOS == "darwin" {
		const p = "/Library/LaunchDaemons/vn.itops.agent.plist"
		if err := os.WriteFile(p, []byte(launchdPlist), 0o644); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", "system/vn.itops.agent").Run()
		return sh("launchctl", "bootstrap", "system", p)
	}
	if err := os.WriteFile("/etc/systemd/system/itops-agent.service", []byte(systemdUnit), 0o644); err != nil {
		return err
	}
	if err := sh("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := sh("systemctl", "enable", "itops-agent"); err != nil {
		return err
	}
	return sh("systemctl", "restart", "itops-agent")
}

func removeService() error {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("launchctl", "bootout", "system/vn.itops.agent").Run()
		_ = os.Remove("/Library/LaunchDaemons/vn.itops.agent.plist")
		return os.Remove(binPath)
	}
	_ = exec.Command("systemctl", "disable", "--now", "itops-agent").Run()
	_ = os.Remove("/etc/systemd/system/itops-agent.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return os.Remove(binPath)
}
