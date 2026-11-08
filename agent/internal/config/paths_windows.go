package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func defaultDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ITOpsAgent")
}

// protect: chỉ SYSTEM và Administrators đọc/ghi được thư mục dữ liệu (mặc định ProgramData cho Users đọc).
func protect(path string) error {
	dir := filepath.Dir(path)
	cmd := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/Q")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd.Run()
}
