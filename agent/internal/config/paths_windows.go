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
// Đặt quyền ở THƯ MỤC (không /T): áp "(OI)(CI)" bằng /T lên từng file cùng /inheritance:r từng làm file
// agent.json mất hết quyền (kể cả SYSTEM) → dịch vụ không đọc được cấu hình. Các file con được /reset để
// thừa kế quyền mới của thư mục.
func protect(path string) error {
	dir := filepath.Dir(path)
	if err := icacls(dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"); err != nil {
		return err
	}
	_ = icacls(filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q") // thư mục trống thì icacls báo lỗi – bỏ qua
	return nil
}

func icacls(args ...string) error {
	cmd := exec.Command("icacls", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd.Run()
}
