package collect

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// run: chạy lệnh hệ thống CHỈ ĐỌC với thời hạn; không qua shell (không chèn lệnh được).
func run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}
