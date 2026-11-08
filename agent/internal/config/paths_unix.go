//go:build !windows

package config

import (
	"os"
	"runtime"
)

func defaultDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/ITOpsAgent"
	}
	return "/var/lib/itops-agent"
}

func protect(path string) error { return os.Chmod(path, 0o600) }
