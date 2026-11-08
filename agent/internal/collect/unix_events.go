//go:build !windows

package collect

import (
	"regexp"
	"strings"
)

// Nhận diện sự kiện đáng chú ý từ dòng log Linux/macOS → (kind, data). Chỉ các loại trong cấu hình server mới được gửi.
var (
	reSSHFail   = regexp.MustCompile(`(?:Failed password for (?:invalid user )?|PAM: authentication error for (?:illegal user )?)(\S+) from (\S+)`)
	rePAMFail   = regexp.MustCompile(`authentication failure;.*?rhost=(\S*).*?user=(\S+)`)
	reSudoFail  = regexp.MustCompile(`^\s*(\S+) : (?:\d+ )?incorrect password attempts?`)
	reUserAdd   = regexp.MustCompile(`new user: name=([^,\s]+)`)
	reUsermod   = regexp.MustCompile(`add '([^']+)' to (?:shadow )?group '([^']+)'`)
	reGpasswd   = regexp.MustCompile(`user (\S+) added by \S+ to group (\S+)`)
	reOOM       = regexp.MustCompile(`Out of memory: Killed process \d+ \(([^)]+)\)`)
	reSvcFail   = regexp.MustCompile(`^(\S+\.service): Failed with result '([^']+)'`)
	reDiskIO    = regexp.MustCompile(`(?:I/O error, dev (\w+)|EXT4-fs error \(device (\w+)\)|XFS \((\w+)\): .*(?:error|corruption)|(\w+): .*Medium Error)`)
	adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true, "root": true}
)

func classify(ident, msg string) (string, map[string]string) {
	switch {
	case ident == "sshd" || strings.HasPrefix(ident, "sshd"):
		if m := reSSHFail.FindStringSubmatch(msg); m != nil {
			return "auth_fail", map[string]string{"user": m[1], "src": m[2], "service": "SSH"}
		}
		return "", nil
	case ident == "sudo":
		if m := reSudoFail.FindStringSubmatch(msg); m != nil {
			return "sudo_fail", map[string]string{"user": m[1]}
		}
		return "", nil
	case ident == "useradd":
		if m := reUserAdd.FindStringSubmatch(msg); m != nil {
			return "user_added", map[string]string{"user": m[1]}
		}
	case ident == "usermod" || ident == "gpasswd":
		m := reUsermod.FindStringSubmatch(msg)
		if m == nil {
			m = reGpasswd.FindStringSubmatch(msg)
		}
		if m != nil && adminGroups[m[2]] {
			return "group_admin", map[string]string{"user": m[1], "group": m[2]}
		}
	case ident == "kernel":
		if m := reOOM.FindStringSubmatch(msg); m != nil {
			return "oom", map[string]string{"process": m[1]}
		}
		if m := reDiskIO.FindStringSubmatch(msg); m != nil {
			dev := ""
			for _, x := range m[1:] {
				if x != "" {
					dev = x
					break
				}
			}
			return "disk_error", map[string]string{"device": dev}
		}
	case ident == "systemd":
		if m := reSvcFail.FindStringSubmatch(msg); m != nil {
			return "service_failed", map[string]string{"unit": m[1], "result": m[2]}
		}
	case ident == "login" || ident == "su" || strings.HasPrefix(ident, "gdm") || ident == "lightdm" || ident == "vsftpd":
		if m := rePAMFail.FindStringSubmatch(msg); m != nil {
			return "auth_fail", map[string]string{"user": m[2], "src": m[1], "service": ident}
		}
	}
	return "", nil
}
