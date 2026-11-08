package collect

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct{ ident, msg, kind, k, v string }{
		{"sshd", "Failed password for invalid user admin from 45.1.2.3 port 52211 ssh2", "auth_fail", "src", "45.1.2.3"},
		{"sshd", "Failed password for root from 10.0.0.9 port 1 ssh2", "auth_fail", "user", "root"},
		{"sshd", "error: PAM: authentication error for illegal user bob from 10.1.1.1", "auth_fail", "src", "10.1.1.1"}, // macOS
		{"sshd", "Accepted publickey for bob from 10.0.0.5 port 2 ssh2", "", "", ""},                                    // đăng nhập thành công: bỏ
		{"sshd", "pam_unix(sshd:session): session opened for user bob", "", "", ""},                                     // mở phiên: bỏ
		{"sudo", "    bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", "sudo_fail", "user", "bob"},
		{"sudo", "    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update", "", "", ""}, // sudo thành công: bỏ
		{"useradd", "new user: name=tester, UID=1001, GID=1001, home=/home/tester, shell=/bin/bash", "user_added", "user", "tester"},
		{"usermod", "add 'tester' to group 'sudo'", "group_admin", "group", "sudo"},
		{"usermod", "add 'tester' to group 'docker'", "", "", ""}, // nhóm thường: bỏ
		{"gpasswd", "user tester added by root to group wheel", "group_admin", "user", "tester"},
		{"kernel", "Out of memory: Killed process 1234 (java) total-vm:123kB", "oom", "process", "java"},
		{"kernel", "blk_update_request: I/O error, dev sda, sector 123", "disk_error", "device", "sda"},
		{"systemd", "nginx.service: Failed with result 'exit-code'.", "service_failed", "unit", "nginx.service"},
		{"systemd", "Started nginx.service - A high performance web server.", "", "", ""},
	}
	for _, c := range cases {
		kind, d := classify(c.ident, c.msg)
		if kind != c.kind || (c.k != "" && d[c.k] != c.v) {
			t.Errorf("%s %q → %q %v, muốn %q %s=%s", c.ident, c.msg, kind, d, c.kind, c.k, c.v)
		}
	}
}
