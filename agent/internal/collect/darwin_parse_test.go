package collect

import "testing"

// Mẫu lấy đúng định dạng đầu ra của macOS 14/15.
const macTop = `Processes: 612 total, 3 running, 609 sleeping, 3147 threads
2026/11/08 10:00:00
Load Avg: 2.10, 2.35, 2.40
CPU usage: 9.81% user, 6.27% sys, 83.91% idle
SharedLibs: 552M resident, 98M data, 41M linkedit.
Processes: 612 total, 2 running, 610 sleeping, 3150 threads
2026/11/08 10:00:01
Load Avg: 2.10, 2.35, 2.40
CPU usage: 4.52% user, 3.10% sys, 92.38% idle
`

const macVMStat = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               12873.
Pages active:                            301233.
Pages inactive:                          297811.
Pages speculative:                         3412.
Pages throttled:                              0.
Pages wired down:                        151020.
Pages purgeable:                          10221.
"Translation faults":                1201929123.
Pages occupied by compressor:            195214.
`

const macLaunch = `PID	Status	Label
-	0	com.apple.SafariHistoryServiceAgent
512	0	com.apple.Finder
743	0	com.google.keystone.agent
-	78	com.microsoft.update.agent
1201	0	vn.itops.agent
`

const macAppsJSON = `{"SPApplicationsDataType":[
 {"_name":"Safari","version":"18.1","obtained_from":"apple","path":"/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"},
 {"_name":"Google Chrome","version":"131.0.6778.86","obtained_from":"identified_developer","path":"/Applications/Google Chrome.app","lastModified":"2026-11-02T03:12:44Z"},
 {"_name":"Zalo","version":"24.10.1","obtained_from":"identified_developer","path":"/Applications/Zalo.app"},
 {"_name":"Calculator","version":"11.0","obtained_from":"apple","path":"/System/Applications/Calculator.app"},
 {"_name":"Zalo","version":"24.10.1","obtained_from":"identified_developer","path":"/Users/a/Applications/Zalo.app"}
]}`

func TestMacParsers(t *testing.T) {
	if c := macCPU(macTop); c == nil || *c != 7.6 {
		t.Fatalf("CPU phải lấy mẫu cuối (100-92.38=7.6): %v", c)
	}
	// 16 GB, trang 16 KB: trống = (12873+297811+3412)*16384
	if m := macMem(macVMStat, 16*(1<<30), 16384); m == nil || *m < 69 || *m > 71 {
		t.Fatalf("RAM sai: %v", *m)
	}
	if macSerial(`    "IOPlatformSerialNumber" = "C02XG0FDJG5H"`) != "C02XG0FDJG5H" {
		t.Fatal("serial")
	}
	if b := macBoot("{ sec = 1762560000, usec = 0 } Sat Nov  8 00:00:00 2026"); b == nil || b.Unix() != 1762560000 {
		t.Fatal("boot")
	}
	sv := macLaunchctl(macLaunch)
	if len(sv) != 3 || sv[0].Name != "com.google.keystone.agent" || sv[1].State != "stopped" || sv[2].State != "running" {
		t.Fatalf("launchctl: %+v", sv)
	}
	apps, err := macApps([]byte(macAppsJSON))
	if err != nil || len(apps) != 2 || apps[0].Name != "Google Chrome" || apps[0].InstalledOn != "2026-11-02" {
		t.Fatalf("ứng dụng (bỏ app hệ thống, bỏ trùng): %+v %v", apps, err)
	}
	want := map[string]bool{"auth_fail": true, "sudo_fail": true}
	ev, _, ok := macLogLine([]byte(`{"timestamp":"2026-11-08 09:15:02.123456+0700","eventMessage":"error: PAM: authentication error for illegal user admin from 203.0.113.9","processImagePath":"/usr/sbin/sshd"}`), want)
	if !ok || ev.Kind != "auth_fail" || ev.Data["src"] != "203.0.113.9" || ev.TS.Hour() != 2 {
		t.Fatalf("sshd macOS: %+v", ev)
	}
	ev, _, ok = macLogLine([]byte(`{"timestamp":"2026-11-08 09:16:00.000000+0700","eventMessage":"  thiet.ke : 3 incorrect password attempts ; TTY=ttys000 ; PWD=/Users/thiet.ke ; USER=root ; COMMAND=/bin/ls","processImagePath":"/usr/bin/sudo"}`), want)
	if !ok || ev.Kind != "sudo_fail" || ev.Data["user"] != "thiet.ke" {
		t.Fatalf("sudo macOS: %+v", ev)
	}
	if _, _, ok := macLogLine([]byte(`{"timestamp":"2026-11-08 09:16:00.000000+0700","eventMessage":"Accepted publickey for a","processImagePath":"/usr/sbin/sshd"}`), want); ok {
		t.Fatal("đăng nhập thành công phải bị bỏ")
	}
}
