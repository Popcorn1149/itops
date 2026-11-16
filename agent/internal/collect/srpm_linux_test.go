package collect

import "testing"

func TestSrpmName(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.0.7-25.el9.src.rpm":        "openssl",
		"python3.11-3.11.5-1.el9_3.src.rpm":   "python3.11",
		"kernel-5.14.0-362.8.1.el9_3.src.rpm": "kernel",
		"(none)":                              "",
	} {
		if got := srpmName(in); got != want {
			t.Errorf("srpmName(%q) = %q, want %q", in, got, want)
		}
	}
}
