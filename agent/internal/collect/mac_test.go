package collect

import (
	"regexp"
	"testing"
)

func TestLocalMACsFormat(t *testing.T) {
	re := regexp.MustCompile(`^([0-9A-F]{2}:){5}[0-9A-F]{2}$`)
	seen := map[string]bool{}
	for _, m := range LocalMACs() {
		if !re.MatchString(m) || m == "00:00:00:00:00:00" || seen[m] {
			t.Fatalf("MAC sai định dạng / trùng: %q", m)
		}
		seen[m] = true
	}
	if m := simMAC("PC-KT01"); !re.MatchString(m) || m != simMAC("PC-KT01") || m == simMAC("PC-KT02") {
		t.Fatalf("simMAC phải cố định theo tên máy: %s", m)
	}
}
