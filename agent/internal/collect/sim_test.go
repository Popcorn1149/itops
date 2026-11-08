package collect

import (
	"testing"

	"itops/agent/pkg/protocol"
)

func TestSimProducesRealFormats(t *testing.T) {
	cfg := protocol.DefaultConfig()
	cfg.UnixEvents = []string{"auth_fail", "sudo_fail"}
	st := &EventState{}
	srv := NewSim("windows", 1)
	ids := map[int]int{}
	for i := 0; i < 6; i++ {
		srv.Metrics()
		evs, _ := srv.Events(cfg, st, 500)
		for _, e := range evs {
			ids[e.EventID]++
			if e.Channel == "" || e.Provider == "" || e.RecordID == 0 {
				t.Fatalf("sự kiện thiếu trường (XML đọc sai?): %+v", e)
			}
		}
	}
	if ids[4625] < 12 || ids[4740] < 1 || ids[4732] < 1 || ids[7031] < 1 {
		t.Fatalf("máy chủ giả lập phải sinh dò mật khẩu/khoá TK/thêm admin/dịch vụ chết: %v", ids)
	}
	if st.Bookmarks["Security"] < 1000 {
		t.Fatal("record id phải tăng dần như Windows")
	}
	mac := NewSim("darwin", 1)
	n := 0
	for i := 0; i < 6; i++ {
		m := mac.Metrics()
		if m.CPU == nil || m.Mem == nil {
			t.Fatal("CPU/RAM macOS phải đọc được qua hàm đọc top/vm_stat")
		}
		evs, _ := mac.Events(cfg, &EventState{}, 500)
		n += len(evs)
	}
	sw, _ := mac.Software()
	if n < 12 || len(sw) != 3 {
		t.Fatalf("macOS giả lập: %d sự kiện, %d phần mềm (Safari hệ thống phải bị bỏ)", n, len(sw))
	}
}
