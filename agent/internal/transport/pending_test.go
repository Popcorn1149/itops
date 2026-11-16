package transport

import "testing"

func TestPendingFrom(t *testing.T) {
	p := pendingFrom([]byte(`{"detail":{"msg":"Waiting for IT approval","pending":true,"request_id":7,"retry_seconds":300}}`))
	if p == nil || p.RetryS != 300 || p.Msg != "Waiting for IT approval" {
		t.Fatalf("pending không đọc được: %+v", p)
	}
	for _, b := range []string{`{"detail":"Rate limit exceeded"}`, `{"detail":{"msg":"x"}}`, `không phải json`} {
		if pendingFrom([]byte(b)) != nil {
			t.Fatalf("%s không phải chờ duyệt", b)
		}
	}
}
