package agent

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"itops/agent/internal/config"
	"itops/agent/internal/transport"
	"itops/agent/pkg/protocol"
)

// Server giả: tắt (503) một lúc rồi bật lại → agent giữ báo cáo trên đĩa và gửi bù đúng thứ tự.
func TestOfflineQueueAndRevoke(t *testing.T) {
	t.Setenv("ITOPS_AGENT_DIR", t.TempDir())
	var mu sync.Mutex
	down, revoked := true, false
	var seqs []int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/agent/v1/enroll":
			var req protocol.EnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Site != "HCMC" || req.UID == "" || req.OSFamily == "" {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: 7, Key: strings.Repeat("k", 43), Config: protocol.DefaultConfig()})
		case "/api/agent/v1/report":
			if r.Header.Get("Authorization") != "Agent 7."+strings.Repeat("k", 43) {
				w.WriteHeader(401)
				return
			}
			if revoked {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"detail":"revoked"}`))
				return
			}
			if down {
				w.WriteHeader(503)
				return
			}
			zr, _ := gzip.NewReader(r.Body)
			var rep protocol.Report
			if err := json.NewDecoder(zr).Decode(&rep); err != nil || rep.Metrics == nil || rep.Events == nil {
				w.WriteHeader(422)
				return
			}
			seqs = append(seqs, rep.Seq)
			_ = json.NewEncoder(w).Encode(protocol.ReportResponse{OK: true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cert := srv.Certificate()
	cfg := &config.File{ServerURL: srv.URL, CAPin: transport.SPKIPin(cert), UID: "may-test-01", Site: "HCMC"}
	a, err := New("1.0.0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Enroll(); err != nil {
		t.Fatal("đăng ký:", err)
	}
	if cfg.AgentID != 7 {
		t.Fatal("đăng ký xong phải lưu agent_id")
	}
	for i := 0; i < 3; i++ {
		a.Tick() // server tắt → nằm trong hàng đợi
	}
	if a.sp.Len() != 3 || len(seqs) != 0 {
		t.Fatalf("hàng đợi %d, đã gửi %v", a.sp.Len(), seqs)
	}
	mu.Lock()
	down = false
	mu.Unlock()
	a.Tick()
	if a.sp.Len() != 0 || len(seqs) != 4 || seqs[0] != 1 || seqs[3] != 4 {
		t.Fatalf("gửi bù sai thứ tự / thiếu: %v (còn %d)", seqs, a.sp.Len())
	}
	mu.Lock()
	revoked = true
	mu.Unlock()
	a.Tick()
	if !a.st.Revoked {
		t.Fatal("bị thu hồi thì phải ngừng gửi")
	}
	// ca_pin sai → không nói chuyện với server
	bad := *cfg
	bad.CAPin = strings.Repeat("0", 64)
	if _, err := transport.New(&bad, "x").Config(); err == nil || !strings.Contains(err.Error(), "ca_pin") {
		t.Fatal("ca_pin sai phải bị từ chối:", err)
	}
}
