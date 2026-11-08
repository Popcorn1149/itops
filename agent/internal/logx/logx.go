// Package logx: log ra file trong thư mục agent, tự xoay vòng (tối đa 2 file x 5 MB) – không làm đầy ổ máy người dùng.
package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const maxSize = 5 << 20

type rotating struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func (r *rotating) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.size+int64(len(p)) > maxSize {
		if r.f != nil {
			r.f.Close()
			_ = os.Rename(r.path, r.path+".1")
		}
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}
		st, _ := f.Stat()
		r.f, r.size = f, st.Size()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Setup: ghi log ra <dir>/agent.log; alsoStderr = in thêm ra màn hình (chạy tay / systemd journal).
func Setup(dir string, alsoStderr bool) {
	_ = os.MkdirAll(dir, 0o700)
	var w io.Writer = &rotating{path: filepath.Join(dir, "agent.log")}
	if alsoStderr {
		w = io.MultiWriter(w, os.Stderr)
	}
	log.SetOutput(w)
	log.SetFlags(log.LstdFlags | log.LUTC)
}

func Infof(f string, a ...any)  { log.Output(2, "INFO "+fmt.Sprintf(f, a...)) }
func Warnf(f string, a ...any)  { log.Output(2, "WARN "+fmt.Sprintf(f, a...)) }
func Errorf(f string, a ...any) { log.Output(2, "ERROR "+fmt.Sprintf(f, a...)) }
