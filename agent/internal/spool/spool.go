// Package spool: hàng đợi báo cáo trên đĩa. Mất mạng / server tắt → giữ lại, gửi bù theo thứ tự khi kết nối lại.
package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxFiles = 2000      // ~ 1,5 ngày nếu gửi mỗi phút
	maxBytes = 200 << 20 // 200 MB
)

type Spool struct{ dir string }

func Open(dir string) (*Spool, error) {
	return &Spool{dir}, os.MkdirAll(dir, 0o700)
}

func (s *Spool) Put(seq int64, gz []byte) error {
	name := filepath.Join(s.dir, fmt.Sprintf("%020d.json.gz", seq))
	if err := os.WriteFile(name+".tmp", gz, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name+".tmp", name); err != nil {
		return err
	}
	return s.trim()
}

func (s *Spool) list() []string {
	ents, _ := os.ReadDir(s.dir)
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json.gz") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func (s *Spool) Len() int { return len(s.list()) }

// trim: đầy thì bỏ báo cáo CŨ NHẤT (giữ dữ liệu mới).
func (s *Spool) trim() error {
	files := s.list()
	var total int64
	sizes := map[string]int64{}
	for _, f := range files {
		if st, err := os.Stat(filepath.Join(s.dir, f)); err == nil {
			sizes[f] = st.Size()
			total += st.Size()
		}
	}
	for len(files) > maxFiles || total > maxBytes {
		_ = os.Remove(filepath.Join(s.dir, files[0]))
		total -= sizes[files[0]]
		files = files[1:]
	}
	return nil
}

// ErrStop: send trả lỗi này để dừng lượt gửi (giữ file lại).
var ErrStop = errors.New("dừng gửi")

// Flush: gửi lần lượt từ cũ tới mới. send trả nil → xoá file; ErrStop/lỗi mạng → dừng, giữ file;
// drop=true → server từ chối hẳn (dữ liệu hỏng) → xoá để không kẹt hàng đợi.
func (s *Spool) Flush(send func(body []byte) (drop bool, err error)) (sent int, err error) {
	for _, f := range s.list() {
		p := filepath.Join(s.dir, f)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			_ = os.Remove(p)
			continue
		}
		drop, serr := send(b)
		if serr != nil && !drop {
			return sent, serr
		}
		_ = os.Remove(p)
		if serr == nil {
			sent++
		}
	}
	return sent, nil
}
