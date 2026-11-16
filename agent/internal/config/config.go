// Package config: file cấu hình cục bộ của agent (địa chỉ server, khoá máy, khoá công khai kiểm bản cập nhật).
// File chỉ admin/root đọc được – khoá máy nằm ở đây.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	ServerURL string `json:"server_url"`           // https://itops.cty.local:8443
	CAPin     string `json:"ca_pin,omitempty"`     // SHA-256 (hex) khoá công khai chứng chỉ server – dùng với chứng chỉ tự ký
	AllowHTTP bool   `json:"allow_http,omitempty"` // CHỈ để demo: cho phép http:// (khoá máy đi dạng rõ trên mạng)
	UID       string `json:"uid"`                  // định danh máy, giữ nguyên qua các lần cài lại
	AgentID   int64  `json:"agent_id,omitempty"`
	Key       string `json:"key,omitempty"`
	// Khoá công khai Ed25519 (base64) để kiểm chữ ký bản cập nhật. Trống = không tự cập nhật.
	UpdatePubKey string `json:"update_pubkey,omitempty"`
	// Site/Tags: gửi kèm lần đăng ký (tuỳ chọn, --site/--tags lúc cài). Đăng ký MỞ như Wazuh – không cần token.
	Site string `json:"site,omitempty"`
	Tags string `json:"tags,omitempty"`

	path string // khác rỗng: lưu vào đây thay vì Path() (máy giả lập)
}

// WithPath: cấu hình lưu ở thư mục riêng (mỗi máy giả lập một thư mục).
func (f *File) WithPath(dir string) *File { f.path = filepath.Join(dir, "agent.json"); return f }

// Dir: thư mục dữ liệu của agent theo hệ điều hành (ghi đè bằng ITOPS_AGENT_DIR khi test).
func Dir() string {
	if d := os.Getenv("ITOPS_AGENT_DIR"); d != "" {
		return d
	}
	return defaultDir()
}

func Path() string { return filepath.Join(Dir(), "agent.json") }

func Load() (*File, error) {
	b, err := os.ReadFile(Path())
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("agent.json lỗi: %w", err)
	}
	return &f, nil
}

func (f *File) Save() error {
	p := Path()
	if f.path != "" {
		p = f.path
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if f.path != "" {
		return nil
	}
	return protect(p)
}

func (f *File) Validate() error {
	u := strings.ToLower(f.ServerURL)
	switch {
	case f.ServerURL == "":
		return errors.New("thiếu địa chỉ server (server_url)")
	case strings.HasPrefix(u, "https://"):
		return nil
	case strings.HasPrefix(u, "http://") && f.AllowHTTP:
		return nil
	case strings.HasPrefix(u, "http://"):
		return errors.New("server_url là http:// – khoá máy sẽ đi dạng rõ. Dùng https://, hoặc chỉ khi demo: thêm --allow-http")
	}
	return errors.New("server_url phải bắt đầu bằng https://")
}

func NewUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
