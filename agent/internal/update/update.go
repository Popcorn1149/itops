// Package update: tự cập nhật AN TOÀN.
//
// Bản tin (manifest.json) được ký bằng khoá riêng Ed25519 do admin giữ NGOÀI server (cmd/itops-agent-release).
// Agent chỉ tin khoá công khai ghi trong agent.json lúc cài (file chỉ admin sửa được). Vì vậy kẻ chiếm được server
// cũng KHÔNG đẩy được file chạy giả xuống máy trạm: thiếu khoá riêng thì chữ ký không khớp → agent bỏ qua.
// Chỉ nâng phiên bản (không hạ) để chống phát lại bản cũ có lỗi.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Signed: phần được ký. Thứ tự trường cố định + map được Go sắp xếp key → bytes ký luôn giống nhau.
type Signed struct {
	Files    map[string]File `json:"files"`
	SignedAt string          `json:"signed_at"`
	Version  string          `json:"version"`
}

type Manifest struct {
	Signed
	Signature string `json:"signature"`
}

func Canonical(s Signed) []byte {
	b, _ := json.Marshal(s)
	return b
}

func Sign(priv ed25519.PrivateKey, s Signed) Manifest {
	return Manifest{Signed: s, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(s)))}
}

func Verify(pubB64 string, m Manifest) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("update_pubkey trong agent.json không hợp lệ")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, Canonical(m.Signed), sig) {
		return errors.New("CHỮ KÝ bản cập nhật KHÔNG HỢP LỆ – bỏ qua (server có thể đã bị can thiệp)")
	}
	return nil
}

// Newer: so phiên bản dạng 1.2.3.
func Newer(a, b string) bool {
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parse(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(strings.SplitN(v, "-", 2)[0], "v"), ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

type Source interface {
	UpdateManifest() ([]byte, error)
	Download(name string) ([]byte, error)
}

// Check: có bản mới hợp lệ → tải, kiểm SHA-256, thay file chạy. Trả về phiên bản đã cài ("" = không đổi).
func Check(src Source, pubB64, current, platform string) (string, error) {
	raw, err := src.UpdateManifest()
	if err != nil || raw == nil {
		return "", err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("manifest lỗi: %w", err)
	}
	if err := Verify(pubB64, m); err != nil {
		return "", err
	}
	if !Newer(m.Version, current) {
		return "", nil
	}
	f, ok := m.Files[platform]
	if !ok {
		return "", nil
	}
	if strings.ContainsAny(f.Name, `/\`) || strings.Contains(f.Name, "..") {
		return "", errors.New("tên file trong manifest không hợp lệ")
	}
	bin, err := src.Download(f.Name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bin)
	if int64(len(bin)) != f.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), f.SHA256) {
		return "", errors.New("file tải về không khớp kích thước/SHA-256 trong manifest đã ký")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	if err := replaceExe(exe, bin); err != nil {
		return "", err
	}
	return m.Version, nil
}

// replaceExe: ghi bản mới cạnh file cũ rồi đổi tên (Windows cho đổi tên file đang chạy, không cho ghi đè).
func replaceExe(exe string, bin []byte) error {
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe) // trả lại bản cũ
		return err
	}
	return nil
}
