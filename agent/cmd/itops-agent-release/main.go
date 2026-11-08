// itops-agent-release: tạo khoá ký và ký bản cập nhật agent. CHẠY TRÊN MÁY ADMIN, KHÔNG chạy trên server.
//
//	itops-agent-release keygen --out D:\khoa-agent          → update-signing.key (BÍ MẬT) + update-signing.pub
//	itops-agent-release sign --key ...\update-signing.key --version 1.0.1 --dir dist
//	    → dist/manifest.json; chép manifest.json + các file itops-agent-* vào <DATA_DIR>/agent-updates/ trên server
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"itops/agent/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "dùng: itops-agent-release keygen --out THƯ_MỤC | sign --key FILE --version X.Y.Z --dir dist")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		err = errors.New("lệnh không hợp lệ")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "LỖI:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", ".", "thư mục lưu khoá")
	_ = fs.Parse(args)
	priv := filepath.Join(*out, "update-signing.key")
	if _, err := os.Stat(priv); err == nil {
		return fmt.Errorf("%s đã tồn tại – không ghi đè (mất khoá cũ = mọi agent không nhận bản cập nhật nữa)", priv)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(priv, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return err
	}
	p := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(*out, "update-signing.pub"), []byte(p+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("Khoá công khai (dùng cho --update-pubkey khi cài agent):\n  %s\n\n"+
		"Khoá riêng: %s\n  → cất USB/két, KHÔNG để trên server. Lộ khoá này = người khác ký được bản cập nhật.\n", p, priv)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyF := fs.String("key", "", "file update-signing.key")
	ver := fs.String("version", "", "phiên bản, vd. 1.0.1 (phải khớp -X main.Version lúc build)")
	dir := fs.String("dir", "dist", "thư mục chứa itops-agent-<os>-<arch>")
	_ = fs.Parse(args)
	if *keyF == "" || *ver == "" {
		return errors.New("cần --key và --version")
	}
	raw, err := os.ReadFile(*keyF)
	if err != nil {
		return err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(k) != ed25519.PrivateKeySize {
		return errors.New("file khoá không hợp lệ")
	}
	files := map[string]update.File{}
	ents, _ := os.ReadDir(*dir)
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "itops-agent-") || strings.HasPrefix(n, "itops-agent-release") {
			continue
		}
		plat := strings.TrimSuffix(strings.TrimPrefix(n, "itops-agent-"), ".exe")
		b, err := os.ReadFile(filepath.Join(*dir, n))
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		files[plat] = update.File{Name: n, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))}
	}
	if len(files) == 0 {
		return fmt.Errorf("không thấy file itops-agent-* trong %s", *dir)
	}
	m := update.Sign(ed25519.PrivateKey(k), update.Signed{Version: *ver, SignedAt: time.Now().UTC().Format(time.RFC3339), Files: files})
	b, _ := json.MarshalIndent(m, "", "  ")
	out := filepath.Join(*dir, "manifest.json")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("Đã ký %d file, phiên bản %s → %s\nChép manifest.json + các file itops-agent-* vào <DATA_DIR>/agent-updates/ trên server,\n"+
		"rồi bật \"Tự cập nhật\" trong Cài đặt → Máy trạm.\n", len(files), *ver, out)
	return nil
}
