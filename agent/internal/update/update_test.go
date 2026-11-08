package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fakeSrc struct {
	manifest []byte
	files    map[string][]byte
}

func (f fakeSrc) UpdateManifest() ([]byte, error)   { return f.manifest, nil }
func (f fakeSrc) Download(n string) ([]byte, error) { return f.files[n], nil }

func TestVerifyAndNewer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	bin := []byte("ban-moi")
	sum := sha256.Sum256(bin)
	s := Signed{Version: "1.2.0", SignedAt: "2026-11-08T00:00:00Z",
		Files: map[string]File{"linux-amd64": {Name: "itops-agent-linux-amd64", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(bin))}}}
	m := Sign(priv, s)
	if err := Verify(pubB64, m); err != nil {
		t.Fatal(err)
	}
	// sửa phiên bản sau khi ký → chữ ký hỏng
	bad := m
	bad.Version = "9.9.9"
	if Verify(pubB64, bad) == nil {
		t.Fatal("manifest bị sửa vẫn qua kiểm tra")
	}
	// khoá khác (server bị chiếm tự ký) → từ chối
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(pubB64, Sign(priv2, s)) == nil {
		t.Fatal("chữ ký bằng khoá lạ vẫn qua")
	}
	if !Newer("1.2.0", "1.1.9") || Newer("1.1.9", "1.2.0") || Newer("1.2.0", "1.2.0") || !Newer("1.10.0", "1.9.0") {
		t.Fatal("so phiên bản sai")
	}
}

func TestCheckRejectsTamperedBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("ban-moi-that")
	sum := sha256.Sum256(bin)
	m := Sign(priv, Signed{Version: "2.0.0", Files: map[string]File{"linux-amd64": {Name: "a", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(bin))}}})
	raw, _ := json.Marshal(m)
	_, err := Check(fakeSrc{raw, map[string][]byte{"a": []byte("ma-doc-thay-the")}}, base64.StdEncoding.EncodeToString(pub), "1.0.0", "linux-amd64")
	if err == nil {
		t.Fatal("file bị thay vẫn được cài")
	}
	// bản cũ hơn → không làm gì
	v, err := Check(fakeSrc{raw, nil}, base64.StdEncoding.EncodeToString(pub), "3.0.0", "linux-amd64")
	if err != nil || v != "" {
		t.Fatal("không được hạ phiên bản", v, err)
	}
}

func TestReplaceExe(t *testing.T) {
	d := t.TempDir()
	exe := filepath.Join(d, "agent")
	os.WriteFile(exe, []byte("cu"), 0o755)
	if err := replaceExe(exe, []byte("moi")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "moi" {
		t.Fatal("chưa thay")
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "cu" {
		t.Fatal("mất bản cũ")
	}
}
