// Package transport: gọi server qua HTTPS. Hỗ trợ ghim khoá công khai chứng chỉ (ca_pin) cho chứng chỉ tự ký.
package transport

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"itops/agent/internal/config"
	"itops/agent/pkg/protocol"
)

var (
	ErrRevoked = errors.New("server đã thu hồi khoá của máy này")
	ErrAuth    = errors.New("server từ chối khoá máy (401)")
)

// ErrRejected: server nhận được nhưng từ chối dữ liệu (4xx khác 401/429) – gửi lại cũng vô ích.
type ErrRejected struct {
	Status int
	Body   string
}

func (e *ErrRejected) Error() string {
	return fmt.Sprintf("server từ chối (%d): %s", e.Status, e.Body)
}

type Client struct {
	cfg  *config.File
	http *http.Client
	UA   string
}

func New(cfg *config.File, version string) *Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin := strings.ToLower(strings.ReplaceAll(cfg.CAPin, ":", "")); pin != "" {
		// Chứng chỉ tự ký: không dựa vào kho CA, chỉ chấp nhận đúng khoá công khai đã ghim lúc cài.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("server không gửi chứng chỉ")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if SPKIPin(c) != pin {
				return fmt.Errorf("chứng chỉ server không khớp ca_pin (có thể bị giả mạo)")
			}
			return nil
		}
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, MaxIdleConns: 2,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 60 * time.Second}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 120 * time.Second}, UA: "itops-agent/" + version}
}

func SPKIPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func (c *Client) url(p string) string { return strings.TrimRight(c.cfg.ServerURL, "/") + p }

func (c *Client) do(method, path string, body []byte, gz bool, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.url(path), rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}
	if c.cfg.AgentID != 0 && c.cfg.Key != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Agent %d.%s", c.cfg.AgentID, c.cfg.Key))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	switch {
	case resp.StatusCode == 401:
		if strings.Contains(string(data), "revoked") {
			return 401, ErrRevoked
		}
		return 401, ErrAuth
	case resp.StatusCode == 204:
		return 204, nil
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return resp.StatusCode, fmt.Errorf("server bận/lỗi %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return resp.StatusCode, &ErrRejected{resp.StatusCode, strings.ToValidUTF8(string(data[:min(len(data), 300)]), "")}
	}
	if out != nil {
		if b, ok := out.(*[]byte); ok {
			*b = data
			return resp.StatusCode, nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("phản hồi không phải JSON: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func Gzip(v any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) Enroll(r protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	b, _ := json.Marshal(r)
	var out protocol.EnrollResponse
	if _, err := c.do("POST", "/api/agent/v1/enroll", b, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendReport: body là JSON đã gzip (lấy từ hàng đợi trên đĩa).
func (c *Client) SendReport(gzBody []byte) (*protocol.ReportResponse, error) {
	var out protocol.ReportResponse
	if _, err := c.do("POST", "/api/agent/v1/report", gzBody, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Config() (*protocol.Config, error) {
	var out protocol.Config
	if _, err := c.do("GET", "/api/agent/v1/config", nil, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateManifest: nil, nil = không có bản cập nhật (204).
func (c *Client) UpdateManifest() ([]byte, error) {
	var b []byte
	st, err := c.do("GET", "/api/agent/v1/update", nil, false, &b)
	if err != nil || st == 204 {
		return nil, err
	}
	return b, nil
}

func (c *Client) Download(name string) ([]byte, error) {
	var b []byte
	_, err := c.do("GET", "/api/agent/v1/update/file/"+name, nil, false, &b)
	return b, err
}
