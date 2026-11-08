#!/bin/sh
# Build agent cho mọi nền tảng (không cần Internet – thư viện đã nằm trong vendor/).
#   ./scripts/build.sh 1.0.0      → dist/itops-agent-<os>-<arch>[.exe] + SHA256SUMS.txt
set -eu
V="${1:-1.0.0}"
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist
for t in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=vendor -trimpath -ldflags "-s -w -X main.Version=$V" \
    -o "dist/itops-agent-$os-$arch$ext" ./cmd/itops-agent
done
# công cụ ký bản cập nhật – chạy trên máy admin (không đưa lên server)
mkdir -p dist/release-tool
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=vendor -trimpath -ldflags "-s -w" -o dist/release-tool/itops-agent-release.exe ./cmd/itops-agent-release
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -ldflags "-s -w" -o dist/release-tool/itops-agent-release-linux ./cmd/itops-agent-release
(cd dist && sha256sum itops-agent-* > SHA256SUMS.txt)
ls -la dist
