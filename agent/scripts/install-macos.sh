#!/bin/sh
# Cài IT Ops Agent trên macOS (launchd). Chưa có Apple Developer ID → file chạy CHƯA KÝ:
# Gatekeeper sẽ chặn nếu tải qua trình duyệt. Chép bằng USB/scp rồi chạy script này (sudo).
#   sudo ./install-macos.sh https://itops.cty.local:8443 [CA_PIN] [SITE]
set -eu
SERVER="$1"; PIN="${2:-}"; SITE="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in x86_64) A=amd64 ;; arm64) A=arm64 ;; *) echo "Chưa hỗ trợ"; exit 1 ;; esac
BIN="$DIR/itops-agent-darwin-$A"
if [ -f "$DIR/SHA256SUMS.txt" ]; then
  (cd "$DIR" && grep " itops-agent-darwin-$A\$" SHA256SUMS.txt | shasum -a 256 -c -) || { echo "SAI MÃ BĂM – dừng"; exit 1; }
fi
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true
chmod +x "$BIN"
set -- install --server "$SERVER"
[ -n "$PIN" ] && set -- "$@" --ca-pin "$PIN"
[ -n "$SITE" ] && set -- "$@" --site "$SITE"
"$BIN" "$@"
