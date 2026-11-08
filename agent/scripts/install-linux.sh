#!/bin/sh
# Cài IT Ops Agent trên Linux (systemd). Chạy bằng root, file chạy để cùng thư mục với script.
#   sudo ./install-linux.sh https://itops.cty.local:8443 itk_xxx [CA_PIN]
set -eu
SERVER="$1"; TOKEN="$2"; PIN="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) echo "Chưa hỗ trợ $(uname -m)"; exit 1 ;; esac
BIN="$DIR/itops-agent-linux-$A"
if [ -f "$DIR/SHA256SUMS.txt" ]; then
  (cd "$DIR" && grep " itops-agent-linux-$A\$" SHA256SUMS.txt | sha256sum -c -) || { echo "SAI MÃ BĂM – dừng"; exit 1; }
fi
chmod +x "$BIN"
if [ -n "$PIN" ]; then "$BIN" install --server "$SERVER" --token "$TOKEN" --ca-pin "$PIN"
else "$BIN" install --server "$SERVER" --token "$TOKEN"; fi
systemctl --no-pager status itops-agent | head -5
