#!/bin/sh
# Cài IT Ops Agent trên Linux (systemd). Chạy bằng root, file chạy để cùng thư mục với script.
#   sudo ./install-linux.sh https://itops.cty.local:8443 [CA_PIN] [SITE]
set -eu
SERVER="$1"; PIN="${2:-}"; SITE="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in x86_64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) echo "Chưa hỗ trợ $(uname -m)"; exit 1 ;; esac
BIN="$DIR/itops-agent-linux-$A"
if [ -f "$DIR/SHA256SUMS.txt" ]; then
  (cd "$DIR" && grep " itops-agent-linux-$A\$" SHA256SUMS.txt | sha256sum -c -) || { echo "SAI MÃ BĂM – dừng"; exit 1; }
fi
chmod +x "$BIN"
set -- install --server "$SERVER"
[ -n "$PIN" ] && set -- "$@" --ca-pin "$PIN"
[ -n "$SITE" ] && set -- "$@" --site "$SITE"
"$BIN" "$@"
systemctl --no-pager status itops-agent | head -5
