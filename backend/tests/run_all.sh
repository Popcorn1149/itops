#!/usr/bin/env bash
# Chạy toàn bộ QA: lint → unit/integration (pytest) → E2E giao diện → bảo mật UI → tải
set -u
cd "$(dirname "$0")/.."
FAIL=0
step(){ echo; echo "=================== $1 ==================="; }
step "1. Lint backend (ruff)";        ruff check app --select F,B --ignore B008 --output-format concise || FAIL=1
step "2. Lint frontend (eslint)";     (cd ../frontend && npx eslint src) || FAIL=1
step "3. Build frontend";             (cd ../frontend && npx vite build >/dev/null && rm -rf ../backend/static && cp -r dist ../backend/static && echo OK) || FAIL=1
step "4. Pytest (API, collector, flow, bảo mật)"; python3 -m pytest tests -q -p no:cacheprovider || FAIL=1
step "5. E2E giao diện";              python3 tests/e2e_ui.py | grep -E "FAIL|E2E:" || FAIL=1
step "6. Bảo mật giao diện (XSS)";     python3 tests/security_ui.py | grep -E "PASS|FAIL" || FAIL=1
step "7. Tải";                        LOAD_SECONDS=${LOAD_SECONDS:-60} python3 tests/load_test.py | grep -vE "INFO:" | tail -20 || FAIL=1
echo; [ $FAIL = 0 ] && echo "TẤT CẢ ĐẠT" || echo "CÓ BƯỚC LỖI"
exit $FAIL
