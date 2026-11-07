"""Tải PostgreSQL "di động" (không cần cài, không cần quyền admin) cho chế độ chạy demo/dev bằng VS Code.

    python tools/get_postgres.py            # tải bản đúng hệ điều hành vào backend/tools/pgsql
    python tools/get_postgres.py --check    # chỉ kiểm tra đã có chưa

Nguồn: bộ PostgreSQL dựng sẵn phát hành trên npm (@embedded-postgres/<nền tảng>, github.com/leinelissen/embedded-postgres).
Tải thẳng file .tgz qua HTTPS – KHÔNG cần Node.js – và KIỂM TRA mã băm sha512 công bố trên npm trước khi giải nén.
Chạy thật (Docker / máy chủ Linux) dùng image `postgres` chính thức, không dùng bộ này.
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

PG_VERSION = "17.11.0-beta.19"          # PostgreSQL 17.11 (hậu tố -beta.N là version của gói đóng, không phải của PostgreSQL)
PACKAGES = {   # nền tảng → (gói npm, sha512 base64 công bố trên registry.npmjs.org)
    "windows-x64": "z1/SIyBulCYPWYsLWDkgniAYqSd2KBc48zwPOPpyu2YGYIoQ5kRCU6bEJ2q/lcsBuseAdWAn1lBg7KiI/pIg4Q==",
    "linux-x64": "Mg2SUiVf0TW9vECO8qfv41730WgJOKguOaK4acUuIB4L8HeVuiYgQzlIj2kh73Q3OLxRdeub7D8C/SkExMlqrg==",
    "darwin-arm64": "t7SxepOERtwqrkt0lfqLWjeDdYoOvjYRuVFVke7vYJ7XSxMq1sRLRekG6zvcN/zm46XouzXkmrd/E5/RPhlAvw==",
    "darwin-x64": "4p3AnzAizgUGsDt+/mCL5YmfkUubBFvWhbVjZQmjDhnE3UrxFSd6wfKQkhlv4VKMRpfNyLiTrtXWNGi76t5M3Q==",
}
DEST = Path(__file__).resolve().parent / "pgsql"
MARKER = DEST / "VERSION.txt"


def current_platform() -> str:
    sysname = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    key = f"{sysname}-{arch}"
    if key not in PACKAGES:
        raise SystemExit(f"Chưa hỗ trợ nền tảng {platform.system()} {platform.machine()} – hãy cài PostgreSQL 17 và đặt DATABASE_URL.")
    return key


def installed() -> bool:
    return MARKER.exists() and MARKER.read_text().strip() == PG_VERSION and (DEST / "bin").is_dir()


def download(key: str, to: Path) -> Path:
    url = f"https://registry.npmjs.org/@embedded-postgres/{key}/-/{key}-{PG_VERSION}.tgz"
    out = to / f"{key}.tgz"
    print(f"Đang tải PostgreSQL ({key}, ~25–40 MB)…")
    with urllib.request.urlopen(url, timeout=120) as r, open(out, "wb") as f:
        shutil.copyfileobj(r, f)
    got = base64.b64encode(hashlib.sha512(out.read_bytes()).digest()).decode()
    if got != PACKAGES[key]:
        out.unlink()
        raise SystemExit("Mã băm file tải về KHÔNG khớp – dừng lại, không giải nén (file có thể đã bị thay đổi).")
    print("  ✓ mã băm sha512 khớp")
    return out


def extract(tgz: Path):
    tmp = Path(tempfile.mkdtemp(prefix="pgsql-"))
    with tarfile.open(tgz) as t:
        try:
            t.extractall(tmp, filter="data")          # Python ≥ 3.12: chặn đường dẫn ../ và file đặc biệt
        except TypeError:
            t.extractall(tmp)
    native = tmp / "package" / "native"
    links = native / "pg-symlinks.json"
    if links.exists():                                 # Linux/macOS: gói lưu symlink thư viện trong file JSON → dựng lại
        root = tmp / "package"
        for l in json.loads(links.read_text()):
            src, dst = root / l["source"], root / l["target"]
            if not dst.exists():
                os.symlink(os.path.relpath(src, dst.parent), dst)
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.move(str(native), str(DEST))
    shutil.rmtree(tmp, ignore_errors=True)
    MARKER.write_text(PG_VERSION)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if installed():
        print(f"PostgreSQL di động đã có: {DEST}")
        return 0
    if a.check:
        print("Chưa có PostgreSQL di động.")
        return 1
    key = current_platform()
    with tempfile.TemporaryDirectory() as d:
        extract(download(key, Path(d)))
    print(f"  ✓ đã giải nén vào {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
