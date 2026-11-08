"""Kiểm tra mã nguồn có bị sửa / giải nén thiếu so với bản phát hành (đối chiếu MANIFEST.sha256 ở thư mục gốc).

    python backend/tools/kiem_tra_file.py        (chạy ở thư mục itops-v2; CAI-DAT.bat tự chạy)
Báo file bị sửa, thiếu, và lỗi cú pháp Python (vd. thụt lề sai) trước khi bấm F5.
"""
import hashlib
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    man = ROOT / "MANIFEST.sha256"
    bad, missing = [], []
    if man.exists():
        for line in man.read_text(encoding="utf-8").splitlines():
            h, _, rel = line.partition("  ")
            f = ROOT / rel
            if not f.exists():
                missing.append(rel)
            elif hashlib.sha256(f.read_bytes()).hexdigest() != h:
                bad.append(rel)
    syntax = []
    for f in sorted((ROOT / "backend" / "app").rglob("*.py")):
        try:
            py_compile.compile(str(f), doraise=True)
        except py_compile.PyCompileError as e:
            syntax.append(f"{f.relative_to(ROOT)}: {e.exc_value}")
    for title, items in (("File KHÁC bản phát hành (đã bị sửa)", bad), ("File BỊ THIẾU", missing), ("LỖI CÚ PHÁP Python", syntax)):
        if items:
            print(f"{title}:")
            for x in items[:30]:
                print("   ", x)
    if bad or missing or syntax:
        print("\n→ Giải nén lại itops-v2.zip vào THƯ MỤC MỚI (không chép đè), hoặc chép đè đúng các file trên từ file zip.")
        return 1
    print(f"Mã nguồn khớp bản phát hành ({'có' if man.exists() else 'không có'} MANIFEST), không lỗi cú pháp.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
