"""Tạo MANIFEST.sha256 trước khi đóng gói (mã băm các file mã nguồn chạy được)."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATTERNS = ["backend/app/**/*.py", "backend/migrations/**/*.py", "backend/tools/*.py", "backend/requirements*.txt",
            "backend/alembic.ini", "CAI-DAT.bat", "vscode-config/*.json", "backend/agent_dist/*"]
files = sorted({p for pat in PATTERNS for p in ROOT.glob(pat) if p.is_file() and "__pycache__" not in p.parts})
lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}" for p in files]
(ROOT / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(len(lines), "file")
