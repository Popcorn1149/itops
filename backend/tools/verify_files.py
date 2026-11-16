"""Check whether the source was modified / incompletely unzipped compared with the release (against MANIFEST.sha256 in the root folder).

    python backend/tools/verify_files.py        (run in the itops-v2 folder; SETUP.bat runs it automatically)
Reports modified files, missing files and Python syntax errors (e.g. wrong indentation) before you press F5.
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
    for title, items in (("CHANGED files (differ from the release)", bad), ("MISSING files", missing), ("Python SYNTAX ERRORS", syntax)):
        if items:
            print(f"{title}:")
            for x in items[:30]:
                print("   ", x)
    if bad or missing or syntax:
        print("\n-> Unzip itops-v2.zip again into a NEW FOLDER (do not copy over), or copy exactly the files above from the zip.")
        return 1
    print(f"Source matches the release ({'with' if man.exists() else 'no'} MANIFEST), no syntax errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
