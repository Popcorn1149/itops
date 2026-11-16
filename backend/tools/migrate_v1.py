"""Move data from the running v1 (SQLite) -> v2 (PostgreSQL, real devices configuration) - v1 does NOT need to be stopped.

    python tools/migrate_v1.py [V1_FOLDER] [--yes]

- V1_FOLDER defaults to the "itops" folder next to the v2 folder (e.g. Documents\\itops).
- Takes a snapshot of the v1 database with the SQLite backup API (safe while v1 is writing, includes the -wal part) into a temp file,
  loads it into the v2 PostgreSQL (DELETES the current v2 data), copies v1's .secret_key, then deletes the temp file.
- v1 files are only READ. Can be run any number of times (each run takes the latest v1 data).
- Stop the v2 app (Shift+F5) before running.
"""
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DATA_DIR", str(BACKEND / "data-v2-local"))
os.environ.setdefault("PG_LOCAL", "1")
os.environ.setdefault("PG_LOCAL_PORT", "5434")
os.environ.setdefault("PYTHONUTF8", "1")


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def snapshot(src: Path, dst: Path) -> None:
    con = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True, timeout=30)
    out = sqlite3.connect(str(dst))
    try:
        con.backup(out)
    finally:
        out.close()
        con.close()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    v1 = Path(args[0]) if args else ROOT.parent / "itops"
    data1 = v1 / "backend" / "data-local"
    db1 = data1 / "itops.db"
    if not db1.is_file():
        print(f"[ERROR] v1 database not found: {db1}")
        return 1
    if port_open(8100):
        print("[ERROR] The v2 app is running (port 8100) -> Shift+F5 to stop v2, then run again. (v1 does NOT need to stop.)")
        return 1
    print(f"Source v1 : {db1}")
    print(f"Target v2 : PostgreSQL port {os.environ['PG_LOCAL_PORT']}, DATA_DIR={os.environ['DATA_DIR']}")
    print("Current v2 data in the real devices configuration will be DELETED and replaced with the v1 data.")
    if "--yes" not in argv and input("Type YES to continue: ").strip() != "YES":
        print("Cancelled.")
        return 1

    tmp_dir = BACKEND / "data-v2-import"
    tmp_dir.mkdir(exist_ok=True)
    tmp = tmp_dir / f"itops-v1-{time.strftime('%Y%m%d-%H%M%S')}.db"
    t0 = time.time()
    snapshot(db1, tmp)
    print(f"v1 database snapshot taken ({tmp.stat().st_size // 1024} KB, {time.time() - t0:.1f}s)")
    try:
        from app import admin_tools
        print(admin_tools.import_sqlite(str(tmp), keys_from=str(data1), wipe=True))
    finally:
        for f in (tmp, tmp.with_name(tmp.name + "-wal"), tmp.with_name(tmp.name + "-shm")):
            try:
                f.unlink()
            except OSError:
                pass
    print("\nDone. F5 -> choose '▶ Song song với v1' (parallel with v1, recommended) or '▶ Thiết bị thật' (real devices), "
          "sign in with the OLD v1 admin password.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
