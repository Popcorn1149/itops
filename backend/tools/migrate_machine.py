"""Move IT Ops to a new machine with 2 commands (see MIGRATE-TO-NEW-MACHINE.md).

  OLD machine: stop IT Ops (Shift+F5) -> PREPARE-MIGRATION.bat -> python tools/migrate_machine.py pack
               Backs up live data, stops PostgreSQL, regenerates MANIFEST.sha256, packs the source + every file not in Git
               (static, agent_dist, GoFlow2, portable PostgreSQL, .env.local) into one zip file on the Desktop.
               Skipped: .venv (tied to the old machine's Python), node_modules, data-* folders (data travels as the backup),
               _backup (local backups of replaced files).
  NEW machine: unzip -> double-click SETUP-NEW-MACHINE.bat -> tools/setup_new_machine.ps1:
               installs Python/VS Code if missing -> SETUP.bat /auto -> migrate_machine.py restore -> firewall -> VS Code

  python tools/migrate_machine.py pack [--out FOLDER] [--no-backup]
  python tools/migrate_machine.py restore [backup-file.zip]
"""
import os
import socket
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]           # the itops-v2 folder
BACKEND = ROOT / "backend"
DATA = BACKEND / "data-v2-local"                     # the "real devices" launch configuration
PKG_DIR = "_migration"                               # folder holding the backup inside the zip file
LIVE_ENV = {"DATA_DIR": str(DATA), "PG_LOCAL": "1", "PG_LOCAL_PORT": "5434", "PYTHONUTF8": "1"}

# Not packed: recreated on the new machine, or tied to the old one (venv points to the old Python, pgdata is live)
SKIP_DIRS = {"node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", PKG_DIR, "_backup"}
SKIP_PATHS = {"frontend/dist", "agent/dist", "backend/tools/pgsql/share/doc"}


def _venv_python() -> str:
    exe = BACKEND / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return str(exe) if exe.exists() else sys.executable


def _skip(rel: Path) -> bool:
    parts = rel.parts
    if any(p in SKIP_DIRS for p in parts):
        return True
    if parts[:1] == ("backend",) and len(parts) > 1 and parts[1].startswith("data"):   # data-v2-local, data-v2-dev ...
        return True
    s = rel.as_posix()
    return any(s == p or s.startswith(p + "/") for p in SKIP_PATHS)


def _app_running(port: int = 8100) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _opt(args: list[str], *names: str) -> str | None:
    for n in names:
        if n in args and args.index(n) + 1 < len(args):
            return args[args.index(n) + 1]
    return None


def pack(args: list[str]) -> int:
    out_arg = _opt(args, "--out", "--ra")
    out_dir = Path(out_arg) if out_arg else Path.home() / "Desktop"
    if not out_dir.is_dir():
        out_dir = Path.home()
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    out = out_dir / f"itops-migration-{stamp}.zip"

    if _app_running():
        print("[ERROR] IT Ops is running (port 8100). Stop it first: VS Code Shift+F5, then run this file again.")
        return 1
    print("[1/4] Checking files that are not in Git ...")
    need = {"backend/static/index.html": "built web UI", "backend/agent_dist/SHA256SUMS.txt": "agent installers"}
    for rel, what in need.items():
        print(f"      {'OK     ' if (ROOT / rel).exists() else 'MISSING'}  {rel}  ({what})")
    gf = list((BACKEND / "tools" / "goflow2").glob("goflow2*.exe"))
    print(f"      {'OK     ' if gf else 'MISSING'}  GoFlow2 ({gf[0].name if gf else 'the new machine will have to download it'})")
    print(f"      {'OK     ' if (ROOT / '.env.local').exists() else '-      '}  .env.local")
    pg_ok = (BACKEND / "tools" / "pgsql" / "bin").is_dir()
    print(f"      {'OK     ' if pg_ok else '-      '}  portable PostgreSQL ({'packed' if pg_ok else 'the new machine will download it'})")

    backup = None
    if "--no-backup" in args or "--khong-sao-luu" in args:
        print("[2/4] Skipping backup (--no-backup).")
    elif not DATA.is_dir():
        print(f"[2/4] No {DATA.name} (real devices configuration never run) - no live data to back up.")
    else:
        print("[2/4] Backing up live data (database + 2 encryption keys) ...")
        tmp = ROOT / PKG_DIR
        tmp.mkdir(exist_ok=True)
        r = subprocess.run([_venv_python(), "-m", "app.admin_tools", "backup", str(tmp)], cwd=BACKEND,
                           env={**os.environ, **LIVE_ENV})
        found = sorted(tmp.glob("itops-backup-*.zip"), key=lambda p: p.stat().st_mtime)
        if r.returncode != 0 or not found:
            print("[ERROR] Backup failed - see the error above. Not packing without a backup.")
            return 1
        backup = found[-1]
        print(f"      done: {backup.name}")
        # stop the real-devices PostgreSQL - the old machine writes nothing after the backup
        subprocess.run([_venv_python(), "-m", "app.pg_local", "stop"], cwd=BACKEND, env={**os.environ, **LIVE_ENV})

    print("[3/4] Regenerating MANIFEST.sha256 (hashes of the package - the new machine checks against it) ...")
    man = ROOT / "MANIFEST.sha256"
    before = man.read_text(encoding="utf-8") if man.exists() else ""
    r = subprocess.run([_venv_python(), str(ROOT / "tools_make_manifest.py")], cwd=ROOT)
    if r.returncode != 0:
        print("[ERROR] Could not create MANIFEST.sha256.")
        return 1
    old = {l[66:]: l[:64] for l in before.splitlines() if len(l) > 66}
    new = {l[66:]: l[:64] for l in man.read_text(encoding="utf-8").splitlines() if len(l) > 66}
    changed = sorted(k for k in new if old.get(k) != new[k])
    print(f"      {len(new)} files, {len(changed)} differ from the previous manifest" + (f" (e.g. {', '.join(changed[:3])})" if changed else ""))

    print(f"[4/4] Packing -> {out} ...")
    n = 0
    part = out.with_suffix(".zip.part")
    with zipfile.ZipFile(part, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            rel_dir = Path(dirpath).relative_to(ROOT)
            dirnames[:] = [d for d in dirnames if not _skip(rel_dir / d)]
            for f in filenames:
                rel = rel_dir / f
                if _skip(rel) or rel.suffix == ".part":
                    continue
                z.write(Path(dirpath) / f, (Path("itops-v2") / rel).as_posix())
                n += 1
        if backup:
            z.write(backup, f"itops-v2/{PKG_DIR}/{backup.name}")
    os.replace(part, out)
    if backup:
        backup.unlink()
        try:
            (ROOT / PKG_DIR).rmdir()
        except OSError:
            pass
    size = out.stat().st_size / 1e6
    print(f"""
DONE: {out}  ({n} files, {size:.0f} MB)
{'!! This file CONTAINS the 2 data encryption keys - copy it by USB / an IT-only folder, NEVER by email/chat.' if backup else ''}
Next:
  1. From now on do NOT press F5 on the real devices configuration on this machine (new data would not reach the new machine).
  2. Copy the zip to the new machine, unzip it (gives an itops-v2 folder), double-click itops-v2\\SETUP-NEW-MACHINE.bat
""")
    return 0


def restore(args: list[str]) -> int:
    pos = [a for a in args if not a.startswith("--")]
    if pos:
        zip_path = Path(pos[0])
    else:
        found = sorted((ROOT / PKG_DIR).glob("itops-backup-*.zip"), key=lambda p: p.stat().st_mtime)
        if not found:
            print(f"No backup in {PKG_DIR}\\ - skipping the data restore step.")
            print("  Backup file somewhere else: run again  SETUP-NEW-MACHINE.bat \"D:\\path\\itops-backup-....zip\"")
            return 0
        zip_path = found[-1]
    if not zip_path.is_file():
        print(f"[ERROR] Backup file not found: {zip_path}")
        return 1
    if _app_running():
        print("[ERROR] IT Ops is running (port 8100). Stop it with Shift+F5 in VS Code and run again.")
        return 1

    print(f"Restoring live data from {zip_path.name} ...")
    if DATA.exists() and any(DATA.iterdir()):
        # existing data (e.g. a folder copied by hand from the old machine) - rename, never delete, so you can go back
        old = DATA.with_name(f"{DATA.name}.old-{datetime.now():%Y%m%d-%H%M%S}")
        try:
            DATA.rename(old)
        except OSError as e:
            print(f"[ERROR] Could not rename {DATA} ({e}).")
            print("        Close VS Code / stop PostgreSQL (task 12) and run again.")
            return 1
        print(f"      Previous data folder kept as: {old.name} (delete it once everything runs fine)")
    DATA.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([_venv_python(), "-m", "app.admin_tools", "restore", str(zip_path), "--wipe"],
                       cwd=BACKEND, env={**os.environ, **LIVE_ENV})
    if r.returncode != 0:
        print("[ERROR] Restore failed - see the error above.")
        return 1
    if not pos:     # mark as used -> running SETUP-NEW-MACHINE.bat again does not restore over newer data
        try:
            zip_path.rename(zip_path.with_name(zip_path.name + ".restored"))
        except OSError:
            pass
    print("      done.")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = {"pack": pack, "restore": restore, "dong-goi": pack, "khoi-phuc": restore}.get(argv[0])
    if not cmd:
        print(__doc__)
        return 2
    return cmd(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
