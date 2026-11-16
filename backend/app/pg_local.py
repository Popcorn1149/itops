"""Bundled PostgreSQL (PG_LOCAL=1) – for demo/development in VS Code on Windows without a separate PostgreSQL installation.

- Binary: backend/tools/pgsql (downloaded automatically on first run, or manually with `python tools/get_postgres.py`) or the bin directory in PG_BIN.
- Data: <DATA_DIR>/pgdata  ·  random password: <DATA_DIR>/.pg_password  ·  log: <DATA_DIR>/postgres.log
- Listens only on 127.0.0.1 (PG_LOCAL_PORT, default 5433), SCRAM-SHA-256 authentication, no external socket.
- App startup → runs initdb on first use and starts PostgreSQL if it is not running. PostgreSQL remains running after the app is disabled (like a service);
  stop it explicitly with `python -m app.pg_local stop` (VS Code task "PostgreSQL: stop").

For production on Linux/Docker: do NOT use this mode – set DATABASE_URL to a real PostgreSQL instance.

    python -m app.pg_local start|stop|status|url"""
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DB_NAME = "itops"
DB_USER = "itops"
TOOLS_PG = Path(__file__).resolve().parent.parent / "tools" / "pgsql" / "bin"
WIN = os.name == "nt"


class PgLocalError(RuntimeError):
    pass


def _bin(name: str) -> str:
    d = Path(os.environ["PG_BIN"]) if os.environ.get("PG_BIN") else TOOLS_PG
    exe = d / (name + (".exe" if WIN else ""))
    if exe.exists():
        return str(exe)
    found = shutil.which(name)
    if found:
        return found
    if not os.environ.get("PG_BIN") and not getattr(_bin, "_tried", False):
        _bin._tried = True                     # lần chạy đầu: tự tải bộ Portable PostgreSQL (~30 MB, có kiểm tra sha512)
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("get_postgres", TOOLS_PG.parent.parent / "get_postgres.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.main([])
        except (Exception, SystemExit) as e:   # noqa: BLE001 – báo error gọn bên dưới
            raise PgLocalError(f"Unable to download PostgreSQL automatically ({e}). Run manually: python tools/get_postgres.py") from None
        return _bin(name)
    raise PgLocalError("No bundled PostgreSQL found. Run:  python tools/get_postgres.py  (or the VS Code task "
                       "\"0. Download PostgreSQL\"), or set DATABASE_URL to an existing PostgreSQL instance.")


def _paths(data_dir: str):
    d = Path(data_dir).resolve()
    return d / "pgdata", d / ".pg_password", d / "postgres.log"


def port() -> int:
    return int(os.environ.get("PG_LOCAL_PORT", "5433"))


# Windows: chạy ẩn, không enabled cửa sdisk console (pg_ctl gọi cmd.exe để chạy postgres – missing cờ này sẽ hiện cửa sdisk đen)
NO_WINDOW = 0x08000000 if WIN else 0          # CREATE_NO_WINDOW


def _run(args, **kw):
    if WIN:
        kw.setdefault("creationflags", NO_WINDOW)
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _not_root():
    if not WIN and hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PgLocalError("PostgreSQL cannot run under the root account. Run the app as a regular user, "
                           "or use a separate PostgreSQL instance (DATABASE_URL).")


def _init(pgdata: Path, pwfile: Path, p: int):
    pw = secrets.token_hex(24)                       # chỉ chữ số hex → without requiring mã hoá khi đưa ando URL
    pgdata.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pw", encoding="utf-8") as f:
        f.write(pw)
        tmp = f.name
    try:
        rc, out = _run([_bin("initdb"), "-D", str(pgdata), "-U", DB_USER, f"--pwfile={tmp}", "-A", "scram-sha-256",
                        "-E", "UTF8", "--locale=C"])
    finally:
        os.unlink(tmp)
    if rc != 0:
        raise PgLocalError(f"initdb error:\n{out[-1500:]}")
    with open(pgdata / "postgresql.conf", "a", encoding="utf-8") as f:
        f.write("\n# --- IT Ops (pg_local) ---\n"
                "listen_addresses = '127.0.0.1'\n"
                f"port = {p}\n"
                "unix_socket_directories = ''\n"       # chỉ TCP localhost
                "max_connections = 60\n"
                "shared_buffers = 128MB\n"
                "log_min_messages = warning\n"
                "timezone = 'UTC'\n")                  # app lưu hours UTC (naive), hiển thị theo TZ of app
    pwfile.write_text(pw, encoding="utf-8")
    try:
        os.chmod(pwfile, 0o600)
    except OSError:
        pass


def _running(pgdata: Path) -> bool:
    if not (pgdata / "postmaster.pid").exists():
        return False
    rc, _ = _run([_bin("pg_ctl"), "status", "-D", str(pgdata)])
    return rc == 0


def _port_busy(p: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", p)) == 0


def _start(pgdata: Path, log: Path, p: int):
    if _port_busy(p):
        raise PgLocalError(f"Port {p} is already in use by another process (possibly another PostgreSQL instance). Change PG_LOCAL_PORT or stop that process.")
    args = [_bin("pg_ctl"), "start", "-w", "-t", "60", "-D", str(pgdata), "-l", str(log), "-o", f"-p {p}"]
    # Output ghi ra FILE, không dùng pipe: postgres là tiến trình con of pg_ctl and có thể kế thừa handle of pipe
    # → subprocess chờ pipe đóng mãi (hay gặp trên Windows).
    out_file = log.with_name("pg_ctl.out")
    kw = {"stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT}
    with open(out_file, "w", encoding="utf-8", errors="replace") as fo:
        kw["stdout"] = fo
        if WIN:
            # tách khỏi tiến trình VS Code/debugger để Stop debug không "giết" PostgreSQL giữa chừng.
            # DO NOT use DETACHED_PROCESS: pg_ctl gọi cmd.exe → Windows mở cửa sdisk console mới. CREATE_NO_WINDOW = console ẩn.
            base = subprocess.CREATE_NEW_PROCESS_GROUP | NO_WINDOW
            try:
                rc = subprocess.run(args, creationflags=base | 0x01000000, **kw).returncode   # CREATE_BREAKAWAY_FROM_JOB
            except OSError:
                rc = subprocess.run(args, creationflags=base, **kw).returncode
        else:
            rc = subprocess.run(args, start_new_session=True, **kw).returncode
    out = out_file.read_text(encoding="utf-8", errors="replace")
    if rc != 0:
        tail = log.read_text(encoding="utf-8", errors="replace")[-1500:] if log.exists() else ""
        raise PgLocalError(f"Unable to start PostgreSQL:\n{out[-800:]}\n--- postgres.log ---\n{tail}")


def _ensure_db(url_admin: str):
    import psycopg
    for i in range(30):
        try:
            with psycopg.connect(url_admin, autocommit=True, connect_timeout=3) as c:
                if not c.execute("SELECT 1 FROM pg_database WHERE datname=%s", (DB_NAME,)).fetchone():
                    c.execute(f'CREATE DATABASE "{DB_NAME}" OWNER "{DB_USER}" ENCODING \'UTF8\' TEMPLATE template0')
            return
        except psycopg.OperationalError:
            if i == 29:
                raise
            time.sleep(0.5)


def ensure_running(data_dir: str) -> str:
    """Bảo đảm PostgreSQL kèm theo running, trả về DATABASE_URL (SQLAlchemy + psycopg)."""
    _not_root()
    pgdata, pwfile, log = _paths(data_dir)
    p = port()
    if not (pgdata / "PG_VERSION").exists():
        _init(pgdata, pwfile, p)
    if not pwfile.exists():
        raise PgLocalError(f"Missing {pwfile} (database password). Do not delete this file; if it is missing, delete the entire directory {pgdata} to recreate it.")
    pw = pwfile.read_text(encoding="utf-8").strip()
    if not _running(pgdata):
        _start(pgdata, log, p)
    _ensure_db(f"postgresql://{DB_USER}:{pw}@127.0.0.1:{p}/postgres")
    return f"postgresql+psycopg://{DB_USER}:{pw}@127.0.0.1:{p}/{DB_NAME}"


def stop(data_dir: str) -> bool:
    pgdata, _, _ = _paths(data_dir)
    if not _running(pgdata):
        return False
    rc, out = _run([_bin("pg_ctl"), "stop", "-w", "-m", "fast", "-D", str(pgdata)])
    if rc != 0:
        raise PgLocalError(out[-800:])
    return True


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "status"
    data_dir = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
    pgdata, _, _ = _paths(data_dir)
    try:
        if cmd == "start":
            ensure_running(data_dir)
            print(f"PostgreSQL running – 127.0.0.1:{port()}  data: {pgdata}")
        elif cmd == "stop":
            print("PostgreSQL stopped." if stop(data_dir) else "PostgreSQL is not running.")
        elif cmd == "status":
            print(f"PostgreSQL {'RUNNING' if (pgdata / 'PG_VERSION').exists() and _running(pgdata) else 'not running'} – {pgdata}")
        elif cmd == "url":                     # in URL (có password) để dùng với công cụ quản trị DB – cẩn thận khi chia sẻ màn hình
            print(ensure_running(data_dir))
        else:
            print(__doc__)
            return 2
    except PgLocalError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
