"""PostgreSQL chạy kèm (PG_LOCAL=1) – dùng cho demo/dev bằng VS Code trên Windows, không cần cài PostgreSQL.

- Binary: backend/tools/pgsql (lần đầu tự tải, hoặc chạy tay `python tools/get_postgres.py`) hoặc thư mục bin trong biến PG_BIN.
- Dữ liệu: <DATA_DIR>/pgdata  ·  mật khẩu ngẫu nhiên: <DATA_DIR>/.pg_password  ·  log: <DATA_DIR>/postgres.log
- Chỉ nghe 127.0.0.1 (cổng PG_LOCAL_PORT, mặc định 5433), xác thực scram-sha-256, không mở socket ra ngoài.
- App khởi động → tự initdb lần đầu + start nếu chưa chạy. PostgreSQL vẫn chạy sau khi tắt app (như một dịch vụ);
  tắt hẳn: `python -m app.pg_local stop` (task VS Code "PostgreSQL: dừng").

Chạy thật trên Linux/Docker: KHÔNG dùng chế độ này – đặt DATABASE_URL trỏ tới PostgreSQL thật.

    python -m app.pg_local start|stop|status|url
"""
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
        _bin._tried = True                     # lần chạy đầu: tự tải bộ PostgreSQL di động (~30 MB, có kiểm tra sha512)
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("get_postgres", TOOLS_PG.parent.parent / "get_postgres.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.main([])
        except (Exception, SystemExit) as e:   # noqa: BLE001 – báo lỗi gọn bên dưới
            raise PgLocalError(f"Tự tải PostgreSQL không được ({e}). Chạy tay: python tools/get_postgres.py") from None
        return _bin(name)
    raise PgLocalError("Chưa có PostgreSQL di động. Chạy:  python tools/get_postgres.py  (hoặc task VS Code "
                       "\"0. Tải PostgreSQL\"), hoặc đặt DATABASE_URL tới PostgreSQL có sẵn.")


def _paths(data_dir: str):
    d = Path(data_dir).resolve()
    return d / "pgdata", d / ".pg_password", d / "postgres.log"


def port() -> int:
    return int(os.environ.get("PG_LOCAL_PORT", "5433"))


# Windows: chạy ẩn, không bật cửa sổ console (pg_ctl gọi cmd.exe để chạy postgres – thiếu cờ này sẽ hiện cửa sổ đen)
NO_WINDOW = 0x08000000 if WIN else 0          # CREATE_NO_WINDOW


def _run(args, **kw):
    if WIN:
        kw.setdefault("creationflags", NO_WINDOW)
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _not_root():
    if not WIN and hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PgLocalError("PostgreSQL không chạy bằng tài khoản root. Hãy chạy app bằng user thường, "
                           "hoặc dùng PostgreSQL riêng (DATABASE_URL).")


def _init(pgdata: Path, pwfile: Path, p: int):
    pw = secrets.token_hex(24)                       # chỉ chữ số hex → không cần mã hoá khi đưa vào URL
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
        raise PgLocalError(f"initdb lỗi:\n{out[-1500:]}")
    with open(pgdata / "postgresql.conf", "a", encoding="utf-8") as f:
        f.write("\n# --- IT Ops (pg_local) ---\n"
                "listen_addresses = '127.0.0.1'\n"
                f"port = {p}\n"
                "unix_socket_directories = ''\n"       # chỉ TCP localhost
                "max_connections = 60\n"
                "shared_buffers = 128MB\n"
                "log_min_messages = warning\n"
                "timezone = 'UTC'\n")                  # app lưu giờ UTC (naive), hiển thị theo TZ của app
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
        raise PgLocalError(f"Cổng {p} đang có chương trình khác dùng (PostgreSQL khác?). Đổi PG_LOCAL_PORT hoặc tắt chương trình đó.")
    args = [_bin("pg_ctl"), "start", "-w", "-t", "60", "-D", str(pgdata), "-l", str(log), "-o", f"-p {p}"]
    # Output ghi ra FILE, không dùng pipe: postgres là tiến trình con của pg_ctl và có thể kế thừa handle của pipe
    # → subprocess chờ pipe đóng mãi (hay gặp trên Windows).
    out_file = log.with_name("pg_ctl.out")
    kw = {"stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT}
    with open(out_file, "w", encoding="utf-8", errors="replace") as fo:
        kw["stdout"] = fo
        if WIN:
            # tách khỏi tiến trình VS Code/debugger để Stop debug không "giết" PostgreSQL giữa chừng.
            # KHÔNG dùng DETACHED_PROCESS: pg_ctl gọi cmd.exe → Windows mở cửa sổ console mới. CREATE_NO_WINDOW = console ẩn.
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
        raise PgLocalError(f"Không khởi động được PostgreSQL:\n{out[-800:]}\n--- postgres.log ---\n{tail}")


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
    """Bảo đảm PostgreSQL kèm theo đang chạy, trả về DATABASE_URL (SQLAlchemy + psycopg)."""
    _not_root()
    pgdata, pwfile, log = _paths(data_dir)
    p = port()
    if not (pgdata / "PG_VERSION").exists():
        _init(pgdata, pwfile, p)
    if not pwfile.exists():
        raise PgLocalError(f"Thiếu {pwfile} (mật khẩu CSDL). Không xoá file này; nếu đã mất hãy xoá cả thư mục {pgdata} để tạo lại.")
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
            print(f"PostgreSQL đang chạy – 127.0.0.1:{port()}  dữ liệu: {pgdata}")
        elif cmd == "stop":
            print("Đã dừng PostgreSQL." if stop(data_dir) else "PostgreSQL không chạy.")
        elif cmd == "status":
            print(f"PostgreSQL {'ĐANG CHẠY' if (pgdata / 'PG_VERSION').exists() and _running(pgdata) else 'không chạy'} – {pgdata}")
        elif cmd == "url":                     # in URL (có mật khẩu) để dùng với công cụ quản trị DB – cẩn thận khi chia sẻ màn hình
            print(ensure_running(data_dir))
        else:
            print(__doc__)
            return 2
    except PgLocalError as e:
        print(f"LỖI: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
