"""Công cụ quản trị chạy trên máy chủ (không qua web) – dùng khi khẩn cấp hoặc bảo trì.

Chạy trong thư mục backend, với cùng DATA_DIR như app:
    python -m app.admin_tools reset-2fa <username>      # admin duy nhất mất điện thoại
    python -m app.admin_tools reset-password <username> # quên mật khẩu: in mật khẩu mới ngẫu nhiên, thu hồi mọi phiên
    python -m app.admin_tools revoke-sessions <username|--all>
    python -m app.admin_tools backup [thư_mục_đích]       # sao lưu CSDL + 2 khoá + archive ra file .zip
    python -m app.admin_tools restore <file.zip> [--wipe] # khôi phục (dừng app trước); --wipe = xoá sạch CSDL hiện tại
    python -m app.admin_tools import-sqlite <itops.db> [--keys-from THƯ_MỤC] [--wipe]
                                                         # chuyển dữ liệu bản v1 / v2-SQLite sang PostgreSQL
    python -m app.admin_tools gen-cert [tên_máy_hoặc_IP ...]   # chứng chỉ HTTPS tự ký cho LAN
Mọi thao tác đều ghi vào nhật ký (audit) với user "cli".
"""
import asyncio
import ipaddress
import logging
import os
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import DATA_DIR, SessionLocal, engine
from . import models

log = logging.getLogger("itops.admin")
BACKUP_DIR = os.environ.get("BACKUP_DIR", os.path.join(DATA_DIR, "backups"))
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "7"))         # 0 = tắt sao lưu tự động
BACKUP_HOUR = int(os.environ.get("BACKUP_HOUR", "2"))          # giờ địa phương chạy sao lưu hằng ngày
TLS_DIR = os.path.join(DATA_DIR, "tls")


def _audit(db, action: str, detail: str):
    db.add(models.AuditLog(user="cli", action=action, entity="system", detail=detail[:2000], ip="localhost", user_agent="admin_tools"))


# ---------------------------------------------------------------- 2FA / phiên
def reset_2fa(username: str) -> str:
    from .security import revoke_sessions
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(username=username).first()
        if not u:
            raise SystemExit(f"Không có tài khoản '{username}'")
        u.totp_enabled, u.totp_secret, u.totp_pending, u.totp_last_step = False, None, None, 0
        n = revoke_sessions(db, username, "cli")
        _audit(db, "reset_2fa", f"Đặt lại 2FA của {username} bằng dòng lệnh, thu hồi {n} phiên")
        db.commit()
    return f"Đã đặt lại 2FA của {username}. Lần đăng nhập tới sẽ được yêu cầu bật lại 2FA."


def reset_password(username: str) -> str:
    import secrets
    from .security import hash_password, revoke_sessions
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(username=username).first()
        if not u:
            names = ", ".join(x.username for x in db.query(models.User)) or "(chưa có tài khoản nào – chạy app một lần để tạo admin)"
            raise SystemExit(f"Không có tài khoản '{username}'. Tài khoản đang có: {names}")
        pw = secrets.token_urlsafe(12)
        u.password_hash = hash_password(pw)
        n = revoke_sessions(db, username, "cli")
        _audit(db, "reset_password", f"Đặt lại mật khẩu {username} bằng dòng lệnh, thu hồi {n} phiên")
        db.commit()
    return f"Mật khẩu mới của {username}: {pw}\n(2FA giữ nguyên. Đổi mật khẩu sau khi đăng nhập.)"


def revoke(username: str) -> str:
    from .security import now
    with SessionLocal() as db:
        q = db.query(models.LoginSession).filter_by(revoked_at=None)
        if username != "--all":
            q = q.filter_by(username=username)
        n = 0
        for s in q:
            s.revoked_at, s.revoked_by = now(), "cli"
            n += 1
        _audit(db, "revoke", f"Thu hồi {n} phiên ({username}) bằng dòng lệnh")
        db.commit()
    return f"Đã thu hồi {n} phiên."


# ---------------------------------------------------------------- sao lưu
def backup(dest_dir: str | None = None, reason: str = "thủ công") -> Path:
    """Sao lưu nhất quán khi app đang chạy (ảnh chụp REPEATABLE READ, xem dbdump.py) + .secret_key + .enc_key + archive/.
    CẢNH BÁO: file sao lưu chứa khoá giải mã mật khẩu thiết bị → cất ở nơi chỉ admin truy cập được."""
    from . import dbdump
    dest = Path(dest_dir or BACKUP_DIR)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = dest / f"itops-backup-{stamp}.zip"
    data = Path(DATA_DIR)
    tmp = out.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        man = dbdump.dump_to_zip(engine, z)
        for f in (".secret_key", ".enc_key"):
            if (data / f).exists():
                z.write(data / f, f)
        arch = data / "archive"
        if arch.is_dir():
            for p in arch.rglob("*"):
                if p.is_file():
                    z.write(p, str(p.relative_to(data)))
        z.writestr("KHOI-PHUC.txt", RESTORE_NOTE)
    os.replace(tmp, out)            # chỉ xuất hiện file .zip khi đã ghi xong
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    with SessionLocal() as db:
        _audit(db, "backup", f"Sao lưu ({reason}) → {out} · {sum(man['tables'].values())} bản ghi · schema {man['revision']}")
        db.commit()
    return out


RESTORE_NOTE = """Khôi phục IT Ops Workspace v2 từ bản sao lưu
1. Dừng app (PostgreSQL vẫn chạy).
2. Trong thư mục backend, cùng DATA_DIR / PG_LOCAL hoặc DATABASE_URL như khi chạy app:
       python -m app.admin_tools restore <file.zip> --wipe
   (--wipe xoá sạch CSDL hiện tại trước khi nạp; bỏ --wipe nếu CSDL đích còn trống)
   Lệnh tự chép .secret_key, .enc_key và archive/ về DATA_DIR (khoá cũ được giữ lại dạng .bak-<giờ>).
3. Chạy lại app. App tự nâng cấp CSDL nếu bản sao lưu cũ hơn phiên bản hiện tại.
Thiếu .enc_key → mật khẩu/community thiết bị đã lưu KHÔNG giải mã được (phải nhập lại).
"""


def _upgrade(conn, rev: str):
    from alembic import command
    from .db import _alembic_config
    command.upgrade(_alembic_config(conn), rev)


def _install_keys(src_dir: Path | None, z: zipfile.ZipFile | None = None) -> list[str]:
    """Chép .secret_key / .enc_key vào DATA_DIR; khoá đang có được giữ lại dạng .bak-<giờ>."""
    data = Path(DATA_DIR)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    done = []
    for f in (".secret_key", ".enc_key"):
        blob = None
        if z is not None and f in z.namelist():
            blob = z.read(f)
        elif src_dir is not None and (src_dir / f).exists():
            blob = (src_dir / f).read_bytes()
        if blob is None:
            continue
        dst = data / f
        if dst.exists():
            if dst.read_bytes() == blob:
                continue
            dst.rename(data / f"{f}.bak-{stamp}")
        dst.write_bytes(blob)
        try:
            os.chmod(dst, 0o600)
        except OSError:
            pass
        done.append(f)
    return done


def restore(zip_path: str, wipe: bool = False) -> str:
    from . import dbdump
    with zipfile.ZipFile(zip_path) as z:
        try:
            info = dbdump.restore_from_zip(engine, z, _upgrade, wipe_first=wipe)
        except dbdump.DumpError as e:
            raise SystemExit(f"Không khôi phục được: {e}") from None
        keys = _install_keys(None, z)
        data = Path(DATA_DIR)
        for name in z.namelist():
            if name.startswith("archive/") and not name.endswith("/"):
                target = (data / name).resolve()
                if data.resolve() not in target.parents:
                    continue                         # chặn đường dẫn ../ trong file zip
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(name))
    with SessionLocal() as db:
        _audit(db, "restore", f"Khôi phục từ {Path(zip_path).name} (schema {info['revision']}, khoá: {', '.join(keys) or 'giữ nguyên'})")
        db.commit()
    return f"Đã khôi phục {sum(info['tables'].values())} bản ghi (schema {info['revision']} → mới nhất). Khoá: {', '.join(keys) or 'giữ nguyên'}."


def import_sqlite(path: str, keys_from: str | None = None, wipe: bool = False) -> str:
    from . import dbdump
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"Không thấy file {p}")
    try:
        info = dbdump.import_sqlite(engine, str(p), _upgrade, wipe_first=wipe)
    except dbdump.DumpError as e:
        raise SystemExit(f"Không chuyển được: {e}") from None
    keys = _install_keys(Path(keys_from) if keys_from else p.parent)
    # Bí mật dạng Fernet cũ (enc:) được app mã hoá lại sang AES-256-GCM (enc2:) ở LẦN KHỞI ĐỘNG TỚI – lúc đó app
    # mới nạp đúng khoá vừa chép (tiến trình này đã nạp khoá cũ khi import app.security).
    with SessionLocal() as db:
        _audit(db, "import", f"Chuyển dữ liệu SQLite {p.name} → PostgreSQL ({sum(info['tables'].values())} bản ghi)")
        db.commit()
    lines = [f"Đã chuyển {sum(info['tables'].values())} bản ghi từ {p.name}:"]
    lines += [f"  {t:<20} {n}" for t, n in sorted(info["tables"].items()) if n]
    if info["ignored_tables"]:
        lines.append("Bảng không có trong bản v2 (bỏ qua): " + ", ".join(f"{t} ({n})" for t, n in info["ignored_tables"].items()))
    lines.append(f"Khoá đã chép: {', '.join(keys) or 'không có (bí mật thiết bị cũ có thể không giải mã được)'}")
    lines.append("Phiên đăng nhập cũ không chuyển – mọi người đăng nhập lại.")
    lines.append("Chạy app: lần khởi động đầu tự mã hoá lại mật khẩu thiết bị kiểu cũ sang AES-256-GCM.")
    return "\n".join(lines)


def prune_backups(dest_dir: str | None = None, keep: int = BACKUP_KEEP) -> int:
    files = sorted(Path(dest_dir or BACKUP_DIR).glob("itops-backup-*.zip"))
    old = files[:-keep] if keep > 0 else []
    for f in old:
        f.unlink()
    return len(old)


async def backup_loop():
    """Sao lưu tự động mỗi ngày sau BACKUP_HOUR giờ (giờ địa phương), giữ BACKUP_KEEP bản gần nhất."""
    if BACKUP_KEEP <= 0:
        return
    from .automation.engine import TZ
    while True:
        try:
            t = datetime.now(TZ)
            today = t.strftime("%Y%m%d")
            have = list(Path(BACKUP_DIR).glob(f"itops-backup-{today}-*.zip")) if Path(BACKUP_DIR).is_dir() else []
            if t.hour >= BACKUP_HOUR and not have:
                out = await asyncio.to_thread(backup, None, "tự động hằng ngày")
                removed = prune_backups()
                log.warning("Đã sao lưu %s (xoá %d bản cũ)", out.name, removed)
        except Exception:
            log.exception("Sao lưu tự động lỗi")
        await asyncio.sleep(600)


# ---------------------------------------------------------------- HTTPS tự ký
def gen_cert(names: list[str]) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    names = names or ["localhost", "127.0.0.1"]
    san = []
    for n in names:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IT Ops Workspace")])
    t = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(t - timedelta(minutes=5)).not_valid_after(t + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    d = Path(TLS_DIR)
    d.mkdir(parents=True, exist_ok=True)
    kp, cp = d / "key.pem", d / "cert.pem"
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return cp, kp


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]
    flags = {a for a in args if a.startswith("--")}
    pos = [a for a in args if not a.startswith("--")]
    if cmd == "restore" and pos:
        print(restore(pos[0], wipe="--wipe" in flags))
        return 0
    if cmd == "import-sqlite" and pos:
        kf = None
        if "--keys-from" in args:
            i = args.index("--keys-from")
            kf = args[i + 1] if i + 1 < len(args) else None
            pos = [a for a in pos if a != kf]
        print(import_sqlite(pos[0], kf, wipe="--wipe" in flags))
        return 0
    from .db import run_migrations
    run_migrations()             # đảm bảo CSDL đúng phiên bản trước khi thao tác
    if cmd == "reset-password" and args:
        print(reset_password(args[0]))
    elif cmd == "reset-2fa" and args:
        print(reset_2fa(args[0]))
    elif cmd == "revoke-sessions" and args:
        print(revoke(args[0]))
    elif cmd == "backup":
        print(f"Đã sao lưu: {backup(args[0] if args else None)}")
    elif cmd == "gen-cert":
        cp, kp = gen_cert(args)
        print(f"Đã tạo chứng chỉ tự ký:\n  {cp}\n  {kp}\nTrình duyệt sẽ cảnh báo vì chứng chỉ tự ký – bấm Advanced → Proceed (chỉ dùng trong LAN).")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
