"""Công cụ quản trị chạy trên máy chủ (không qua web) – dùng khi khẩn cấp hoặc bảo trì.

Chạy trong thư mục backend, với cùng DATA_DIR như app:
    python -m app.admin_tools reset-2fa <username>      # admin duy nhất mất điện thoại
    python -m app.admin_tools revoke-sessions <username|--all>
    python -m app.admin_tools backup [thư_mục_đích]       # sao lưu CSDL + 2 khoá + archive ra file .zip
    python -m app.admin_tools gen-cert [tên_máy_hoặc_IP ...]   # chứng chỉ HTTPS tự ký cho LAN
Mọi thao tác đều ghi vào nhật ký (audit) với user "cli".
"""
import asyncio
import ipaddress
import logging
import os
import sqlite3
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import DATA_DIR, DATABASE_URL, SessionLocal
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
    """Sao lưu nhất quán khi app đang chạy (sqlite backup API) + .secret_key + .enc_key + archive/.
    CẢNH BÁO: file sao lưu chứa khoá giải mã mật khẩu thiết bị → cất ở nơi chỉ admin truy cập được."""
    if not DATABASE_URL.startswith("sqlite"):
        raise SystemExit("Sao lưu tích hợp chỉ hỗ trợ SQLite. Với PostgreSQL dùng pg_dump.")
    dest = Path(dest_dir or BACKUP_DIR)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = dest / f"itops-backup-{stamp}.zip"
    data = Path(DATA_DIR)
    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / "itops.db"
        src = sqlite3.connect(str(data / "itops.db"))
        dst = sqlite3.connect(str(snap))
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(snap, "itops.db")
            for f in (".secret_key", ".enc_key"):
                if (data / f).exists():
                    z.write(data / f, f)
            arch = data / "archive"
            if arch.is_dir():
                for p in arch.rglob("*"):
                    if p.is_file():
                        z.write(p, str(p.relative_to(data)))
            z.writestr("KHOI-PHUC.txt", RESTORE_NOTE)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    with SessionLocal() as db:
        _audit(db, "backup", f"Sao lưu ({reason}) → {out}")
        db.commit()
    return out


RESTORE_NOTE = """Khôi phục IT Ops Workspace từ bản sao lưu
1. Dừng app.
2. Giải nén toàn bộ file này vào thư mục dữ liệu (DATA_DIR, ví dụ backend/data-v2-local), ghi đè itops.db,
   .secret_key, .enc_key và thư mục archive/. Xoá itops.db-wal và itops.db-shm cũ nếu có.
3. Chạy lại app. App tự nâng cấp CSDL nếu bản sao lưu cũ hơn phiên bản hiện tại.
Thiếu .enc_key → mật khẩu/community thiết bị đã lưu KHÔNG giải mã được (phải nhập lại).
"""


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
    from .db import run_migrations
    run_migrations()             # đảm bảo CSDL đúng phiên bản trước khi thao tác
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]
    if cmd == "reset-2fa" and args:
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
