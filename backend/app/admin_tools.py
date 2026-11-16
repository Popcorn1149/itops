"""Server-side administration tools (not web-based) – for emergencies or maintenance.

Run from the backend directory with the same DATA_DIR as the app:
    python -m app.admin_tools reset-2fa <username>      # the only admin has lost their phone
    python -m app.admin_tools reset-password <username> # forgot password: print a random new password and revoke all sessions
    python -m app.admin_tools revoke-sessions <username|--all>
    python -m app.admin_tools backup [destination_directory]       # back up the database, two keys, and archive to a .zip file
    python -m app.admin_tools restore <file.zip> [--wipe] # restore (stop the app first); --wipe = wipe the current database
    python -m app.admin_tools import-sqlite <itops.db> [--keys-from DIRECTORY] [--wipe]
                                                         # migrate v1 / v2-SQLite data to PostgreSQL
    python -m app.admin_tools gen-cert [hostname_or_IP ...]   # self-signed HTTPS certificate for LAN
All operations are recorded in the audit log under user "cli"."""
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
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "7"))         # 0 = disabled sao lưu tự động
BACKUP_HOUR = int(os.environ.get("BACKUP_HOUR", "2"))          # hours địa phương chạy sao lưu daily
TLS_DIR = os.path.join(DATA_DIR, "tls")


def _audit(db, action: str, detail: str):
    db.add(models.AuditLog(user="cli", action=action, entity="system", detail=detail[:2000], ip="localhost", user_agent="admin_tools"))


# ---------------------------------------------------------------- 2FA / sessions
def reset_2fa(username: str) -> str:
    from .security import revoke_sessions
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(username=username).first()
        if not u:
            raise SystemExit(f"Account not found '{username}'")
        u.totp_enabled, u.totp_secret, u.totp_pending, u.totp_last_step = False, None, None, 0
        n = revoke_sessions(db, username, "cli")
        _audit(db, "reset_2fa", f"Reset 2FA for {username} via CLI; revoked {n} sessions")
        db.commit()
    return f"2FA reset for {username}. The user will be prompted to re-enable 2FA at the next sign-in."


def reset_password(username: str) -> str:
    import secrets
    from .security import hash_password, revoke_sessions
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(username=username).first()
        if not u:
            names = ", ".join(x.username for x in db.query(models.User)) or "(no accounts found – run the app once to create the admin account)"
            raise SystemExit(f"Account '{username}' not found. Existing accounts: {names}")
        pw = secrets.token_urlsafe(12)
        u.password_hash = hash_password(pw)
        n = revoke_sessions(db, username, "cli")
        _audit(db, "reset_password", f"Reset password for {username} via CLI; revoked {n} sessions")
        db.commit()
    return f"New password for {username}: {pw}\n(2FA is unchanged. Change the password after signing in.)"


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
        _audit(db, "revoke", f"Revoked {n} sessions ({username}) via the command line")
        db.commit()
    return f"Revoked {n} sessions."


# ---------------------------------------------------------------- sao lưu
def backup(dest_dir: str | None = None, reason: str = "manual") -> Path:
    """Create a consistent backup while the app is running (ảnh chụp REPEATABLE READ, xem dbdump.py) + .secret_key + .enc_key + archive/.
    WARNING: the backup contains keys used to decrypt device passwords. Store it where only administrators have access."""
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
    os.replace(tmp, out)            # Publish the archive only after the write completes.
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    with SessionLocal() as db:
        _audit(db, "backup", f"Backup ({reason}) → {out} · {sum(man['tables'].values())} records · schema {man['revision']}")
        db.commit()
    return out


RESTORE_NOTE = """Restore IT Ops Workspace v2 from a backup
1. Stop the app (leave PostgreSQL running).
2. From the backend directory, use the same DATA_DIR / PG_LOCAL or DATABASE_URL settings as the original app:
       python -m app.admin_tools restore <file.zip> --wipe
   (--wipe wipe the current database before restoring; omit --wipe if the target database is empty)
   The command copies .secret_key, .enc_key, and archive/ into DATA_DIR (existing keys are preserved as .bak-<hours>).
3. Restart the app. The app upgrades the database automatically if the backup is from an older version.
If .enc_key is missing, stored device passwords/community strings cannot be decrypted and must be entered again.
"""


def _upgrade(conn, rev: str):
    from alembic import command
    from .db import _alembic_config
    command.upgrade(_alembic_config(conn), rev)


def _install_keys(src_dir: Path | None, z: zipfile.ZipFile | None = None) -> list[str]:
    """Copy .secret_key / .enc_key into DATA_DIR; existing keys are preserved as .bak-<timestamp>."""
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
            raise SystemExit(f"Restore failed: {e}") from None
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
        _audit(db, "restore", f"Restored from {Path(zip_path).name} (schema {info['revision']}, keys: {', '.join(keys) or 'unchanged'})")
        db.commit()
    return f"Restored {sum(info['tables'].values())} records (schema {info['revision']} → latest). Keys: {', '.join(keys) or 'unchanged'}."


def import_sqlite(path: str, keys_from: str | None = None, wipe: bool = False) -> str:
    from . import dbdump
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"File not found: {p}")
    try:
        info = dbdump.import_sqlite(engine, str(p), _upgrade, wipe_first=wipe)
    except dbdump.DumpError as e:
        raise SystemExit(f"Migration failed: {e}") from None
    keys = _install_keys(Path(keys_from) if keys_from else p.parent)
    # Bí mật dạng Fernet cũ (enc:) được app mã hoá lại sang AES-256-GCM (enc2:) ở LẦN KHỞI ĐỘNG TỚI – lúc đó app
    # mới restored đúng khoá vừa chép (this process has already loaded khoá cũ khi import app.security).
    with SessionLocal() as db:
        _audit(db, "import", f"Imported SQLite data from {p.name} → PostgreSQL ({sum(info['tables'].values())} records)")
        db.commit()
    lines = [f"Migrated {sum(info['tables'].values())} records from {p.name}:"]
    lines += [f"  {t:<20} {n}" for t, n in sorted(info["tables"].items()) if n]
    if info["ignored_tables"]:
        lines.append("Tables not present in v2 (skipped): " + ", ".join(f"{t} ({n})" for t, n in info["ignored_tables"].items()))
    lines.append(f"Keys copied: {', '.join(keys) or 'none (legacy device secrets may not be decryptable)'}")
    lines.append("Existing sessions are not migrated; all users must sign in again.")
    lines.append("On first startup, the app re-encrypts legacy device passwords using AES-256-GCM.")
    return "\n".join(lines)


def prune_backups(dest_dir: str | None = None, keep: int = BACKUP_KEEP) -> int:
    files = sorted(Path(dest_dir or BACKUP_DIR).glob("itops-backup-*.zip"))
    old = files[:-keep] if keep > 0 else []
    for f in old:
        f.unlink()
    return len(old)


async def backup_loop():
    """Run an automatic backup daily after BACKUP_HOUR (local time), retaining the latest BACKUP_KEEP copies."""
    if BACKUP_KEEP <= 0:
        return
    from .automation.engine import TZ
    while True:
        try:
            t = datetime.now(TZ)
            today = t.strftime("%Y%m%d")
            have = list(Path(BACKUP_DIR).glob(f"itops-backup-{today}-*.zip")) if Path(BACKUP_DIR).is_dir() else []
            if t.hour >= BACKUP_HOUR and not have:
                out = await asyncio.to_thread(backup, None, "daily automatic")
                removed = prune_backups()
                log.warning("Backup created: %s (%d old backups removed)", out.name, removed)
        except Exception:
            log.exception("Automatic backup failed")
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
    run_migrations()             # đảm bảo CSDL đúng sessions bản trước khi thao tác
    if cmd == "reset-password" and args:
        print(reset_password(args[0]))
    elif cmd == "reset-2fa" and args:
        print(reset_2fa(args[0]))
    elif cmd == "revoke-sessions" and args:
        print(revoke(args[0]))
    elif cmd == "backup":
        print(f"Backup created:  {backup(args[0] if args else None)}")
    elif cmd == "gen-cert":
        cp, kp = gen_cert(args)
        print(f"Self-signed certificate created: \n  {cp}\n  {kp}\nThe browser will warn about the self-signed certificate. Click Advanced → Proceed (LAN use only).")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
