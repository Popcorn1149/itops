"""Logical backup / restore / data migration (no pg_dump required – also works with the bundled PostgreSQL executable on Windows).

ZIP archive format:
    db/manifest.json          {"format": 1, "revision": "<alembic>", "tables": {"users": 3, ...}}
    db/<table>.jsonl          one JSON record per line
    .secret_key, .enc_key     copied separately; never included in the database dump
    archive/                  archived files

The dump is database-independent and can be restored through SQLAlchemy."""
import json
import zipfile
from datetime import date, datetime
from decimal import Decimal
from typing import Iterable, Iterator

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, MetaData, inspect, select, text
from sqlalchemy.dialects.postgresql import JSON, JSONB
from sqlalchemy.types import JSON as SA_JSON

FORMAT = 1
BATCH = 1000
SKIP_TABLES = {"alembic_version", "flow_1m", "flow_1h"}   # traffic history: large, rebuilt from live data – not backed up


class DumpError(RuntimeError):
    pass


def _enc(v):
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (bytes, memoryview)):
        raise DumpError("Binary columns are not supported by logical backup")
    return v


def _reflect(conn) -> MetaData:
    md = MetaData()
    md.reflect(bind=conn)
    for t in SKIP_TABLES:
        if t in md.tables:
            md.remove(md.tables[t])
    return md


def current_revision(conn) -> str | None:
    from alembic.runtime.migration import MigrationContext
    return MigrationContext.configure(conn).get_current_revision()


# ---------------------------------------------------------------- xuất
def dump_to_zip(engine, z: zipfile.ZipFile, prefix: str = "db/") -> dict:
    counts = {}
    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="REPEATABLE READ", postgresql_readonly=True)
        with conn.begin():
            rev = current_revision(conn)
            md = _reflect(conn)
            for t in md.sorted_tables:
                pk = list(t.primary_key.columns)
                q = select(t).order_by(*pk) if pk else select(t)
                n = 0
                with z.open(f"{prefix}{t.name}.jsonl", "w", force_zip64=True) as f:
                    for row in conn.execution_options(yield_per=BATCH).execute(q).mappings():
                        f.write((json.dumps({k: _enc(v) for k, v in row.items()}, ensure_ascii=False) + "\n").encode())
                        n += 1
                counts[t.name] = n
    manifest = {"format": FORMAT, "revision": rev, "tables": counts, "created": datetime.now().isoformat(timespec="seconds"),
                "dialect": engine.dialect.name}
    z.writestr(f"{prefix}manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
    return manifest


# ---------------------------------------------------------------- restored
def _coerce(col, v):
    """Đưa value (from JSONL hoặc SQLite) về đúng kiểu cột PostgreSQL."""
    if v is None:
        return None
    t = col.type
    if isinstance(t, (JSON, JSONB, SA_JSON)):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except ValueError:
                return v
        return v
    if isinstance(t, Boolean):
        if isinstance(v, str):
            return v.strip().lower() in ("1", "true", "t", "yes")
        return bool(v)
    if isinstance(t, DateTime):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
        return v
    if isinstance(t, Date) and isinstance(v, str):
        return date.fromisoformat(v[:10])
    if isinstance(t, Integer) and not isinstance(v, bool) and isinstance(v, (str, float)):
        return int(float(v))
    if isinstance(t, Float) and isinstance(v, str):
        return float(v)
    if hasattr(t, "length") and getattr(t, "length", None) and isinstance(v, str) and len(v) > t.length:
        return v[: t.length]          # SQLite unlimited độ dài, PostgreSQL có
    return v


def is_empty(conn) -> bool:
    md = _reflect(conn)
    for t in md.tables.values():
        if conn.execute(select(text("1")).select_from(t).limit(1)).first():
            return False
    return True


def wipe(conn):
    """Xoá sạch schema public (cần quyền owner). TRUNCATE audit_logs bị trigger chặn nên phải DROP cả schema."""
    conn.execute(text("DROP SCHEMA public CASCADE"))
    conn.execute(text("CREATE SCHEMA public"))


def load_rows(conn, md: MetaData, rows_by_table) -> dict:
    """rows_by_table(name) → iterable các dict. Chỉ chép cột có ở cả hai phía; cột missing dùng default of model."""
    from . import models  # noqa: F401 – restored model để lấy default (Column.default) cho cột không có trong nguồn
    from .db import Base
    counts = {}
    for t in md.sorted_tables:
        model_t = Base.metadata.tables.get(t.name)
        self_fk = [fk.parent.name for fk in t.foreign_keys if fk.column.table.name == t.name]
        deferred = []           # (pk, {col: val}) cho khoá ngoại trỏ về chính bảng (e.g. assets.parent_id)
        n = 0
        batch = []
        # bảng of model (có default cho cột missing) chỉ dùng khi schema đích already đúng như model (khôi phục ở head / import)
        target = model_t if model_t is not None and set(model_t.c.keys()) <= set(t.c.keys()) else t

        cols_seen = None
        for raw in rows_by_table(t.name):
            row = {}
            for k, v in raw.items():
                c = t.columns.get(k)
                if c is None:
                    continue
                row[k] = _coerce(c, v)
            if cols_seen is None:
                cols_seen = set(row)
            row = {k: row.get(k) for k in cols_seen}          # cùng tập cột trong một lô executemany
            for k in self_fk:
                if row.get(k) is not None:
                    deferred.append((row.get("id"), k, row[k]))
                    row[k] = None
            batch.append(row)
            n += 1
            if len(batch) >= BATCH:
                conn.execute(target.insert(), batch)
                batch.clear()
        if batch:
            conn.execute(target.insert(), batch)
        for pk, k, v in deferred:
            conn.execute(t.update().where(t.c.id == pk).values({k: v}))
        counts[t.name] = n
    reset_sequences(conn, md)
    return counts


def reset_sequences(conn, md: MetaData):
    for t in md.tables.values():
        if "id" not in t.columns or not isinstance(t.columns["id"].type, Integer):
            continue
        seq = conn.execute(text("SELECT pg_get_serial_sequence(:t, 'id')"), {"t": t.name}).scalar()
        if seq:
            conn.execute(text(f'SELECT setval(:s, COALESCE((SELECT MAX(id) FROM "{t.name}"), 1), '
                              f'(SELECT MAX(id) IS NOT NULL FROM "{t.name}"))'), {"s": seq})


def _jsonl(z: zipfile.ZipFile, name: str) -> Iterator[dict]:
    try:
        f = z.open(name)
    except KeyError:
        return
    with f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def restore_from_zip(engine, z: zipfile.ZipFile, upgrade_fn, prefix: str = "db/", wipe_first: bool = False) -> dict:
    """upgrade_fn(conn, revision) chạy alembic upgrade tới revision chỉ định trên kết nối conn."""
    try:
        man = json.loads(z.read(f"{prefix}manifest.json"))
    except KeyError:
        raise DumpError("This is not a v2 backup (db/manifest.json is missing). For legacy SQLite backups, use import-sqlite.") from None
    if man.get("format") != FORMAT:
        raise DumpError(f"Backup format {man.get('format')} is not supported")
    # một transaction duy nhất (DDL of PostgreSQL cũng nằm trong transaction): error giữa chừng → CSDL cũ remaining nguyên
    with engine.begin() as conn:
        if wipe_first:
            wipe(conn)
        if not is_empty(conn):
            raise DumpError("The target database is not empty. Use --wipe to clear it before restoring.")
        upgrade_fn(conn, man["revision"])
        md = _reflect(conn)
        counts = load_rows(conn, md, lambda name: _jsonl(z, f"{prefix}{name}.jsonl"))
        for name, n in man["tables"].items():
            if counts.get(name, 0) != n:
                raise DumpError(f"Row count mismatch for table {name}; backup has {n}; restored {counts.get(name, 0)}")
        upgrade_fn(conn, "head")
    return {"revision": man["revision"], "tables": counts}


# ---------------------------------------------------------------- SQLite (bản v1 / v2 cũ) → PostgreSQL
SQLITE_SKIP = {"login_sessions", "sqlite_sequence"}     # sessions sign-in cũ không chuyển – sign-in lại


def _sqlite_rows(path: str, table: str) -> Iterable[dict]:
    import sqlite3
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    try:
        have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if table not in have or table in SQLITE_SKIP:
            return
        cur = c.execute(f'SELECT * FROM "{table}" ORDER BY rowid')
        while True:
            rows = cur.fetchmany(BATCH)
            if not rows:
                break
            for r in rows:
                yield dict(r)
    finally:
        c.close()


def sqlite_counts(path: str) -> dict:
    import sqlite3
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return {n: c.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names
                if n not in SQLITE_SKIP and n != "alembic_version"}
    finally:
        c.close()


def import_sqlite(engine, path: str, upgrade_fn, wipe_first: bool = False) -> dict:
    with engine.begin() as conn:
        if wipe_first:
            wipe(conn)
        if not is_empty(conn):
            raise DumpError("The target PostgreSQL database is not empty. Use --wipe to clear it before migration.")
        upgrade_fn(conn, "head")
        md = _reflect(conn)
        counts = load_rows(conn, md, lambda name: _sqlite_rows(path, name))
    src = sqlite_counts(path)
    missing = {t: n for t, n in src.items() if t not in counts and n}
    return {"tables": counts, "source": src, "ignored_tables": missing}


def table_names(engine) -> list[str]:
    return inspect(engine).get_table_names()
