import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'itops.db')}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {},
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------- migration (Alembic)
MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "migrations")
BASELINE_REV = "0001"   # migration nền = schema của bản v1 (trước khi có Alembic)


def _alembic_config(connection=None):
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", os.path.abspath(MIGRATIONS_DIR))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def _baseline_metadata():
    """Schema đúng như migration 0001 – dựng bằng cách chạy 0001 trên SQLite trong RAM rồi đọc ngược lại."""
    from alembic import command
    from sqlalchemy import MetaData
    mem = create_engine("sqlite://")
    with mem.begin() as conn:
        command.upgrade(_alembic_config(conn), BASELINE_REV)
    md = MetaData()
    md.reflect(bind=mem)
    md.remove(md.tables["alembic_version"])
    return md


def _legacy_to_baseline() -> list[str]:
    """CSDL tạo từ bản v1 (create_all + auto_migrate, chưa có alembic_version): chỉ THÊM bảng/cột còn thiếu
    cho khớp migration 0001. Không xoá, không sửa dữ liệu."""
    from sqlalchemy import inspect, text
    base = _baseline_metadata()
    insp = inspect(engine)
    added = []
    with engine.begin() as conn:
        for table in base.sorted_tables:
            if not insp.has_table(table.name):
                table.create(conn)
                added.append(table.name)
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            model_tbl = Base.metadata.tables.get(table.name)
            for col in table.columns:
                if col.name in have:
                    continue
                ctype = col.type.compile(dialect=engine.dialect)
                default = ""
                mcol = model_tbl.columns.get(col.name) if model_tbl is not None else None
                if mcol is not None and mcol.default is not None and getattr(mcol.default, "is_scalar", False):
                    v = mcol.default.arg
                    default = f" DEFAULT {int(v) if isinstance(v, bool) else repr(v) if isinstance(v, str) else v}"
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ctype}{default}'))
                added.append(f"{table.name}.{col.name}")
    return added


def run_migrations() -> dict:
    """Gọi khi app khởi động. CSDL trống → tạo theo migration; CSDL bản v1 → bù cho khớp 0001, stamp 0001;
    sau đó luôn `upgrade head`. Trả về thông tin để ghi log."""
    import logging
    from alembic import command
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect
    logging.getLogger("alembic").setLevel(logging.WARNING)   # app tự ghi 1 dòng tóm tắt (main.init_db)
    info = {"legacy": False, "added": [], "from": None, "to": None}
    tables = set(inspect(engine).get_table_names())
    if tables and "alembic_version" not in tables:
        info["legacy"] = True
        info["added"] = _legacy_to_baseline()
        with engine.begin() as conn:
            command.stamp(_alembic_config(conn), BASELINE_REV)
    with engine.connect() as conn:
        info["from"] = MigrationContext.configure(conn).get_current_revision()
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "head")
    with engine.connect() as conn:
        info["to"] = MigrationContext.configure(conn).get_current_revision()
    return info
