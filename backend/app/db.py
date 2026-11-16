import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)


def _database_url() -> str:
    """PostgreSQL only.
    - DATABASE_URL=postgresql+psycopg://user:pass@host:5432/itops  → PostgreSQL thật (Linux/Docker)
    - PG_LOCAL=1                                                     → PostgreSQL kèm theo, tự chạy (demo VS Code)"""
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        if url.startswith("postgres://") or url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url.split("://", 1)[1]
        if not url.startswith("postgresql+psycopg://"):
            raise SystemExit("DATABASE_URL must point to PostgreSQL (postgresql+psycopg://...). v2 no longer uses SQLite – "
                             "migrate legacy SQLite data with: python -m app.admin_tools import-sqlite <itops.db>")
        return url
    if os.environ.get("PG_LOCAL", "").lower() in ("1", "true", "yes"):
        from . import pg_local
        try:
            return pg_local.ensure_running(DATA_DIR)
        except pg_local.PgLocalError as e:
            raise SystemExit(f"Bundled PostgreSQL: {e}") from None
    raise SystemExit("Database is not configured: set PG_LOCAL=1 (demo, bundled PostgreSQL) or DATABASE_URL=postgresql+psycopg://...")


DATABASE_URL = _database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,                 # bỏ kết nối chết (PostgreSQL restart, mạng flapping)
    pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
    pool_recycle=1800,
    connect_args={"connect_timeout": 10, "application_name": "itops"},
)

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


def _alembic_config(connection=None):
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", os.path.abspath(MIGRATIONS_DIR))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def run_migrations() -> dict:
    """Called at application startup: always run `alembic upgrade head`. Returns information for logging."""
    import logging
    logging.getLogger("alembic").setLevel(logging.WARNING)   # app tự ghi 1 dòng tóm disabled (main.init_db)
    from alembic import command
    from alembic.runtime.migration import MigrationContext
    info = {"from": None, "to": None}
    with engine.connect() as conn:
        info["from"] = MigrationContext.configure(conn).get_current_revision()
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "head")
    with engine.connect() as conn:
        info["to"] = MigrationContext.configure(conn).get_current_revision()
    return info
