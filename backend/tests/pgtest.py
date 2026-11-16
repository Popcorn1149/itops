"""CSDL PostgreSQL dùng cho test – every lần chạy một CSDL mới tinh, chạy xong xoá.

Hai cách (chọn tự động):
1) TEST_DATABASE_URL=postgresql://user:pass@host:port/postgres  (user có quyền CREATEDB)
   → tạo CSDL itops_test_<ngẫu nhiên>, chạy xong DROP.  Dùng cho CI / Docker / PostgreSQL có sẵn.
2) Không đặt gì → PostgreSQL kèm theo (PG_LOCAL) trong thư items tạm, cổng trống ngẫu nhiên, chạy xong dừng.
   Cần đã tải binary: python tools/get_postgres.py
"""
import os
import secrets
import socket

_STATE = {}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def setup():
    admin = os.environ.get("TEST_DATABASE_URL", "").strip()
    if admin:
        import psycopg
        admin = admin.replace("postgresql+psycopg://", "postgresql://")
        name = f"itops_test_{secrets.token_hex(4)}"
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{name}" ENCODING \'UTF8\' TEMPLATE template0')
        base = admin.rsplit("/", 1)[0]
        os.environ["DATABASE_URL"] = f"{base.replace('postgresql://', 'postgresql+psycopg://')}/{name}"
        _STATE.update(mode="url", admin=admin, name=name)
    else:
        os.environ.pop("DATABASE_URL", None)
        os.environ["PG_LOCAL"] = "1"
        os.environ["PG_LOCAL_PORT"] = str(_free_port())
        _STATE.update(mode="local", data_dir=os.environ["DATA_DIR"])
    return os.environ.get("DATABASE_URL", "")


def admin_url() -> str:
    """URL psycopg (không có +psycopg) tới CSDL test – dùng cho test cần SQL thô."""
    from app.db import engine
    return engine.url.set(drivername="postgresql").render_as_string(hide_password=False)


def teardown():
    try:
        from app.db import engine
        engine.dispose()
    except Exception:
        pass
    if _STATE.get("mode") == "url":
        import psycopg
        with psycopg.connect(_STATE["admin"], autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{_STATE["name"]}" WITH (FORCE)')
    elif _STATE.get("mode") == "local":
        from app import pg_local
        try:
            pg_local.stop(_STATE["data_dir"])
        except Exception:
            pass


def sql(query: str, params=()):
    """Chạy SQL thô trên CSDL test (kết nối riêng, autocommit) – trả về list tuple."""
    import psycopg
    with psycopg.connect(admin_url(), autocommit=True) as c:
        cur = c.execute(query, params)
        return cur.fetchall() if cur.description else []


class scratch_db:
    """CSDL PostgreSQL trống tạm thời trên cùng machines chủ test (cho test khôi phục / chuyển dữ liệu)."""

    def __enter__(self):
        import psycopg
        from sqlalchemy import create_engine
        from app.db import engine
        self.name = f"itops_scratch_{secrets.token_hex(4)}"
        self.server = engine.url.set(drivername="postgresql", database="postgres").render_as_string(hide_password=False)
        with psycopg.connect(self.server, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{self.name}" ENCODING \'UTF8\' TEMPLATE template0')
        self.engine = create_engine(engine.url.set(database=self.name))
        return self.engine

    def __exit__(self, *exc):
        import psycopg
        self.engine.dispose()
        with psycopg.connect(self.server, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')


def head_revision() -> str:
    from alembic.script import ScriptDirectory
    from app.db import _alembic_config
    return ScriptDirectory.from_config(_alembic_config()).get_current_head()
