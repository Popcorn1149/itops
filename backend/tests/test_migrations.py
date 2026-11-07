"""Quality gate: schema do migration tạo ra phải khớp models.py.
Sửa models.py mà quên `alembic revision --autogenerate` → test này đỏ."""
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from tests.pgtest import scratch_db


def test_migrations_match_models():
    """Chạy toàn bộ migration trên CSDL PostgreSQL trống rồi so với models.py."""
    from alembic import command
    from app import db as dbm
    from app import models  # noqa: F401
    with scratch_db() as eng:
        with eng.begin() as conn:
            command.upgrade(dbm._alembic_config(conn), "head")
        with eng.connect() as conn:
            mc = MigrationContext.configure(conn, opts={"compare_type": True})
            diff = compare_metadata(mc, dbm.Base.metadata)
    assert diff == [], f"models.py lệch với migration – cần tạo migration mới: {diff}"


def test_downgrade_then_upgrade_roundtrip():
    """Migration phải đi ngược được (để rollback khi nâng cấp lỗi) và đi lại không lỗi."""
    from alembic import command
    from sqlalchemy import inspect, text
    from app import db as dbm
    with scratch_db() as eng:
        with eng.begin() as conn:
            command.upgrade(dbm._alembic_config(conn), "head")
        with eng.begin() as conn:
            command.downgrade(dbm._alembic_config(conn), "0002")
            assert not conn.execute(text("select 1 from pg_trigger where tgname='audit_logs_no_update_delete'")).first()
        with eng.begin() as conn:
            command.upgrade(dbm._alembic_config(conn), "head")
        assert "audit_logs" in inspect(eng).get_table_names()


def test_single_head():
    from alembic.script import ScriptDirectory
    from app import db as dbm
    heads = ScriptDirectory.from_config(dbm._alembic_config()).get_heads()
    assert len(heads) == 1, f"Có nhiều nhánh migration: {heads}"
