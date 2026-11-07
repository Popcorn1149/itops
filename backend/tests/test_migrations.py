"""Quality gate: schema do migration tạo ra phải khớp models.py.
Sửa models.py mà quên `alembic revision --autogenerate` → test này đỏ."""
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine


def test_migrations_match_models(tmp_path):
    from alembic import command
    from app import db as dbm
    from app import models  # noqa: F401
    eng = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    with eng.begin() as conn:
        command.upgrade(dbm._alembic_config(conn), "head")
    with eng.connect() as conn:
        mc = MigrationContext.configure(conn, opts={"compare_type": True, "render_as_batch": True})
        diff = compare_metadata(mc, dbm.Base.metadata)
    assert diff == [], f"models.py lệch với migration – cần tạo migration mới: {diff}"


def test_single_head():
    from alembic.script import ScriptDirectory
    from app import db as dbm
    heads = ScriptDirectory.from_config(dbm._alembic_config()).get_heads()
    assert len(heads) == 1, f"Có nhiều nhánh migration: {heads}"
