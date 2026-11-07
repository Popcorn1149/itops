"""Alembic env – dùng chung engine/metadata của app (app.db) nên DATA_DIR / DATABASE_URL áp dụng giống hệt khi chạy app.

Chạy tay (trong thư mục backend):
    alembic upgrade head                     # nâng cấp CSDL theo DATA_DIR hiện tại
    alembic revision --autogenerate -m "..."  # tạo migration mới sau khi sửa models.py
App tự chạy `upgrade head` khi khởi động (app/db.py → run_migrations), nên thường không cần chạy tay.
"""
from alembic import context

from app.db import Base, engine
from app import models  # noqa: F401  – nạp model để metadata đầy đủ

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=str(engine.url), target_metadata=target_metadata, literal_binds=True,
                      render_as_batch=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    conn = config.attributes.get("connection")
    if conn is not None:
        _run(conn)
        return
    with engine.connect() as connection:
        _run(connection)


def _run(connection) -> None:
    # render_as_batch: SQLite không hỗ trợ ALTER đầy đủ → Alembic tự dựng lại bảng khi cần
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True,
                      compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
