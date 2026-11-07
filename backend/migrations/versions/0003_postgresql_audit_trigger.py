"""PostgreSQL: nhật ký thao tác chỉ ghi thêm (trigger plpgsql), chỉ mục bổ sung

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-08

Bản v2 chỉ chạy PostgreSQL (ADR 0003). Migration 0001/0002 vẫn giữ nguyên để lịch sử schema liền mạch;
0003 khoá audit_logs ở mức CSDL và thêm chỉ mục.
Cột JSON hiện có GIỮ kiểu `json` (giữ nguyên thứ tự key như bản cũ); `jsonb` sắp xếp lại key nên chỉ dùng
cho bảng mới cần truy vấn bên trong JSON (vd. inventory của agent).
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

AUDIT_FN = "itops_audit_append_only"


def create_audit_append_only() -> None:
    """Chặn UPDATE / DELETE / TRUNCATE trên audit_logs – kể cả khi code lỗi hay bị SQL injection.
    Muốn dọn nhật ký cũ phải làm có chủ đích bằng tài khoản owner: tạm DISABLE TRIGGER (và việc đó cũng để lại dấu vết trong log PostgreSQL)."""
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {AUDIT_FN}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs: chi duoc ghi them, khong duoc % (append-only)', lower(TG_OP)
                USING ERRCODE = 'insufficient_privilege';
        END $$;""")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute(f"CREATE TRIGGER audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs "
               f"FOR EACH ROW EXECUTE FUNCTION {AUDIT_FN}()")
    op.execute(f"CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
               f"FOR EACH STATEMENT EXECUTE FUNCTION {AUDIT_FN}()")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Bản v2 chỉ hỗ trợ PostgreSQL")
    create_audit_append_only()
    # Tra cứu thường dùng trên bảng lớn
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_ts ON audit_logs (ts)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_status_opened ON alerts (status, opened_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_alerts_status_opened")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_ts")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs")
    op.execute(f"DROP FUNCTION IF EXISTS {AUDIT_FN}()")
