"""PostgreSQL: English error message for the append-only audit_logs trigger (behaviour unchanged)

Revision ID: 0006
Revises: 0005

Only the text raised by the trigger function changes; the triggers themselves (UPDATE/DELETE/TRUNCATE blocked)
are untouched, so the append-only guarantee is identical before and after this migration.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0006"
down_revision: Union[str, Sequence[str], None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

AUDIT_FN = "itops_audit_append_only"


def _replace_function(message: str) -> None:
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {AUDIT_FN}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '{message}', lower(TG_OP)
                USING ERRCODE = 'insufficient_privilege';
        END $$;""")


def upgrade() -> None:
    _replace_function("audit_logs is append-only: % is not allowed")


def downgrade() -> None:
    _replace_function("audit_logs: chi duoc ghi them, khong duoc % (append-only)")
