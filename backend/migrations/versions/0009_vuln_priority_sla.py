"""CVE module parts 4–5: priority, SLA deadline and alert marker on findings

Revision ID: 0009
Revises: 0008
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, Sequence[str], None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vuln_findings", sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("vuln_findings", sa.Column("sla_category", sa.String(16), nullable=False, server_default=""))
    op.add_column("vuln_findings", sa.Column("sla_start", sa.DateTime(), nullable=True))
    op.add_column("vuln_findings", sa.Column("due_at", sa.DateTime(), nullable=True))
    op.add_column("vuln_findings", sa.Column("alerted_at", sa.DateTime(), nullable=True))
    op.create_index("ix_vuln_findings_due_at", "vuln_findings", ["due_at"])
    op.create_index("ix_vuln_findings_priority", "vuln_findings", ["priority"])


def downgrade() -> None:
    op.drop_index("ix_vuln_findings_priority", "vuln_findings")
    op.drop_index("ix_vuln_findings_due_at", "vuln_findings")
    for c in ("alerted_at", "due_at", "sla_start", "sla_category", "priority"):
        op.drop_column("vuln_findings", c)
