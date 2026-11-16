"""Remediation Mapping: cache of structured vendor advisories (Microsoft MSRC first)

Revision ID: 0011
Revises: 0010
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, Sequence[str], None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "advisories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("doc_id", sa.String(64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("found", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(300), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_advisories_cve_id", "advisories", ["cve_id"])
    op.create_index("ux_advisories_source_cve", "advisories", ["source", "cve_id"], unique=True)


def downgrade() -> None:
    op.drop_table("advisories")
