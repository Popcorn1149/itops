"""Monitoring reports: daily summaries and outages kept after raw check results are purged

Revision ID: 0012
Revises: 0011
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, Sequence[str], None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "check_daily",
        sa.Column("check_id", sa.Integer(), sa.ForeignKey("checks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("day", sa.DateTime(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("down", sa.Integer(), nullable=False),
        sa.Column("lat_n", sa.Integer(), nullable=False),
        sa.Column("lat_sum", sa.Float(), nullable=False),
        sa.Column("lat_min", sa.Float(), nullable=True),
        sa.Column("lat_max", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("check_id", "day"),
    )
    op.create_table(
        "check_outages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("check_id", sa.Integer(), sa.ForeignKey("checks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("start", sa.DateTime(), nullable=False),
        sa.Column("end", sa.DateTime(), nullable=True),
        sa.Column("message", sa.String(500), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_check_outages_check_id", "check_outages", ["check_id"])
    op.create_index("ix_check_outages_start", "check_outages", ["start"])


def downgrade() -> None:
    op.drop_table("check_outages")
    op.drop_table("check_daily")
