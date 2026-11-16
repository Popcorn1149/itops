"""Agent: re-enrolment over an existing machine needs IT approval; MAC addresses

Revision ID: 0010
Revises: 0009
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, Sequence[str], None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("macs", sa.JSON(), nullable=False, server_default="[]"))
    op.create_table(
        "agent_enroll_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("uid", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_family", sa.String(16), nullable=False),
        sa.Column("agent_version", sa.String(32), nullable=False),
        sa.Column("system", sa.JSON(), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("token_id", sa.Integer(), nullable=True),
        sa.Column("token_name", sa.String(128), nullable=False),
        sa.Column("matched_by", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decided_by", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["token_id"], ["agent_enroll_tokens.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_enroll_requests_agent_id", "agent_enroll_requests", ["agent_id"])
    op.create_index("ix_agent_enroll_requests_uid", "agent_enroll_requests", ["uid"])
    op.create_index("ix_agent_enroll_requests_status", "agent_enroll_requests", ["status"])


def downgrade() -> None:
    op.drop_table("agent_enroll_requests")
    op.drop_column("agents", "macs")
