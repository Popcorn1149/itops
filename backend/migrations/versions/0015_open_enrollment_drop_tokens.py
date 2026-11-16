"""Open agent enrollment (Wazuh-style): the agent only needs the server address, no registration token.

Drops the agent_enroll_tokens table and the token columns on agents / agent_enroll_requests.
Enrolled machines are untouched – each keeps its own key. Re-enrolment over an existing machine still needs IT approval.

Revision ID: 0015
Revises: 0014
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, Sequence[str], None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _drop_fk(table: str, column: str) -> None:
    insp = sa.inspect(op.get_bind())
    for fk in insp.get_foreign_keys(table):
        if fk["constrained_columns"] == [column]:
            op.drop_constraint(fk["name"], table, type_="foreignkey")


def upgrade() -> None:
    _drop_fk("agents", "token_id")
    op.drop_column("agents", "token_id")
    _drop_fk("agent_enroll_requests", "token_id")
    op.drop_column("agent_enroll_requests", "token_id")
    op.drop_column("agent_enroll_requests", "token_name")
    op.drop_table("agent_enroll_tokens")


def downgrade() -> None:
    op.create_table(
        "agent_enroll_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=12), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("tags", sa.String(length=255), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.add_column("agent_enroll_requests", sa.Column("token_name", sa.String(128), nullable=False, server_default=""))
    op.add_column("agent_enroll_requests", sa.Column("token_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "agent_enroll_requests", "agent_enroll_tokens", ["token_id"], ["id"], ondelete="SET NULL")
    op.add_column("agents", sa.Column("token_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "agents", "agent_enroll_tokens", ["token_id"], ["id"], ondelete="SET NULL")
