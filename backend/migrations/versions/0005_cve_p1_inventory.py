"""Module CVE – phần 1: chuẩn hoá dữ liệu tài sản (build/UBR, người dùng gần nhất, machine-id, tên phần mềm chuẩn)

Revision ID: 0005
Revises: 0004
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for name, col in [("machine_id", sa.String(64)), ("os_release", sa.String(32)), ("os_build", sa.String(32)),
                      ("last_user", sa.String(128)), ("user_source", sa.String(16))]:
        op.add_column("agents", sa.Column(name, col, nullable=False, server_default=""))
    op.add_column("agents", sa.Column("os_ubr", sa.Integer(), nullable=True))
    op.add_column("agents", sa.Column("last_user_at", sa.DateTime(), nullable=True))
    op.create_index("ix_agents_machine_id", "agents", ["machine_id"])
    for name, n in [("source_pkg", 255), ("norm_name", 255), ("norm_vendor", 128), ("norm_version", 128)]:
        op.add_column("agent_software", sa.Column(name, sa.String(n), nullable=False, server_default=""))
    op.create_index("ix_agent_software_norm_name", "agent_software", ["norm_name"])
    # dữ liệu đã có: người dùng gần nhất = người đang đăng nhập
    op.execute("UPDATE agents SET last_user = logged_user, last_user_at = last_seen WHERE logged_user <> ''")


def downgrade() -> None:
    op.drop_index("ix_agent_software_norm_name", "agent_software")
    for name in ("source_pkg", "norm_name", "norm_vendor", "norm_version"):
        op.drop_column("agent_software", name)
    op.drop_index("ix_agents_machine_id", "agents")
    for name in ("machine_id", "os_release", "os_build", "os_ubr", "last_user", "last_user_at", "user_source"):
        op.drop_column("agents", name)
