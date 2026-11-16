"""Network traffic: flow tables (NetFlow / IPFIX through GoFlow2)

flow_1m   – 1-minute totals per (exporter, interface, local IP, remote IP, protocol, port, direction)
flow_1h   – hourly roll-up without the remote IP, for long history
flow_exporters – devices that send flows and the interface names IT gave them

Time-series tables use a BRIN index on ts (tiny, ideal for append-only data). Not included in the daily backup.

Revision ID: 0014
Revises: 0013
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, Sequence[str], None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _counters():
    return [
        sa.Column("bytes_out", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_in", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("pkts_out", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("pkts_in", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("flows", sa.Integer(), nullable=False, server_default="0"),
    ]


def upgrade() -> None:
    op.create_table(
        "flow_1m",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("exporter", sa.String(45), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("local_ip", sa.String(45), nullable=False),
        sa.Column("remote_ip", sa.String(45), nullable=False),
        sa.Column("proto", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("direction", sa.String(1), nullable=False),
        *_counters(),
    )
    op.create_index("ix_flow_1m_ts", "flow_1m", ["ts"], postgresql_using="brin")
    op.create_index("ix_flow_1m_local_ts", "flow_1m", ["local_ip", "ts"])

    op.create_table(
        "flow_1h",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("exporter", sa.String(45), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("local_ip", sa.String(45), nullable=False),
        sa.Column("proto", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("direction", sa.String(1), nullable=False),
        *_counters(),
        sa.Column("remotes", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_flow_1h_ts", "flow_1h", ["ts"], postgresql_using="brin")

    op.create_table(
        "flow_exporters",
        sa.Column("ip", sa.String(45), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, server_default=""),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("flows_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("interfaces", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("if_names", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("flow_exporters")
    op.drop_index("ix_flow_1h_ts", table_name="flow_1h")
    op.drop_table("flow_1h")
    op.drop_index("ix_flow_1m_local_ts", table_name="flow_1m")
    op.drop_index("ix_flow_1m_ts", table_name="flow_1m")
    op.drop_table("flow_1m")
