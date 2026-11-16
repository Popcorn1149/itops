"""CVE module part 2: CVE catalogue (NVD + CISA KEV + FIRST EPSS)

Revision ID: 0007
Revises: 0006
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_severity", sa.String(length=16), nullable=False),
        sa.Column("cvss_version", sa.String(length=8), nullable=False),
        sa.Column("cvss_vector", sa.String(length=200), nullable=False),
        sa.Column("cwe", sa.JSON(), nullable=False),
        sa.Column("products", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("kev_added", sa.DateTime(), nullable=True),
        sa.Column("kev_due", sa.DateTime(), nullable=True),
        sa.Column("kev_ransomware", sa.Boolean(), nullable=False),
        sa.Column("kev_name", sa.String(length=255), nullable=False),
        sa.Column("kev_action", sa.Text(), nullable=False),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"], unique=True)
    op.create_index("ix_cves_published", "cves", ["published"])
    op.create_index("ix_cves_kev", "cves", ["kev"])
    op.create_index("ix_cves_severity", "cves", ["cvss_severity"])


def downgrade() -> None:
    op.drop_table("cves")
