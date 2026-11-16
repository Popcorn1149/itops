"""CVE module part 3: vulnerability sources, findings, detections; NVD CPE ranges

Revision ID: 0008
Revises: 0007
"""
import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, Sequence[str], None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cves", sa.Column("cpe_match", sa.JSON(), nullable=False, server_default="[]"))
    op.create_table(
        "vuln_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="high"),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("state", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "vuln_findings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("target", sa.String(32), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime(), nullable=True),
        sa.Column("reopened", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="high"),
        sa.Column("sources_active", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("triage", sa.String(16), nullable=False, server_default=""),
        sa.Column("triage_until", sa.DateTime(), nullable=True),
        sa.Column("triage_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("triage_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("triage_at", sa.DateTime(), nullable=True),
        sa.Column("provider_score", sa.Float(), nullable=True),
        sa.Column("provider_severity", sa.String(16), nullable=False, server_default=""),
        sa.Column("packages", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_index("ux_vuln_findings_target_cve", "vuln_findings", ["target", "cve_id"], unique=True)
    op.create_index("ix_vuln_findings_status", "vuln_findings", ["status"])
    op.create_index("ix_vuln_findings_cve_id", "vuln_findings", ["cve_id"])
    op.create_index("ix_vuln_findings_agent_id", "vuln_findings", ["agent_id"])
    op.create_index("ix_vuln_findings_asset_id", "vuln_findings", ["asset_id"])
    op.create_table(
        "vuln_detections",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("finding_id", sa.BigInteger(), sa.ForeignKey("vuln_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("vuln_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package", sa.String(255), nullable=False, server_default=""),
        sa.Column("version", sa.String(128), nullable=False, server_default=""),
        sa.Column("fixed_version", sa.String(128), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default=""),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("detected_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ux_vuln_det", "vuln_detections", ["finding_id", "source_id", "package"], unique=True)
    op.create_index("ix_vuln_detections_finding_id", "vuln_detections", ["finding_id"])
    op.create_index("ix_vuln_detections_source_id", "vuln_detections", ["source_id"])
    # the built-in CPE-matching source is created at startup (app/vuln.py ensure_builtin), not here,
    # so a backup can be restored into a freshly migrated, empty database
    # CPE version ranges are new: make the next NVD sync reload the backfill window so they get filled
    bind = op.get_bind()
    row = bind.execute(sa.text("SELECT value FROM settings WHERE key = 'cve_sync'")).first()
    if row and row[0]:
        v = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        nvd = dict(v.get("nvd") or {})
        nvd.pop("last_modified_until", None)
        nvd["kev_loaded"] = False
        v["nvd"] = nvd
        bind.execute(sa.text("UPDATE settings SET value = :v WHERE key = 'cve_sync'"), {"v": json.dumps(v)})


def downgrade() -> None:
    op.drop_table("vuln_detections")
    op.drop_table("vuln_findings")
    op.drop_table("vuln_sources")
    op.drop_column("cves", "cpe_match")
