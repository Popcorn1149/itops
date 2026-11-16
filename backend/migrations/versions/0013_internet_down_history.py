"""Internet checks with IT's own targets: past results where none of them answered become DOWN

Before 2.9.x an "internet" check pinging e.g. one WAN's public IP only gave a warning when that IP stopped
answering (DNS / HTTP still worked through the server's other route), so uptime and reports showed 100%.
Results with 100% packet loss on such checks are now DOWN – this fixes the history the same way.
Also clears the fake latency stored for runs without any ping reply (it was the probe's total run time).

Revision ID: 0013
Revises: 0012
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, Sequence[str], None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULT = {"1.1.1.1", "8.8.8.8", "208.67.222.222"}
PUBLIC_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220", "9.9.9.9", "149.112.112.112"}


def _targets(t):
    return {x.strip() for x in (t or "").replace(";", ",").split(",") if x.strip()} or DEFAULT


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, target FROM checks WHERE type = 'internet'")).fetchall()
    custom = [cid for cid, t in rows if not _targets(t) <= PUBLIC_RESOLVERS]     # same rule as collectors.network.is_custom_inet
    allc = [cid for cid, _ in rows]
    if allc:
        conn.execute(sa.text("UPDATE check_results SET latency = NULL WHERE check_id = ANY(:ids) AND value >= 100"), {"ids": allc})
    if custom:
        conn.execute(sa.text("UPDATE check_results SET down = TRUE, status = 'fail' WHERE check_id = ANY(:ids) AND value >= 100"),
                     {"ids": custom})


def downgrade() -> None:
    pass
