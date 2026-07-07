"""hard spend enforcement + per-agent quota

Revision ID: b9c4d2e6f370
Revises: a8b3c1d5e260
Create Date: 2026-07-06 00:00:23.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b9c4d2e6f370'
down_revision: str | None = 'a8b3c1d5e260'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column(
            'enforce_cost_budget', sa.Boolean(), nullable=False, server_default='0'
        ),
    )
    op.add_column(
        'organizations',
        sa.Column('agent_cost_quota_usd', sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('organizations', 'agent_cost_quota_usd')
    op.drop_column('organizations', 'enforce_cost_budget')
