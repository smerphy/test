"""org monthly agent-spend cost budget

Revision ID: c4d1e6b8a920
Revises: b3c92a1f7e42
Create Date: 2026-07-05 00:00:18.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c4d1e6b8a920'
down_revision: str | None = 'b3c92a1f7e42'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column('monthly_cost_budget_usd', sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('organizations', 'monthly_cost_budget_usd')
