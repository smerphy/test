"""AI cost budgeting: org budget + monthly usage ledger

Revision ID: a69b2c3d4e75
Revises: f58a1b2c3d64
Create Date: 2026-07-05 00:00:10.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a69b2c3d4e75'
down_revision: str | None = 'f58a1b2c3d64'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column('ai_monthly_budget_usd', sa.Float(), nullable=True),
    )
    op.create_table(
        'ai_usage',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('month', sa.String(length=7), nullable=False),
        sa.Column('input_tokens', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('output_tokens', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cost_usd', sa.Float(), nullable=False, server_default='0'),
        sa.Column('call_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('alerted', sa.Boolean(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'month', name='uq_ai_usage_org_month'
        ),
    )


def downgrade() -> None:
    op.drop_table('ai_usage')
    op.drop_column('organizations', 'ai_monthly_budget_usd')
