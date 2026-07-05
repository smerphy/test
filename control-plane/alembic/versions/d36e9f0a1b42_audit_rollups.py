"""audit daily rollups (retention)

Revision ID: d36e9f0a1b42
Revises: c25d8e9f0a31
Create Date: 2026-07-05 00:00:07.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd36e9f0a1b42'
down_revision: str | None = 'c25d8e9f0a31'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'audit_daily_rollups',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('day', sa.Date(), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'day', 'agent_id', 'decision',
            name='uq_audit_rollup_key',
        ),
    )
    op.create_index(
        'ix_audit_rollup_org_day', 'audit_daily_rollups',
        ['organization_id', 'day'],
    )


def downgrade() -> None:
    op.drop_index('ix_audit_rollup_org_day', table_name='audit_daily_rollups')
    op.drop_table('audit_daily_rollups')
