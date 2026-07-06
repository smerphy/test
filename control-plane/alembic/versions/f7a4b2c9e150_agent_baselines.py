"""per-agent behavioral baselines (UEBA)

Revision ID: f7a4b2c9e150
Revises: e6f3a1c8d240
Create Date: 2026-07-06 00:00:21.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f7a4b2c9e150'
down_revision: str | None = 'e6f3a1c8d240'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'agent_baselines',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False),
        sa.Column('tool_counts', sa.JSON(), nullable=False),
        sa.Column('decision_counts', sa.JSON(), nullable=False),
        sa.Column('distinct_tools', sa.Integer(), nullable=False),
        sa.Column('distinct_sessions', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.UniqueConstraint(
            'organization_id', 'agent_id', name='uq_agent_baseline'
        ),
    )
    op.create_index(
        'ix_agent_baseline_org', 'agent_baselines', ['organization_id']
    )


def downgrade() -> None:
    op.drop_index('ix_agent_baseline_org', table_name='agent_baselines')
    op.drop_table('agent_baselines')
