"""agents

Revision ID: 9f2a6b7c8d04
Revises: 8e1f5a6b7c93
Create Date: 2026-07-05 00:00:03.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '9f2a6b7c8d04'
down_revision: str | None = '8e1f5a6b7c93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'agents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('agent_version', sa.String(length=64), nullable=True),
        sa.Column('sdk_version', sa.String(length=64), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'agent_id', name='uq_agent_org_agentid'
        ),
    )
    op.create_index(
        'ix_agent_org_lastseen', 'agents', ['organization_id', 'last_seen']
    )


def downgrade() -> None:
    op.drop_index('ix_agent_org_lastseen', table_name='agents')
    op.drop_table('agents')
