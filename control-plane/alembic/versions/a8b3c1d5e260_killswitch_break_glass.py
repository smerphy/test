"""global kill-switch + break-glass grants

Revision ID: a8b3c1d5e260
Revises: f7a4b2c9e150
Create Date: 2026-07-06 00:00:22.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a8b3c1d5e260'
down_revision: str | None = 'f7a4b2c9e150'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column('halt_all', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.create_table(
        'break_glass_grants',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('granted_by', sa.String(length=255), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
    )
    op.create_index(
        'ix_break_glass_org_agent',
        'break_glass_grants',
        ['organization_id', 'agent_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_break_glass_org_agent', table_name='break_glass_grants')
    op.drop_table('break_glass_grants')
    op.drop_column('organizations', 'halt_all')
