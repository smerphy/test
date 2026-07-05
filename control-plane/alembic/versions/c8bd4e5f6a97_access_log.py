"""access log (who viewed/exported what)

Revision ID: c8bd4e5f6a97
Revises: b7ac3d4e5f86
Create Date: 2026-07-05 00:00:12.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c8bd4e5f6a97'
down_revision: str | None = 'b7ac3d4e5f86'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'access_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('actor', sa.String(length=255), nullable=False),
        sa.Column('actor_kind', sa.String(length=16), nullable=False),
        sa.Column('resource', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=16), nullable=False),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=512), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('detail', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_access_log_org_created', 'access_logs',
        ['organization_id', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_access_log_org_created', table_name='access_logs')
    op.drop_table('access_logs')
