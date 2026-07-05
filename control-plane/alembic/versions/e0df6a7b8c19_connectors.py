"""notification connectors

Revision ID: e0df6a7b8c19
Revises: d9ce5f6a7b08
Create Date: 2026-07-05 00:00:14.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e0df6a7b8c19'
down_revision: str | None = 'd9ce5f6a7b08'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'notification_connectors',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column(
            'min_severity', sa.String(length=16), nullable=False,
            server_default='high',
        ),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('last_status', sa.String(length=16), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'name', name='uq_connector_org_name'
        ),
    )


def downgrade() -> None:
    op.drop_table('notification_connectors')
