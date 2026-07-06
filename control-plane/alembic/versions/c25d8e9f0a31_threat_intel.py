"""threat intel feeds + indicators

Revision ID: c25d8e9f0a31
Revises: b14c7d8e9f20
Create Date: 2026-07-05 00:00:06.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c25d8e9f0a31'
down_revision: str | None = 'b14c7d8e9f20'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'threat_feeds',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(length=2048), nullable=True),
        sa.Column('format', sa.String(length=16), nullable=False),
        sa.Column('default_indicator_type', sa.String(length=32), nullable=True),
        sa.Column('auth_header', sa.String(length=1024), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('tlp', sa.String(length=8), nullable=False, server_default='amber'),
        sa.Column(
            'default_confidence', sa.Integer(), nullable=False, server_default='50'
        ),
        sa.Column(
            'default_severity', sa.String(length=16), nullable=False,
            server_default='high',
        ),
        sa.Column(
            'refresh_minutes', sa.Integer(), nullable=False, server_default='60'
        ),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'last_status', sa.String(length=16), nullable=False,
            server_default='never',
        ),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column(
            'indicator_count', sa.Integer(), nullable=False, server_default='0'
        ),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'name', name='uq_threat_feed_org_name'
        ),
    )
    op.create_table(
        'threat_indicators',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('feed_id', sa.String(length=36), nullable=True),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.String(length=1024), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='50'),
        sa.Column(
            'severity', sa.String(length=16), nullable=False, server_default='high'
        ),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tlp', sa.String(length=8), nullable=False, server_default='amber'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['feed_id'], ['threat_feeds.id'], ondelete='SET NULL'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'type', 'value',
            name='uq_indicator_org_type_value',
        ),
    )
    op.create_index(
        'ix_indicator_org_type', 'threat_indicators',
        ['organization_id', 'type'],
    )
    op.create_index(
        'ix_indicator_org_enabled', 'threat_indicators',
        ['organization_id', 'enabled'],
    )
    op.create_index('ix_indicator_feed', 'threat_indicators', ['feed_id'])


def downgrade() -> None:
    op.drop_index('ix_indicator_feed', table_name='threat_indicators')
    op.drop_index('ix_indicator_org_enabled', table_name='threat_indicators')
    op.drop_index('ix_indicator_org_type', table_name='threat_indicators')
    op.drop_table('threat_indicators')
    op.drop_table('threat_feeds')
