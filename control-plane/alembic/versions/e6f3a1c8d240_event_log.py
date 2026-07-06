"""durable event log + consumer offsets

Revision ID: e6f3a1c8d240
Revises: d5e2f7c9b031
Create Date: 2026-07-06 00:00:20.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e6f3a1c8d240'
down_revision: str | None = 'd5e2f7c9b031'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'log_records',
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
                  primary_key=True, autoincrement=True),
        sa.Column('topic', sa.String(length=64), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('partition_key', sa.String(length=512), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
    )
    op.create_index('ix_log_topic_id', 'log_records', ['topic', 'id'])
    op.create_table(
        'log_offsets',
        sa.Column('topic', sa.String(length=64), primary_key=True),
        sa.Column('consumer_group', sa.String(length=128), primary_key=True),
        sa.Column('last_offset', sa.BigInteger(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('log_offsets')
    op.drop_index('ix_log_topic_id', table_name='log_records')
    op.drop_table('log_records')
