"""audit anchors (immutable tamper-evidence)

Revision ID: d9ce5f6a7b08
Revises: c8bd4e5f6a97
Create Date: 2026-07-05 00:00:13.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd9ce5f6a7b08'
down_revision: str | None = 'c8bd4e5f6a97'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'audit_anchors',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('chain_count', sa.Integer(), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False),
        sa.Column('root', sa.String(length=64), nullable=False),
        sa.Column('prev_anchor_hash', sa.String(length=64), nullable=False),
        sa.Column('anchor_hash', sa.String(length=64), nullable=False),
        sa.Column('chains', sa.JSON(), nullable=False),
        sa.Column('published_to', sa.String(length=1024), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_audit_anchor_org_created', 'audit_anchors',
        ['organization_id', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_audit_anchor_org_created', table_name='audit_anchors')
    op.drop_table('audit_anchors')
