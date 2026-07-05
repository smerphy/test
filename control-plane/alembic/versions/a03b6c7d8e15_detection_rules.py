"""detection_rules

Revision ID: a03b6c7d8e15
Revises: 9f2a6b7c8d04
Create Date: 2026-07-05 00:00:04.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a03b6c7d8e15'
down_revision: str | None = '9f2a6b7c8d04'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('spec', sa.JSON(), nullable=False),
        sa.Column('atlas_technique', sa.String(length=64), nullable=True),
        sa.Column('owasp_llm', sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'name', name='uq_detection_rule_org_name'
        ),
    )


def downgrade() -> None:
    op.drop_table('detection_rules')
