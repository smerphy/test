"""AI-native advisory: org config + rule suggestions

Revision ID: e47f0a1b2c53
Revises: d36e9f0a1b42
Create Date: 2026-07-05 00:00:08.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e47f0a1b2c53'
down_revision: str | None = 'd36e9f0a1b42'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column('ai_enabled', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.add_column(
        'organizations',
        sa.Column(
            'ai_mode', sa.String(length=16), nullable=False,
            server_default='advisory',
        ),
    )
    op.add_column(
        'organizations',
        sa.Column(
            'ai_provider', sa.String(length=32), nullable=False, server_default=''
        ),
    )
    op.add_column(
        'organizations',
        sa.Column(
            'ai_model', sa.String(length=128), nullable=False, server_default=''
        ),
    )
    op.add_column(
        'organizations',
        sa.Column('ai_base_url', sa.String(length=1024), nullable=True),
    )
    op.add_column(
        'organizations',
        sa.Column('ai_api_key', sa.String(length=1024), nullable=True),
    )

    op.create_table(
        'rule_suggestions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('spec', sa.JSON(), nullable=False),
        sa.Column('atlas_technique', sa.String(length=64), nullable=True),
        sa.Column('owasp_llm', sa.String(length=32), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0'),
        sa.Column(
            'source', sa.String(length=64), nullable=False, server_default='ai'
        ),
        sa.Column(
            'status', sa.String(length=16), nullable=False,
            server_default='pending',
        ),
        sa.Column('reviewed_by', sa.String(length=255), nullable=True),
        sa.Column('created_rule_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_rule_suggestion_org_status', 'rule_suggestions',
        ['organization_id', 'status'],
    )


def downgrade() -> None:
    op.drop_index('ix_rule_suggestion_org_status', table_name='rule_suggestions')
    op.drop_table('rule_suggestions')
    op.drop_column('organizations', 'ai_api_key')
    op.drop_column('organizations', 'ai_base_url')
    op.drop_column('organizations', 'ai_model')
    op.drop_column('organizations', 'ai_provider')
    op.drop_column('organizations', 'ai_mode')
    op.drop_column('organizations', 'ai_enabled')
