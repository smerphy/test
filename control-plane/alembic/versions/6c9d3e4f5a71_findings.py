"""findings

Revision ID: 6c9d3e4f5a71
Revises: 5b8c2d3e4f60
Create Date: 2026-07-05 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '6c9d3e4f5a71'
down_revision: str | None = '5b8c2d3e4f60'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('dedup_key', sa.String(length=512), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('atlas_technique', sa.String(length=64), nullable=True),
        sa.Column('owasp_llm', sa.String(length=32), nullable=True),
        sa.Column('assignee', sa.String(length=255), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_finding_org_status', 'findings', ['organization_id', 'status']
    )
    op.create_index(
        'ix_finding_org_severity', 'findings', ['organization_id', 'severity']
    )
    op.create_index(
        'ix_finding_org_dedup', 'findings', ['organization_id', 'dedup_key']
    )


def downgrade() -> None:
    op.drop_index('ix_finding_org_dedup', table_name='findings')
    op.drop_index('ix_finding_org_severity', table_name='findings')
    op.drop_index('ix_finding_org_status', table_name='findings')
    op.drop_table('findings')
