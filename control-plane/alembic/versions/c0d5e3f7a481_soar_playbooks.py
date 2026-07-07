"""SOAR response playbooks + execution log

Revision ID: c0d5e3f7a481
Revises: b9c4d2e6f370
Create Date: 2026-07-07 00:00:11.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c0d5e3f7a481'
down_revision: str | None = 'b9c4d2e6f370'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'response_playbooks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column(
            'enabled', sa.Boolean(), nullable=False, server_default='1'
        ),
        sa.Column(
            'priority', sa.Integer(), nullable=False, server_default='100'
        ),
        sa.Column(
            'stop_on_match', sa.Boolean(), nullable=False, server_default='0'
        ),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('actions', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'organization_id', 'name', name='uq_playbook_org_name'
        ),
    )
    op.create_index(
        'ix_playbook_org_enabled',
        'response_playbooks',
        ['organization_id', 'enabled'],
    )

    op.create_table(
        'playbook_executions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('playbook_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('results', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['playbook_id'], ['response_playbooks.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_pbexec_org_finding',
        'playbook_executions',
        ['organization_id', 'finding_id'],
    )
    op.create_index(
        'ix_pbexec_org_playbook',
        'playbook_executions',
        ['organization_id', 'playbook_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_pbexec_org_playbook', table_name='playbook_executions')
    op.drop_index('ix_pbexec_org_finding', table_name='playbook_executions')
    op.drop_table('playbook_executions')
    op.drop_index('ix_playbook_org_enabled', table_name='response_playbooks')
    op.drop_table('response_playbooks')
