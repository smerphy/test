"""audit event async-verify + authoritative-archive columns

Revision ID: d5e2f7c9b031
Revises: c4d1e6b8a920
Create Date: 2026-07-05 00:00:19.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd5e2f7c9b031'
down_revision: str | None = 'c4d1e6b8a920'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing rows were verified under the synchronous ingest path.
    op.add_column(
        'audit_events',
        sa.Column(
            'verified', sa.Boolean(), nullable=False, server_default='1'
        ),
    )
    op.add_column(
        'audit_events',
        sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        'ix_audit_org_verified', 'audit_events', ['organization_id', 'verified']
    )
    op.create_index(
        'ix_audit_org_archived', 'audit_events', ['organization_id', 'archived_at']
    )


def downgrade() -> None:
    op.drop_index('ix_audit_org_archived', table_name='audit_events')
    op.drop_index('ix_audit_org_verified', table_name='audit_events')
    op.drop_column('audit_events', 'archived_at')
    op.drop_column('audit_events', 'verified')
