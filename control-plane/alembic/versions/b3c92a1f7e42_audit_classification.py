"""audit event data classification

Revision ID: b3c92a1f7e42
Revises: a2f18c9d0e31
Create Date: 2026-07-05 00:00:17.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b3c92a1f7e42'
down_revision: str | None = 'a2f18c9d0e31'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'audit_events',
        sa.Column(
            'classification',
            sa.String(length=32),
            nullable=False,
            server_default='standard',
        ),
    )
    op.create_index(
        'ix_audit_org_class',
        'audit_events',
        ['organization_id', 'classification'],
    )


def downgrade() -> None:
    op.drop_index('ix_audit_org_class', table_name='audit_events')
    op.drop_column('audit_events', 'classification')
