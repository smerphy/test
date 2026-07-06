"""finding_forwarding

Revision ID: 8e1f5a6b7c93
Revises: 7d0e4f5a6b82
Create Date: 2026-07-05 00:00:02.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '8e1f5a6b7c93'
down_revision: str | None = '7d0e4f5a6b82'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('finding_webhook_url', sa.String(length=1024), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                'finding_min_severity',
                sa.String(length=16),
                nullable=False,
                server_default='high',
            )
        )


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('finding_min_severity')
        batch_op.drop_column('finding_webhook_url')
