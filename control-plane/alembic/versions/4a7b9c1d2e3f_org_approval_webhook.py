"""org_approval_webhook

Revision ID: 4a7b9c1d2e3f
Revises: 338fffd05d7a
Create Date: 2026-07-02 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '4a7b9c1d2e3f'
down_revision: str | None = '338fffd05d7a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('approval_webhook_url', sa.String(length=1024), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('approval_webhook_url')
