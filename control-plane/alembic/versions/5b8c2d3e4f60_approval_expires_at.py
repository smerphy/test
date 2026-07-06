"""approval_expires_at

Revision ID: 5b8c2d3e4f60
Revises: 4a7b9c1d2e3f
Create Date: 2026-07-02 00:00:01.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '5b8c2d3e4f60'
down_revision: str | None = '4a7b9c1d2e3f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('approval_requests', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table('approval_requests', schema=None) as batch_op:
        batch_op.drop_column('expires_at')
