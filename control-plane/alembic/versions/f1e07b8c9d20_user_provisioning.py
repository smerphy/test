"""user provisioning + session mgmt (active, external_id, session_epoch)

Revision ID: f1e07b8c9d20
Revises: e0df6a7b8c19
Create Date: 2026-07-05 00:00:15.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f1e07b8c9d20'
down_revision: str | None = 'e0df6a7b8c19'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('active', sa.Boolean(), nullable=False, server_default='1'),
    )
    op.add_column(
        'users', sa.Column('external_id', sa.String(length=255), nullable=True)
    )
    op.add_column(
        'users',
        sa.Column(
            'session_epoch', sa.Integer(), nullable=False, server_default='0'
        ),
    )


def downgrade() -> None:
    op.drop_column('users', 'session_epoch')
    op.drop_column('users', 'external_id')
    op.drop_column('users', 'active')
