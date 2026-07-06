"""user role (RBAC)

Revision ID: b14c7d8e9f20
Revises: a03b6c7d8e15
Create Date: 2026-07-05 00:00:05.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b14c7d8e9f20'
down_revision: str | None = 'a03b6c7d8e15'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing users predate RBAC; default them to 'admin' so access is
    # preserved. New rows get their role set explicitly at creation.
    op.add_column(
        'users',
        sa.Column(
            'role',
            sa.String(length=16),
            nullable=False,
            server_default='admin',
        ),
    )


def downgrade() -> None:
    op.drop_column('users', 'role')
