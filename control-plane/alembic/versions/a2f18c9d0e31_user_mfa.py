"""user TOTP MFA

Revision ID: a2f18c9d0e31
Revises: f1e07b8c9d20
Create Date: 2026-07-05 00:00:16.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a2f18c9d0e31'
down_revision: str | None = 'f1e07b8c9d20'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.add_column(
        'users', sa.Column('mfa_secret', sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('users', 'mfa_secret')
    op.drop_column('users', 'mfa_enabled')
