"""org PII redaction toggle

Revision ID: b7ac3d4e5f86
Revises: a69b2c3d4e75
Create Date: 2026-07-05 00:00:11.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'b7ac3d4e5f86'
down_revision: str | None = 'a69b2c3d4e75'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column(
            'pii_redaction_enabled', sa.Boolean(), nullable=False,
            server_default='0',
        ),
    )


def downgrade() -> None:
    op.drop_column('organizations', 'pii_redaction_enabled')
