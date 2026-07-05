"""finding impact/fidelity/source + org fidelity threshold

Revision ID: f58a1b2c3d64
Revises: e47f0a1b2c53
Create Date: 2026-07-05 00:00:09.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f58a1b2c3d64'
down_revision: str | None = 'e47f0a1b2c53'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'findings',
        sa.Column(
            'source', sa.String(length=32), nullable=False,
            server_default='detection_engine',
        ),
    )
    op.add_column(
        'findings',
        sa.Column(
            'impact', sa.String(length=16), nullable=False,
            server_default='moderate',
        ),
    )
    op.add_column(
        'findings',
        sa.Column('fidelity', sa.Float(), nullable=False, server_default='1'),
    )
    op.add_column(
        'organizations',
        sa.Column(
            'finding_fidelity_threshold', sa.Float(), nullable=False,
            server_default='0.4',
        ),
    )
    op.create_index(
        'ix_finding_org_source', 'findings', ['organization_id', 'source']
    )


def downgrade() -> None:
    op.drop_index('ix_finding_org_source', table_name='findings')
    op.drop_column('organizations', 'finding_fidelity_threshold')
    op.drop_column('findings', 'fidelity')
    op.drop_column('findings', 'impact')
    op.drop_column('findings', 'source')
