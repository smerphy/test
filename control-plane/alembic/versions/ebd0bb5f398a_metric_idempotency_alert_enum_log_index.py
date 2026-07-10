"""metric_idempotency_alert_enum_log_index

Revision ID: ebd0bb5f398a
Revises: c0d5e3f7a481
Create Date: 2026-07-10 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "ebd0bb5f398a"
down_revision: str | None = "c0d5e3f7a481"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # #3 metric_events idempotency: dedup at-least-once shipments on
    # (organization_id, request_id) so a retried metric can't double-count cost.
    with op.batch_alter_table("metric_events", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_metric_org_request", ["organization_id", "request_id"]
        )

    # #29 log_records: front the org FK with an index (the only org-scoped
    # table missing one), so ON DELETE CASCADE doesn't seq-scan the log.
    with op.batch_alter_table("log_records", schema=None) as batch_op:
        batch_op.create_index("ix_log_records_org", ["organization_id"])

    # #28 alert_events.state: widen the declared enum domain to include
    # ACKNOWLEDGED, which the model and acknowledge path already write. The
    # column is native_enum=False (a plain VARCHAR), so this only corrects the
    # declared value domain; it emits no CHECK constraint and is a no-op on the
    # stored data.
    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.alter_column(
            "state",
            existing_type=sa.Enum(
                "FIRING", "RESOLVED", name="alertstate", native_enum=False, length=16
            ),
            type_=sa.Enum(
                "FIRING",
                "ACKNOWLEDGED",
                "RESOLVED",
                name="alertstate",
                native_enum=False,
                length=16,
            ),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.alter_column(
            "state",
            existing_type=sa.Enum(
                "FIRING",
                "ACKNOWLEDGED",
                "RESOLVED",
                name="alertstate",
                native_enum=False,
                length=16,
            ),
            type_=sa.Enum(
                "FIRING", "RESOLVED", name="alertstate", native_enum=False, length=16
            ),
            existing_nullable=False,
        )
    with op.batch_alter_table("log_records", schema=None) as batch_op:
        batch_op.drop_index("ix_log_records_org")
    with op.batch_alter_table("metric_events", schema=None) as batch_op:
        batch_op.drop_constraint("uq_metric_org_request", type_="unique")
