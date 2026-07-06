"""Event-store operations: hot/cold/rollup stats and manual retention runs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import Organization, Role
from app.services.archive import archive_pending, replay_archive
from app.services.audit_verify import verify_pending
from app.services.event_store import get_event_sink
from app.services.retention import apply_retention, telemetry_stats
from app.settings import Settings, get_settings

router = APIRouter(tags=["telemetry"])


@router.get("/telemetry/stats")
def get_stats(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Event-store posture for this org: hot counts, rollup coverage, and the
    configured cold-archive / retention settings."""
    stats = telemetry_stats(session, org.id)
    stats.update(
        {
            "archive_enabled": get_event_sink().enabled,
            "retention_days": settings.audit_retention_days,
            "retention_days_by_classification": settings.audit_retention_days_by_class,
            "classify_telemetry": settings.classify_telemetry,
            "field_encryption_enabled": settings.telemetry_field_encryption,
        }
    )
    return stats


@router.post("/telemetry/retention/run")
def run_retention(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Trigger a retention pass for this org now (roll up + prune aged raw
    audit events). No-op unless `PRAETOR_AUDIT_RETENTION_DAYS` is set."""
    result = apply_retention(
        session,
        org_id=org.id,
        retention_days=settings.audit_retention_days,
        retention_by_class=settings.audit_retention_days_by_class,
        now=datetime.now(UTC),
        batch_size=settings.retention_batch_size,
    )
    session.flush()
    return result


@router.post("/telemetry/verify/run")
def run_verify(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, int]:
    """Run a chain-verification pass now (async-verify mode): flip verified
    events and flag any tamper. No-op when nothing is pending."""
    result = verify_pending(
        session, org.id, max_chains=settings.audit_maintenance_batch_size
    )
    session.flush()
    return result


@router.post("/telemetry/archive/run")
def run_archive(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Write not-yet-archived audit events to the authoritative cold tier now.
    No-op unless `PRAETOR_EVENT_ARCHIVE_DIR` is configured."""
    result = archive_pending(
        session, org.id, batch_size=settings.audit_maintenance_batch_size
    )
    session.flush()
    return result


@router.post("/telemetry/replay")
def run_replay(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, int]:
    """Rebuild the hot store from the authoritative cold archive by re-ingesting
    it (idempotent on (org, hash)). Returns {read, reingested, skipped}."""
    result = replay_archive(session, org.id)
    session.flush()
    return result
