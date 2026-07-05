"""Threat-intel feeds & indicators (IOCs): CRUD, sync, and search.

Feeds are configuration (admin-managed); syncing a feed and curating manual
indicators are analyst operations; reading is available to any member.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    IndicatorType,
    Organization,
    Role,
    ThreatFeed,
    ThreatIndicator,
)
from app.schemas import (
    ThreatFeedIn,
    ThreatFeedOut,
    ThreatFeedSyncResult,
    ThreatFeedUpdateIn,
    ThreatIndicatorIn,
    ThreatIndicatorOut,
)
from app.services.egress import EgressBlocked, assert_safe_webhook_url
from app.services.threat_intel import normalize_indicator, sync_feed

router = APIRouter(tags=["threat-intel"])


def _validate_feed_url(url: str | None) -> None:
    """Reject internal/non-global feed URLs up front (SSRF guard)."""
    if not url:
        return
    try:
        assert_safe_webhook_url(url)
    except EgressBlocked as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"feed url rejected: {exc}",
        ) from exc


# --- feeds ------------------------------------------------------------------
@router.post(
    "/threat/feeds",
    response_model=ThreatFeedOut,
    status_code=status.HTTP_201_CREATED,
)
def create_feed(
    body: ThreatFeedIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ThreatFeed:
    _validate_feed_url(body.url)
    feed = ThreatFeed(
        organization_id=org.id,
        name=body.name,
        description=body.description,
        url=body.url,
        format=body.format,
        default_indicator_type=(
            body.default_indicator_type.value
            if body.default_indicator_type
            else None
        ),
        auth_header=body.auth_header,
        enabled=body.enabled,
        tlp=body.tlp.value,
        default_confidence=body.default_confidence,
        default_severity=body.default_severity.value,
        refresh_minutes=body.refresh_minutes,
    )
    session.add(feed)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"a threat feed named {body.name!r} already exists",
        ) from exc
    return feed


@router.get("/threat/feeds", response_model=list[ThreatFeedOut])
def list_feeds(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[ThreatFeed]:
    return list(
        session.execute(
            select(ThreatFeed)
            .where(ThreatFeed.organization_id == org.id)
            .order_by(ThreatFeed.created_at.desc())
        ).scalars()
    )


@router.get("/threat/feeds/{feed_id}", response_model=ThreatFeedOut)
def get_feed(
    feed_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ThreatFeed:
    return get_owned(session, ThreatFeed, feed_id, org, detail="feed not found")


@router.patch("/threat/feeds/{feed_id}", response_model=ThreatFeedOut)
def update_feed(
    feed_id: str,
    body: ThreatFeedUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ThreatFeed:
    feed = get_owned(session, ThreatFeed, feed_id, org, detail="feed not found")
    fields = body.model_dump(exclude_unset=True)
    if "url" in fields:
        _validate_feed_url(fields["url"])
    for key, value in fields.items():
        if value is None and key in {"name", "format"}:
            continue
        # Store enum members as their string value to match the columns.
        setattr(feed, key, value.value if hasattr(value, "value") else value)
    session.flush()
    return feed


@router.delete(
    "/threat/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_feed(
    feed_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> None:
    feed = get_owned(session, ThreatFeed, feed_id, org, detail="feed not found")
    session.delete(feed)
    session.flush()


@router.post("/threat/feeds/{feed_id}/sync", response_model=ThreatFeedSyncResult)
def sync_now(
    feed_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> ThreatFeedSyncResult:
    feed = get_owned(session, ThreatFeed, feed_id, org, detail="feed not found")
    result = sync_feed(session, feed)
    session.flush()
    return ThreatFeedSyncResult(**result)


# --- indicators -------------------------------------------------------------
@router.get("/threat/indicators", response_model=list[ThreatIndicatorOut])
def list_indicators(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    type_filter: Annotated[IndicatorType | None, Query(alias="type")] = None,
    feed_id: str | None = None,
    q: str | None = None,
    enabled: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ThreatIndicator]:
    stmt = (
        select(ThreatIndicator)
        .where(ThreatIndicator.organization_id == org.id)
        .order_by(ThreatIndicator.last_seen.desc())
        .limit(limit)
        .offset(offset)
    )
    if type_filter:
        stmt = stmt.where(ThreatIndicator.type == type_filter.value)
    if feed_id:
        stmt = stmt.where(ThreatIndicator.feed_id == feed_id)
    if enabled is not None:
        stmt = stmt.where(ThreatIndicator.enabled.is_(enabled))
    if q:
        stmt = stmt.where(ThreatIndicator.value.ilike(f"%{q}%"))
    return list(session.execute(stmt).scalars().all())


@router.post(
    "/threat/indicators",
    response_model=ThreatIndicatorOut,
    status_code=status.HTTP_201_CREATED,
)
def create_indicator(
    body: ThreatIndicatorIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> ThreatIndicator:
    value = normalize_indicator(body.type.value, body.value)
    if value is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{body.value!r} is not a valid {body.type.value} indicator",
        )
    now = datetime.now(UTC)
    existing = session.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.organization_id == org.id,
            ThreatIndicator.type == body.type.value,
            ThreatIndicator.value == value,
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Refresh in place rather than 409 — re-adding an IOC is idempotent.
        existing.last_seen = now
        existing.confidence = body.confidence
        existing.severity = body.severity.value
        existing.tags = body.tags
        existing.references = body.references
        existing.description = body.description
        existing.tlp = body.tlp.value
        existing.enabled = True
        existing.expires_at = body.expires_at
        session.flush()
        return existing
    indicator = ThreatIndicator(
        organization_id=org.id,
        feed_id=None,
        type=body.type.value,
        value=value,
        confidence=body.confidence,
        severity=body.severity.value,
        tags=body.tags,
        references=body.references,
        description=body.description,
        tlp=body.tlp.value,
        first_seen=now,
        last_seen=now,
        expires_at=body.expires_at,
    )
    session.add(indicator)
    session.flush()
    return indicator


@router.delete(
    "/threat/indicators/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_indicator(
    indicator_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> None:
    indicator = get_owned(
        session, ThreatIndicator, indicator_id, org, detail="indicator not found"
    )
    session.delete(indicator)
    session.flush()
