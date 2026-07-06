"""Shared router dependencies.

`get_owned` is the single enforcement point for tenant isolation on
by-id lookups: fetch a row and 404 unless it belongs to the calling
organization. Every router uses this instead of hand-writing the
`session.get(...); if obj is None or obj.<owner> != org.id: 404` check,
so the tenancy boundary is one mechanism rather than a convention that a
new endpoint can silently forget.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import Organization

T = TypeVar("T")


def get_owned(
    session: Session,
    model: type[T],
    obj_id: str,
    org: Organization,
    *,
    owner: Callable[[T], Any] = lambda obj: obj.organization_id,  # type: ignore[attr-defined]
    detail: str = "not found",
) -> T:
    """Return the row of `model` with `obj_id`, or raise 404 if it is
    missing or not owned by `org`.

    `owner` extracts the owning organization id from the row; override it
    for models that own through a relationship (e.g. a bundle owned via
    `bundle.project.organization_id`).
    """
    obj = session.get(model, obj_id)
    if obj is None or owner(obj) != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return obj


__all__ = ["get_owned"]
