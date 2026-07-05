"""Record and query the access log (who viewed/exported what)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.auth import Principal, current_principal
from app.db import get_session
from app.models import AccessLog


def _actor(principal: Principal, session: Session) -> tuple[str, str]:
    if principal.kind == "user" and principal.user_id:
        from app.models import User

        user = session.get(User, principal.user_id)
        if user is not None:
            return user.email, "user"
    return "api_key", "api_key"


def record_access(
    session: Session,
    principal: Principal,
    request: Request,
    *,
    resource: str,
    action: str = "read",
    detail: dict[str, Any] | None = None,
) -> None:
    """Best-effort access-log write. Never raises."""
    try:
        actor, kind = _actor(principal, session)
        client = request.client
        session.add(
            AccessLog(
                organization_id=principal.org.id,
                actor=actor,
                actor_kind=kind,
                resource=resource,
                action=action,
                method=request.method,
                path=request.url.path[:512],
                source_ip=client.host if client else None,
                detail=detail or {},
            )
        )
    except Exception:
        session.rollback()


def access_log(
    resource: str, action: str = "read"
) -> Callable[..., None]:
    """Dependency factory: record access to a sensitive read/export surface."""

    def dependency(
        request: Request,
        principal: Principal = Depends(current_principal),
        session: Session = Depends(get_session),
    ) -> None:
        record_access(
            session, principal, request, resource=resource, action=action
        )

    return dependency


__all__ = ["access_log", "record_access"]
