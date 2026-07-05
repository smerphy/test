"""Role-based access control primitives.

Defines the privilege ordering over :class:`app.models.Role` and a helper to
test whether a principal's role satisfies a required minimum. The FastAPI
dependency that enforces this (``require_role``) and the ``Principal``
abstraction live in :mod:`app.auth`, which resolves the caller's role from
either the session cookie (a ``User.role``) or the API key
(``settings.api_key_roles``).
"""

from __future__ import annotations

from app.models import Role

# Higher number = more privilege. A role satisfies a requirement iff its level
# is >= the required role's level, so each role subsumes the ones below it.
ROLE_LEVELS: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 10,
    Role.ADMIN: 20,
    Role.OWNER: 30,
}


def role_level(role: Role | str) -> int:
    """Privilege level for a role. Unknown values map to 0 (least privilege)."""
    try:
        return ROLE_LEVELS[Role(role)]
    except ValueError:
        return 0


def role_at_least(role: Role | str, minimum: Role | str) -> bool:
    """True iff ``role`` is at least as privileged as ``minimum``."""
    return role_level(role) >= role_level(minimum)


__all__ = ["ROLE_LEVELS", "role_at_least", "role_level"]
