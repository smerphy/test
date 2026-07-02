"""Current-organization settings (e.g. approval-notification webhook)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import Organization
from app.schemas import OrganizationOut, OrganizationUpdateIn

router = APIRouter(tags=["org"])


@router.get("/org", response_model=OrganizationOut)
def get_org(org: Organization = Depends(current_org)) -> Organization:
    return org


@router.patch("/org", response_model=OrganizationOut)
def update_org(
    body: OrganizationUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> Organization:
    # Only mutate fields explicitly present in the request so a partial
    # update doesn't clobber unrelated settings.
    fields = body.model_dump(exclude_unset=True)
    if "approval_webhook_url" in fields:
        org.approval_webhook_url = fields["approval_webhook_url"]
    session.flush()
    return org
