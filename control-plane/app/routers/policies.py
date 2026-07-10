"""Policy bundle authoring + versioning + staged rollout."""

from __future__ import annotations

from typing import Any

# We import the engine parser to validate YAML on the way in.
from ephorate_engine.parser import PolicyParseError, parse_bundle
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    Organization,
    PolicyBundle,
    PolicyRollout,
    PolicyVersion,
    Project,
    Role,
    RolloutState,
)
from app.schemas import (
    PolicyBacktestIn,
    PolicyBundleIn,
    PolicyBundleOut,
    PolicyRolloutIn,
    PolicyRolloutOut,
    PolicyVersionIn,
    PolicyVersionOut,
    PolicyVersionSummary,
    ProjectIn,
    ProjectOut,
)
from app.services.access_log import access_log
from app.services.backtest import backtest_policy

router = APIRouter(tags=["policies"])


def _bundle_out(bundle: PolicyBundle) -> PolicyBundleOut:
    return PolicyBundleOut(
        id=bundle.id,
        project_id=bundle.project_id,
        name=bundle.name,
        description=bundle.description,
        version_count=len(bundle.versions),
    )


@router.post(
    "/projects",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    body: ProjectIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> Project:
    project = Project(organization_id=org.id, name=body.name, slug=body.slug)
    session.add(project)
    session.flush()
    return project


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[Project]:
    stmt = select(Project).where(Project.organization_id == org.id)
    return list(session.execute(stmt).scalars().all())


@router.post(
    "/projects/{project_id}/bundles",
    response_model=PolicyBundleOut,
    status_code=status.HTTP_201_CREATED,
)
def create_bundle(
    project_id: str,
    body: PolicyBundleIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> PolicyBundleOut:
    project = get_owned(session, Project, project_id, org, detail="project not found")
    bundle = PolicyBundle(
        project_id=project.id, name=body.name, description=body.description
    )
    session.add(bundle)
    session.flush()
    return _bundle_out(bundle)


@router.get(
    "/projects/{project_id}/bundles", response_model=list[PolicyBundleOut]
)
def list_bundles(
    project_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[PolicyBundleOut]:
    project = get_owned(session, Project, project_id, org, detail="project not found")
    return [_bundle_out(b) for b in project.bundles]


@router.post(
    "/bundles/{bundle_id}/versions",
    response_model=PolicyVersionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    bundle_id: str,
    body: PolicyVersionIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> PolicyVersion:
    bundle = get_owned(
        session,
        PolicyBundle,
        bundle_id,
        org,
        owner=lambda b: b.project.organization_id,
        detail="bundle not found",
    )

    try:
        policies = parse_bundle(body.yaml_text)
    except PolicyParseError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid policy bundle: {exc}",
        ) from exc

    next_version = (
        max((v.version_number for v in bundle.versions), default=0) + 1
    )
    version = PolicyVersion(
        bundle_id=bundle.id,
        version_number=next_version,
        yaml_text=body.yaml_text,
        policy_count=len(policies),
        author_email=body.author_email,
        notes=body.notes,
    )
    session.add(version)
    session.flush()
    return version


@router.get(
    "/bundles/{bundle_id}/versions", response_model=list[PolicyVersionSummary]
)
def list_versions(
    bundle_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[PolicyVersion]:
    """List versions of a bundle. Omits `yaml_text` for payload sanity;
    fetch one version's full text via `GET /versions/{version_id}`."""
    bundle = get_owned(
        session,
        PolicyBundle,
        bundle_id,
        org,
        owner=lambda b: b.project.organization_id,
        detail="bundle not found",
    )
    return list(bundle.versions)


@router.get(
    "/bundles/{bundle_id}/versions/full",
    response_model=list[PolicyVersionOut],
)
def list_versions_full(
    bundle_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[PolicyVersion]:
    """List versions of a bundle *with* their full `yaml_text` in one call.

    The version rows are already loaded by the relationship, so this is a
    single round-trip — it lets a client render every version's YAML without
    an N+1 of `GET /versions/{id}` per version."""
    bundle = get_owned(
        session,
        PolicyBundle,
        bundle_id,
        org,
        owner=lambda b: b.project.organization_id,
        detail="bundle not found",
    )
    return list(bundle.versions)


@router.get("/versions/{version_id}", response_model=PolicyVersionOut)
def get_version(
    version_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> PolicyVersion:
    version = get_owned(
        session,
        PolicyVersion,
        version_id,
        org,
        owner=lambda v: v.bundle.project.organization_id,
        detail="version not found",
    )
    return version


@router.post(
    "/bundles/{bundle_id}/rollouts",
    response_model=PolicyRolloutOut,
    status_code=status.HTTP_201_CREATED,
)
def create_rollout(
    bundle_id: str,
    body: PolicyRolloutIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> PolicyRollout:
    bundle = get_owned(
        session,
        PolicyBundle,
        bundle_id,
        org,
        owner=lambda b: b.project.organization_id,
        detail="bundle not found",
    )
    version = session.get(PolicyVersion, body.version_id)
    if version is None or version.bundle_id != bundle.id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="version not found in this bundle"
        )

    # Active rollout must be 100%.
    if body.state is RolloutState.ACTIVE and body.rollout_percentage != 100:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="active rollout must be 100%; use 'staged' for partial rollout",
        )

    rollout = PolicyRollout(
        version_id=version.id,
        state=body.state,
        rollout_percentage=body.rollout_percentage,
    )
    session.add(rollout)
    session.flush()
    return rollout


@router.post("/policies/backtest")
def backtest(
    body: PolicyBacktestIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
    _al: None = Depends(access_log("audit", "backtest")),
) -> dict[str, Any]:
    """Replay recorded audit events through a candidate policy bundle and diff
    the decisions (what would this policy have done?). Read-only."""
    try:
        return backtest_policy(
            session,
            org.id,
            yaml_text=body.yaml_text,
            since=body.since,
            until=body.until,
            limit=body.limit,
        )
    except PolicyParseError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid policy bundle: {exc}",
        ) from exc
