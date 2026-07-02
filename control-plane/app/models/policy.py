from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class RolloutState(StrEnum):
    DRAFT = "draft"
    STAGED = "staged"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"


class Project(IdMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (UniqueConstraint("organization_id", "slug", name="uq_project_org_slug"),)

    organization = relationship("Organization", back_populates="projects")
    bundles: Mapped[list[PolicyBundle]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class PolicyBundle(IdMixin, TimestampMixin, Base):
    __tablename__ = "policy_bundles"

    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="bundles")
    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="bundle",
        cascade="all, delete-orphan",
        order_by="PolicyVersion.version_number",
    )


class PolicyVersion(IdMixin, TimestampMixin, Base):
    __tablename__ = "policy_versions"

    bundle_id: Mapped[str] = mapped_column(
        ForeignKey("policy_bundles.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_text: Mapped[str] = mapped_column(Text, nullable=False)
    policy_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    author_email: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("bundle_id", "version_number", name="uq_version_bundle_num"),
        CheckConstraint("version_number > 0", name="ck_version_number_positive"),
    )

    bundle: Mapped[PolicyBundle] = relationship(back_populates="versions")


class PolicyRollout(IdMixin, TimestampMixin, Base):
    __tablename__ = "policy_rollouts"

    version_id: Mapped[str] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False
    )
    state: Mapped[RolloutState] = mapped_column(
        Enum(RolloutState, native_enum=False, length=32),
        nullable=False,
        default=RolloutState.DRAFT,
    )
    rollout_percentage: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        CheckConstraint(
            "rollout_percentage >= 0 AND rollout_percentage <= 100",
            name="ck_rollout_percentage_range",
        ),
    )

    version: Mapped[PolicyVersion] = relationship()
