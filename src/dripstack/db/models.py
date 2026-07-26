"""SQLAlchemy 2.0 models — 1:1 port of packages/db/prisma/schema.prisma.

Strict multi-tenancy: every row (except Organization) carries organization_id,
and `for_org()` (db/tenant.py) scopes all reads/writes to one organization.

Column attribute names are snake_case (Python idiom); the API response builders
emit the camelCase JSON the dashboard expects. Enum string *values* match the
Prisma enums exactly so persisted/serialized values are unchanged.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..ids import cuid


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


# ── Enums (values match Prisma) ──────────────────────────────────────────────


class Role(enum.StrEnum):
    admin = "admin"
    member = "member"


class EventStatus(enum.StrEnum):
    received = "received"
    matched = "matched"
    ignored = "ignored"


class SequenceStatus(enum.StrEnum):
    draft = "draft"
    active = "active"
    paused = "paused"


class RunStatus(enum.StrEnum):
    running = "running"
    resolved = "resolved"
    escalated = "escalated"
    completed = "completed"
    failed = "failed"


class MessageStatus(enum.StrEnum):
    queued = "queued"
    sent = "sent"
    delivered = "delivered"
    failed = "failed"
    opened = "opened"
    clicked = "clicked"


class Channel(enum.StrEnum):
    email = "email"
    slack = "slack"
    teams = "teams"


class EventSourceType(enum.StrEnum):
    generic_webhook = "generic_webhook"
    sentry = "sentry"


class PermissionCategory(enum.StrEnum):
    user_management = "user_management"
    customer_management = "customer_management"
    configuration = "configuration"


class RoleScope(enum.StrEnum):
    platform = "platform"
    organization = "organization"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> Enum:
    # Store the enum *value* (matches Prisma); native_enum keeps a real PG type.
    return Enum(
        py_enum,
        name=name,
        values_callable=lambda e: [m.value for m in e],
    )


def _id() -> Mapped[str]:
    return mapped_column(String, primary_key=True, default=cuid)


# ── Models ───────────────────────────────────────────────────────────────────


class Organization(Base):
    __tablename__ = "Organization"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class User(Base):
    __tablename__ = "User"
    __table_args__ = (
        # Email is a single platform-wide identity (one email = one account), so
        # login is unambiguous. Org membership is still tracked via organization_id.
        UniqueConstraint("email", name="User_email_key"),
        Index("User_org_idx", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    # Legacy flat role kept for back-compat; RBAC reads role_id → Role → permissions.
    role: Mapped[Role] = mapped_column(_pg_enum(Role, "Role"), default=Role.member)
    role_id: Mapped[str | None] = mapped_column(ForeignKey("Role_rbac.id", ondelete="SET NULL"))
    is_platform_staff: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Suspended users keep their row + history but cannot log in or hold a session.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    rbac_role: Mapped[RbacRole | None] = relationship(lazy="selectin")


class ApiKey(Base):
    __tablename__ = "ApiKey"
    __table_args__ = (Index("ApiKey_org_idx", "organization_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    hashed_key: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Contact(Base):
    __tablename__ = "Contact"
    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="Contact_org_email_key"),
        Index("Contact_org_idx", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String)
    phone: Mapped[str | None] = mapped_column(String)
    slack_user_id: Mapped[str | None] = mapped_column(String)
    # Technician fields: customers configure these on the Technicians page.
    title: Mapped[str | None] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    custom_attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class EventSource(Base):
    __tablename__ = "EventSource"
    __table_args__ = (Index("EventSource_org_idx", "organization_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[EventSourceType] = mapped_column(
        _pg_enum(EventSourceType, "EventSourceType"), default=EventSourceType.generic_webhook
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    signing_secret: Mapped[str] = mapped_column(String, nullable=False)
    contact_email_path: Mapped[str] = mapped_column(String, default="$.technician.email")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Event(Base):
    __tablename__ = "Event"
    __table_args__ = (
        Index("Event_org_type_idx", "organization_id", "type"),
        Index("Event_org_hash_idx", "organization_id", "payload_hash", "received_at"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    event_source_id: Mapped[str | None] = mapped_column(ForeignKey("EventSource.id", ondelete="SET NULL"))
    type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    contact_email: Mapped[str | None] = mapped_column(String)
    payload_hash: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[EventStatus] = mapped_column(_pg_enum(EventStatus, "EventStatus"), default=EventStatus.received)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Sequence(Base):
    __tablename__ = "Sequence"
    __table_args__ = (Index("Sequence_org_status_idx", "organization_id", "status"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[SequenceStatus] = mapped_column(
        _pg_enum(SequenceStatus, "SequenceStatus"), default=SequenceStatus.draft
    )
    trigger_rule: Mapped[dict] = mapped_column(JSONB, nullable=False)
    steps: Mapped[list] = mapped_column(JSONB, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SequenceRun(Base):
    __tablename__ = "SequenceRun"
    __table_args__ = (
        Index(
            "SequenceRun_lookup_idx",
            "organization_id",
            "sequence_id",
            "contact_id",
            "status",
        ),
        Index("SequenceRun_org_status_idx", "organization_id", "status"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    sequence_id: Mapped[str] = mapped_column(ForeignKey("Sequence.id", ondelete="CASCADE"), nullable=False)
    contact_id: Mapped[str] = mapped_column(ForeignKey("Contact.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("Event.id", ondelete="SET NULL"))
    temporal_workflow_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    status: Mapped[RunStatus] = mapped_column(_pg_enum(RunStatus, "RunStatus"), default=RunStatus.running)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_time_seconds: Mapped[int | None] = mapped_column(Integer)

    sequence: Mapped[Sequence] = relationship(lazy="selectin")
    contact: Mapped[Contact] = relationship(lazy="selectin")
    event: Mapped[Event | None] = relationship(lazy="selectin")
    message_logs: Mapped[list[MessageLog]] = relationship(
        back_populates="run", lazy="selectin", cascade="all, delete-orphan"
    )
    action_clicks: Mapped[list[ActionClick]] = relationship(
        back_populates="run", lazy="selectin", cascade="all, delete-orphan"
    )


class MessageLog(Base):
    __tablename__ = "MessageLog"
    __table_args__ = (Index("MessageLog_org_run_idx", "organization_id", "run_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("SequenceRun.id", ondelete="CASCADE"), nullable=False)
    step_id: Mapped[str] = mapped_column(String, nullable=False)
    channel: Mapped[Channel] = mapped_column(_pg_enum(Channel, "Channel"), nullable=False)
    status: Mapped[MessageStatus] = mapped_column(
        _pg_enum(MessageStatus, "MessageStatus"), default=MessageStatus.queued
    )
    provider_message_id: Mapped[str | None] = mapped_column(String)
    rendered_html: Mapped[str | None] = mapped_column(Text)
    rendered_text: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped[SequenceRun] = relationship(back_populates="message_logs")


class ActionClick(Base):
    __tablename__ = "ActionClick"
    __table_args__ = (Index("ActionClick_org_run_idx", "organization_id", "run_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[str] = mapped_column(ForeignKey("SequenceRun.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    ip_hash: Mapped[str | None] = mapped_column(String)
    clicked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped[SequenceRun] = relationship(back_populates="action_clicks")


class OutboundWebhook(Base):
    __tablename__ = "OutboundWebhook"
    __table_args__ = (Index("OutboundWebhook_org_idx", "organization_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    secret: Mapped[str] = mapped_column(String, nullable=False)
    events: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ChannelIntegration(Base):
    """Per-org delivery channel credential (Slack/Teams incoming webhook URL).

    The webhook URL is a posting credential, so it lives here (NOT in
    Organization.settings, which is serialized to every user) and is never
    returned raw by the API — only a masked target + connected flag.
    """

    __tablename__ = "ChannelIntegration"
    __table_args__ = (
        UniqueConstraint("organization_id", "channel", name="ChannelIntegration_org_channel_key"),
        Index("ChannelIntegration_org_idx", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    channel: Mapped[str] = mapped_column(String, nullable=False)  # slack | teams
    webhook_url: Mapped[str] = mapped_column(String, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


# ── RBAC ──────────────────────────────────────────────────────────────────────


class Permission(Base):
    __tablename__ = "Permission"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    key: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    category: Mapped[PermissionCategory] = mapped_column(_pg_enum(PermissionCategory, "PermissionCategory"), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")


class RbacRole(Base):
    """A role is a named bundle of permissions. System roles have organization_id
    NULL; custom org roles carry an organization_id. Table name `Role_rbac` keeps
    it distinct from the legacy `Role` enum's PG type."""

    __tablename__ = "Role_rbac"
    __table_args__ = (Index("Role_rbac_org_idx", "organization_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    scope: Mapped[RoleScope] = mapped_column(_pg_enum(RoleScope, "RoleScope"), nullable=False)
    organization_id: Mapped[str | None] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"))
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list[Permission]] = relationship(
        secondary="RolePermission", lazy="selectin"
    )


class RolePermission(Base):
    __tablename__ = "RolePermission"

    role_id: Mapped[str] = mapped_column(ForeignKey("Role_rbac.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("Permission.id", ondelete="CASCADE"), primary_key=True)


# ── SSO (OIDC) ─────────────────────────────────────────────────────────────────


class SsoConnection(Base):
    """Per-org OpenID Connect (OIDC) SSO configuration.

    Like ChannelIntegration, this holds a secret (`client_secret`) so it lives in
    its own table — NEVER in Organization.settings, which is serialized to every
    user. The API only ever returns a masked view (see serialize.sso_connection).
    """

    __tablename__ = "SsoConnection"
    __table_args__ = (
        UniqueConstraint("organization_id", name="SsoConnection_org_key"),
        Index("SsoConnection_org_idx", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False, default="oidc")
    issuer: Mapped[str] = mapped_column(String, nullable=False)
    client_id: Mapped[str] = mapped_column(String, nullable=False)
    client_secret: Mapped[str] = mapped_column(String, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # When true, a verified SSO login with no matching user creates one (in this
    # org, with default_role_slug). When false, only existing users can sign in.
    auto_provision: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Optional hard restriction on the email domain allowed to sign in via SSO.
    allowed_domain: Mapped[str | None] = mapped_column(String)
    default_role_slug: Mapped[str] = mapped_column(String, nullable=False, default="customer-member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


# ── Audit log ──────────────────────────────────────────────────────────────────


class AuditLog(Base):
    """Append-only record of security-relevant actions (logins, user/role/config
    changes). Scoped per-org; platform actions carry the actor's org."""

    __tablename__ = "AuditLog"
    __table_args__ = (
        Index("AuditLog_org_idx", "organization_id", "created_at"),
        Index("AuditLog_org_action_idx", "organization_id", "action"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=cuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("Organization.id", ondelete="CASCADE"), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String)  # user id, "apikey", or None (system/anon)
    actor_label: Mapped[str | None] = mapped_column(String)  # email / friendly label at the time
    action: Mapped[str] = mapped_column(String, nullable=False)  # e.g. auth.login, user.create
    target: Mapped[str | None] = mapped_column(String)  # affected entity id/key
    ip_hash: Mapped[str | None] = mapped_column(String)
    meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
