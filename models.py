from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (UniqueConstraint("organization_id", "source_type", "source_event_id", name="uq_source_event"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    source_event_id: Mapped[str] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(96), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_identity_id: Mapped[str | None] = mapped_column(String(96), index=True)
    target_identity_id: Mapped[str | None] = mapped_column(String(96), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(96))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    destination: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str | None] = mapped_column(String(64))
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    scenario_id: Mapped[str | None] = mapped_column(String(64), index=True)
    source_mode: Mapped[str] = mapped_column(String(32), default="synthetic")
    demo_managed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class RuleHit(Base):
    __tablename__ = "rule_hits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    identity_id: Mapped[str] = mapped_column(String(96), index=True)
    rule_id: Mapped[str] = mapped_column(String(8), index=True)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_ids: Mapped[list[str]] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    primary_identity_id: Mapped[str] = mapped_column(String(96), index=True)
    correlation_key: Mapped[str] = mapped_column(String(256), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(24), index=True)
    score: Mapped[int] = mapped_column(Integer)
    confidence_label: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(24), default="New", index=True)
    event_ids: Mapped[list[str]] = mapped_column(JSON)
    rule_ids: Mapped[list[str]] = mapped_column(JSON)
    explanations: Mapped[list[dict]] = mapped_column(JSON)
    recommendations: Mapped[list[str]] = mapped_column(JSON)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    assigned_analyst: Mapped[str | None] = mapped_column(String(96))


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str] = mapped_column(String(96))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(96), index=True)
    action: Mapped[str] = mapped_column(String(96))
    actor: Mapped[str] = mapped_column(String(96), default="demo-operator")
    previous_state: Mapped[dict] = mapped_column(JSON, default=dict)
    new_state: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DemoSession(Base):
    __tablename__ = "demo_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default="main")
    scenario_id: Mapped[str | None] = mapped_column(String(64))
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

