from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class EventInput(BaseModel):
    source_event_id: str = Field(min_length=1, max_length=128)
    source_type: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=96)
    event_timestamp: datetime
    actor_identity_id: str | None = None
    target_identity_id: str | None = None
    asset_id: str | None = None
    source_ip: str | None = None
    destination: str | None = None
    action: str | None = None
    outcome: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str | None = None
    source_mode: Literal["synthetic", "imported"] = "synthetic"


class IncidentUpdate(BaseModel):
    status: Literal["New", "Acknowledged", "Investigating", "Escalated", "Resolved", "Reopened"] | None = None
    assigned_analyst: str | None = Field(default=None, max_length=96)


class NoteInput(BaseModel):
    author: str = Field(default="Demo analyst", min_length=1, max_length=96)
    note: str = Field(min_length=1, max_length=2000)
