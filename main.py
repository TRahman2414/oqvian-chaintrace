from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete, inspect, select, text
from sqlalchemy.orm import Session

from .correlation.engine import correlate
from .correlation.rules import RULES
from .db import Base, engine, get_db
from .models import AuditEvent, DemoSession, Incident, InvestigationNote, RuleHit, SecurityEvent, utcnow
from .scenarios import ORG_ID, SCENARIOS
from .schemas import EventInput, IncidentUpdate, NoteInput

Base.metadata.create_all(bind=engine)
if engine.dialect.name == "sqlite" and inspect(engine).has_table("security_events"):
    columns = {column["name"] for column in inspect(engine).get_columns("security_events")}
    if "demo_managed" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE security_events ADD COLUMN demo_managed BOOLEAN NOT NULL DEFAULT 0"))
            connection.execute(text("UPDATE security_events SET demo_managed = 1 WHERE scenario_id IN ('full-chain', 'partial-chain', 'benign-comparison') AND source_mode = 'synthetic' AND source_event_id LIKE scenario_id || '-%'"))
app = FastAPI(title="OQVIAN CHAINTRACE API", version="0.1.0", description="Synthetic local demo API")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()


def event_dict(event: SecurityEvent) -> dict:
    return {"id": event.id, "organization_id": event.organization_id, "source_event_id": event.source_event_id,
        "source_type": event.source_type, "event_type": event.event_type, "event_timestamp": iso(event.event_timestamp),
        "ingested_at": iso(event.ingested_at), "actor_identity_id": event.actor_identity_id, "target_identity_id": event.target_identity_id,
        "asset_id": event.asset_id, "source_ip": event.source_ip, "destination": event.destination, "action": event.action,
        "outcome": event.outcome, "attributes": event.attributes or {}, "raw_evidence": event.raw_evidence or {},
        "scenario_id": event.scenario_id, "source_mode": event.source_mode}


def incident_dict(incident: Incident, db: Session, include_events: bool = False) -> dict:
    result = {"id": incident.id, "organization_id": incident.organization_id, "primary_identity_id": incident.primary_identity_id,
        "title": incident.title, "description": incident.description, "severity": incident.severity, "score": incident.score,
        "confidence_label": incident.confidence_label, "status": incident.status, "event_ids": incident.event_ids or [],
        "rule_ids": incident.rule_ids or [], "explanations": incident.explanations or [], "recommendations": incident.recommendations or [],
        "first_event_at": iso(incident.first_event_at), "last_event_at": iso(incident.last_event_at), "created_at": iso(incident.created_at),
        "updated_at": iso(incident.updated_at), "assigned_analyst": incident.assigned_analyst}
    if include_events:
        records = [db.get(SecurityEvent, event_id) for event_id in incident.event_ids or []]
        result["events"] = [event_dict(event) for event in records if event is not None]
        result["notes"] = [{"id": note.id, "author": note.author, "note": note.note, "created_at": iso(note.created_at)} for note in db.scalars(select(InvestigationNote).where(InvestigationNote.incident_id == incident.id).order_by(InvestigationNote.created_at))]
    return result


def add_event(db: Session, payload: dict, *, demo_managed: bool = False) -> tuple[SecurityEvent, bool]:
    parsed = EventInput.model_validate(payload)
    existing = db.scalar(select(SecurityEvent).where(SecurityEvent.organization_id == ORG_ID,
        SecurityEvent.source_type == parsed.source_type, SecurityEvent.source_event_id == parsed.source_event_id))
    if existing:
        return existing, False
    event_id = sha256(f"{ORG_ID}|{parsed.source_type}|{parsed.source_event_id}".encode()).hexdigest()[:24]
    event = SecurityEvent(id=event_id, organization_id=ORG_ID, demo_managed=demo_managed, **parsed.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, True


def _demo_state(db: Session) -> DemoSession:
    state = db.get(DemoSession, "main")
    if state is None:
        state = DemoSession(id="main", scenario_id=None, cursor=0)
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


def _reset_seeded_data(db: Session) -> int:
    demo_events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.organization_id == ORG_ID, SecurityEvent.demo_managed.is_(True))))
    event_ids = {event.id for event in demo_events}
    demo_incidents = [incident for incident in db.scalars(select(Incident).where(Incident.organization_id == ORG_ID)) if event_ids.intersection(incident.event_ids or [])]
    incident_ids = [item.id for item in demo_incidents]
    if incident_ids:
        db.execute(delete(InvestigationNote).where(InvestigationNote.incident_id.in_(incident_ids)))
        for incident in demo_incidents:
            db.delete(incident)
    if event_ids:
        for hit in list(db.scalars(select(RuleHit).where(RuleHit.organization_id == ORG_ID))):
            if event_ids.intersection(hit.event_ids or []):
                db.delete(hit)
        db.execute(delete(SecurityEvent).where(SecurityEvent.id.in_(event_ids)))
    count = len(event_ids)
    db.add(AuditEvent(id=uuid4().hex, entity_type="demo", entity_id="seeded-scenarios", action="reset", previous_state={"removed_scenario_events": count}, new_state={"scenario_id": None, "cursor": 0}))
    state = _demo_state(db)
    state.scenario_id = None
    state.cursor = 0
    state.updated_at = utcnow()
    db.commit()
    return count


@app.get("/api/health")
def health():
    return {"status": "ok", "product": "OQVIAN CHAINTRACE", "mode": "local synthetic demo", "model_connected": False}


@app.get("/api/system/status")
def system_status(db: Session = Depends(get_db)):
    state = _demo_state(db)
    return {"api": "online", "database": "sqlite", "environment": "Meridian Digital Services (fictional)", "source_mode": "synthetic demo", "scenario_id": state.scenario_id, "scenario_cursor": state.cursor, "correlation": "deterministic", "model": "not configured"}


@app.get("/api/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.organization_id == ORG_ID)))
    incidents = list(db.scalars(select(Incident).where(Incident.organization_id == ORG_ID).order_by(Incident.updated_at.desc())))
    severities = {key: sum(1 for item in incidents if item.severity == key) for key in ["Critical", "High", "Medium", "Low"]}
    identities = sorted({event.actor_identity_id for event in events if event.actor_identity_id} | {event.target_identity_id for event in events if event.target_identity_id})
    return {"event_count": len(events), "rule_match_count": len(list(db.scalars(select(RuleHit).where(RuleHit.organization_id == ORG_ID)))),
        "active_incident_count": sum(1 for item in incidents if item.status not in {"Resolved"}), "critical_incident_count": severities["Critical"],
        "identity_count": len(identities), "severity_distribution": severities, "recent_incidents": [incident_dict(item, db) for item in incidents[:5]],
        "recent_events": [event_dict(item) for item in sorted(events, key=lambda e: e.event_timestamp, reverse=True)[:8]]}


@app.get("/api/events")
def list_events(search: str | None = None, event_type: str | None = None, identity_id: str | None = None,
                limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    query = select(SecurityEvent).where(SecurityEvent.organization_id == ORG_ID)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if identity_id:
        query = query.where((SecurityEvent.actor_identity_id == identity_id) | (SecurityEvent.target_identity_id == identity_id))
    items = list(db.scalars(query.order_by(SecurityEvent.event_timestamp.desc())))
    if search:
        needle = search.casefold()
        items = [item for item in items if needle in " ".join([item.source_event_id, item.event_type, item.actor_identity_id or "", item.target_identity_id or "", item.source_ip or "", item.destination or ""]).casefold()]
    return {"items": [event_dict(item) for item in items[offset:offset + limit]], "total": len(items), "limit": limit, "offset": offset}


@app.get("/api/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if event is None or event.organization_id != ORG_ID:
        raise HTTPException(status_code=404, detail="Event not found")
    return event_dict(event)


@app.post("/api/events/import")
def import_event(payload: EventInput, db: Session = Depends(get_db)):
    event, created = add_event(db, payload.model_dump())
    correlate(db, ORG_ID)
    return {"event": event_dict(event), "created": created}


@app.get("/api/rules")
def list_rules():
    return {"items": RULES}


@app.post("/api/correlation/run")
def run_correlation(db: Session = Depends(get_db)):
    incidents = correlate(db, ORG_ID)
    return {"created_or_updated": len(incidents), "incidents": [incident_dict(item, db) for item in incidents]}


@app.get("/api/correlation/results")
def correlation_results(db: Session = Depends(get_db)):
    hits = list(db.scalars(select(RuleHit).where(RuleHit.organization_id == ORG_ID).order_by(RuleHit.first_event_at)))
    return {"items": [{"id": h.id, "rule_id": h.rule_id, "identity_id": h.identity_id, "event_ids": h.event_ids, "explanation": h.explanation, "score": h.score, "first_event_at": iso(h.first_event_at), "last_event_at": iso(h.last_event_at)} for h in hits]}


@app.get("/api/incidents")
def list_incidents(status: str | None = None, db: Session = Depends(get_db)):
    query = select(Incident).where(Incident.organization_id == ORG_ID).order_by(Incident.updated_at.desc())
    if status:
        query = query.where(Incident.status == status)
    return {"items": [incident_dict(item, db) for item in db.scalars(query)]}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None or incident.organization_id != ORG_ID:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_dict(incident, db, include_events=True)


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, payload: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None or incident.organization_id != ORG_ID:
        raise HTTPException(status_code=404, detail="Incident not found")
    before = {"status": incident.status, "assigned_analyst": incident.assigned_analyst}
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(incident, key, value)
    incident.updated_at = utcnow()
    db.add(AuditEvent(id=uuid4().hex, entity_type="incident", entity_id=incident.id, action="update", previous_state=before, new_state=changes))
    db.commit()
    return incident_dict(incident, db)


@app.post("/api/incidents/{incident_id}/notes")
def add_note(incident_id: str, payload: NoteInput, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None or incident.organization_id != ORG_ID:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = InvestigationNote(id=uuid4().hex, incident_id=incident.id, author=payload.author, note=payload.note)
    db.add(note)
    db.add(AuditEvent(id=uuid4().hex, entity_type="incident", entity_id=incident.id, action="note_added", new_state={"note_id": note.id}))
    db.commit()
    return {"id": note.id, "author": note.author, "note": note.note, "created_at": iso(note.created_at)}


@app.get("/api/demo/scenarios")
def demo_scenarios(db: Session = Depends(get_db)):
    state = _demo_state(db)
    return {"active_scenario_id": state.scenario_id, "cursor": state.cursor, "items": [{"id": key, "title": value["title"], "description": value["description"], "event_count": len(value["events"]())} for key, value in SCENARIOS.items()]}


@app.post("/api/demo/scenarios/{scenario_id}/load")
def load_scenario(scenario_id: str, db: Session = Depends(get_db)):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown demo scenario")
    _reset_seeded_data(db)
    state = _demo_state(db)
    state.scenario_id = scenario_id
    state.cursor = 0
    state.updated_at = utcnow()
    db.add(AuditEvent(id=uuid4().hex, entity_type="demo", entity_id=scenario_id, action="scenario_loaded", new_state={"scenario_id": scenario_id, "cursor": 0}))
    db.commit()
    return {"scenario_id": scenario_id, "title": SCENARIOS[scenario_id]["title"], "total_events": len(SCENARIOS[scenario_id]["events"]()), "cursor": 0, "message": "Scenario loaded. Step through the fictional events or run the full sequence."}


@app.post("/api/demo/scenarios/{scenario_id}/next")
def next_scenario_event(scenario_id: str, db: Session = Depends(get_db)):
    state = _demo_state(db)
    if state.scenario_id != scenario_id:
        raise HTTPException(status_code=409, detail="Load this scenario before stepping through it")
    fixture_events = SCENARIOS[scenario_id]["events"]()
    if state.cursor >= len(fixture_events):
        return {"done": True, "cursor": state.cursor, "total_events": len(fixture_events), "event": None, "incidents": []}
    event, _ = add_event(db, fixture_events[state.cursor], demo_managed=True)
    state.cursor += 1
    state.updated_at = utcnow()
    db.commit()
    incidents = correlate(db, ORG_ID)
    return {"done": False, "cursor": state.cursor, "total_events": len(fixture_events), "event": event_dict(event), "incidents": [incident_dict(item, db) for item in incidents]}


@app.post("/api/demo/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str, db: Session = Depends(get_db)):
    state = _demo_state(db)
    if state.scenario_id != scenario_id:
        raise HTTPException(status_code=409, detail="Load this scenario before running it")
    fixture_events = SCENARIOS[scenario_id]["events"]()
    added = []
    while state.cursor < len(fixture_events):
        event, _ = add_event(db, fixture_events[state.cursor], demo_managed=True)
        added.append(event)
        state.cursor += 1
    state.updated_at = utcnow()
    db.commit()
    incidents = correlate(db, ORG_ID)
    return {"scenario_id": scenario_id, "cursor": state.cursor, "total_events": len(fixture_events), "ingested_now": len(added), "incidents": [incident_dict(item, db) for item in incidents]}


@app.post("/api/demo/reset")
def reset_demo(db: Session = Depends(get_db)):
    removed = _reset_seeded_data(db)
    return {"status": "reset", "removed_scenario_events": removed, "message": "Seeded synthetic scenario state was reset. Other local records were preserved."}
