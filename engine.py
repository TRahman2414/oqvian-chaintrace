from datetime import datetime, timedelta, timezone
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Incident, RuleHit, SecurityEvent, utcnow
from .rules import Signal

SCORES = {"R001": 15, "R002": 20, "R003": 25, "R004": 20, "R005": 20}


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _event_key(event: SecurityEvent) -> tuple[datetime, str]:
    return (_aware(event.event_timestamp), event.id)


def _signal(identity: str, rule_id: str, events: list[SecurityEvent], explanation: str) -> Signal:
    unique = tuple(sorted({event.id for event in events}))
    salt = f"{identity}|{rule_id}|{'|'.join(unique)}"
    return Signal(rule_id, unique, explanation, SCORES[rule_id])


def severity_for(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def correlate(db: Session, organization_id: str) -> list[Incident]:
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.organization_id == organization_id)))
    by_identity: dict[str, list[SecurityEvent]] = {}
    for event in events:
        # Authentication and file activity are attributed to the actor; admin changes correlate by target.
        identity = event.target_identity_id if event.event_type == "identity.role_granted" else event.actor_identity_id
        if identity:
            by_identity.setdefault(identity, []).append(event)

    generated: list[Incident] = []
    for identity, identity_events in by_identity.items():
        ordered = sorted(identity_events, key=_event_key)
        failures = [e for e in ordered if e.event_type == "auth.login_failed"]
        successes = [e for e in ordered if e.event_type == "auth.login_success"]
        for success in successes:
            success_at = _aware(success.event_timestamp)
            prior_failures = [f for f in failures if timedelta(0) <= success_at - _aware(f.event_timestamp) <= timedelta(minutes=10)]
            failure_windows = [
                [f for f in prior_failures if _aware(f.event_timestamp) >= _aware(anchor.event_timestamp) and _aware(f.event_timestamp) <= _aware(anchor.event_timestamp) + timedelta(minutes=5)]
                for anchor in prior_failures
            ]
            burst = max(failure_windows, key=len, default=[])
            if len(burst) < 6 or not bool((success.attributes or {}).get("unfamiliar_source")):
                continue

            r2_events = [*burst, success]
            signals = [
                _signal(identity, "R001", burst, f"{len(burst)} failed sign-ins against {identity} within five minutes."),
                _signal(identity, "R002", r2_events, "A successful sign-in followed the failure burst within ten minutes; the fixture explicitly marks its source unfamiliar."),
            ]

            def followups(event_type: str, minutes: int) -> list[SecurityEvent]:
                return [e for e in ordered if e.id != success.id and _aware(e.event_timestamp) >= success_at and _aware(e.event_timestamp) <= success_at + timedelta(minutes=minutes) and e.event_type == event_type]

            grants = [e for e in followups("identity.role_granted", 20) if e.target_identity_id == identity]
            if grants:
                signals.append(_signal(identity, "R003", grants, "A privilege grant targeted the investigated identity within twenty minutes of the unusual sign-in; the administrator remains the separate actor."))

            forwards = []
            for e in followups("mail.forwarding_rule_created", 30):
                destination = (e.destination or "").strip().lower()
                domain = destination.rsplit("@", 1)[-1] if "@" in destination else destination.lstrip("@").split(":")[-1]
                approved = {d.lower().lstrip("@").removeprefix("*").lstrip(".") for d in (e.attributes or {}).get("approved_domains", [])}
                if domain and not any(domain == d or domain.endswith("." + d) for d in approved):
                    forwards.append(e)
            if forwards:
                signals.append(_signal(identity, "R004", forwards, "A forwarding destination is outside the explicit approved-domain list within thirty minutes of sign-in."))

            downloads = [e for e in followups("files.bulk_download", 30) if float((e.attributes or {}).get("download_mb", 0)) >= 250]
            if downloads:
                signals.append(_signal(identity, "R005", downloads, "The investigated identity downloaded at least 250 MB within thirty minutes of sign-in; this threshold is demo-specific and does not prove exfiltration."))

            distinct_stages = {signal.rule_id for signal in signals}
            has_high_risk_followup = bool(grants or forwards or downloads)
            chain_events = [db.get(SecurityEvent, event_id) for signal in signals for event_id in signal.event_ids]
            chain_events = [event for event in chain_events if event is not None]
            if len(distinct_stages) < 3 or not has_high_risk_followup:
                continue
            times = [_aware(event.event_timestamp) for event in chain_events]
            if max(times) - min(times) > timedelta(minutes=45):
                continue

            score = min(100, sum(signal.score for signal in signals))
            event_ids = sorted({event.id for event in chain_events}, key=lambda event_id: _event_key(db.get(SecurityEvent, event_id)))
            rule_ids = [signal.rule_id for signal in signals] + ["R006"]
            correlation_key = f"{organization_id}|{identity}|{success.id}"
            incident_id = sha256(correlation_key.encode()).hexdigest()[:24]
            incident = db.scalar(select(Incident).where(Incident.correlation_key == correlation_key))
            if incident is None:
                incident = Incident(id=incident_id, organization_id=organization_id, primary_identity_id=identity, correlation_key=correlation_key,
                    title="Potential account compromise with suspicious post-login activity", description="A deterministic sequence of authentication and post-login signals requires analyst review.",
                    status="New", confidence_label="Moderate", recommendations=["Validate the sign-in with the account owner through an approved channel.", "Review the privilege grant and forwarding destination.", "Confirm whether the download matches the user's expected work."],
                    first_event_at=min(times), last_event_at=max(times), event_ids=event_ids, rule_ids=rule_ids, score=score, severity=severity_for(score),
                    explanations=[{"rule_id": signal.rule_id, "text": signal.explanation, "score": signal.score} for signal in signals])
                db.add(incident)
            else:
                incident.event_ids = event_ids
                incident.rule_ids = rule_ids
                incident.explanations = [{"rule_id": signal.rule_id, "text": signal.explanation, "score": signal.score} for signal in signals]
                incident.score = score
                incident.severity = severity_for(score)
                incident.first_event_at = min(times)
                incident.last_event_at = max(times)
                incident.updated_at = utcnow()
            chain_signal = Signal("R006", tuple(event_ids), "Three or more supported suspicious stages, including an unusual sign-in and a later high-risk action, were linked within forty-five minutes.", 0)
            for signal in [*signals, chain_signal]:
                hit_id = sha256(f"{organization_id}|{identity}|{signal.rule_id}|{'|'.join(signal.event_ids)}".encode()).hexdigest()[:24]
                if db.get(RuleHit, hit_id) is None:
                    hit_events = [db.get(SecurityEvent, event_id) for event_id in signal.event_ids]
                    hit_times = [_aware(item.event_timestamp) for item in hit_events if item is not None]
                    db.add(RuleHit(id=hit_id, organization_id=organization_id, identity_id=identity, rule_id=signal.rule_id,
                        first_event_at=min(hit_times), last_event_at=max(hit_times), event_ids=list(signal.event_ids), explanation=signal.explanation, score=signal.score))
            generated.append(incident)
    db.commit()
    return generated

