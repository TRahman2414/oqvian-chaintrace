from dataclasses import dataclass


RULES = [
    {"id": "R001", "name": "Authentication failure burst", "purpose": "Repeated failures against one identity", "window": "5 minutes", "score": 15},
    {"id": "R002", "name": "Unusual successful sign-in", "purpose": "Explicitly unfamiliar success after a failure burst", "window": "10 minutes", "score": 20},
    {"id": "R003", "name": "Privilege change after sign-in", "purpose": "Privilege grant targets the investigated identity", "window": "20 minutes", "score": 25},
    {"id": "R004", "name": "External forwarding change", "purpose": "Forwarding destination is outside approved domains", "window": "30 minutes", "score": 20},
    {"id": "R005", "name": "Large download after sign-in", "purpose": "At least 250 MB by the same identity", "window": "30 minutes", "score": 20},
    {"id": "R006", "name": "Multi-stage chain", "purpose": "Three or more distinct supported stages in one 45-minute chain", "window": "45 minutes", "score": None},
]


@dataclass(frozen=True)
class Signal:
    rule_id: str
    event_ids: tuple[str, ...]
    explanation: str
    score: int

