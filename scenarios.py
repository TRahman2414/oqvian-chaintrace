from datetime import datetime, timedelta, timezone

ORG_ID = "meridian-demo"
BASE_TIME = datetime(2026, 10, 31, 14, 0, tzinfo=timezone.utc)
APPROVED_DOMAINS = ["meridian.example"]


def _event(event_id: str, minute: int, event_type: str, identity: str, **extra) -> dict:
    record = {
        "source_event_id": event_id,
        "source_type": "Identity Provider" if event_type.startswith("auth.") else "Cloud Audit",
        "event_type": event_type,
        "event_timestamp": (BASE_TIME + timedelta(minutes=minute)).isoformat(),
        "actor_identity_id": identity,
        "target_identity_id": None,
        "asset_id": "mds-lt-042",
        "source_ip": None,
        "destination": None,
        "action": event_type,
        "outcome": "success" if event_type != "auth.login_failed" else "failure",
        "attributes": {},
        "raw_evidence": {"demo_record": True, "source_event_id": event_id, "event_type": event_type},
        "scenario_id": None,
        "source_mode": "synthetic",
    }
    record.update(extra)
    return record


def _chain(scenario_id: str, omit_privilege: bool = False) -> list[dict]:
    identity = "identity-maya-chen"
    events = []
    for n, minute in enumerate([0, 0, 1, 2, 3, 4], start=1):
        events.append(_event(f"{scenario_id}-fail-{n:02d}", minute, "auth.login_failed", identity,
                             source_ip="192.0.2.41", attributes={"attempt": n}))
    events.append(_event(f"{scenario_id}-success", 5, "auth.login_success", identity,
                         source_ip="198.51.100.17", attributes={"unfamiliar_source": True, "device": "unrecognized-demo-device"}))
    if not omit_privilege:
        events.append(_event(f"{scenario_id}-grant", 10, "identity.role_granted", "identity-ops-admin",
                             target_identity_id=identity, source_type="Administrative Audit", action="grant:billing-admin",
                             attributes={"role": "billing-admin"}))
    events.append(_event(f"{scenario_id}-forward", 16, "mail.forwarding_rule_created", identity,
                         source_type="Cloud Mail Audit", destination="maya.archive@external.example",
                         attributes={"approved_domains": APPROVED_DOMAINS}))
    events.append(_event(f"{scenario_id}-download", 25, "files.bulk_download", identity,
                         source_type="File Access Audit", attributes={"download_mb": 684, "file_count": 19}))
    for item in events:
        item["scenario_id"] = scenario_id
    return events


def full_chain() -> list[dict]:
    return _chain("full-chain")


def partial_chain() -> list[dict]:
    return _chain("partial-chain", omit_privilege=True)


def benign_comparison() -> list[dict]:
    identity_a = "identity-riley-jones"
    identity_b = "identity-sam-taylor"
    events = []
    for n, minute in enumerate([0, 1, 1, 2, 3, 4], start=1):
        events.append(_event(f"benign-fail-{n:02d}", minute, "auth.login_failed", identity_a,
                             source_ip="192.0.2.80", attributes={"attempt": n}))
    events.append(_event("benign-success", 6, "auth.login_success", identity_b,
                         source_ip="203.0.113.60", attributes={"unfamiliar_source": False}))
    events.append(_event("benign-grant", 9, "identity.role_granted", "identity-ops-admin",
                         target_identity_id="identity-finance-lead", source_type="Administrative Audit",
                         action="grant:report-viewer", attributes={"role": "report-viewer"}))
    events.append(_event("benign-forward", 12, "mail.forwarding_rule_created", identity_b,
                         source_type="Cloud Mail Audit", destination="archive@meridian.example",
                         attributes={"approved_domains": APPROVED_DOMAINS}))
    events.append(_event("benign-download", 18, "files.bulk_download", "identity-finance-lead",
                         source_type="File Access Audit", attributes={"download_mb": 18, "file_count": 3}))
    for item in events:
        item["scenario_id"] = "benign-comparison"
    return events


SCENARIOS = {
    "full-chain": {"title": "Suspicious post-login sequence", "description": "Five synthetic behaviors tied to one identity.", "events": full_chain},
    "benign-comparison": {"title": "Legitimate activity challenge", "description": "Nearby events from different identities and an approved destination.", "events": benign_comparison},
    "partial-chain": {"title": "Partial suspicious sequence", "description": "A plausible chain without a privilege-change event.", "events": partial_chain},
}
