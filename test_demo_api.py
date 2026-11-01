from fastapi.testclient import TestClient

from app.db import Base, engine
from app.main import app
from app.scenarios import SCENARIOS


client = TestClient(app)


def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def load_and_run(scenario: str):
    loaded = client.post(f"/api/demo/scenarios/{scenario}/load")
    assert loaded.status_code == 200
    return client.post(f"/api/demo/scenarios/{scenario}/run")


def test_full_chain_creates_one_critical_evidence_linked_incident_and_replay_is_idempotent():
    first = load_and_run("full-chain")
    assert first.status_code == 200
    incident = first.json()["incidents"][0]
    assert incident["severity"] == "Critical"
    assert incident["score"] == 100
    assert set(incident["rule_ids"]) == {"R001", "R002", "R003", "R004", "R005", "R006"}
    assert len(client.get("/api/correlation/results").json()["items"]) == 6
    detail = client.get(f"/api/incidents/{incident['id']}").json()
    assert len(detail["events"]) == 10
    grant = next(event for event in detail["events"] if event["event_type"] == "identity.role_granted")
    assert grant["actor_identity_id"] == "identity-ops-admin"
    assert grant["target_identity_id"] == "identity-maya-chen"

    rerun = client.post("/api/correlation/run").json()
    listed = client.get("/api/incidents").json()["items"]
    assert len(listed) == 1
    assert rerun["created_or_updated"] == 1
    assert len(client.get("/api/events").json()["items"]) == 10


def test_benign_scenario_never_fabricates_cross_identity_chain():
    result = load_and_run("benign-comparison")
    assert result.status_code == 200
    assert result.json()["incidents"] == []
    assert client.get("/api/incidents").json()["items"] == []


def test_partial_chain_has_no_privilege_stage_and_scores_below_full_chain():
    result = load_and_run("partial-chain")
    incident = result.json()["incidents"][0]
    assert incident["score"] == 75
    assert incident["severity"] == "High"
    assert "R003" not in incident["rule_ids"]
    assert not any(event["event_type"] == "identity.role_granted" for event in client.get(f"/api/incidents/{incident['id']}").json()["events"])


def test_scenario_can_be_replayed_in_reverse_event_time_order():
    client.post("/api/demo/scenarios/full-chain/load")
    for record in reversed(SCENARIOS["full-chain"]["events"]()):
        response = client.post("/api/events/import", json=record)
        assert response.status_code == 200
    result = client.post("/api/correlation/run").json()
    assert len(result["incidents"]) == 1
    assert result["incidents"][0]["score"] == 100


def test_duplicate_ingestion_does_not_duplicate_event_or_increase_score():
    client.post("/api/demo/scenarios/full-chain/load")
    record = SCENARIOS["full-chain"]["events"]()[0]
    first = client.post("/api/events/import", json=record).json()
    second = client.post("/api/events/import", json=record).json()
    assert first["created"] is True
    assert second["created"] is False
    assert client.get("/api/events").json()["total"] == 1


def test_reset_only_removes_seeded_demo_records_and_records_audit():
    load_and_run("full-chain")
    response = client.post("/api/demo/reset")
    assert response.status_code == 200
    assert response.json()["removed_scenario_events"] == 10
    assert client.get("/api/events").json()["total"] == 0
    assert client.get("/api/incidents").json()["items"] == []


def test_reset_preserves_imported_records_even_if_they_claim_a_scenario_id():
    imported = {
        "source_event_id": "customer-import-01", "source_type": "Identity Provider", "event_type": "auth.login_failed",
        "event_timestamp": "2026-10-31T12:00:00Z", "actor_identity_id": "identity-imported",
        "attributes": {}, "raw_evidence": {"source": "external adapter"}, "scenario_id": "full-chain", "source_mode": "imported",
    }
    assert client.post("/api/events/import", json=imported).status_code == 200
    load_and_run("full-chain")
    result = client.post("/api/demo/reset").json()
    assert result["removed_scenario_events"] == 10
    listed = client.get("/api/events").json()
    assert listed["total"] == 1
    assert listed["items"][0]["source_event_id"] == "customer-import-01"


def test_incident_lifecycle_is_validated_and_audited():
    incident = load_and_run("full-chain").json()["incidents"][0]
    updated = client.patch(f"/api/incidents/{incident['id']}", json={"status": "Acknowledged", "assigned_analyst": "Demo analyst"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "Acknowledged"
    invalid = client.patch(f"/api/incidents/{incident['id']}", json={"status": "Deleted"})
    assert invalid.status_code == 422

