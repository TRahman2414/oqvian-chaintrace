# Test Report

# Test Report

Status: first vertical slice verified locally (Python 3.14.8, FastAPI/SQLite, Node 26.11.1, Vite).

## Backend

- uv run pytest -q: 8 passed.
- Full chain creates one Critical incident with score 100, R001–R006 links, and all 10 evidence records.
- Re-correlation is idempotent; duplicate event imports do not duplicate records.
- Benign cross-identity activity does not create a multi-stage incident.
- Partial chain scores 75 (High) and contains no fabricated privilege event.
- Reverse-order event imports still correlate using occurrence time.
- Actor/target identity distinction is verified on the privilege grant.
- Demo reset removes only scenario-managed fixture records and preserves separately imported records.
- Incident status validation and analyst updates pass.

## Frontend

- npm run build: passed (TypeScript check and Vite production bundle).
- Browser walkthrough: load scenario, run all, open the incident, and inspect all rule explanations through the rendered application.
- Responsive overview metrics and UTC labels were corrected after visual inspection.

## Limitations

The tests validate demo contracts and deterministic fixture behavior only. They are not a production readiness, detection efficacy, or customer telemetry assessment. TestClient emits an upstream Starlette/httpx deprecation warning; it does not affect these results.
