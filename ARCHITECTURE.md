# Architecture

## Local components

- React + TypeScript + Vite browser interface.
- FastAPI application with Pydantic request/response contracts.
- SQLite database for organizations, identities, assets, normalized events, rule hits, incidents, evidence links, notes, and audit events.
- Deterministic correlation engine; no model dependency.
- Local scenario fixtures that use the same ingestion and correlation path as API events.

The first release is a modular monolith: simple to run on a laptop and easy to replace adapters later. Bind to `127.0.0.1` by default. No external telemetry or notifications are sent.

## Data path

`scenario fixture → validated normalized event → idempotent local persistence → deterministic R001–R006 evaluation → evidence-linked incident upsert → dashboard API → analyst review`

Event time drives correlation; ingestion time remains available for audit. Event IDs are stable source identifiers. Actor and target identity fields remain distinct. Correlation always scopes to one organization and investigated identity.

## Optional future model seam

If a locally hosted model is integrated later, use a separate provider interface and an explicit health/config page. It can summarize evidence or suggest questions, with source citations and human review. It cannot set rule matches, alter scores, resolve incidents, or execute actions. The core remains functional when no model is configured.

## Local security boundaries

- Synthetic demo records only.
- No shell execution, remote collection, automatic containment, or delete action.
- Do not expose the dev server to a network; no authentication is implemented for this demo.
- Reset is limited to demo state in the local database.
- Validate and bound API inputs; keep raw evidence JSON as inert data.
