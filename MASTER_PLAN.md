# OQVIAN CHAINTRACE — Master Plan

## Goal

Deliver a small, locally runnable showcase that proves the core product idea: deterministic, explainable correlation can turn fragmented security events into a reviewable potential attack chain. The project is a demo for discussion and customization; it is not a production security product.

## Product boundary

The current build uses synthetic events only, local SQLite, one FastAPI process, and a browser UI. No cloud dependencies, customer data, live collectors, automated response, or model dependency. A future model may provide optional analyst assistance after the core deterministic API is stable; it must never create or suppress correlations.

## Initial vertical slice

1. Define normalized event / incident contracts and synthetic scenario fixtures.
2. Implement R001–R006 as deterministic, replay-safe correlation over event timestamps.
3. Persist original evidence, rule hits, incident state, and audit entries locally.
4. Prove full-chain, partial-chain, benign separation, duplicates, and out-of-order ingestion.
5. Build a distinctive investigation-first UI connected to the API.
6. Add scenario playback, reset, operator workflow, local start steps, and known limits.
7. Review reliability, accessibility, and security boundaries; package the reproducible demo.

## Design concept

Use a restrained operations-console visual language rather than a stock cyber dashboard: near-black slate surfaces, warm paper-white text, a muted signal-orange accent, and a vivid mint evidence color. The signature interaction is an **evidence rail**: each incident opens into a chronological, selectable chain with rule labels and a right-hand explanation panel. Avoid neon/glow, decorative terminal streams, and fake live telemetry. Color is never the only severity indicator; labels and icons accompany it. The UI remains responsive and keyboard-operable.

## Reliability improvements over the brief

- Idempotent ingestion through a unique `(organization_id, source_type, source_event_id)` key.
- UTC-normalized event and ingestion timestamps; out-of-order events evaluated by occurrence time.
- Tenant and investigated-identity scoping on every correlation; administrator actor is kept distinct from target identity.
- Evidence-preserving incident upserts with deterministic correlation keys and stable linked event IDs.
- Explicit `unfamiliar_source` context; never infer unfamiliarity from an IP or geography alone.
- Rule explanations and score contributions stored in the response; confidence is separate from severity.
- Reset is restricted to the seeded demo organization and writes a local audit entry.
- Health/status endpoints, clear validation errors, bounded list pagination, and tests for replay and cross-identity isolation.
- Safe-by-default local bind, synthetic-only fixture data, and no command execution or automated remediation.

## Work slices and acceptance

### Slice A — correlation core

Implement schema, fixtures, deterministic engine, storage, API endpoints for scenario control / events / incidents, and tests. Acceptance: full scenario produces exactly one evidence-linked critical incident; rerun creates no duplicate; benign scenario creates no full-chain incident; partial scenario has lower score and no fabricated privilege event.

### Slice B — investigation UI

Implement overview, event stream, chain timeline, incident details, rules, and demo controller. Acceptance: key information comes from API state; event selection reveals source evidence; scenario step/run/reset controls work; empty, loading, and error states are clear.

### Slice C — packaging

Document local setup and guided demo, record test results and limits, inspect dependency/license/security posture, and publish an initial reviewable GitHub change if repository access permits.

## Not in this demo

Production authentication, real SIEM connectors, collection agents, cloud integrations, malware execution, packet capture, auto-blocking, account suspension, external notifications, model fine-tuning, high availability, or validated production risk scoring.
