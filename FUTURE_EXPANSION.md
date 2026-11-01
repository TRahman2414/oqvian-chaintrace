# Future Expansion and Reliability

## Before any production pilot

- Authentication, authorization, tenant isolation, secrets management, secure configuration, and audit review.
- Durable backup/restore, schema migrations, retention/deletion policies, observability, and load testing.
- Signed/versioned source adapters with replay checkpoints and explicit schema validation.
- Customer-approved identity, asset, and domain baselines; rule tuning with measured false-positive/false-negative performance.
- Privacy review and secure handling of raw evidence.
- Independent security review and operational runbooks.

## Safe extensions

- Read-only Wazuh or other SIEM adapters behind a normalized event contract.
- Optional local model connector for evidence-grounded summaries only, disabled by default and unable to alter deterministic detection.
- Human-approved notification integrations (e.g., a separate automation service).
- Investigation notes, assignment, escalation, and lifecycle audit trail.
- Versioned rule configuration and scenario-based regression tests.

Do not market the current prototype as production-ready or as an autonomous response system.
