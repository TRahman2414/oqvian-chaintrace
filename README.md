# OQVIAN CHAINTRACE

**Connect the signals. Reveal the attack.**

OQVIAN CHAINTRACE is a local-first, synthetic-data demonstration of explainable security event correlation. It turns related identity, mailbox, and file activity into an evidence-linked investigation timeline. It is a prototype, not a SIEM, SOAR, or production security service.

## What the demo shows

- Deterministic rules R001–R006; no language model decides whether events are related.
- A five-stage fictional incident, an unrelated-activity comparison, and a partial-chain case.
- Evidence links, a transparent demo score, and incident lifecycle actions.
- A local SQLite database and API, with a browser dashboard.
- Repeatable scenario playback and reset.

All names, addresses, events, and assets are fictional. Do not load customer telemetry into this demo.

## Run locally

Requirements: Python 3.11+, uv, Node.js 20+, and npm. Run ./scripts/bootstrap.sh once, then ./scripts/start-dev.sh. Open http://127.0.0.1:4174; API health is at http://127.0.0.1:8001/api/health. Both services bind to loopback by default. Use ./scripts/reset-demo.sh to reset seeded scenario data.

See [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) for the guided presentation.

## Product and engineering notes

- [Master plan](MASTER_PLAN.md)
- [Product context](docs/PRODUCT_CONTEXT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Correlation rules](docs/CORRELATION_RULES.md)
- [Demo script](docs/DEMO_SCRIPT.md)
- [Known limits and future work](docs/FUTURE_EXPANSION.md)
- [Test report](docs/TEST_REPORT.md)
- [GitHub repository](https://github.com/TRahman2414/oqvian-chaintrace) (private while the demo is under construction)

## Safety and limits

CHAINTRACE only analyzes synthetic structured records. It does not connect to Wazuh, cloud identity, email, endpoints, or networks; it does not take remediation actions. Scores are scenario heuristics, not probabilities. Human review is required before acting on any real security alert.
