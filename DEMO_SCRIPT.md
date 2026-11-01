# Local Demo Script

## Start

Prerequisites: Python 3.11+, uv, Node.js 20+, and npm. The app is designed for loopback only and uses fictional records.

1. Run ./scripts/bootstrap.sh once to install local dependencies.
2. Run ./scripts/start-dev.sh to start the API and Vite UI.
3. Open the local frontend URL. Confirm API status reports local/demo mode.

## Presenter flow

1. Open Overview and point out counts read from the backend, the active synthetic tenant, and the deterministic-correlation indicator.
2. Open Demo Control and load the full suspicious sequence.
3. Step through the failed-login burst, unfamiliar successful sign-in, privilege grant, external forwarding, and large download. Explain that each record is fictional and individually not proof of compromise.
4. Run correlation. Open the generated incident and follow its chronological evidence rail. Inspect the rule explanation, identity target/actor distinction, score contributions, and recommendations.
5. Load the legitimate-activity comparison. Show that identities remain separated and the full chain is not fabricated.
6. Load the partial chain. Show the reduced score and visibly absent privilege stage.
7. Reset the seeded demo and confirm a clean state.

## Limitations to say aloud

This demo does not ingest live logs, make production risk predictions, contact users, or take remediation actions. A real deployment would require identity/access controls, customer-specific integrations, retention policies, operational monitoring, and independent validation.
