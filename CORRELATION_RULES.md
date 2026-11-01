# Correlation Rules

Rules are deterministic and evaluated against UTC occurrence timestamps within one organization and primary identity. A signal describes observed synthetic activity; it does not prove compromise.

| ID | Stage | Required condition | Score |
|---|---|---|---:|
| R001 | Authentication failure burst | 6+ failures for one identity in 5 minutes | 15 |
| R002 | Unusual successful authentication | R001 plus successful sign-in within 10 minutes, explicitly marked unfamiliar by fixture context | 20 |
| R003 | Privilege change | R002 plus privilege grant targeting the same investigated identity within 20 minutes of the sign-in | 25 |
| R004 | External forwarding | R002 plus forwarding for same identity to a domain outside configured approved domains within 30 minutes | 20 |
| R005 | Large download | R002 plus same identity downloads at least 250 MB within 30 minutes | 20 |
| R006 | Multi-stage chain | R002 and at least one subsequent high-risk action, three distinct supported stages, within 45 minutes | derived |

Each stage contributes once, capped at 100. Severity bands are Low 0–39, Medium 40–59, High 60–79, Critical 80–100. The numeric score is a demonstration heuristic, not a calibrated probability. Confidence is a separate qualitative field.

R004 compares the destination domain explicitly against an approved-domain list. R003 uses `target_identity_id` for the affected account and preserves `actor_identity_id` as the administrator. Duplicate event IDs do not add score or evidence. Out-of-order arrival triggers a deterministic reevaluation by event time. Relatedness is never inferred from time proximity alone.
