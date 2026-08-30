# v1.1 Governance Remediation Record

## Verdict

The v1.0 bundle was not implementation-admissible because the higher-authority decision register contradicted reference choices in the build specification, two dependency graphs disagreed, critical requirements were not machine classified, and the root build specification was outside the integrity manifest. Implementation was paused as required by BLD-009.

The four findings are closed in v1.1. `contracts/remediation-tickets.yaml` is the machine-readable ticket record.

## Closure ledger

| ID | Class | Root cause | Corrective baseline | Closure evidence |
|---|---|---|---|---|
| RMD-001 | Blocker | Reference implementation choices existed only in a lower-authority artifact | DEC-016–DEC-021 approve the choices with profile scope, rationale, owner and packets; OPEN-001–OPEN-005 are closed or narrowed | Decision and open-status validation |
| RMD-002 | Blocker | Prose diagrams encoded incompatible, untyped dependencies | One YAML graph defines `cannot_begin`, `cannot_integrate` and `cannot_pass`; both Markdown projections are generated | Graph schema, acyclicity and no-diff checks |
| RMD-003 | Verification gap | “Critical” had no executable classification or complete mapping | All 135 requirements are registered with criticality, owner, implementation, enforcement, gates, evidence and acceptance | Registry completeness and reference validation |
| RMD-004 | Material risk | Root build spec was not covered by the internal architecture manifest | Internal manifest is regenerated and a bundle manifest covers the build spec plus the complete architecture subtree | Nested checksum verification |

## Signature status

The bundle manifest is intentionally unsigned because no architecture-owner release-signing key was provided. Generating an untrusted key inside the bundle would add no independent authenticity. Integrity is complete; authenticity becomes mandatory when an owner-controlled public trust root is established and does not block contract implementation.

## Admission result

W00 may begin only from an archive for which both manifests validate, both generated graph projections match the canonical YAML, all 135 requirements validate, every referenced gate and packet exists, all remediation tickets are closed, and the v1.0 decision contradiction is absent.
