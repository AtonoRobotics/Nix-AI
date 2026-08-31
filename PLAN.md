# Plan: Complete and qualify Nix AI V2

Depth: tree 4   Mode: orchestrated
Budget note: multi-subsystem production completion with live image qualification

## Contract

- Interfaces: preserve all public `habitat-*` names and the immutable V2.0.1 contract; Agent ABI remains protobuf/tonic over authenticated UDS; PostgreSQL is operational truth and evidence bytes are digest addressed through the Garage S3 boundary.
- Data ownership: baseline/audit owns `.gitignore`, audit tools, and audit tests; ABI owns `contracts/proto/nix_ai_agent_v2.proto` and `crates/habitat-abi`; packages/change owns `crates/habitat-packages` and its tests; runtime owns runtime coordinator sources and `nix/modules`; qualification owns `tools/qualification*`, `tools/qualify_v2_*`, and release tests. Shared manifests are integrated only by the driver.
- Naming and conventions: Rust is rustfmt-clean and strict-clippy-clean; Python evidence uses canonical sorted JSON; failures are fail-closed and use typed error codes; no caller-supplied pass booleans.

## Tree

- 1 Complete and qualify Nix AI V2
  - 1.1 Trust boundaries and admission .......... gates/node-1.1.md
    - 1.1.1 ABI identity and durable replay ........ gates/leaf-abi.md
    - 1.1.2 Content-bound package/change admission . gates/leaf-package-change.md
  - 1.2 Autonomous operation and proof .......... gates/node-1.2.md
    - 1.2.1 Bootable runtime service graph .......... gates/leaf-runtime.md
    - 1.2.2 Live qualification and evidence .......... gates/leaf-qualification.md
  - 1.3 Governance and final integration ........ gates/node-1.3.md
    - 1.3.1 Audit classification and tracking ........ gates/leaf-audit-tracking.md
    - 1.3.2 Full clean acceptance matrix .............. gates/leaf-final.md

## Status log

- 2026-08-30 plan written; public interfaces and file ownership fixed
- 2026-08-30 baseline preserved at backup/pre-v2-completion-20260830-2042 and stash@{0}; main aligned to da3bc5d
- 2026-08-30 generated-output and Rust formatting commits completed
- 2026-08-30 ABI, package/change, and runtime leaves dispatched
- 2026-08-30 tracker parent #31 and child issues #32-#36 created and linked
- 2026-08-30 ABI leaf verified 3/3 and committed as 706165d
- 2026-08-30 package/change leaf verified 3/3 and committed as 6c56146
- 2026-08-30 runtime leaf verified 4/4, parent integration verified, committed as 7a3eb41
- 2026-08-30 qualification verifier leaf verified 3/3 and committed as 824ba32
- 2026-08-30 current-core audit leaf self-verified; final regeneration awaits live-runner completion
- 2026-08-30 exact committed tree: 91 Python tests pass with 11 service-configuration skips; Rust fmt, strict clippy, and workspace tests pass
- 2026-08-30 production acceptance abandoned honestly: nixpkgs rejects abandoned vulnerable MinIO, preventing the fresh QEMU/release run; runtime PostgreSQL/MinIO coordinator persistence remains incomplete

## V2 gap-remediation contract

Depth: tree 4   Mode: orchestrated

- Interfaces: preserve the immutable V2.0.1 contract, public `habitat-*` names, the protobuf/tonic ABI, and the existing operator-facing runtime request surface. Internal authority and effect requests must be structured, identity-bound, versioned, and fail closed.
- Data ownership: `habitat-authority` exclusively owns grants, revocations, and decisions; `habitat-effects` exclusively owns reservations, attempts, observations, and reconciliation; PostgreSQL owns transactional lifecycle and command truth; the supported S3-compatible store owns digest-addressed evidence bytes.
- Packet ownership: runtime/trust owns `crates/habitat-runtime`, `crates/habitat-authority`, `crates/habitat-effects`, `src/habitat_state`, `nix/modules/habitat-runtime.nix`, runtime-focused tests, and all runtime/deployment portions of `flake.nix`; governed change owns `crates/habitat-packages`, `tools/qualify_v2_change.py`, and its focused tests/evidence schema; qualification owns the remaining `tools/qualif*`, qualification tests, and the V2 drift checker; final integration owns release evidence, public docs, and these ledgers, and does not change `flake.nix` unless a defect is returned to the runtime owner as a separately reviewed corrective packet.
- Conventions: Rust remains rustfmt- and strict-clippy-clean; Python remains canonical, typed at trust boundaries, and fail closed; no pass result may be inferred from process exit, test names, source strings, or caller-supplied booleans.
- Review rule: every packet is reviewed by a fresh agent after implementation. A packet may be committed and pushed only when the reviewer records `APPROVED`, reports no unresolved bugs or V2 drift, and the driver independently reruns its gates.
- Exact-tree sequence: packet ledgers and review records are completed from a preliminary full acceptance run, then all non-evidence sources are committed and frozen. Qualification is rerun from that frozen commit, after which only `evidence/` changes may be committed. Exact-tree verification and push occur without any further non-evidence edit; the pushed SHA and verification result are recorded under excluded `evidence/remediation/` so bookkeeping cannot stale the release digest.

## V2 gap-remediation tree

- 2 Close every V2 review and release gap .......... gates/remediation-root.md
  - 2.1 Runtime trust and durable ownership ........ gates/remediation-runtime.md
  - 2.2 Governed-change binding .................... gates/remediation-change.md
  - 2.3 Live qualification evidence ................ gates/remediation-qualification.md
  - 2.4 Exact-tree release and drift closure ........ gates/remediation-release.md

## V2 gap-remediation status log

- 2026-08-30 remediation plan written; interfaces, ownership, packet gates, independent review, commit, and push policy fixed
- 2026-08-30 Garage approved in ADR 0001 as the canonical embedded S3 backend because no admissible MinIO version is available; the prior combined Garage/state/QEMU experiment remains quarantined in the recovery stash and will not be restored wholesale
- 2026-08-30 requalification reopened: migrate Garage, persistence wiring, and strict QEMU behavior as isolated reviewed commits; no prior MinIO abandonment is treated as current acceptance evidence
