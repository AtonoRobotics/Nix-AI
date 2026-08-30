# Plan: Complete and qualify Nix AI V2

Depth: tree 4   Mode: orchestrated
Budget note: multi-subsystem production completion with live image qualification

## Contract

- Interfaces: preserve all public `habitat-*` names and the immutable V2.0.1 contract; Agent ABI remains protobuf/tonic over authenticated UDS; PostgreSQL is operational truth and evidence bytes are digest addressed.
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
