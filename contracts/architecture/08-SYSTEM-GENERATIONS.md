# System Generation and Rollback Contract

## 1. Construction model

Nix is the reference construction mechanism. Habitat OS generations are immutable closures containing the kernel profile, boot artifacts, low-level services, Habitat services, policy versions and recovery compatibility metadata.

Operational state is stored separately and is never rolled back merely because software is rolled back.

## 2. Generation state machine

`CANDIDATE → BUILT → VERIFIED → SIGNED → STAGED → BOOT_PENDING → ACTIVE_UNCONFIRMED → CONFIRMED`

Failure states: `REJECTED`, `BOOT_FAILED`, `ROLLED_BACK`, `QUARANTINED`, `RECOVERY_REQUIRED`.

## 3. Normative requirements

**GEN-001 — Reproducible closure.** Every generation SHALL be constructible from locked source and package inputs and SHALL produce a complete manifest of content digests.

**GEN-002 — Signature separation.** The actor producing a candidate SHALL NOT alone supply the trusted signature authorizing activation.

**GEN-003 — Boot independence.** The previous confirmed generation and recovery generation SHALL remain bootable until the new generation is confirmed and retention policy permits removal.

**GEN-004 — Confirmation.** A generation SHALL be confirmed only after machine identity, authoritative state, evidence access, authority service, execution isolation and effect reconciliation reach coherent health.

**GEN-005 — Watchdog rollback.** Absence of confirmation within the profile-specific deadline SHALL cause automatic rollback without human action.

**GEN-006 — Migration gate.** A generation requiring state migration SHALL prove migration interruption safety and backward compatibility or provide a separately verified restore path before staging.

**GEN-007 — Driver matrix.** Kernel, firmware, GPU driver, userspace driver injection and capability packages SHALL be qualified as one hardware-profile matrix.

**GEN-008 — Measured boot.** Supported profiles SHALL measure boot artifacts and Habitat generation identity into the TPM or equivalent root of trust.

**GEN-009 — Recovery protection.** Normal agents and candidate generations SHALL not possess write authority over the recovery generation, signing trust root or independent boot evidence.

**GEN-010 — Self-change.** Authorized agents MAY autonomously propose, build, evaluate and request activation of generations. Promotion SHALL respect class-based separation of duties in `00-GOVERNANCE.md`.

## 4. Activation evidence

Required evidence includes:

- closure and manifest digest;
- source lock digest;
- build provenance and SBOM;
- schema and contract compatibility report;
- VM boot and rollback test;
- hardware-profile test where applicable;
- security scan result;
- live Habitat bootstrap evidence;
- effect-recovery conformance result;
- signer and activation decision.

## 5. Mutable paths

The reference layout separates:

- immutable `/nix/store` closures;
- signed `/boot` generations;
- authoritative `/var/lib/habitat` state;
- capability-owned `/srv/habitat` data;
- disposable execution storage;
- protected recovery media.

Unmanaged writes outside declared mutable paths are conformance failures.

