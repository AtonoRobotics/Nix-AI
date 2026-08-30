# Traceability Ledger

`contracts/requirements.yaml` is the executable, complete traceability registry for all 135 normative requirements. The tables below are human-readable objective and invariant summaries; they do not replace the registry.

## 1. Objective mapping

| Objective | Requirements | Implementation owner | Required evidence |
|---|---|---|---|
| Autonomous operation without login | ARC-001, STA-003, GEN-004 | Bootstrap, Scheduler | V-BOOT, V-DISASTER |
| Durable agent continuity | ARC-002, ABI-001, STA-001 | Agent/Activation services | V-BACKEND, V-WAKE |
| Frontier-model reasoning with correct context | CTX-001–012, ABI-007 | Context service, Model service | V-CONTEXT, V-CONTEXT-FAULT |
| Governed real-world work | AUT-001–010, EFF-001–012 | Authority, Effect service | V-CAPABILITY, V-EFFECT |
| Hot-loadable modular capability | PKG-001–010, ARC-006 | Package controller | V-PACKAGE |
| Autonomous self-healing | STA-003, EFF-010, OBS-002 | Bootstrap, recovery agents | V-DISASTER, integrated scenario |
| Autonomous self-improvement | GEN-002, GEN-009–010, SEC-007 | Generation controller | V-SELF-CHANGE |
| Brand/domain neutrality | ARC-010, HWP-001–008 | ABI and profile owners | Conformance on all reference profiles |
| System rollback and recovery | GEN-003–009 | Generation controller | V-ROLLBACK |

## 2. Invariant mapping

| Invariant | Enforcement | Failure behavior | Evidence |
|---|---|---|---|
| Agent continuity | Durable Agent/Objective records | New activation recovers work | State transition history |
| No ambient authority | Capability broker plus Linux isolation | Deny/fail closed | Decision and negative-test evidence |
| Context on demand | ContextRequest ABI and broker | Explicit missing/unknown context | Bundle provenance and request chain |
| Effects are durable | Reservation and attempt ledger | Outcome unknown and reconciliation | Effect history and external observation |
| Transactional truth | PostgreSQL command transactions | Conflict/read-only recovery | Commit and restore tests |
| Harness independence | Backend-neutral ABI | Replace/retry activation | Cross-backend conformance |
| Pinned composition | ActivationSet identity in envelope | Degrade without silent rebind | Activation-set evidence |
| Independent evidence | Separate evidence authority | Completion remains unconfirmed | Evaluator and digest records |
| Bounded self-change | Classed authority and separated roles | Reject/rollback/quarantine | Candidate and activation chain |

## 3. Gate coverage

All critical requirements are covered by at least one gate in `12-VERIFICATION-MATRIX.md`. The contract validator SHALL check identifier existence and duplicate identifiers; semantic gate completeness is reviewed at each release.

## 4. Residual risks

| Risk | Current treatment | Release condition |
|---|---|---|
| Nix/vendor BSP incompatibility | Hardware profiles permit vendor kernels and compatibility capsules | Reference profile boots and passes driver matrix |
| Model fails to recognize context need | Persistent metacognitive rule plus evidence-trigger hints | Context-fault and repeated-failure tests pass |
| External provider lacks reconciliation | Consequence-class restriction | Provider cannot advertise unsupported class |
| Linux isolation bypass | Layered namespaces/LSM/microVM and negative tests | Applicable escape suite passes |
| Self-change evaluator capture | Authority separation and protected evidence | V-SELF-CHANGE adversarial cases pass |
