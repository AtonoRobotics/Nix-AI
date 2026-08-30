# Verification and Acceptance Matrix

## 1. Verification rule

Structural validation is necessary but insufficient. Every critical claim requires live behavior under nominal, boundary, failure, recovery and adversarial conditions.

## 2. Required gates

| Gate | Required evidence | Pass condition |
|---|---|---|
| V-CONTRACT | Schema, link, ID, decision, graph, traceability and layered checksum reports | All authoritative registries validate; generated projections match; no unresolved decision or integrity error exists |
| V-BOOT | QEMU and hardware boot logs, generation identity, state reconciliation | Habitat resumes without login and confirms only after coherence |
| V-ROLLBACK | Deliberately defective generation | Automatic return to previous confirmed generation |
| V-IDENTITY | Signed command and negative authentication cases | No command accepted under wrong or unverifiable principal |
| V-CAPABILITY | Positive, denied, expired, revoked and delegated invocations | No authority widening or bypass |
| V-ISOLATION | Host, cross-workspace, network, device and secret escape attempts | No prohibited access |
| V-WAKE | Crash/restart during enqueue, lease and acknowledgement | No lost durable wake; duplicates harmless |
| V-CONTEXT | Stale, contradictory, missing, injected and oversized sources | Provenance preserved; omissions and uncertainty explicit |
| V-CONTEXT-FAULT | Agent semantically requests evidence/procedure without identifier | Correct applicable context loaded and linked |
| V-EFFECT | Duplicate proposal, timeout, disconnect, provider crash | One semantic effect; ambiguity reconciled, never blind retry |
| V-COMPENSATION | Successful original effect and failing compensation | Histories remain distinct and truthful |
| V-BACKEND | Same agent/objective across direct model and two harnesses | Identity, grants, effects and completion unchanged |
| V-PACKAGE | Install, activate, replace, drain, revoke and rollback | Work remains pinned; no silent rebind |
| V-SELF-CHANGE | Agent proposes defective and valid changes | Defective rejected/rolled back; valid bounded change promoted with independent evidence |
| V-DISASTER | Database restart, evidence-store loss, host power loss | Declared fail-closed/degraded semantics and recovery invariants observed |

## 3. Fault injection points

Tests SHALL interrupt execution:

- before and after every authoritative commit;
- before and after effect dispatch;
- after provider action but before acknowledgement;
- during context retrieval;
- during package activation and drain;
- during state migration;
- before boot confirmation;
- during evidence upload;
- during capability revocation propagation.

## 4. Acceptance requirements

**VER-001 — Contract coverage.** Every critical normative requirement SHALL map to at least one automated test or documented inspection whose result is stored as evidence.

**VER-002 — Negative proof.** Authority, isolation, injection and safety requirements SHALL include negative attempts that would succeed if the boundary were absent.

**VER-003 — Live behavior.** Capability packages and system generations SHALL be tested through their externally meaningful operation, not solely through mocks, imports, compilation or process health.

**VER-004 — Reproducibility.** A release candidate SHALL reproduce its system and package digests from locked inputs or document and accept every nondeterministic input.

**VER-005 — Independent evaluator.** The evaluated activation SHALL not control evaluator configuration, evidence store or acceptance threshold.

**VER-006 — No open blockers.** Release is prohibited while any critical test is absent, outcome-unknown without containment, or governing contract contradicts its schema.

## 5. Reference autonomous-work scenario

The integrated release shall demonstrate:

1. An objective is created while no human session is active.
2. An observation wakes the responsible agent.
3. The agent detects insufficient causal context and requests it semantically.
4. Habitat injects evidence and an applicable diagnostic procedure.
5. The agent proposes a bounded repair.
6. The repair executes in isolation.
7. Independent live verification proves the outcome.
8. A consequential activation effect is admitted and recorded.
9. The host is interrupted and recovers without duplicate effect.
10. The objective resumes and completes with evidence.

This scenario does not replace the individual gates.
