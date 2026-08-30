# Authoritative State and Lifecycle

## 1. Ownership

PostgreSQL implements authoritative operational state. Each entity has one owning Habitat service and optimistic concurrency version. All durable commands execute in a transaction that records state transition and evidence metadata together.

## 2. Core entities

| Entity | Owner | Required identity |
|---|---|---|
| Agent | Agent Registry | `agent_id` |
| Objective | Objective Service | `objective_id` |
| Wake | Wake Scheduler | `wake_id` |
| Activation | Activation Service | `activation_id` |
| ContextBundle | Context Service | `context_bundle_id` |
| CapabilityGrant | Authority Service | `grant_id` |
| EffectInstance | Effect Service | `effect_id` |
| Evidence | Evidence Service | `evidence_id` |
| PackageActivationSet | Package Controller | `activation_set_id` |
| SystemGeneration | Generation Controller | `generation_id` |
| ResourceLease | Execution Service | `lease_id` |
| Uncertainty | Objective Service | `uncertainty_id` |

## 3. State machines

### Agent

`REGISTERED → AVAILABLE ↔ SUSPENDED → RETIRED`

Retirement prevents new activations but preserves attribution and evidence.

### Objective

`PROPOSED → ACTIVE ↔ WAITING → SATISFIED | FAILED | CANCELLED`

`SATISFIED` requires an accepted CompletionClaim. `FAILED` means the objective is no longer achievable under declared constraints, not merely that one activation failed.

### Activation

`REQUESTED → LEASED → PREPARING → RUNNING`

From `RUNNING`: `WAITING_CONTEXT`, `WAITING_EFFECT`, `SLEEPING`, `COMPLETED`, `FAILED`, or `CANCELLED`.

Waiting states may return to `REQUESTED` through a new activation; the original activation remains immutable after terminalization.

### Wake

`PENDING → LEASED → ACKNOWLEDGED | RELEASED | EXPIRED`

Wake delivery is at least once. Command idempotency prevents duplicate state transitions.

## 4. Normative requirements

**STA-001 — Transactional transition.** Every authoritative state transition SHALL atomically record previous version, new version, command identity, actor, timestamp and evidence reference.

**STA-002 — No mutable history.** Historical activation, effect attempt, evidence and decision records SHALL be append-only. Corrections SHALL reference the corrected record rather than overwrite it.

**STA-003 — Lease recovery.** On bootstrap, expired leases SHALL be classified before release. Effects in progress SHALL enter reconciliation, not generic retry.

**STA-004 — Wake durability.** A wake SHALL be durably committed before notification. Loss of an in-memory signal SHALL NOT lose responsibility.

**STA-005 — Projection status.** Vector, graph, search and telemetry projections SHALL expose source version and lag. Consumers SHALL be able to fall back to authoritative records.

**STA-006 — Concurrency.** Conflicting commands SHALL fail with `CONFLICT` and current version. Automatic merge is permitted only for explicitly commutative fields.

**STA-007 — Time.** Durable records SHALL store UTC timestamps and monotonic durations where elapsed time matters. Security and lease decisions SHALL reject clocks outside the configured trust bound.

**STA-008 — Retention.** Retention and deletion SHALL preserve legal, safety, attribution and effect-reconciliation obligations. Decommissioning an agent SHALL NOT orphan its effects or evidence.

**STA-009 — Backup consistency.** Backups SHALL capture authoritative state and referenced evidence under a common consistency marker. Restore SHALL verify referential integrity before agents resume.

**STA-010 — Schema migration.** State migrations SHALL declare forward and backward compatibility, interruption behavior, evidence and rollback limits before activation.

## 5. Bootstrap reconciliation order

1. Verify machine and generation identity.
2. Open state read-only and validate schema compatibility.
3. Open evidence store and verify consistency marker.
4. Enable writes only after invariants pass.
5. Expire stale resource and wake leases.
6. Classify interrupted activations.
7. Move nonterminal effects to appropriate reconciliation states.
8. Restore package-provider observations.
9. Create recovery wakes.
10. Confirm system generation only after critical services report coherent state.

## 6. Disaster states

- If authoritative state is unavailable, new effects fail closed.
- If state is readable but not writable, agents may inspect but may not claim completion or create effects.
- If evidence is unavailable, work whose acceptance requires durable evidence remains unconfirmed.
- If referential integrity fails, autonomous operation enters `RECOVERY_REQUIRED`; automated repair may operate only within a dedicated recovery capability set.

