# Evidence, Observability and SLOs

## 1. Evidence model

Evidence is an immutable reference to an observation, artifact, provider record, measurement or signed decision. Evidence records include producer, subject, time, source version, content digest, retention class and access policy.

Telemetry assists diagnosis. Telemetry alone is not acceptance evidence unless the governing contract names the measurement and integrity source.

## 2. Required signals

- current system generation and boot confirmation;
- agent and objective state;
- pending and expired wakes;
- activation state, backend and resource use;
- context bundle composition, omissions and freshness;
- capability decisions and revocation epoch;
- effect state, attempts and reconciliation age;
- provider health and activation-set availability;
- evidence-store integrity and lag;
- recovery and rollback actions;
- security and physical-safety observations.

## 3. Normative requirements

**OBS-001 — Correlation.** Every activation, capability invocation, effect attempt and evidence record SHALL carry trace, agent, objective and generation correlation.

**OBS-002 — Cause visibility.** Operational state SHALL expose current cause, consequence, authority and safe next action for degraded or failed conditions.

**OBS-003 — No success by silence.** Missing telemetry, missing provider response or absent error SHALL NOT be interpreted as success.

**OBS-004 — Protected audit.** Critical authority and effect audit records SHALL be outside ordinary activation mutation authority.

**OBS-005 — Model observability.** Provider, model identity, request digest, context bundle, tool schema version, latency, usage and normalized disposition SHALL be recorded without requiring private chain-of-thought.

**OBS-006 — SLO evidence.** SLO calculations SHALL be derived from durable state transitions or protected observations, not ephemeral counters alone.

## 4. Baseline SLOs

These are reference acceptance thresholds and may be tightened by a hardware profile:

| Measure | Threshold |
|---|---|
| Durable wake loss | 0 under tested single-fault scenarios |
| Duplicate committed effect from duplicate command | 0 |
| Unauthorized capability success | 0 |
| Stale physical command accepted | 0 |
| Boot rollback after unconfirmed generation | 100% within profile deadline |
| Agent continuity across supported backend replacement | 100% in conformance cases |
| Authority decision attribution | 100% |
| Critical effect records with evidence or explicit unknown | 100% |
| Recovery point for authoritative committed state | 0 committed transactions lost under declared storage fault model |

Latency targets are hardware- and provider-specific. Correctness invariants SHALL NOT be weakened to satisfy latency.

## 5. Health semantics

Health has four levels:

- `COHERENT`: invariants satisfied and critical services available.
- `DEGRADED`: operation continues within explicitly reduced capabilities.
- `RECOVERY`: autonomous recovery is active; new consequential work may be restricted.
- `UNSAFE_OR_UNKNOWN`: required authority, evidence or physical state is unavailable; relevant operations fail closed.

