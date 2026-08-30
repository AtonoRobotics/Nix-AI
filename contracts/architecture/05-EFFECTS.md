# Durable Effect Contract

## 1. Definition

An effect is an operation that may change state outside the authoritative Habitat transaction or produce externally consequential output. Reads that trigger billing, disclosure or irreversible computation may also be classified as effects.

## 2. State machine

```text
PROPOSED
├── REJECTED
└── RESERVED
    └── EXECUTING
        ├── OBSERVED_SUCCEEDED
        ├── OBSERVED_FAILED
        └── OUTCOME_UNKNOWN
            └── RECONCILING
                └── RESOLVED_SUCCEEDED | RESOLVED_FAILED | MANUAL_AUTHORITY_REQUIRED
```

Compensation is a new EffectInstance linked by `compensates_effect_id`. It SHALL NOT mutate the original effect into a state implying the original action never occurred.

## 3. Proposal fields

- actor, activation and objective;
- capability and operation;
- target identity;
- canonical parameters or content digest;
- expected precondition and result;
- idempotency key;
- consequence class;
- evidence requirements;
- expiry and timeout;
- compensation reference when available.

## 4. Normative requirements

**EFF-001 — Admission transaction.** Authority evaluation, precondition validation and idempotency reservation SHALL commit atomically before provider execution.

**EFF-002 — Stable idempotency.** An idempotency key SHALL identify semantic intent, not an individual transport attempt. Duplicate proposals return the existing effect.

**EFF-003 — No blind retry.** Timeout, disconnect or executor loss after dispatch SHALL produce `OUTCOME_UNKNOWN` unless independent evidence proves an outcome. Such effects SHALL enter reconciliation and SHALL NOT be retried as new effects.

**EFF-004 — Attempt evidence.** Every provider attempt SHALL record request digest, dispatch time, provider identity, transport identifier, response, observation source and terminal classification.

**EFF-005 — Independent observation.** Success SHALL require the operation-specific evidence contract. A provider acknowledgement alone is sufficient only when the capability contract declares it authoritative.

**EFF-006 — Reconciliation.** Each effect provider SHALL declare whether it supports lookup by idempotency key, external identifier, target state, or no reconciliation. Lack of reconciliation support SHALL constrain permitted consequence classes.

**EFF-007 — Cancellation.** Cancellation before dispatch terminates the reservation. Cancellation after dispatch does not establish failure; the outcome remains governed by observation.

**EFF-008 — Compensation.** Compensation SHALL have its own authority, admission, execution, observation and evidence. Compensation failure SHALL not erase original success.

**EFF-009 — Ordering.** Ordering requirements SHALL be declared per target or effect group. Habitat SHALL not infer global ordering from timestamps alone.

**EFF-010 — Recovery.** Bootstrap SHALL classify every nonterminal effect before dependent objectives resume.

**EFF-012 — Completion coupling.** An objective SHALL NOT be marked satisfied while a required effect remains nonterminal or outcome-unknown.

## 5. Consequence classes

| Class | Examples | Minimum property |
|---|---|---|
| E0 | Pure bounded computation | Invocation evidence |
| E1 | Reversible local state | Transaction or verified rollback |
| E2 | External communication or record mutation | Stable idempotency plus reconciliation |
| E3 | Financial, legal, production activation | Independent outcome evidence and stronger authority |
| E4 | Irreversible external consequence | Independent authorization, bounded validity and observed external state |

Providers SHALL NOT advertise a consequence class they cannot reconcile and evidence.
