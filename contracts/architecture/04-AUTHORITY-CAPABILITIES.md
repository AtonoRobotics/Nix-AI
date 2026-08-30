# Identity, Authority and Capabilities

## 1. Authority model

Authority is granted, scoped, attenuated, expiring, revocable and attributable. Capability possession authorizes only the operation, target, constraints and time window recorded in the grant.

## 2. Grant fields

Every grant includes:

- grant identity and schema version;
- issuer and subject principals;
- capability definition and version;
- allowed operations;
- target selector;
- constraints and quotas;
- issue, not-before and expiry times;
- delegation depth and attenuation rules;
- activation and system-generation bounds;
- revocation handle;
- policy and evidence references;
- signature or authenticated issuance proof.

## 3. Capability categories

- `ContextCap`
- `ModelCap`
- `ComputeCap`
- `StoreCap`
- `ToolCap`
- `EffectCap`
- `MessageCap`
- `DelegateCap`
- `PackageCap`
- `SystemChangeCap`
- `DeviceCap`
- `RecoveryCap`

## 4. Normative requirements

**AUT-001 — Authentication.** Every command SHALL authenticate the originating machine, service and activation principal before authority evaluation.

**AUT-002 — Complete mediation.** Semantic authorization SHALL occur at every capability invocation and effect admission. Cached decisions SHALL be bounded by grant version and revocation epoch.

**AUT-003 — Attenuation.** Delegation SHALL only reduce operations, targets, duration, quotas, delegation depth or change class. A child grant SHALL never exceed any parent bound.

**AUT-004 — No ambient credentials.** Provider secrets SHALL be held by the provider or secret service and SHALL NOT be exposed to model context, generated code or general activation environment variables.

**AUT-005 — Revocation.** Revocation SHALL prevent new invocation immediately after the configured propagation bound. In-progress effects SHALL be allowed to finish, cancelled or reconciled according to the effect contract; revocation SHALL NOT erase their history.

**AUT-006 — Generation binding.** Grants MAY be bound to a package or system generation. A bound grant SHALL become unusable outside that generation without explicit reissuance.

**AUT-007 — Fail closed.** Authority-service unavailability, stale revocation state or unverifiable identity SHALL deny new consequential operations.

**AUT-009 — Self-authority prohibition.** An agent SHALL NOT issue, widen, approve or activate a grant that increases its own authority unless an independent pre-authorized delegation rule explicitly permits the exact attenuation-preserving operation.

**AUT-010 — Attribution.** Every capability invocation SHALL record subject, issuer chain, activation, objective, target, operation, decision, policy version and result evidence.

## 5. Policy evaluation

Policy evaluation is deterministic. Model recommendations MAY be inputs to an operator or policy-authorized decision but SHALL NOT substitute for capability verification.

Policies may inspect current authoritative state, but each decision records the state version used. If the decision depends on state that changes before effect reservation, admission SHALL be re-evaluated transactionally.

## 6. Human authority

Human approval is a capability issuance or effect-admission event, not a special side channel. Approvals are used only when explicit policy requires human authority. Routine safe actions SHALL use bounded standing grants rather than repeated approval.
