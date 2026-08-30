# Native Agent ABI

## 1. Purpose

The Agent ABI defines the versioned operations by which a durable agent participates in Habitat. It separates durable identity from disposable cognition and permits direct model drivers, traditional harnesses, deterministic programs and future runtimes to execute the same agent.

## 2. Activation envelope

Every activation receives an immutable envelope containing:

- `activation_id`
- `agent_id`
- `objective_ids`
- `wake_id`
- `abi_version`
- `system_generation_id`
- `capability_activation_set_id`
- `context_bundle_id`
- `capability_grant_ids`
- `isolation_profile_id`
- `resource_lease_id`
- activation deadline
- correlation and trace identifiers

The envelope SHALL contain references and bounded inputs, not ambient host credentials.

## 3. Operations

| Operation | Semantics | Durable result |
|---|---|---|
| `GetActivation` | Retrieve immutable envelope | Access evidence |
| `RequestContext` | Declare a material information or procedure deficiency | ContextRequest and subsequent ContextBundle |
| `InvokeCapability` | Perform a non-consequential read or bounded computation | CapabilityInvocation and Observation |
| `ProposeEffect` | Request a consequential external state change | EffectInstance |
| `ObserveEffect` | Read current effect observation | Observation reference |
| `DelegateObjective` | Create attenuated responsibility for another agent | Delegation and child Objective |
| `SendAgentMessage` | Deliver typed information without transferring hidden authority | Message record |
| `Checkpoint` | Commit activation progress and unresolved state | Checkpoint record |
| `Sleep` | Suspend until a durable wake condition | Sleep condition |
| `DeclareUncertainty` | Record unresolved fact or external outcome | Uncertainty record |
| `ClaimCompletion` | Submit objective completion with evidence | CompletionClaim pending validation |
| `FailActivation` | Terminate activation with classified reason | Terminal activation evidence |

## 4. Disposition contract

An activation response SHALL be one of:

- `CONTEXT_REQUEST`
- `CAPABILITY_INVOCATION`
- `EFFECT_PROPOSAL`
- `DELEGATION`
- `MESSAGE`
- `CHECKPOINT`
- `SLEEP`
- `COMPLETION_CLAIM`
- `ACTIVATION_FAILURE`

An activation MAY emit multiple compatible dispositions in one response, but an effect proposal SHALL have an independent idempotency key and authority evaluation.

## 5. Normative requirements

**ABI-001 — Backend neutrality.** All execution backends SHALL consume and emit the same semantic ABI even when transport encodings differ.

**ABI-002 — No implicit success.** Process exit code zero, model stop, lack of a tool call, or harness completion SHALL NOT imply objective completion.

**ABI-003 — Structured disposition.** Model-facing drivers SHALL validate dispositions against the active schema. Invalid output SHALL be recorded and MAY be retried within the activation budget; it SHALL NOT be interpreted heuristically as an effect.

**ABI-004 — Idempotent commands.** Every state-mutating ABI command SHALL carry `command_id`; duplicate delivery SHALL return the previously committed result.

**ABI-005 — Deadline enforcement.** The execution service SHALL terminate or suspend work that exceeds its lease. Termination SHALL produce a classified observation and preserve committed progress.

**ABI-006 — Cancellation.** Cancellation SHALL be durable, attributable and propagated to cooperative backends. Uncooperative execution SHALL be isolated and terminated without deleting effect uncertainty.

**ABI-007 — Context immutability.** A `ContextBundle` SHALL be immutable. Additional context creates a new bundle linked to the request and predecessor.

**ABI-008 — Capability visibility.** A backend SHALL receive descriptors only for capabilities visible to that activation. Unavailable capability names SHALL NOT be advertised as usable tools.

**ABI-009 — Error semantics.** Errors SHALL identify class, retryability, authority impact, current durable state and safe next action. Free-text errors are supplementary only.

**ABI-010 — No chain-of-thought dependency.** Habitat SHALL NOT require hidden model reasoning as operational evidence. Required rationale SHALL be a concise decision artifact tied to sources and actions.

## 6. Standard error classes

- `INVALID_REQUEST`
- `UNSUPPORTED_ABI_VERSION`
- `IDENTITY_INVALID`
- `AUTHORITY_DENIED`
- `CAPABILITY_UNAVAILABLE`
- `CONTEXT_STALE`
- `LEASE_EXPIRED`
- `RESOURCE_EXHAUSTED`
- `DEPENDENCY_LOST`
- `PROVIDER_FAILED`
- `OUTCOME_UNKNOWN`
- `CONFLICT`
- `CANCELLED`
- `INTERNAL_INVARIANT_VIOLATION`

Each error includes `retry_disposition`: `NEVER`, `SAME_ACTIVATION`, `NEW_ACTIVATION`, `AFTER_DEPENDENCY`, or `RECONCILE_ONLY`.

