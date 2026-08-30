# Context Compilation and Cognitive Page Faults

## 1. Purpose

Habitat supplies each activation with the smallest sufficient, provenance-bearing working reality. The model supplies general reasoning. Habitat supplies current state, relevant history, affordances, constraints and ways to request what is missing.

## 2. Context bundle

A bundle contains versioned sections:

- agent identity and role;
- active objective and completion contract;
- authoritative current state;
- changes since predecessor bundle;
- relevant attempts and observations;
- unresolved uncertainty and contradictions;
- visible capability descriptors;
- applicable skill descriptors;
- constraints and consequence notices;
- evidence references;
- provenance and freshness metadata;
- context budget and omitted-section summary.

## 3. Semantic context request

Every request includes:

- `deficiency`: what is missing;
- `materiality`: why it changes the next decision;
- `requested_kind`: fact, evidence, procedure, capability documentation, precedent or fresh observation;
- `resolution_condition`: what becomes decidable;
- optional source and freshness constraints.

The agent does not need to know the identifier of a skill or data source.

## 4. Normative requirements

**CTX-001 — Provenance.** Every fact or summary used as operational context SHALL identify source, source version, observation time and compilation time.

**CTX-002 — Truth separation.** Context SHALL distinguish authoritative state, raw observation, interpreted claim, model suggestion and unresolved uncertainty.

**CTX-003 — Freshness.** Context-sensitive facts SHALL carry freshness requirements. Stale data SHALL be labelled and SHALL trigger refresh when required by the decision.

**CTX-004 — Immutable bundles.** Context bundles are immutable and content-addressed. Augmentation creates a successor linked to the request it resolves.

**CTX-005 — Descriptor-first skills.** Skill applicability descriptors MAY be injected broadly; complete skill procedures SHALL be injected only when selected by the agent, a context policy or a deterministic safety requirement.

**CTX-006 — Applicability.** Every skill SHALL declare `use_when`, `do_not_use_when`, inputs, outputs and termination conditions. Skills SHALL NOT require ceremonial execution when direct action is justified.

**CTX-007 — Agent-recognized need.** The ABI SHALL permit an agent to request context semantically without naming a stored skill, table or implementation.

**CTX-008 — Trigger hints.** Habitat MAY inject concise hints after repeated failure, contradiction, stale evidence, uncertain effect, irreversible proposal or unsupported completion claim. A hint SHALL identify the observed condition and SHALL NOT fabricate a cause.

**CTX-009 — Bounded recursion.** A context request SHALL state materiality and resolution condition. Requests that cannot affect the next decision MAY be rejected as non-material.

**CTX-010 — Source access.** When summarization could remove consequential detail, the activation SHALL have a bounded capability to inspect original evidence.

**CTX-011 — Injection defense.** Untrusted content SHALL be labelled as data, isolated from system instructions and prevented from granting capabilities or changing policy.

**CTX-012 — No silent omission.** If required context cannot fit or cannot be retrieved, the bundle SHALL state the omission and resulting uncertainty.

## 5. Context-policy behavior tree

The standard context policy evaluates epistemic readiness:

```text
Can current context justify action?
├── yes: act
└── no: identify deficiency
    ├── missing fact/evidence: retrieve or observe
    ├── missing method: load applicable skill
    ├── unexplained consequential failure: load diagnosis procedure and evidence
    ├── uncertain completion: load verification procedure and outcome evidence
    └── missing authority: stop; context cannot create authority
```

This policy selects context. It does not dictate the domain solution.

## 6. Memory

- Operational state is authoritative.
- Episodic history is append-only event and evidence history.
- Semantic memory is a derived retrieval index with provenance.
- Procedural memory is a versioned skill package.
- Working memory is the immutable ContextBundle.

No private harness transcript may become the only copy of information required for agent continuity.

