# Governance and Source of Truth

## 1. Authority order

When artifacts conflict, authority descends in this order:

1. Explicit user decision recorded in `14-DECISION-REGISTER.md`.
2. Governing invariant in `README.md`.
3. Normative requirement in numbered specifications.
4. Machine-readable schema or Protobuf definition.
5. Verification and implementation artifacts.
6. Non-normative examples and rationale.

Schema and prose conflicts are release blockers. Neither silently overrides the other.

`contracts/requirements.yaml` is authoritative for requirement criticality, packet ownership, implementation, enforcement, gate, evidence and acceptance mappings. It does not override normative requirement semantics. `contracts/work-packets.yaml` is authoritative for W00–W15 dependency strength and exit evidence. Markdown projections of either registry are generated views.

## 2. Scope

### In scope

- Bootable Habitat OS built on a Linux kernel.
- Agent-native userspace and ABI.
- Durable agents, objectives, activations, context, capabilities and effects.
- Native and compatibility execution backends.
- Governed self-change, system generations and rollback.
- Server, workstation, edge, simulation and physical-AI hardware profiles.
- Autonomous operation without an active human session.

### Out of scope

- Reimplementing the Linux kernel.
- Reimplementing real-time motor control or hardware safety controllers.
- Embedding domain-specific business behavior in the Habitat core.
- Requiring one model, harness, GPU brand, robot brand, cloud or connector.
- Treating model chain-of-thought as authoritative state or required evidence.

## 3. Actors

| Actor | Definition |
|---|---|
| Machine principal | Cryptographic identity of one Habitat OS installation |
| Agent principal | Durable autonomous identity with objectives and capability policy |
| Activation principal | Short-lived identity derived for one bounded activation |
| Human principal | Authenticated operator or authority holder |
| Service principal | Deterministic service or capability provider identity |
| Robot principal | Authenticated embodied system or controller identity |
| External principal | Remote provider or system outside Habitat trust |

## 4. Change classification

| Class | Examples | Minimum authority |
|---|---|---|
| C0 data/projection | Rebuild search index, regenerate projection | Automatic repair authority |
| C1 contextual | Skill text, retrieval policy, context hint | Bounded self-change authority plus regression evaluation |
| C2 capability | Tool provider, connector, model driver | Package build, evaluation, signing and activation separation |
| C3 governor | Capability policy, effect admission, evidence protection | Independent governor-change authority |
| C4 system | Kernel, driver, Habitat bootstrap, recovery generation | System-generation authority and boot rollback proof |
| C5 physical safety | Safety limits, stop authority, drive firmware | External safety authority; never model-only approval |

## 5. Requirement governance

**GOV-001 — Stable identifiers.** Normative requirements SHALL use stable identifiers and SHALL NOT be renumbered after publication. Removed requirements SHALL remain tombstoned with rationale.

**GOV-002 — Complete requirement semantics.** Each critical requirement SHALL identify its trigger, behavior, boundary, failure behavior, evidence and objective acceptance condition either locally or by an explicit normative reference.

**GOV-003 — No hidden policy.** Implementation tasks, code comments, prompts and tests SHALL NOT introduce consequential product policy absent from this package or an approved successor.

**GOV-004 — Change propagation.** A change to an invariant, state transition, authority rule or interface SHALL update every affected schema, traceability entry, test and dependent contract in one governed change.

**GOV-005 — Evidence before completion.** Artifact creation, compilation, schema validity and process startup SHALL NOT alone establish completion of a behavioral requirement.

**GOV-006 — Unknowns.** Unknown external outcomes and missing information SHALL be represented explicitly and SHALL NOT be coerced into success or failure for workflow convenience.

## 6. Versioning

- Package versions use semantic versioning.
- Breaking wire or state semantics require a major version.
- Additive optional fields require a minor version.
- Corrections that do not change semantics require a patch version.
- Every persisted record carries `schema_version`.
- Every activation carries `abi_version`, `system_generation_id`, and `capability_activation_set_id`.

## 7. Acceptance authority

No agent or service may be the sole source of both a completion claim and the evidence required to validate that claim when the evidence can be independently observed.
