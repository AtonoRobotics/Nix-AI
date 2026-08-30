# Capability Package and Activation Contract

## 1. Universal extension model

Everything exposed to an agent is a capability. A capability package may execute as:

- trusted native service;
- Cordis module within a declared trusted host;
- WASI component;
- OCI container;
- microVM image;
- authenticated remote provider;
- physical device or robot adapter.

Runtime kind does not change authority, evidence or activation semantics.

## 2. Package manifest

Every package declares:

- package identity, semantic version and content digest;
- publisher identity, signature and provenance;
- runtime kind and immutable artifact reference;
- provided capability contracts and versions;
- required capabilities and version ranges;
- resource and device requirements;
- isolation profile;
- network and storage requirements;
- configuration schema;
- state compatibility and migration contract;
- health and live-verification contract;
- consequence classes supported;
- activation, drain, rollback and decommission behavior;
- supported hardware profiles and ABI ranges.

## 3. Activation graph

Dependency resolution produces an immutable, content-addressed activation set. Each set records exact provider digests, configuration digests, state-schema versions and grants.

New work may bind to a new set only after admission and verification. Existing activations remain pinned unless explicitly migrated.

## 4. Normative requirements

**PKG-001 — Signed admission.** Unsigned, unverifiable or revoked packages SHALL NOT enter an active set.

**PKG-002 — Exact artifact.** Runtime artifacts SHALL be addressed by immutable digest. Mutable tags or branches are insufficient activation identity.

**PKG-003 — Dependency closure.** A set SHALL activate only when all required capability versions, hardware resources, isolation features and state schemas resolve without conflict.

**PKG-004 — No implicit privilege.** Installation SHALL NOT grant runtime authority. Package admission, provider authority and agent grants are separate decisions.

**PKG-005 — Live verification.** Provider process health SHALL NOT establish activation. The declared capability SHALL pass a behaviorally meaningful verification operation.

**PKG-006 — Drain.** Removing or replacing a provider SHALL stop new binding, preserve pinned work, and either drain, migrate or terminate according to the declared compatibility contract.

**PKG-007 — Revocation.** Emergency revocation MAY terminate affected work. Habitat SHALL record unresolved effects and create recovery wakes before replacement work resumes.

**PKG-008 — State migration.** Stateful providers SHALL declare migration direction, interruption behavior, rollback limit and evidence. Unproven destructive migrations are prohibited.

**PKG-009 — Cordis boundary.** Cordis effects govern in-process registrations and cleanup only. They SHALL NOT represent external Habitat effects, durable package admission or OS generation rollback.

**PKG-010 — Supply chain.** Builds SHALL record sources, lock inputs, build environment, SBOM, vulnerability results and reproducibility evidence where supported.

## 5. Provider health states

`DISCOVERED → ADMITTED → STAGED → STARTING → VERIFYING → ACTIVE`

Failure states: `DEGRADED`, `UNAVAILABLE`, `QUARANTINED`, `DRAINING`, `REVOKED`, `RETIRED`.

Provider disappearance does not mutate the activation graph. It changes availability observations and wakes dependent objectives.

## 6. Compatibility rules

- Major contract versions are incompatible unless an adapter is explicitly admitted.
- Minor versions may add optional fields and operations.
- Provider configuration is part of activation identity.
- State compatibility is independent of wire compatibility.
- A remote provider's advertised version is not trusted until a capability probe confirms it.

