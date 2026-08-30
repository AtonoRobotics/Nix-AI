# Habitat OS Architecture

## 1. Selected architecture

Habitat OS SHALL use a Linux kernel and a Nix-constructed Habitat-native userspace. The system SHALL boot into Habitat recovery and autonomous reconciliation rather than a human desktop or operator-launched agent application.

```text
Hardware and firmware
└── Linux kernel and hardware profile
    ├── Low-level boot, device, storage and network mechanisms
    └── Habitat-native userspace
        ├── Bootstrap and recovery
        ├── Identity and authority
        ├── Durable agent/objective state
        ├── Wake and cognition scheduler
        ├── Context compiler and broker
        ├── Capability and effect kernel
        ├── Package and generation controller
        ├── Execution substrate
        ├── Evidence and observability
        └── Agent and operator surfaces
```

## 2. Component ownership

| Component | Owns | Shall not own |
|---|---|---|
| Linux kernel | CPU, memory, devices, filesystem, network, isolation mechanisms | Agent identity, semantic authority or objectives |
| Habitat Bootstrap | Boot verification, state opening, reconciliation, generation confirmation | Domain behavior or model reasoning |
| Agent Registry | Durable agent identity and lifecycle | Harness sessions as truth |
| Objective Service | Desired state, responsibility and completion contract | Predetermined reasoning path |
| Wake Scheduler | Durable wake delivery, leases and cognition scheduling | Business outcome interpretation |
| Context Compiler | Activation context, provenance, semantic context-fault resolution | Authoritative truth mutation |
| Model Service | Provider protocol, model invocation and normalized results | Agent identity or external authority |
| Capability Kernel | Capability definitions, grants, delegation and revocation | Provider implementation state |
| Effect Service | Consequential action admission, reservation, observation and reconciliation | Invented success after ambiguity |
| Package Controller | Signed packages, dependencies, immutable activation graphs | OS generation activation |
| Generation Controller | System closure staging, boot confirmation and rollback | Operational database truth |
| Evidence Service | Protected evidence references, integrity and retention | Unverifiable model claims |
| Execution Service | Process, WASI, OCI, microVM and remote execution | Semantic permission decisions |

## 3. Trust boundaries

1. Model outputs are untrusted proposals.
2. Harnesses are untrusted with respect to Habitat authority and operational truth.
3. Context sources retain provenance and may be untrusted or stale.
4. Capability providers are trusted only for their declared contract and observed evidence.
5. Generated code executes outside the Habitat control-plane address space.
6. External systems may acknowledge, reject, duplicate or ambiguously complete requests.
7. Evidence used to evaluate an agent shall be protected from that activation's write authority.

## 4. Native execution flow

1. A durable event or state change creates a `Wake`.
2. The scheduler leases the wake to an eligible agent activation.
3. The context compiler constructs a versioned `ContextBundle`.
4. The runtime selector chooses a direct model driver or specialized harness.
5. The activation returns a typed disposition.
6. Context requests re-enter compilation; capability reads execute within the grant; consequential writes enter the effect service.
7. Results are observed and committed before the next activation.
8. The objective is completed only when its evidence contract passes.

## 5. Normative requirements

**ARC-001 — Boot autonomy.** After power restoration, Habitat SHALL restore a coherent operating state and resume eligible objectives without requiring a human login or manual service launch.

**ARC-002 — Agent-native ownership.** Durable agent identity, objectives, grants, effects and evidence SHALL be owned by Habitat services rather than by a harness, model provider, container or process.

**ARC-003 — Backend replaceability.** Replacing a model or harness SHALL NOT alter the agent identity, objective identity, capability grants, effect history or completion contract.

**ARC-004 — Isolation selection.** Every activation SHALL be assigned an execution boundary from a declared isolation profile before model or executable code runs.

**ARC-005 — No bypass.** Capability providers SHALL be unreachable from an activation except through granted Habitat interfaces or explicitly mounted read-only inputs.

**ARC-006 — Pinned generation.** An activation SHALL remain bound to its system generation and capability activation set for its lifetime. Rebinding requires a new activation or an explicit migration recorded as evidence.

**ARC-007 — Failure containment.** A failed activation SHALL NOT corrupt durable agent identity, authoritative objective state, protected evidence, other workspaces or the recovery generation.

**ARC-008 — Compatibility capsules.** Vendor userspaces such as Ubuntu SHALL execute as declared capability workloads. They SHALL NOT become the administrative or authority plane of Habitat OS.

**ARC-009 — Single operational truth.** PostgreSQL-backed Habitat state SHALL be authoritative for operational entities. Message buses, telemetry, graphs, vector indexes and model transcripts SHALL be projections or evidence.

**ARC-010 — Domain neutrality.** Core contracts SHALL refer to principals, objectives, observations, contexts, capabilities, effects and evidence, not to a specific application domain.

## 6. Deployment topology

The reference deployment is one Habitat machine with local authoritative state. Multi-machine deployments MAY place execution providers remotely, but one objective and effect record retains exactly one authoritative owner at a time. Distributed placement SHALL NOT introduce multiple writers for the same effect instance.

## 7. Degraded operation

- Loss of a model provider suspends cognition but does not lose objectives.
- Loss of a capability provider marks dependent capabilities unavailable and creates affected wakes; active work remains pinned.
- Loss of semantic retrieval degrades to provenance-bearing direct state access.
- Loss of external telemetry does not permit completion without required evidence.
- Loss of the authority store fails closed for new effects.
- Loss of the evidence store prevents confirmation of requirements whose evidence cannot be durably recorded.
