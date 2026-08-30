# Habitat OS Architecture and Contract Package

Version: 1.1.0  
Status: Governing implementation baseline  
Date: 2026-08-29

## Mission

Habitat OS is a brand- and domain-agnostic, Linux-kernel operating system whose native principals are autonomous agents. Habitat shall enable agents to perform real work continuously while mechanically bounding authority, preserving operational truth, recovering from interruption, and permitting governed self-change.

The operating system is not a conventional Linux distribution with an agent application installed. Linux owns hardware mechanisms. Habitat owns agent identity, objectives, cognition scheduling, context, capabilities, effects, evidence, package activation, recovery, and operator surfaces.

## Governing invariants

1. **Agent continuity:** A durable agent identity and its responsibilities shall survive every model call, harness exit, process crash, provider change, and host reboot.
2. **No ambient authority:** An activation shall possess only explicitly granted, attenuated, expiring capabilities.
3. **Context on demand:** Context shall be compiled for the current activation and may be expanded by a semantic context request; the system shall not depend on an indefinitely growing transcript.
4. **Effects are durable:** Consequential external actions shall cross the effect boundary and shall never be blindly retried after an ambiguous outcome.
5. **Truth is transactional:** Authoritative operational state shall be committed transactionally; projections, prompts, model outputs, and telemetry are not truth.
6. **Harness independence:** Harnesses and models are disposable cognition backends, not owners of agent identity, authority, memory, or completion.
7. **Pinned composition:** Work shall execute against an immutable activation graph and shall not silently rebind when a provider changes.
8. **Independent evidence:** Completion and recovery claims shall be supported by evidence not solely produced or controlled by the actor making the claim.
9. **Bounded self-change:** Agents may propose and, when pre-authorized, promote changes; they shall not combine change, evaluation, signing, activation, and evidence authority in one principal.
10. **Physical safety independence:** Model cognition shall never be the final enforcement boundary for actuator safety.

## Package map

| Artifact | Governs |
|---|---|
| `00-GOVERNANCE.md` | Authority of artifacts, terminology, requirement form, change control |
| `01-ARCHITECTURE.md` | System boundary, components, trust and deployment architecture |
| `02-AGENT-ABI.md` | Native operations available to agents and activations |
| `03-STATE-AND-LIFECYCLE.md` | Authoritative entities, ownership, state machines and recovery |
| `04-AUTHORITY-CAPABILITIES.md` | Identity, capability grant, delegation, revocation and enforcement |
| `05-EFFECTS.md` | Consequential action admission, execution, uncertainty and reconciliation |
| `06-CONTEXT.md` | Context compilation, semantic context faults, skills and provenance |
| `07-CAPABILITY-PACKAGES.md` | Signed extension packages, runtime kinds, dependency graphs and activation |
| `08-SYSTEM-GENERATIONS.md` | Nix-built OS generations, boot confirmation, migration and rollback |
| `09-THREAT-SAFETY.md` | Threat model, security boundaries, prompt injection and physical safety |
| `10-HARDWARE-PROFILES.md` | Hardware qualification and invariant Habitat ABI across platforms |
| `11-OBSERVABILITY-SLOS.md` | Evidence, telemetry, health, SLOs and operational diagnosis |
| `12-VERIFICATION-MATRIX.md` | Required nominal, failure, adversarial and recovery acceptance evidence |
| `13-IMPLEMENTATION-WORK-GRAPH.md` | Contract-driven implementation order and release gates |
| `14-DECISION-REGISTER.md` | Approved architectural decisions and rejected alternatives |
| `15-TRACEABILITY.md` | Objective-to-requirement-to-evidence mapping |
| `17-REMEDIATION-RECORD.md` | Closure record for the v1.0 implementation blockers |
| `contracts/work-packets.yaml` | Canonical typed W00–W15 dependency and exit graph |
| `contracts/requirements.yaml` | Executable registry for every normative requirement |
| `schemas/` | Machine-readable external contract schemas |
| `proto/` | Internal versioned ABI service definitions |
| `tests/generate_work_graph.py` | Generates both Markdown work-graph projections from the canonical YAML |
| `tests/validate_contracts.py` | Structural, graph, traceability and integrity validator |

## Normative language

`SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative. Requirements use stable identifiers. Examples are non-normative unless explicitly incorporated by a requirement.

## Implementation release condition

Implementation may begin from this baseline. A production release shall not be declared until every critical requirement in `15-TRACEABILITY.md` has an implementation, enforcement mechanism, objective evidence, and passing acceptance result under `12-VERIFICATION-MATRIX.md`.
