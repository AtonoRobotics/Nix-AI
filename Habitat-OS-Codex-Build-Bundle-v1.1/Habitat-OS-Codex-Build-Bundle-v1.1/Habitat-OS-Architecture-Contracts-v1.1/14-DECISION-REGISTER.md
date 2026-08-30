# Architecture Decision Register

## Approved decisions

| ID | Decision | Rationale |
|---|---|---|
| DEC-001 | Habitat is a bootable agent-centric OS | Agents require native continuity, context, authority and recovery |
| DEC-002 | Linux is the hardware kernel | Required driver, GPU, robotics, storage, network and virtualization mechanisms |
| DEC-003 | Nix is the reference system-construction mechanism | Declarative closures, coexistence, atomic activation and rollback align with autonomous self-change |
| DEC-004 | Habitat supplies the operational userspace | Prevents a human-oriented distro from remaining the true authority plane |
| DEC-005 | Durable agent identity is independent of activation, model and harness | Preserves continuity and backend replaceability |
| DEC-006 | Context is compiled and demand-loaded | Avoids transcript dependence and enables semantic context faults |
| DEC-007 | Capabilities are the universal extension abstraction | Applies consistently across local, container, remote and physical providers |
| DEC-008 | Consequential actions use durable effect instances | Required for idempotency, ambiguity, reconciliation and evidence |
| DEC-009 | PostgreSQL implements operational truth | Provides transactional authority and recovery; projections remain derived |
| DEC-010 | Capability activation sets are immutable and pinned | Prevents silent provider rebind during work |
| DEC-011 | Cordis is first-class but not universal | Strong for harness-local composition; insufficient for OS-wide durable packages and isolation |
| DEC-012 | Traditional harnesses are optional cognition backends | Preserves useful specialization without surrendering agent ownership |
| DEC-013 | Ubuntu is a compatibility capsule or hardware profile, not the authority plane | Preserves proprietary/vendor ABI without weakening Habitat identity |
| DEC-014 | Physical safety remains outside model authority | Models and general networks cannot be final actuator safety enforcement |
| DEC-015 | Self-change uses separated build, evaluation, signing and activation authority | Prevents self-authorization and evaluator capture |

## Approved reference implementation decisions

These decisions select the first conforming implementation without making the platform ABI dependent on one distribution, kernel, object store, runtime or model provider. A different profile MAY use another qualified implementation only when it preserves the same semantic contracts and passes its declared gates.

| ID | Decision | Rationale | Scope | Owner | Affected packets |
|---|---|---|---|---|---|
| DEC-016 | Privileged Habitat services use Rust from the locked Nix toolchain | Memory safety and a single strongly typed service workspace reduce privileged implementation risk | `qemu-x86_64-conformance` and reference Habitat services; ABI remains language-neutral | W00 contract/toolchain owner | W00, W03–W10, W14 |
| DEC-017 | The reference image locks `nixos-26.05`, Linux 6.12 LTS, UEFI and systemd-boot boot counting | Supplies a reproducible LTS hardware kernel and an automatable rollback path | `qemu-x86_64-conformance`; other profiles may use qualified LTS/BSP kernels and boot mechanisms | W01 image owner | W00, W01, W14, W15 |
| DEC-018 | PostgreSQL 17 is operational truth and MinIO is the local S3-compatible content-addressed evidence store | Preserves transactional state and protected large evidence with available production implementations | Single-machine reference deployment; remote deployments retain the same state and evidence contracts | W02 state/evidence owner | W02, W05, W08, W15 |
| DEC-019 | Firecracker is the reference microVM provider when KVM is available | Provides a small KVM isolation boundary; unsupported hosts truthfully declare the feature absent | `qemu-x86_64-conformance` feature mode; GPU/device profiles may qualify another KVM provider | W06 execution owner | W06, W10, W12, W15 |
| DEC-020 | OpenAI Responses and Anthropic Messages are the first direct model drivers | Qualifies provider replacement against two independent frontier-model protocols without coupling the ABI to either | Reference provider set; boot and core authority do not require either provider | W09 model owner | W09, W11, W15 |
| DEC-021 | systemd supervises host services; containerd and Wasmtime provide OCI and WASI execution | Uses mature Linux mechanisms while retaining Habitat as the semantic authority plane | `qemu-x86_64-conformance`; runtime availability remains profile-declared | W01/W06 owners | W01, W06, W10, W15 |

## Rejected alternatives

| ID | Alternative | Reason rejected |
|---|---|---|
| REJ-001 | Habitat as an application on Ubuntu | Leaves agent identity, recovery and machine authority subordinate to human-oriented host operation |
| REJ-002 | Arch as reference base | Mutable rolling model lacks native whole-system generation and autonomous rollback semantics |
| REJ-003 | New custom kernel | Reimplements solved hardware mechanisms and loses essential NVIDIA/robotics compatibility |
| REJ-004 | seL4 with Linux guest as primary hardware path | Linux guest would remain practical GPU/device authority and divide the control model |
| REJ-005 | Traditional harness as Habitat kernel | Harnesses own sessions and loops but not machine-wide durable authority or recovery |
| REJ-006 | Cordis for every component | In-process lifecycle cannot represent all containers, devices, state migrations and OS generations |
| REJ-007 | Temporal as Habitat truth/lifecycle | Duplicates durable truth and imposes workflow structure on dynamic agent reasoning |
| REJ-008 | Universal behavior tree | Encodes anticipated solutions rather than using frontier-model reasoning; trees remain useful for context routing |
| REJ-009 | Mandatory planner/critic/verifier agents | Adds ceremonial cognition and cost without evidence that every task requires those roles |
| REJ-010 | Human approval as routine governance | Conceals missing bounded authority and prevents genuine autonomy |

## Closed bounded decisions

| ID | Status | Resolution | Remaining platform flexibility |
|---|---|---|---|
| OPEN-001 | Closed | DEC-016 selects Rust for privileged reference services | ABI-compatible non-reference services may use another memory-safe implementation after equivalent qualification |
| OPEN-002 | Closed for reference profile | DEC-017 fixes the reference release and kernel | Each additional hardware profile records and qualifies its exact LTS/BSP matrix |
| OPEN-003 | Closed for reference deployment | DEC-018 selects MinIO | Remote deployments may use another S3-compatible evidence store that passes retention, integrity and isolation gates |
| OPEN-004 | Closed for reference feature mode | DEC-019 selects Firecracker on KVM | Profiles requiring GPU/device passthrough may qualify another microVM provider without changing the runtime contract |
| OPEN-005 | Closed for reference release | DEC-020 selects the first two direct drivers | Additional providers remain plugins behind the provider-neutral model contract |

No open bounded decision blocks W00 or W01. Profile-specific alternatives become new explicit decisions in that profile; they do not reopen these reference choices.
