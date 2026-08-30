# Hardware Profile Contract

## 1. Purpose

Brand and domain neutrality are provided by a stable Habitat ABI over qualified generic hardware profiles, not by assuming identical kernels or drivers.

## 2. Required profile fields

- profile identity and version;
- CPU architecture and virtualization features;
- kernel and BSP source/digest;
- firmware and boot requirements;
- storage and recovery layout;
- TPM or trust-root support;
- GPU, accelerator and driver matrix;
- device classes and isolation limits;
- network interfaces and time source;
- power, thermal and watchdog capabilities;
- supported execution runtimes;
- capacity limits and qualification evidence.

## 3. Reference profiles

1. `qemu-x86_64-conformance`: deterministic boot, interruption and rollback tests.
2. `generic-x86_64-accelerated`: optional accelerator model execution, OCI and KVM workloads.

Additional profiles MAY include generic ARM64, accelerated hosts and cloud VMs.

## 4. Normative requirements

**HWP-001 — ABI invariance.** Hardware profiles SHALL expose the same semantic Agent ABI and capability/effect contracts for supported features.

**HWP-002 — Declared absence.** Unsupported isolation, device, GPU or trust features SHALL be explicitly absent. Habitat SHALL not emulate security guarantees it cannot enforce.

**HWP-003 — Qualification matrix.** Kernel, firmware, driver and userspace compatibility SHALL be version-pinned and tested together.

**HWP-004 — Capacity admission.** The scheduler SHALL reject or defer activations whose declared resource requirements exceed enforceable profile capacity.

**HWP-005 — Device mediation.** Devices SHALL be assigned only through the execution and capability services. General activations SHALL not inherit host device access.

**HWP-006 — Thermal and power state.** Profiles that can throttle or lose power SHALL expose those observations to scheduling and recovery.

**HWP-007 — Recovery proof.** Each profile SHALL prove boot into a known-good generation after a deliberately defective candidate.

**HWP-008 — Vendor capsule.** Vendor applications MAY use compatibility containers, but the host retains Habitat identity, authority and generation control.

