# Nix AI

Nix AI is a bootable autonomous agent operating system whose durable work remains governed, recoverable, and independently verifiable without an active human session.

## Language

**Authoritative State**:
The single operational truth for objectives, wakes, activations, leases, command replay, effects, packages, governed change, and evidence references.
_Avoid_: State store, lifecycle store, command ledger

**Runtime Coordination**:
The progression and recovery of durable objectives across authority, execution, context, effects, and Authoritative State.
_Avoid_: Role dispatcher, runtime routing

**Attested Qualification Run**:
A complete execution whose commands, source tree, closure, observations, and artifacts are independently bound by digest.
_Avoid_: Test run, report generation

**Evidence Object**:
Digest-addressed bytes whose reference and metadata live in Authoritative State and whose content is independently verified before trust.
_Avoid_: Evidence record, report blob

**System Generation**:
An immutable, digest-addressed activation set promoted, drained, recovered, or rolled back as one governed change.
_Avoid_: Deployment version, release bundle
