# ADR 0001: Use Garage as the embedded object store

- Status: Accepted
- Date: 2026-08-30
- Decision owner: Nix AI V2 maintainers
- Supersedes: the implementation assumption that MinIO is the canonical
  embedded S3 service

## Context

Nix AI V2 requires PostgreSQL to remain the authoritative store for lifecycle,
leases, command replay, effects, packages, and governed-change state. Evidence
bytes are content addressed and stored behind an S3-compatible interface.

The NixOS package set used by the production image no longer contains a MinIO
release that can be admitted under the normal security policy. Its available
MinIO package is marked insecure and abandoned. Allowing that package would
make a successful image evaluation weaker evidence, not production
qualification.

An earlier experiment replaced MinIO while also redesigning state and QEMU
qualification. That combined change was not accepted. This ADR authorizes only
the object-store architecture decision; implementation and qualification remain
separate reviewed changes.

## Decision

Garage is the canonical embedded S3 backend for NixOS and QEMU deployments.
PostgreSQL remains the authoritative metadata and lifecycle store. Evidence
objects remain addressed and verified by their cryptographic digest, and
Garage-specific behavior stays behind the S3 storage boundary.

The migration must not weaken:

- independent digest verification before evidence is trusted;
- least-privilege credentials and bucket permissions;
- fail-closed startup, readiness, and recovery behavior;
- persistence and integrity across service restart and full reboot; or
- exact-tree, command-attested release evidence.

The immutable V2.0.1 contract and its generated architecture projections are
unchanged. A future object-store replacement requires another explicit
decision and the same live compatibility qualification.

## Acceptance consequences

Garage is accepted only when all of the following are demonstrated under the
normal Nix security policy:

1. deterministic, idempotent node, layout, key, and bucket initialization;
2. isolated credentials and narrowly scoped evidence-bucket access;
3. live put, get, digest verification, tamper detection, and restart tests;
4. readiness that proves S3 connectivity instead of checking credential files;
5. a fresh QEMU image completing the required objective and recovery scenarios;
6. independently verifiable evidence bound to the exact committed source and
   built closure.

