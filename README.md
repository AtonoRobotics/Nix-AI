# Nix AI / Habitat OS

This repository is bootstrapped from the governing Habitat OS v1.1 contract bundle.
The original bundle remains under `Habitat-OS-Codex-Build-Bundle-v1.1/`, while
byte-identical contract projections live under `contracts/` for implementation.

## Validate contracts

With Nix flakes enabled, one command verifies both nested SHA-256 manifests, runs
the existing bundle and contract validators, checks the generated work graph, and
proves that every repository projection remains byte-identical to its source:

```console
nix run .#validate-contracts
```

Use `nix develop` for the locked W00 developer environment. The same validation is
also part of `nix flake check --show-trace`.

The gate independently validates all 135 executable requirement mappings, all 16
typed work packets, each dependency relation, verification-gate references, and
both generated work-graph projections.

The validation gate formats a temporary copy of the immutable Protobuf sources,
lints and compiles both contracts, regenerates the descriptor and Prost bindings,
checks them byte-for-byte, and proves that an incompatible fixture is rejected.
Regenerate the checked-in artifacts after an intentional ABI change with:

```console
nix run .#generate-proto
```

Run the complete W00 qualification, including from-source regeneration in a
temporary workspace and checked packet-evidence validation, with:

```console
nix run .#apps.x86_64-linux.qualify
```

Qualification never rewrites the checkout. Digest-addressed reports and the
packet result are retained under `evidence/work-packets/W00/`.
