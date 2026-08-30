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
