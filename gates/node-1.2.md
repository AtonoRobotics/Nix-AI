# Gates: Autonomous-operation integration

Scope: Runtime and qualification execute as one image-level behavior.

- [x] G1: Nix closure and image checks pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix flake check --show-trace && echo flake-ok
  EXPECT: flake-ok
  EVIDENCE: `nix flake check --show-trace` evaluated the Garage-backed system images and built all 66 clean-tree checks, including the normalized 577-member closure, release qualification, packet qualification, and contract validation: exit 0.
