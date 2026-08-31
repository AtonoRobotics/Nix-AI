# Gates: Autonomous-operation integration

Scope: Runtime and qualification execute as one image-level behavior.

- [ ] G1: Nix closure and image checks pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix flake check --show-trace && echo flake-ok
  EXPECT: flake-ok
  EVIDENCE: pending Garage migration and requalification under normal policy
