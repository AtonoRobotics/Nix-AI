# Gates: Autonomous-operation integration

Scope: Runtime and qualification execute as one image-level behavior.

- [ ] G1: Nix closure and image checks pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix flake check --show-trace && echo flake-ok
  EXPECT: flake-ok
  EVIDENCE: normal-policy evaluation rejects the abandoned insecure MinIO package before producing the image.
ABANDON: G1 Autonomous image qualification is blocked by leaf-runtime G5/G6 and leaf-final G5/G6; no insecure-package override is accepted as production evidence.
