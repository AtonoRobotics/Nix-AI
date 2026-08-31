# Authoritative activation resolution slice

- [x] G1 State resolves a live activation only when credential and every V2.0.1 RequestBinding field backed by activation state matches exactly.
  CHECK: `nix run path:.#test-w05`
  EXPECT: exit 0, zero skips, with forged identity, future fence, stale scope, bad credential, and out-of-scope deadline rejected.
  EVIDENCE: `nix run path:.#test-w05` exited 0 on 2026-08-31 with 15 live PostgreSQL tests and zero skips; forged fields, bool/zero/negative/overflow scalars, stale/future fences, scope, credential, deadline, and terminal state were rejected.

- [x] G2 Resolution is available only to the authenticated ABI principal and returns no credential digest/key material.
  CHECK: `nix run path:.#test-w05`
  EXPECT: exit 0 with principal-denial and secret-nondisclosure assertions.
  EVIDENCE: The same live W05 run passed ABI-principal denial/allow and secret-nondisclosure assertions; protocol allowlist exposes activation_resolve only to service:abi.

- [x] G3 A fresh adversarial review approves this state-resolution slice.
  EVIDENCE: Final review by activation_claim_adversarial returned APPROVE after three adversarial passes; git diff --check passed and no blocker remained.
