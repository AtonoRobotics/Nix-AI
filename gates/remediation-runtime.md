# Gates: Runtime trust and durable ownership

Scope: Replace permissive runtime stubs with fail-closed authority/effect services and prove PostgreSQL plus digest-addressed evidence ownership end to end.

- [ ] G1: Authority permits matching active grants and correctly attenuated active child grants, while denying absent, revoked, stale, peer-mismatched, widened, expired, quota/target/operation/depth/generation-violating grants.
  CHECK: cargo test -p habitat-authority --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G2: Effects cannot be proposed or dispatched without a current authority decision; atomic idempotency reservation, provider classification, attempts, unknown-outcome reconciliation, compensation, and objective-completion blocking satisfy EFFECT-001 through EFFECT-005 and are owned by the effect service.
  CHECK: cargo test -p habitat-effects --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G3: Fault tests cover duplicate dispatch, crash-after-dispatch, unknown outcome, reconciliation, stale authority, provider mismatch, compensation, and incomplete-objective denial with exact V-EFFECT metrics.
  CHECK: cargo test -p habitat-effects --test fault_matrix --test admission
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G4: A live PostgreSQL/Garage runtime test proves the deployed coordinator uses transactional state and digest-addressed evidence, contains no automatic `ALLOW`, survives restart, and does not persist effects in runtime state.
  CHECK: nix run .#test-runtime-live
  EXPECT: /"outcome"\s*:\s*"passed"/
  EVIDENCE: pending

- [ ] G5: Runtime packet is formatting- and strict-clippy-clean.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-authority -p habitat-effects -p habitat-runtime --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: pending

- [ ] G6: A fresh adversarial agent found no unresolved runtime bug, trust-boundary bypass, ownership violation, EFFECT-001 through EFFECT-005 gap, persistence gap, or V2 drift.
  EVIDENCE: pending

- [ ] G7: Driver independently reran G1-G5 after review; the approved source packet was committed and pushed before the next packet began.
  EVIDENCE: pending
