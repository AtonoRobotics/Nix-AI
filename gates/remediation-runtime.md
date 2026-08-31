# Gates: Runtime trust and durable ownership

Scope: Replace permissive runtime stubs with fail-closed authority/effect services and prove PostgreSQL plus digest-addressed evidence ownership end to end.

- [x] G1: Authority permits matching active grants and correctly attenuated active child grants, while denying absent, revoked, stale, peer-mismatched, widened, expired, quota/target/operation/depth/generation-violating grants.
  CHECK: cargo test -p habitat-authority --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: 2026-08-31 pinned Nix shell run passed all targets: attenuation/revocation 5/5 and authorization 6/6, with no skips.

- [x] G2: Effects cannot be proposed or dispatched without a current authority decision; atomic idempotency reservation, provider classification, attempts, unknown-outcome reconciliation, compensation, and objective-completion blocking satisfy EFFECT-001 through EFFECT-005 and are owned by the effect service.
  CHECK: cargo test -p habitat-effects --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: 2026-08-31 pinned Nix shell run passed all targets: admission 6/6 (including bound terminal retry/guard repair) and fault matrix 5/5, with no skips.

- [x] G3: Fault tests cover duplicate dispatch, crash-after-dispatch, unknown outcome, reconciliation, stale authority, provider mismatch, compensation, and incomplete-objective denial with exact V-EFFECT metrics.
  CHECK: cargo test -p habitat-effects --test fault_matrix --test admission
  EXPECT: /test result: ok/
  EVIDENCE: 2026-08-31 exact focused run passed admission 6/6 and fault_matrix 5/5; runtime 5/5, harness backend 1/1, and runtime-boundary 4/4 also passed.

- [x] G4: A live PostgreSQL/Garage runtime test proves the deployed coordinator uses transactional state and digest-addressed evidence, contains no automatic `ALLOW`, survives restart, and does not persist effects in runtime state.
  CHECK: nix run .#test-runtime-live
  EXPECT: /"outcome"\s*:\s*"passed"/
  EVIDENCE: 2026-08-31 genuine VM gate passed with artifact /nix/store/0p0r91s3d66xab75j1jj7ridgw6xrqm9-vm-test-run-habitat-runtime-live/runtime-live-probe.json; exact drv /nix/store/cmkrv8glddcggh8a4jridszj11xs680i-vm-test-run-habitat-runtime-live.drv also passed forced `nix-store --realise --check`. Both runs independently verified the same real Garage object at `s3://habitat-evidence/sha256/35b4537c0ad34f55a7d5f2ccbd154a6c3a0a361400adebf1af1d38af7330f0d1`; the artifact also records PostgreSQL, 0 runtime effect files, restart reconciliation, revocation persistence, and all fail-closed outage probes.

- [x] G5: Runtime packet is formatting- and strict-clippy-clean.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-authority -p habitat-effects -p habitat-runtime --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: 2026-08-31 exact rustfmt check and strict clippy command passed in the pinned Nix shell; live W05 PostgreSQL qualification also passed 5/5 with skip_count 0.

- [ ] G6: A fresh adversarial agent found no unresolved runtime bug, trust-boundary bypass, ownership violation, EFFECT-001 through EFFECT-005 gap, persistence gap, or V2 drift.
  EVIDENCE: pending

- [ ] G7: Driver independently reran G1-G5 after review; the approved source packet was committed and pushed before the next packet began.
  EVIDENCE: pending
