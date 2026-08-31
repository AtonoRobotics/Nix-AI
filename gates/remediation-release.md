# Gates: Exact-tree V2 release and drift closure

Scope: Integrate approved packets, run the full production-policy acceptance matrix, regenerate evidence from the exact committed candidate, and prove the binding completion predicate.

- [ ] G1: Full Python acceptance runs with zero skips and zero failures under its declared service harness.
  CHECK: nix run .#test-all-python
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G2: Rust workspace formatting, strict clippy, and all tests pass.
  CHECK: nix develop --command sh -c 'cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace'
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G3: Normal-policy Nix flake evaluation and checks pass with no insecure-package override.
  CHECK: nix flake check --show-trace && echo 'checks passed'
  EXPECT: /checks passed/
  EVIDENCE: pending

- [ ] G4: Fresh QEMU boot, interruption recovery, effect reconciliation, governed rollback, and end-to-end objective completion produce live passing evidence.
  CHECK: nix run .#qualify-v2-release
  EXPECT: /completion_predicate.*true/
  EVIDENCE: pending

- [ ] G5: Exact-tree W13 verification accepts every W00-W13 packet, every V gate, protected evidence, and all binding completion predicates.
  CHECK: nix run .#test-w13
  EXPECT: /V2 release evidence is complete and valid/
  EVIDENCE: pending

- [ ] G6: Public documentation, generated projections, manifests, scope classification, and release evidence contain no stale V1/MinIO claims, inadmissible source, generated-output drift, or source/closure digest mismatch.
  CHECK: python3 tools/verify_v2_drift.py --root . && python3 tools/derive_v2_contract.py --root . --check && nix run .#validate-contracts && nix run .#test-w13
  EXPECT: /drift-free/
  EVIDENCE: pending

- [ ] G7: A fresh adversarial agent found no unresolved integration bug, release-claim inflation, stale evidence, or V2 drift.
  EVIDENCE: pending

- [ ] G8: Driver independently reran G1-G6 after review, completed all tracked ledger/review updates from that preliminary run, and froze the non-evidence source commit. Final qualification may change only `evidence/`; push verification is recorded in `evidence/remediation/final-push.json`.
  EVIDENCE: pending
