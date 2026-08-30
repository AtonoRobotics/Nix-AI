# Gates: Full clean acceptance matrix

Scope: Re-run every binding check from the exact committed tree.

- [x] G1: Rust formatting is clean.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command sh -c 'cargo fmt --all -- --check && echo fmt-ok'
  EXPECT: fmt-ok
  EVIDENCE: building '/nix/store/0fkp45v1a52j1b6njlwg1flghv959msh-qualify-w02.drv'... | building '/nix/store/dgm2swyb9pylwq976m85nbggxxrp03bk-nix-shell-env.drv'...
- [x] G2: Rust strict clippy is clean.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command sh -c 'cargo clippy --workspace --all-targets -- -D warnings && echo clippy-ok'
  EXPECT: clippy-ok
  EVIDENCE: Checking habitat-runtime v0.1.0 (/home/samuel/nixai/crates/habitat-runtime) | Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.27s
- [x] G3: Complete Rust workspace tests pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command cargo test --workspace
  EXPECT: /test result: ok/
  EVIDENCE: Doc-tests habitat_packages | Doc-tests habitat_runtime
- [ ] G4: Complete Python suite passes with zero skips.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command python -m unittest discover -s tests -v
  EXPECT: /OK/
  EVIDENCE: Ran 91 tests in 31.262s; OK (skipped=11). The dedicated live W02 and W05 runners separately passed those 7+4 tests with zero skips.
ABANDON: G4 The required single full-suite invocation is not zero-skip because it does not provision PostgreSQL/MinIO; passing the same tests in separate provisioned runners does not satisfy the literal gate.
- [ ] G5: Nix flake check passes.
  CHECK: /nix/var/nix/profiles/default/bin/nix flake check --show-trace && echo flake-ok
  EXPECT: flake-ok
  EVIDENCE: evaluation stops at minio-2025-10-15T17-29-55Z, which nixpkgs marks insecure and abandoned, listing six 2026 CVEs.
ABANDON: G5 Production policy correctly refuses the configured abandoned MinIO build. Permitting the insecure package would invalidate rather than satisfy this gate.
- [ ] G6: Fresh QEMU objective, interruption recovery, governed rollback, and exact-tree evidence all pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command qualify-v2-release
  EXPECT: /"outcome": "passed"/
  EVIDENCE: blocked before image execution by G5 and by runtime G5's missing reviewed PostgreSQL/MinIO coordinator repository.
ABANDON: G6 A fresh production-policy image cannot be built, so QEMU behavior and exact-tree release evidence cannot truthfully be asserted.
