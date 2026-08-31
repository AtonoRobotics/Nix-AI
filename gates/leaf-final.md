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
- [x] G4: Complete Python suite passes with zero skips.
  CHECK: /nix/var/nix/profiles/default/bin/nix run .#test-python
  EXPECT: /OK/
  EVIDENCE: The unified runner provisioned pinned PostgreSQL 17 and Garage, supplied the pinned contract toolchain, and completed 99 tests in 37.675 seconds: `OK`, zero skips.
- [ ] G5: Nix flake check passes.
  CHECK: /nix/var/nix/profiles/default/bin/nix flake check --show-trace && echo flake-ok
  EXPECT: flake-ok
  EVIDENCE: pending Garage migration and full flake check
- [ ] G6: Fresh QEMU objective, interruption recovery, governed rollback, and exact-tree evidence all pass.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command qualify-v2-release
  EXPECT: /"outcome": "passed"/
  EVIDENCE: `nix run .#test-boot` and `nix run .#test-rollback` pass with live PostgreSQL/Garage objectives and two coordinator SIGKILL/replacement boundaries per boot. Final release-orchestrator execution and exact-tree evidence regeneration remain pending, so this aggregate gate stays open.
