# Gates: Resolve every architecture-review candidate

Scope: all six modules are deep, integrated, adversarially approved, exactly qualified, committed, and pushed without stubs, placeholders, fakes, drift, or goal hacking.

- [ ] G1: Authenticated transport gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-transport.md
  EXPECT: /4\/4 met/
  EVIDENCE: pending

- [ ] G2: Authoritative state gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-state.md
  EXPECT: /4\/4 met/
  EVIDENCE: pending

- [ ] G3: Durable effect gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-effects.md
  EXPECT: /5\/5 met/
  EVIDENCE: pending

- [ ] G4: Runtime coordination gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-runtime.md
  EXPECT: /4\/4 met/
  EVIDENCE: pending

- [ ] G5: Qualification gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-qualification.md
  EXPECT: /5\/5 met/
  EVIDENCE: pending

- [ ] G6: Deployment graph gates are fully met.
  CHECK: node /home/samuel/.agents/skills/unlazy/scripts/gate-check.mjs --status gates/architecture-deployment.md
  EXPECT: /5\/5 met/
  EVIDENCE: pending

- [ ] G7: Fresh combined-tree adversarial review reports no unresolved gap, drift, bug, shallow module, seam leak, stub, placeholder, fake, or unqualified behavior.
  EVIDENCE: pending

- [ ] G8: Exact frozen-tree Python, Rust, contracts, artifacts, normal-policy flake, live QEMU objective/interruption/effect/rollback, W00-W13, and all release predicates pass.
  CHECK: nix run .#test-all-python && nix develop --command sh -c 'cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace' && nix flake check --show-trace && nix run .#qualify-v2-release && nix run .#test-w13
  EXPECT: all commands exit 0
  EVIDENCE: pending

- [ ] G9: Reviewable commits are pushed to the configured upstream `main`, remote SHA equals local HEAD, and exact-tree release evidence binds that pushed non-evidence source.
  EVIDENCE: pending
