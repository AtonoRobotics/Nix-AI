# Gates: Runtime coordination module

Scope: one deep runtime coordination module owns objective preparation, resumption, authority/effect mediation, evidence, and completion; UDS translation remains outside it.

- [ ] G1: Obsolete file-backed `DurableState` truth is deleted; coordination uses typed state, authority, and effect interfaces rather than parsing domain decisions from strings.
  CHECK: cargo test -p habitat-runtime --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G2: Public coordinator tests cover cold boot, prepare/resume/inspect, lost wake, stale lease, authority denial, effect uncertainty, restart after each commit boundary, truthful completion, and continued scheduling.
  CHECK: nix run .#test-runtime-live && nix run .#test-boot
  EXPECT: /"outcome": "passed"/
  EVIDENCE: pending

- [ ] G3: UDS protocol dispatch is an adapter; the coordination module passes the deletion test, formatting, and strict clippy with no inline transport implementation, stub, placeholder, or fake.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-runtime --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: pending

- [ ] G4: A fresh adversarial reviewer reports no split truth, string-shaped semantic seam, recovery gap, completion inflation, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G3.
  EVIDENCE: pending
