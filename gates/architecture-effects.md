# Gates: Durable effect execution module

Scope: the deployed effect path owns admission, reservation, authorization, dispatch, uncertainty, observation, reconciliation, compensation, evidence, and terminal disposition behind one interface.

- [ ] G1: The deployed request preserves command identity, request digest, idempotency key, current authority decision, provider contract/operation, objective, activation, generation, and evidence bindings through every durable transition.
  CHECK: cargo test -p habitat-effects --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G2: PostgreSQL performs atomic reservation and state transitions; the direct `RECORD_EFFECT` → `COMMITTED` shortcut is deleted, and duplicate/uncertain/crash outcomes reconcile without blind redispatch.
  CHECK: nix run .#test-runtime-live && nix run .#test-w05
  EXPECT: /"outcome": "passed"/
  EVIDENCE: pending

- [ ] G3: Provider behavior remains behind a real adapter seam with production and deterministic conformance adapters; objective completion is blocked until truthful terminal observation.
  CHECK: cargo test -p habitat-effects --test admission --test fault_matrix
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G4: Formatting and strict clippy pass; the module passes the deletion test and contains no alternate in-memory production ledger, stub, placeholder, or fake.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-effects --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: pending

- [ ] G5: A fresh adversarial reviewer reports no duplicate-dispatch path, terminal-state shortcut, authority drift, reconciliation gap, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G4.
  EVIDENCE: pending
