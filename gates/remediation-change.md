# Gates: Governed-change binding

Scope: Make every candidate binding mandatory and immutable before evaluation or signing.

- [ ] G1: Empty or malformed source, dependency-closure, test, evidence, threshold, contract-version, or rollback bindings are rejected before signing.
  CHECK: cargo test -p habitat-packages --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G2: Valid proposals retain their exact bindings through build, independent evaluation, signing, staging, activation, confirmation, and rollback.
  CHECK: cargo test -p habitat-packages --test lifecycle
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G3: Governed-change packet is formatting- and strict-clippy-clean.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-packages --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: pending

- [ ] G4: A live candidate-chain report binds every CHANGE-002 field, rejects mutation after every transition, and derives `unbound_signed_candidate_count == 0` from observed attempts rather than unit-test names.
  CHECK: python3 tools/qualify_v2_change.py --root . --output /tmp/v2-change-report.json && python3 -c 'import json; value=json.load(open("/tmp/v2-change-report.json")); assert value["outcome"] == "passed" and value["metrics"]["unbound_signed_candidate_count"] == 0; print("live-change-ok")'
  EXPECT: /live-change-ok/
  EVIDENCE: pending

- [ ] G5: A fresh adversarial agent found no unbound signing path, binding mutation, state-machine bypass, synthetic evidence, bug, or V2 drift.
  EVIDENCE: pending

- [ ] G6: Driver independently reran G1-G4 after review; the approved source packet was committed and pushed before the next packet began.
  EVIDENCE: pending
