# Gates: Release qualification evidence module

Scope: canonical evidence attestation/verification is one deep module; each gate owns live execution and observation-to-metric meaning; orchestration is declarative.

- [ ] G1: Canonical hashing, source/closure identity, execution attestation, artifact binding, structured-result validation, report serialization, and verification have one implementation and one mutation-tested interface.
  CHECK: python3 -m unittest tests.test_v2_release_qualification tests.test_packet_qualification_runners -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G2: Gate definitions own their required actions, deployed dependencies, observations, and metric derivation; the orchestrator contains no gate-name switch, synthesized pass claim, or runner-argv identity inference.
  CHECK: python3 tools/verify_v2_drift.py --root .
  EXPECT: /drift-free/
  EVIDENCE: pending

- [ ] G3: Every W00-W13/V gate fails closed on missing action observation, skipped execution, process-only success, handwritten result, stale source/closure, digest mismatch, malformed evidence, or unavailable required deployment.
  CHECK: nix run .#test-all-python
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G4: The module passes the deletion test; packet modules add gate meaning rather than forwarding boilerplate, and no stub, placeholder, fake, or tautological evidence exists.
  CHECK: python3 -m compileall -q tools tests
  EXPECT: exit 0
  EVIDENCE: pending

- [ ] G5: A fresh adversarial reviewer reports no synthetic pass, stale binding, duplicated canonical JSON, gate switch drift, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G4.
  EVIDENCE: pending
