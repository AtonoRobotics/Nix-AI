# Gates: Live qualification evidence

Scope: Make every applicable V2 gate produce independently verifiable structured live evidence and reject synthetic or incomplete claims.

- [ ] G1: Every gate runner supplies a structured result with an explicit outcome, exercised action boundary, required deployed services, and artifact/source/closure bindings; no gate is exempted as “not applicable.”
  CHECK: python3 -m unittest tests.test_v2_release_qualification tests.test_packet_qualification_runners -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G2: Adversarial fixtures prove missing observations, process-only success, skips, stale evidence, digest mismatch, and malformed V-CHANGE results fail closed.
  CHECK: python3 -m unittest tests.test_v2_release_qualification.ReleaseVerifierTests tests.test_packet_qualification_runners.PacketRunnerAdversarialTests -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G3: A checked per-gate observation matrix requires deployed action-boundary observations for V-AUTH, V-EFFECT, and V-CHANGE, and derives their acceptance metrics exclusively from those observations.
  CHECK: python3 -m unittest tests.test_v2_release_qualification -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G4: A fresh adversarial agent found no process-only proof, mock-only proof, synthetic-pass path, unbound evidence, missing action-boundary observation, bug, or V2 drift.
  EVIDENCE: pending

- [ ] G5: Driver independently reran G1-G3 after review; the approved source packet was committed and pushed before the next packet began.
  EVIDENCE: pending
