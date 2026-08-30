# Gates: Live qualification and evidence

Scope: Derive every gate from real command/QEMU observations with independently verifiable attestations.

- [x] G1: Qualification rejects skips, missing services, stale/handwritten evidence, and hash mismatches.
  CHECK: python3 -m unittest tests.test_v2_release_qualification -v
  EXPECT: /OK/
  EVIDENCE: Ran 7 tests in 0.070s | OK
- [x] G2: Every command attestation binds source, closure, argv, status, timestamps, output/artifact digests, and runner.
  CHECK: python3 -m unittest tests.test_v2_release_qualification.QualificationPrimitiveTests -v
  EXPECT: /OK/
  EVIDENCE: Ran 3 tests in 0.073s | OK
- [x] G3: The release verifier accepts only 13 complete live gates and all W00-W13 packet results.
  CHECK: python3 -m unittest tests.test_v2_release_qualification.ReleaseVerifierTests -v
  EXPECT: /OK/
  EVIDENCE: Ran 4 tests in 0.043s | OK
