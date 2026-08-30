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

## Packet runner integration leaf

- [x] G4: Every retained W00-W11 packet CLI emits an executed command attestation with artifact digests and a structured behavioral result; no runner infers acceptance from test names or source strings.
  CHECK: python3 -m unittest tests.test_packet_qualification_runners -v
  EXPECT: /OK/
  EVIDENCE: Ran 7 tests in 0.090s | OK; rg found no --list/test_names inference in owned runners.
- [x] G5: Packet runners fail closed for skipped tests, absent required live services, failed behavioral assertions, missing artifacts, and unsuccessful commands.
  CHECK: python3 -m unittest tests.test_packet_qualification_runners.PacketRunnerAdversarialTests -v
  EXPECT: /OK/
  EVIDENCE: Ran 5 adversarial tests in 0.069s | OK
- [x] G6: All dependency-independent owned runner tests pass without qualification skips; live suites are forced to fail if their configured service run skips.
  CHECK: python3 -m unittest tests.test_w00_qualification tests.test_w01_profile tests.test_packet_qualification_runners -v
  EXPECT: /OK/
  EVIDENCE: Ran 11 tests in 0.482s | OK; pinned-environment discovery run exposed 9 expected service-unconfigured skips, and strict_unittest_argv now converts any such runner skip to failure.
