# Gates: Close every V2 review and release gap

Scope: Prove all four remediation packets compose into an exact-tree V2.0.1 release with no unresolved review finding.

- [ ] G1: Runtime trust and durable ownership packet is fully verified and pushed.
  CHECK: node /home/samuel/.codex/skills/unlazy/scripts/gate-check.mjs --status gates/remediation-runtime.md
  EXPECT: /7\/7 met/
  EVIDENCE: pending

- [ ] G2: Governed-change binding packet is fully verified and pushed.
  CHECK: node /home/samuel/.codex/skills/unlazy/scripts/gate-check.mjs --status gates/remediation-change.md
  EXPECT: /6\/6 met/
  EVIDENCE: pending

- [ ] G3: Live qualification evidence packet is fully verified and pushed.
  CHECK: node /home/samuel/.codex/skills/unlazy/scripts/gate-check.mjs --status gates/remediation-qualification.md
  EXPECT: /5\/5 met/
  EVIDENCE: pending

- [ ] G4: Exact-tree release and drift closure packet is fully verified and pushed.
  CHECK: node /home/samuel/.codex/skills/unlazy/scripts/gate-check.mjs --status gates/remediation-release.md
  EXPECT: /8\/8 met/
  EVIDENCE: pending

- [ ] G5: A final fresh adversarial reviewer approves the combined tree with no unresolved V2 requirement gap, drift, or bug.
  EVIDENCE: pending

- [ ] G6: The frozen non-evidence source commit has no later non-evidence changes, and the binding V2 completion predicate verifies against its exact digest; final push verification is emitted only under excluded `evidence/remediation/`.
  CHECK: python3 tools/verify_v2_drift.py --root . && nix run .#test-w13
  EXPECT: /V2 release evidence is complete and valid/
  EVIDENCE: pending
