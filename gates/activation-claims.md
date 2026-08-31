# Authoritative activation claim slice

- [x] G1 Expired V2 activations release their wake and append recovery history bound to new protected recovery evidence.
  CHECK: `nix run path:.#test-w05`
  EXPECT: exit 0, zero skips, including recovery evidence rollback/reclaim cases.
  EVIDENCE: `nix run path:.#test-w05` exited 0 on 2026-08-31; 15 live PostgreSQL tests passed with skip_count 0, including publisher-failure rollback and exact recovery-history evidence assertions.

- [x] G2 Capability-set replacement records activation and deactivation against the same CAS-bound publication evidence.
  CHECK: `nix run path:.#test-w05`
  EXPECT: exit 0, including delayed publication rejection and immutable history assertions.
  EVIDENCE: The same live W05 run passed delayed-publication CAS rejection and asserted the replacement evidence ref on both activation and deactivation history rows.

- [x] G3 Garage accepts and reads back canonical state-owned activation recovery evidence.
  CHECK: `nix run path:.#test-w02`
  EXPECT: exit 0, zero skips, including service:state activation.recover evidence.
  EVIDENCE: `nix run path:.#test-w02` exited 0 on 2026-08-31 with live PostgreSQL and Garage, skip_count 0, including canonical `service:state` `activation.recover` put/readback.

- [x] G4 A fresh adversarial review approves the activation-claim slice.
  EVIDENCE: Fourth fresh review by activation_claim_adversarial returned APPROVE after source inspection and an independent live W05 run; no blocker or production fake found.
