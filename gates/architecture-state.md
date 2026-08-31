# Gates: Authoritative state module

Scope: one authoritative state seam hides transactional PostgreSQL lifecycle/replay implementation and the Garage evidence adapter; UDS translation and process wiring are separate modules.

- [ ] G1: Storage adapters, authoritative transactions, UDS protocol translation, and process composition are separate deep modules; `command_ledger.py` no longer mixes all four responsibilities.
  CHECK: python3 -m unittest tests.test_w02_state tests.test_w05_lifecycle -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G2: Every objective, wake, activation, command, effect, package, and change transition crosses the authoritative state interface and remains atomic, replay-safe, restart-safe, and fail-closed under PostgreSQL/Garage outage or corruption.
  CHECK: nix run .#test-w02 && nix run .#test-w05
  EXPECT: /"outcome": "passed"/
  EVIDENCE: pending

- [ ] G3: No alternate file-backed lifecycle truth, direct SQL from protocol handlers, or Garage-specific behavior above the evidence adapter seam remains.
  CHECK: python3 tools/verify_v2_drift.py --root .
  EXPECT: /drift-free/
  EVIDENCE: pending

- [ ] G4: A fresh adversarial reviewer reports no transaction leak, split truth, recovery gap, storage coupling, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G3.
  EVIDENCE: pending
