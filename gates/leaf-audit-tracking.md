# Gates: Audit classification and tracking

Scope: Separate historical disposition from current retained-core audit and keep work durably tracked.

- [x] G1: Current source is exhaustively singly owned, V2-mapped, and free of prohibited concepts/stale evidence.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command python -m unittest tests.test_v2_core_audit tests.test_v2_scope_classification -v
  EXPECT: /OK/
  EVIDENCE: Exact Nix gate passed 22 tests in 18.496s (OK); generated current audit is valid with 63 candidate files, 40 source units, 18 tests, 5 fixtures, 61 dependency records, and zero unresolved candidates.
- [x] G2: Production completion parent and subsystem child issues exist with dependencies and acceptance criteria.
  EVIDENCE: Parent #31; children #32-#36; parent comment records links and recovery refs.
