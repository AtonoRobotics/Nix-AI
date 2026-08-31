# State-owned activation fence allocation

- [x] G1 PostgreSQL allocates the next lease fence while holding the objective activation and wake locks.
  CHECK: `nix run path:.#test-w05`
  EXPECT: initial claim receives fence 1; expiry recovery releases the wake; reclaim receives fence 2; stale and future fences fail resolution.
  EVIDENCE: 2026-08-31 live W05 passed 16 PostgreSQL tests with zero skips, including state-evidence publication rollback and replay outage cases.

- [x] G2 Scheduler claim input and protected claim evidence cannot assert a lease fence.
  CHECK: `rg -n 'expected_lease_fence' src tests`
  EXPECT: no match.
  EVIDENCE: 2026-08-31 exact search returned no matches.

- [x] G3 A fresh adversarial review approves state-owned allocation and replay semantics.
  EVIDENCE: Fresh review approved transaction-owned fence derivation, complete state-produced binding evidence, fail-closed replay verification, rollback, concurrency, and reclaim behavior.
