# Activation-bound command ledger slice

- [x] G1 Activation validation and command compare/insert occur in one PostgreSQL transaction.
  CHECK: `nix run path:.#test-w05`
  EXPECT: exact replay returns the original result; forged/stale binding and bad credential make zero ledger mutation.
  EVIDENCE: 2026-08-31 `nix run path:.#test-w05` passed 15 live PostgreSQL tests with zero skips; the activation test covers exact replay, forged fence/credential rejection, two concurrent first commits, and one immutable ledger row.

- [x] G2 Digest mismatch and unavailable/corrupt evidence fail closed without semantic overwrite.
  CHECK: `nix run path:.#test-w05`
  EXPECT: mismatch returns the committed disposition and immutable row count remains one.
  EVIDENCE: The same live run verified canonical digest rejection, typed mismatch returning the original result, stored-evidence revalidation, exact six-field result validation, and no overwrite.

- [x] G3 A fresh adversarial review approves the atomic activation-command slice.
  EVIDENCE: Fresh review approved the isolated authoritative-state subset after verifying transaction, replay, evidence, result-shape, concurrency, authorization, and legacy-route invariants. Rust ABI/Nix deployment is explicitly excluded for a later vertical slice.
