# Gates: Authenticated UDS transport module

Scope: one deep Rust module owns bounded framing, socket lifecycle, typed peer principals, allowlists, permissions, and readiness transport for every local runtime caller.

- [ ] G1: Authority, effects, and runtime use the shared transport module; duplicate `SO_PEERCRED`, framing, query, stale-socket, and permission implementations are removed.
  CHECK: rg -n 'SO_PEERCRED|getsockopt|UnixStream::connect|read_line' crates/habitat-authority crates/habitat-effects crates/habitat-runtime
  EXPECT: no production transport implementation outside habitat-uds
  EVIDENCE: pending

- [ ] G2: Public-seam tests reject forged/disallowed peers, oversized or partial frames, malformed UTF-8/JSON, stale socket replacement, disconnects, and permissive modes while admitting an allowlisted typed principal.
  CHECK: cargo test -p habitat-uds --all-targets
  EXPECT: /test result: ok/
  EVIDENCE: pending

- [ ] G3: The module passes the deletion test, formatting, and strict clippy; no stub, placeholder, fake, or pass-through-only interface remains.
  CHECK: cargo fmt --all -- --check && cargo clippy -p habitat-uds --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: pending

- [ ] G4: A fresh adversarial reviewer reports no transport bypass, identity drift, framing bug, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G3.
  EVIDENCE: pending
