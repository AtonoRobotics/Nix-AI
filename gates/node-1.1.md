# Gates: Trust-boundary integration

Scope: ABI, package, and governed-change trust boundaries compose.

- [x] G1: ABI and package suites pass together under strict clippy.
  CHECK: /nix/var/nix/profiles/default/bin/nix develop --command sh -c 'cargo clippy --workspace --all-targets -- -D warnings && echo clippy-ok'
  EXPECT: clippy-ok
  EVIDENCE: warning: Git tree '/home/samuel/nixai' is dirty | Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.08s
