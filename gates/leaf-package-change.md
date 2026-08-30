# Gates: Content-bound package admission and governed change

Scope: Verify candidate bytes independently and enforce protected evaluation, activation, confirmation, and rollback.

- [x] G1: Admission hashes bundle bytes and independently verifies signature, provenance, SBOM, closure, authority/resources, ABI, migration, and live probe.
  CHECK: /nix/var/nix/profiles/default/bin/nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#rustfmt nixpkgs#clippy --command cargo test -p habitat-packages
  EXPECT: /test result: ok/
  EVIDENCE: admission.rs: 3 passed; byte/material tampering, policy violations, failed live probe, and staging race rejected without mutation.
- [x] G2: Governed change has durable proposal through rollback states and rejects evaluator capture/self-confirmation.
  CHECK: /nix/var/nix/profiles/default/bin/nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#rustfmt nixpkgs#clippy --command cargo test -p habitat-packages
  EXPECT: /test result: ok/
  EVIDENCE: lifecycle.rs: 4 passed; durable restore, protected evaluator, rejection, self-confirmation denial, quarantine, and rollback exercised.
- [x] G3: The package crate is formatted and warning-free under strict Clippy.
  CHECK: /nix/var/nix/profiles/default/bin/nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#rustfmt nixpkgs#clippy --command cargo clippy -p habitat-packages --all-targets -- -D warnings
  EXPECT: /Finished/
  EVIDENCE: Finished dev profile; zero warnings under -D warnings. cargo fmt --all -- --check exited 0.
