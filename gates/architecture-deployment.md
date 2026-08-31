# Gates: Canonical deployment graph module

Scope: one canonical module owns deployment identities, dependency/readiness edges, credential relationships, and graph validation; Nix composition, runtime readiness, and conformance consume it.

- [ ] G1: Repeated graph names/edges are removed from `flake.nix`, runtime Rust, and Nix declarations; all three projections are derived from one canonical graph and checked for equality.
  CHECK: nix eval .#checks.x86_64-linux.deployment-graph --apply 'x: x.drvPath' --raw
  EXPECT: /nix\/store/
  EVIDENCE: pending

- [ ] G2: QEMU conformance implementation is a normal test module rather than Python embedded in `flake.nix`; `flake.nix` composes packages, apps, checks, and images without owning conformance behavior.
  CHECK: python3 -m unittest tests.test_w01_profile -v
  EXPECT: /OK/
  EVIDENCE: pending

- [ ] G3: Graph validation rejects cycles, absent identities, readiness mismatches, credential-edge drift, and undeclared runtime clients; normal-policy image evaluation passes.
  CHECK: nix flake check --show-trace
  EXPECT: /all checks passed/
  EVIDENCE: pending

- [ ] G4: The graph module passes the deletion test and contains no duplicated projection, stub, placeholder, fake, or speculative adapter.
  CHECK: nix-instantiate --parse nix/lib/habitat-deployment-graph.nix >/dev/null && nix-instantiate --parse nix/modules/habitat-runtime.nix >/dev/null
  EXPECT: exit 0
  EVIDENCE: pending

- [ ] G5: A fresh adversarial reviewer reports no graph drift, deployment mismatch, embedded behavior, shallow forwarding, stub, placeholder, or fake; driver fixes all findings and reruns G1-G4.
  EVIDENCE: pending
