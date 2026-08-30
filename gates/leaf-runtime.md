# Gates: Bootable autonomous runtime

Scope: Deploy the fail-closed state-to-coordinator service graph and reach OPERATIONAL only after recovery.

- [x] G1: Dedicated systemd services form PostgreSQL/MinIO -> state/scheduler -> authority/effect -> ABI -> coordinator dependencies.
  CHECK: rg -n "habitat-(state|scheduler|authority|effects|abi|runtime)|postgresql|minio|OPERATIONAL|RECOVERING" nix/modules
  EXPECT: /OPERATIONAL/
  EVIDENCE: nix/modules/habitat-runtime.nix defines ordered state/scheduler/authority/effects/ABI/runtime units, a dedicated habitat-abi-server ExecStart, and per-component socket directories/client groups.
- [x] G2: Runtime tests execute cold boot recovery, wake delivery, objective completion, reconciliation, and continued scheduling.
  CHECK: sh -c 'rustc --edition=2021 --test crates/habitat-runtime/src/lib.rs -o /tmp/habitat-runtime-gate-tests && /tmp/habitat-runtime-gate-tests'
  EXPECT: /test result: ok/
  EVIDENCE: test result: ok. 3 passed; state/scheduler/authority/effects/coordinator RPC integration completes an objective and records the effect in authoritative state.

- [x] G3: Runtime source has no declaration-only entrypoint, TODO, or placeholder implementation.
  CHECK: sh -c '! rg -n "TODO|FIXME|declaration-only|unimplemented!|todo!" crates/habitat-runtime nix/modules/habitat-runtime.nix && echo CLEAN'
  EXPECT: /CLEAN/
  EVIDENCE: CLEAN

- [x] G4: The NixOS runtime module evaluates as part of the conformance profile.
  CHECK: nix-instantiate --parse nix/modules/habitat-runtime.nix
  EXPECT: /habitat-runtime/
  EVIDENCE: ({ config, lib, pkgs, ... }: (let cfg = (config).habitat.runtime; components = [ ("state") ("scheduler") ("authority") ("effects") ("abi") ("runtime") ]; unit = (component: { after = (cfg).dependencie

- [ ] G5: PostgreSQL is the transactional lifecycle/command ledger and MinIO stores content-addressed evidence bytes.
  EVIDENCE: pending
ABANDON: G5 No PostgreSQL/MinIO Rust client or schema exists in the owned runtime crate; credential-file presence is not accepted as proof of persistence readiness. Runtime remains a local durable-state implementation until a reviewed repository/schema migration is added.

- [ ] G6: The current NixOS image evaluates with its configured object store under the normal security policy.
  EVIDENCE: `nix eval --raw .#packages.x86_64-linux.habitat-raw.drvPath` rejects minio-2025-10-15T17-29-55Z as insecure; evaluation otherwise succeeds only with the one-shot NIXPKGS_ALLOW_INSECURE override.
ABANDON: G6 nixpkgs marks the configured MinIO release abandoned and affected by multiple 2026 vulnerabilities. Silently permitting an insecure package is not an acceptable production fix; the object-store design must migrate to a supported S3-compatible service or an explicitly reviewed pinned implementation.
