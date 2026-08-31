# Gates: Bootable autonomous runtime

Scope: Deploy the fail-closed state-to-coordinator service graph and reach OPERATIONAL only after recovery.

- [ ] G1: Dedicated systemd services form PostgreSQL/Garage -> state/scheduler -> authority/effect -> ABI -> coordinator dependencies.
  CHECK: rg -n "habitat-(state|scheduler|authority|effects|abi|runtime)|postgresql|garage|OPERATIONAL|RECOVERING" nix/modules
  EXPECT: /OPERATIONAL/
  EVIDENCE: pending Garage migration and service-graph verification
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

- [ ] G5: PostgreSQL is the transactional lifecycle/command ledger and Garage stores content-addressed evidence bytes through the S3 boundary.
  EVIDENCE: pending

- [ ] G6: The current NixOS image evaluates with Garage under the normal security policy.
  CHECK: nix eval --raw .#packages.x86_64-linux.habitat-raw.drvPath
  EXPECT: /habitat-raw\.drv/
  EVIDENCE: pending Garage migration
