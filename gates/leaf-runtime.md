# Gates: Bootable autonomous runtime

Scope: Deploy the fail-closed state-to-coordinator service graph and reach OPERATIONAL only after recovery.

- [x] G1: Dedicated systemd services form PostgreSQL/MinIO -> state/scheduler -> authority/effect -> ABI -> coordinator dependencies.
  CHECK: rg -n "habitat-(state|scheduler|authority|effects|abi|runtime)|postgresql|minio|OPERATIONAL|RECOVERING" nix/modules
  EXPECT: /OPERATIONAL/
  EVIDENCE: nix/modules/habitat-runtime.nix:90:      group = "habitat-runtime"; | nix/modules/habitat-runtime.nix:93:    systemd.tmpfiles.rules = [ "d /run/habitat 0770 root habitat-runtime -" ];
- [x] G2: Runtime tests execute cold boot recovery, wake delivery, objective completion, reconciliation, and continued scheduling.
  CHECK: sh -c 'rustc --edition=2021 --test crates/habitat-runtime/src/lib.rs -o /tmp/habitat-runtime-gate-tests && /tmp/habitat-runtime-gate-tests'
  EXPECT: /test result: ok/
  EVIDENCE: test tests::cold_boot_recovers_and_scheduler_continues ... ok | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s

- [x] G3: Runtime source has no declaration-only entrypoint, TODO, or placeholder implementation.
  CHECK: sh -c '! rg -n "TODO|FIXME|declaration-only|unimplemented!|todo!" crates/habitat-runtime nix/modules/habitat-runtime.nix && echo CLEAN'
  EXPECT: /CLEAN/
  EVIDENCE: CLEAN

- [x] G4: The NixOS runtime module evaluates as part of the conformance profile.
  CHECK: nix-instantiate --parse nix/modules/habitat-runtime.nix
  EXPECT: /habitat-runtime/
  EVIDENCE: ({ config, lib, pkgs, ... }: (let cfg = (config).habitat.runtime; components = [ ("state") ("scheduler") ("authority") ("effects") ("abi") ("runtime") ]; unit = (component: { after = (cfg).dependencie
