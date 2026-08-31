# Gates: Bootable autonomous runtime

Scope: Deploy the fail-closed state-to-coordinator service graph and reach OPERATIONAL only after recovery.

- [x] G1: Dedicated systemd services form PostgreSQL/Garage -> state/scheduler -> authority/effect -> ABI -> coordinator dependencies.
  CHECK: rg -n "habitat-(state|scheduler|authority|effects|abi|runtime)|postgresql|garage|OPERATIONAL|RECOVERING" nix/modules
  EXPECT: /OPERATIONAL/
  EVIDENCE: Fresh QEMU boot started Garage, completed `habitat-garage-initialize`, then started state, command ledger, scheduler, authority, effects, ABI, and runtime in dependency order before reaching multi-user.
- [x] G2: Runtime tests execute cold boot recovery, wake delivery, objective completion, reconciliation, and continued scheduling.
  CHECK: sh -c 'rustc --edition=2021 --test crates/habitat-runtime/src/lib.rs -o /tmp/habitat-runtime-gate-tests && /tmp/habitat-runtime-gate-tests'
  EXPECT: /test result: ok/
  EVIDENCE: test result: ok. 4 passed; state/scheduler/authority/effects/coordinator RPC integration prepares, resumes, completes, and replays an objective while recording the effect in authoritative state.

- [x] G3: Runtime source has no declaration-only entrypoint, TODO, or placeholder implementation.
  CHECK: sh -c '! rg -n "TODO|FIXME|declaration-only|unimplemented!|todo!" crates/habitat-runtime nix/modules/habitat-runtime.nix && echo CLEAN'
  EXPECT: /CLEAN/
  EVIDENCE: CLEAN

- [x] G4: The NixOS runtime module evaluates as part of the conformance profile.
  CHECK: nix-instantiate --parse nix/modules/habitat-runtime.nix
  EXPECT: /habitat-runtime/
  EVIDENCE: ({ config, lib, pkgs, ... }: (let cfg = (config).habitat.runtime; components = [ ("state") ("scheduler") ("authority") ("effects") ("abi") ("runtime") ]; unit = (component: { after = (cfg).dependencie

- [x] G5: PostgreSQL is the transactional lifecycle/command ledger and Garage stores content-addressed evidence bytes through the S3 boundary.
  CHECK: nix run .#test-boot
  EXPECT: /"gate": "V-BOOT".*"result": "pass"/
  EVIDENCE: Strict two-boot QEMU qualification passed with zero skips. Baseline and candidate each completed a fresh objective to PostgreSQL `SATISFIED` / `COMMITTED`; the verifier fetched each `s3://habitat-evidence/sha256/<digest>` object from Garage, matched its SHA-256 and objective binding, and confirmed duplicate resume returned the committed disposition. The runtime events truthfully report `interruptions: []`; interruption recovery remains a separate open gate.

- [x] G6: The current NixOS image evaluates with Garage under the normal security policy.
  CHECK: nix eval --raw .#packages.x86_64-linux.habitat-raw.drvPath
  EXPECT: /habitat-raw\.drv/
  EVIDENCE: Normal-policy evaluation produced `/nix/store/2s57nrz08d5ymym1wihycimqb42s0b79-habitat-raw.drv`; `nix build .#habitat-raw` built `/nix/store/1jfyhz1zdn5by4k0mzlzf3zc1s7ihq65-habitat-raw.drv` without an insecure-package override.
