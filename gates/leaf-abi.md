# Gates: ABI identity and durable replay

Scope: Bind every command to authenticated activation context and make replay fail closed.

- [x] G1: ABI requests carry all canonical identity, lease, generation, deadline, trace, evidence, and credential bindings.
  CHECK: rg -n "machine_id|agent_id|objective_id|lease_fence|system_generation_id|capability_activation_set_id|deadline|trace_id|evidence_refs|activation_credential" contracts/proto/nix_ai_agent_v2.proto
  EXPECT: /activation_credential/
  EVIDENCE: `RequestBinding` lines 23-37 carries schema/command/machine/agent/objective/activation/fence/generation/capability-set/deadline/trace/evidence/credential; every RPC request embeds it.
- [x] G2: Missing/forged/expired/stale bindings and peer mismatch are rejected without mutation.
  CHECK: env PATH=/nix/store/gxyz15yg1gjm2bcf7g4svy50w2ahvbrp-cargo-1.95.0/bin:/nix/store/4838cpsffgmc4xw856y0zdpvgssjljm0-rustc-1.95.0/bin:/usr/bin:/bin cargo test -p habitat-abi
  EXPECT: /test result: ok/
  EVIDENCE: 2026-08-30 transport suite passed; `invalid_bindings_fail_before_ledger_mutation` covers every required field, forged credential, expiration, stale fence, command/activation/scope mismatch, and verifies no ledger file; peer mismatch is separately exercised.
- [x] G3: PostgreSQL/state-service replay fails closed on corruption/unavailability and exact duplicates return the committed result.
  CHECK: env PATH=/nix/store/gxyz15yg1gjm2bcf7g4svy50w2ahvbrp-cargo-1.95.0/bin:/nix/store/4838cpsffgmc4xw856y0zdpvgssjljm0-rustc-1.95.0/bin:/usr/bin:/bin cargo test -p habitat-abi
  EXPECT: /test result: ok/
  EVIDENCE: Escalated `cargo test -p habitat-abi` passed 6 tests, including exact duplicate/restart replay, digest mismatch INTERNAL, unavailable/corrupt repository INTERNAL, and direct UDS authoritative/malformed-response coverage; no local ledger remains.

- [x] G4: State and lifecycle focused tests pass against provisioned PostgreSQL and MinIO with zero skips.
  CHECK: .venv/bin/python tools/qualify_w02.py --evidence-dir /tmp/nixai-w02-evidence && .venv/bin/python tools/qualify_w05.py --evidence-dir /tmp/nixai-w05-evidence
  EXPECT: /"outcome": "passed"/
  EVIDENCE: W02 provisioned PostgreSQL+MinIO and passed 7 live state tests with skip_count=0; W05 provisioned PostgreSQL and passed 4 live lifecycle/effect tests with skip_count=0.
