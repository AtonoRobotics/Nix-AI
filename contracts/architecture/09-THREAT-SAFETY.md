# Threat and safety

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

| Requirement | Boundary | Failure | Enforcement |
| --- | --- | --- | --- |
| AUTH-001 | Context, model output, code, package metadata, and possession of credentials are not grants. | Deny with UNAUTHORIZED. | capability_broker, effect_admission_hook |
| AUTH-002 | A child cannot exceed any parent bound. | Reject without issuing a grant. | attenuation_comparator |
| AUTH-003 | No new consequential operation may use stale authority. | Fail closed; reconcile in-flight effects according to their state. | revocation_epoch, fail_closed_cache |
| AUTH-004 | No ambient credentials or bypass path may exist in activation context or environment. | Deny and emit an attributed security observation. | namespace_policy, lsm_policy, network_policy, secret_provider |
