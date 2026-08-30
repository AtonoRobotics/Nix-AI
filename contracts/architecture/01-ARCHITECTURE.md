# Architecture

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

## Records

`Machine`, `SystemGeneration`, `Agent`, `Objective`, `Wake`, `Activation`, `Lease`, `ContextRequest`, `ContextBundle`, `CapabilityDefinition`, `Grant`, `Revocation`, `AuthorityDecision`, `Command`, `Effect`, `EffectAttempt`, `Observation`, `Reconciliation`, `Package`, `PackageEvaluation`, `ActivationSet`, `EvidenceObject`, `ChangeProposal`, `QualificationResult`

## Services and ownership

| Service | Owns | Must not own |
| --- | --- | --- |
| bootstrap | recovery_order, readiness | objectives, effect_execution |
| identity | principal_identity, activation_identity | authority_policy, effects |
| state | transactional_truth, transition_history | cognition, external_effects |
| scheduler | wakes, leases, activation_admission | effect_execution, authority_policy |
| context | context_requests, context_bundles, context_provenance | authority, effect_execution |
| authority | grants, revocations, decisions | provider_credentials, effects, cognition |
| effect | reservations, attempts, observations, reconciliation | cognition, grant_issuance |
| execution | isolation, resources, workspaces | semantic_authority, durable_agent_identity |
| cognition | normalized_reasoning_invocation | durable_agent_identity, effects, authority |
| package | package_admission, activation_sets | self_approval, system_signing |
| evidence | protected_evidence, evidence_references | evaluated_execution, completion_policy |
| generation | build, stage, activation, rollback | unilateral_evaluation, unilateral_signing |
