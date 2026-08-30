# Nix AI v2 build specification

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

## Execution order

| Order | Action | Blocked by |
| --- | --- | --- |
| 1 | record_actual_baseline_commit | — |
| 2 | install_immutable_v2_contract_package | 1 |
| 3 | inventory_all_tracked_paths_symbols_dependencies_generated_outputs_and_build_closure | 2 |
| 4 | apply_disposition_and_retention_classification | 3 |
| 5 | delete_all_DELETE_targets | 4 |
| 6 | replace_W00_contracts_schemas_registries_graph_and_validators | 5 |
| 7 | delete_and_rebuild_authority_and_effects | 6 |
| 8 | audit_retention_candidates_and_rebuild_failures | 6 |
| 9 | regenerate_all_generated_artifact_classes | 7, 8 |
| 10 | rebuild_clean_cargo_and_nix_closures | 9 |
| 11 | run_all_work_packet_and_verification_gates | 10 |
| 12 | run_final_semantic_scope_and_closure_audit | 11 |
| 13 | emit_migration_retention_deletion_and_qualification_evidence | 12 |
| 14 | evaluate_completion_predicate | 13 |

## Work packets

| Packet | Deliverable | Gates |
| --- | --- | --- |
| W00 | immutable_v2_contracts_schemas_registries_graph_generators_validators | V-SCOPE, V-CONTRACT |
| W01 | reproducible_image_and_generic_hardware_profiles | V-BOOT, V-ROLLBACK |
| W02 | authoritative_state_and_protected_evidence | V-STATE |
| W03 | agent_abi_and_authenticated_local_transport | V-ABI |
| W04 | identity_and_capability_authority | V-AUTH |
| W05 | objectives_wakes_activations_scheduler_and_leases | V-STATE, V-ABI |
| W06 | execution_isolation_and_resource_enforcement | V-ISOLATION |
| W07 | context_compiler_and_broker | V-CONTEXT |
| W08 | durable_effect_service_and_reconciliation | V-EFFECT |
| W09 | provider_neutral_cognition_interface_and_adapter_conformance | V-ABI, V-CONTEXT |
| W10 | signed_capability_package_controller | V-PACKAGE |
| W11 | optional_harness_adapter_conformance | V-ABI, V-ISOLATION |
| W12 | governed_self_change_system_generations_and_recovery | V-CHANGE, V-ROLLBACK |
| W13 | complete_release_qualification | V-SCOPE, V-CONTRACT, V-BOOT, V-ROLLBACK, V-STATE, V-ABI, V-AUTH, V-ISOLATION, V-CONTEXT, V-EFFECT, V-PACKAGE, V-CHANGE, V-END-TO-END |
