# Verification matrix

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

| Gate | Runner | Pass condition | Evidence |
| --- | --- | --- | --- |
| V-SCOPE | scope_qualification | unmapped_semantic_count == 0 && inadmissible_source_count == 0 && contaminated_retained_unit_count == 0 | scope-report.json, retention-ledger.json |
| V-CONTRACT | contract_qualification | schema_errors == 0 && reference_errors == 0 && graph_errors == 0 && hash_errors == 0 && stale_generated_count == 0 | contract-report.json, manifest-report.json |
| V-BOOT | qemu_boot_qualification | booted == true && active_human_session_required == false && identity_reported == true | boot-report.json |
| V-ROLLBACK | candidate_rollback_qualification | defective_candidate_confirmed == false && previous_generation_restored == true | defective-rollback-report.json |
| V-STATE | state_crash_migration_restore_qualification | lost_wake_count == 0 && partial_commit_count == 0 && stale_fence_commit_count == 0 && silent_coercion_count == 0 | state-report.json, migration-report.json, backup-restore-report.json |
| V-ABI | abi_conformance | duplicate_execution_count == 0 && semantic_mismatch_count == 0 && removed_semantic_admission_count == 0 | abi-report.json, backend-replacement-report.json |
| V-AUTH | authority_adversarial_qualification | unauthorized_action_count == 0 && widening_delegation_acceptance_count == 0 && post_bound_revoked_invocation_count == 0 | authority-report.json |
| V-ISOLATION | execution_adversarial_qualification | escape_count == 0 && ambient_authority_path_count == 0 && adapter_bypass_count == 0 | isolation-report.json |
| V-CONTEXT | context_fault_qualification | context_created_authority_count == 0 && silent_contradiction_resolution_count == 0 && context_item_without_provenance_count == 0 && unbounded_process_count == 0 | context-report.json |
| V-EFFECT | effect_fault_recovery_qualification | unledgered_external_dispatch_count == 0 && duplicate_effect_execution_count == 0 && blind_retry_count == 0 && premature_completion_count == 0 | effect-report.json |
| V-PACKAGE | package_lifecycle_qualification | invalid_package_staged_count == 0 && silent_rebind_count == 0 && package_core_semantic_admission_count == 0 | package-report.json |
| V-CHANGE | self_change_adversarial_qualification | self_confirmed_candidate_count == 0 && evaluator_capture_count == 0 && in_place_contract_mutation_count == 0 | self-change-report.json |
| V-END-TO-END | headless_interruption_recovery_qualification | objective_completed == true && active_human_session_required == false && lost_work_count == 0 && duplicate_effect_count == 0 && independent_evidence_verified == true | end-to-end-report.json |
