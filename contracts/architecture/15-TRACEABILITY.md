# Traceability

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

| Requirement | Owner | Source | Evidence | Acceptance |
| --- | --- | --- | --- | --- |
| SCOPE-001 | W00 | user-directive:2026-08-30:keep-only-non-domain-specific | scope-report.json | unmapped_semantic_count == 0 and inadmissible_source_count == 0 |
| SCOPE-002 | W00 | user-directive:2026-08-30:delete-domain-specific-implementation | deletion-report.json, retention-ledger.json | contaminated_retained_unit_count == 0 |
| SCOPE-003 | W00 | SCOPE-001 | manifest-report.json, contract-mutation-negative-test.json | all_contract_hashes_match == true and released_contract_modified == false |
| CORE-001 | W03 | project-goal:autonomous-governed-agents-inside-os-habitat | backend-replacement-report.json, activation-recovery-report.json | agent_id is unchanged across backend replacement and host restart |
| CORE-002 | W05 | project-goal:autonomous-real-work | headless-autonomy-report.json | end_to_end_objective_completed_without_active_human_session == true |
| SYS-001 | W01 | CORE-002 | reproducibility-report.json, closure-report.json | two_clean_builds_match == true or accepted_nondeterministic_input_count == declared_count |
| SYS-002 | W01 | CORE-002 | candidate-confirmation-report.json, defective-rollback-report.json | defective_candidate_confirmed == false and previous_generation_restored == true |
| SYS-003 | W12 | CORE-002 | interruption-recovery-report.json | lost_wake_count == 0 and duplicate_effect_count == 0 and stale_lease_admission_count == 0 |
| SYS-004 | W01 | SCOPE-001 | hardware-profile-report.json | undeclared_feature_count == 0 and over_capacity_admission_count == 0 |
| STATE-001 | W02 | CORE-001 | transaction-crash-matrix.json, duplicate-command-report.json | partial_commit_count == 0 and duplicate_execution_count == 0 |
| STATE-002 | W05 | CORE-002 | wake-crash-matrix.json, lease-fencing-report.json | lost_wake_count == 0 and stale_fence_commit_count == 0 |
| STATE-003 | W02 | SYS-003 | migration-report.json, backup-restore-report.json | silent_coercion_count == 0 and restored_reference_failure_count == 0 |
| STATE-004 | W02 | STATE-001 | projection-staleness-report.json | unlabelled_stale_response_count == 0 |
| ABI-001 | W03 | CORE-001 | abi-envelope-report.json | invalid_envelope_mutation_count == 0 |
| ABI-002 | W03 | STATE-001 | duplicate-command-report.json | replayed_handler_execution_count == 0 |
| ABI-003 | W09 | CORE-001 | backend-replacement-report.json | cross_backend_semantic_mismatch_count == 0 |
| ABI-004 | W03 | SCOPE-001 | v1-rejection-report.json | removed_semantic_admission_count == 0 |
| CTX-001 | W07 | project-decision:context-injection-on-recognized-need | context-fault-report.json | unlabelled_missing_context_count == 0 and context_created_authority_count == 0 |
| CTX-002 | W07 | CTX-001 | context-provenance-report.json | context_item_without_provenance_count == 0 |
| CTX-003 | W07 | CTX-001 | context-contradiction-report.json | silent_contradiction_resolution_count == 0 |
| CTX-004 | W07 | project-decision:process-context-only-when-necessary | metacognitive-hint-report.json | unbounded_process_count == 0 and eligible_hint_omission_count == 0 |
| AUTH-001 | W04 | CORE-002 | authority-negative-report.json | unauthorized_action_count == 0 |
| AUTH-002 | W04 | AUTH-001 | attenuation-property-report.json | widening_delegation_acceptance_count == 0 |
| AUTH-003 | W04 | AUTH-001 | revocation-report.json | post_bound_revoked_invocation_count == 0 |
| AUTH-004 | W06 | SCOPE-001 | isolation-adversarial-report.json | ambient_authority_path_count == 0 |
| EFFECT-001 | W08 | CORE-002 | effect-boundary-report.json | unledgered_external_dispatch_count == 0 |
| EFFECT-002 | W08 | EFFECT-001 | effect-idempotency-report.json | duplicate_effect_execution_count == 0 |
| EFFECT-003 | W08 | project-principle:unknown-is-not-success-or-failure | ambiguous-outcome-report.json | blind_retry_count == 0 and ambiguous_failure_coercion_count == 0 |
| EFFECT-004 | W08 | EFFECT-001 | provider-conformance-report.json | overclaimed_provider_class_count == 0 and incomplete_attempt_record_count == 0 |
| EFFECT-005 | W08 | EFFECT-001 | compensation-report.json, completion-coupling-report.json | history_erasure_count == 0 and premature_completion_count == 0 |
| EXEC-001 | W06 | AUTH-004 | execution-isolation-report.json | escape_count == 0 and unenforced_activation_count == 0 |
| EXEC-002 | W06 | EFFECT-003 | termination-report.json | post_termination_access_count == 0 and dispatched_effect_false_failure_count == 0 |
| EXEC-003 | W11 | ABI-003 | harness-conformance-report.json | adapter_bypass_count == 0 |
| PKG-001 | W10 | SCOPE-001 | package-admission-report.json | invalid_package_staged_count == 0 |
| PKG-002 | W10 | CORE-001 | activation-set-report.json | silent_rebind_count == 0 |
| PKG-003 | W10 | SCOPE-001 | package-scope-negative-report.json | package_core_semantic_admission_count == 0 |
| CHANGE-001 | W12 | project-goal:autonomous-self-improving-governed-os | self-change-adversarial-report.json | self_confirmed_candidate_count == 0 and evaluator_capture_count == 0 |
| CHANGE-002 | W12 | CHANGE-001 | candidate-chain-report.json | unbound_signed_candidate_count == 0 |
| CHANGE-003 | W12 | SCOPE-003 | contract-upgrade-report.json | in_place_contract_mutation_count == 0 |
| VERIFY-001 | W13 | SCOPE-001 | qualification-summary.json | missing_gate_count == 0 and handwritten_pass_evidence_count == 0 |
