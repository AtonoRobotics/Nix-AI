# Implementation work graph

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

| Packet | Deliverable | Requirements | Begin after | Integrate after | Pass after | Gates |
| --- | --- | --- | --- | --- | --- | --- |
| W00 | immutable_v2_contracts_schemas_registries_graph_generators_validators | SCOPE-001, SCOPE-002, SCOPE-003 | — | — | — | V-SCOPE, V-CONTRACT |
| W01 | reproducible_image_and_generic_hardware_profiles | SYS-001, SYS-002, SYS-004 | W00 | — | W00 | V-BOOT, V-ROLLBACK |
| W02 | authoritative_state_and_protected_evidence | STATE-001, STATE-003, STATE-004 | W00 | — | W00 | V-STATE |
| W03 | agent_abi_and_authenticated_local_transport | CORE-001, ABI-001, ABI-002, ABI-004 | W00 | W02 | W00, W02 | V-ABI |
| W04 | identity_and_capability_authority | AUTH-001, AUTH-002, AUTH-003 | W02, W03 | — | W02, W03 | V-AUTH |
| W05 | objectives_wakes_activations_scheduler_and_leases | CORE-002, STATE-002 | W02, W03, W04 | — | W02, W03, W04 | V-STATE, V-ABI |
| W06 | execution_isolation_and_resource_enforcement | AUTH-004, EXEC-001, EXEC-002 | W01, W03, W04 | W05 | W01, W03, W04 | V-ISOLATION |
| W07 | context_compiler_and_broker | CTX-001, CTX-002, CTX-003, CTX-004 | W03, W05, W06 | — | W03, W05, W06 | V-CONTEXT |
| W08 | durable_effect_service_and_reconciliation | EFFECT-001, EFFECT-002, EFFECT-003, EFFECT-004, EFFECT-005 | W02, W03, W04, W06 | W05 | W02, W03, W04, W06 | V-EFFECT |
| W09 | provider_neutral_cognition_interface_and_adapter_conformance | ABI-003 | W03, W05, W06, W07 | W08 | W03, W05, W06, W07 | V-ABI, V-CONTEXT |
| W10 | signed_capability_package_controller | PKG-001, PKG-002, PKG-003 | W03, W04, W06, W08 | W09 | W03, W04, W06, W08 | V-PACKAGE |
| W11 | optional_harness_adapter_conformance | EXEC-003 | W05, W09, W10 | — | W05, W09, W10 | V-ABI, V-ISOLATION |
| W12 | governed_self_change_system_generations_and_recovery | SYS-003, CHANGE-001, CHANGE-002, CHANGE-003 | W01, W04, W08, W10 | W11 | W01, W04, W08, W10 | V-CHANGE, V-ROLLBACK |
| W13 | complete_release_qualification | VERIFY-001 | W11, W12 | W01, W02, W03, W04, W05, W06, W07, W08, W09, W10 | W00, W01, W02, W03, W04, W05, W06, W07, W08, W09, W10, W11, W12 | V-SCOPE, V-CONTRACT, V-BOOT, V-ROLLBACK, V-STATE, V-ABI, V-AUTH, V-ISOLATION, V-CONTEXT, V-EFFECT, V-PACKAGE, V-CHANGE, V-END-TO-END |
