# Binding decisions

> Generated from `contracts/v2.0.1/nix-ai-v2.0.1.contract.json` (`sha256:f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a`). Do not edit by hand.

| Disposition | Selector | Action | Reason | Proof |
| --- | --- | --- | --- | --- |
| D-007 | {"path": "crates/habitat-effects"} | DELETE_AND_REBUILD | Generic service contains domain-specific class, fields, errors, behavior, and fixtures. | new_tree_digest, v2_requirement_mapping, V-EFFECT |
| D-008 | {"path": "crates/habitat-authority"} | DELETE_AND_REBUILD | Generic service contains domain-specific authority semantics and tests. | new_tree_digest, v2_requirement_mapping, V-AUTH |
| D-009 | {"path": "contracts/architecture/00-GOVERNANCE.md"} | DELETE_AND_REBUILD | Contaminated actor, scope, and change model. | generated_from_v2 |
| D-010 | {"path": "contracts/architecture/04-AUTHORITY-CAPABILITIES.md"} | DELETE_AND_REBUILD | Contaminated principal and capability model. | generated_from_v2 |
| D-011 | {"path": "contracts/architecture/05-EFFECTS.md"} | DELETE_AND_REBUILD | Contaminated consequence and effect model. | generated_from_v2 |
| D-012 | {"path": "contracts/architecture/09-THREAT-SAFETY.md"} | DELETE_AND_REBUILD | Domain safety family embedded in core. | generated_from_v2 |
| D-013 | {"path": "contracts/architecture/10-HARDWARE-PROFILES.md"} | DELETE_AND_REBUILD | Domain- and vendor-specific core profiles. | generated_from_v2 |
| D-014 | {"path": "contracts/architecture/12-VERIFICATION-MATRIX.md"} | DELETE_AND_REBUILD | Domain release gate embedded in core. | generated_from_v2 |
| D-015 | {"path": "contracts/architecture/13-IMPLEMENTATION-WORK-GRAPH.md"} | REGENERATE | Contaminated work packets and dependencies. | generated_from_v2_work_graph |
| D-016 | {"path": "contracts/architecture/14-DECISION-REGISTER.md"} | DELETE_AND_REBUILD | Domain and vendor decisions promoted to core. | generated_from_v2 |
| D-017 | {"path": "contracts/architecture/15-TRACEABILITY.md"} | REGENERATE | Contaminated requirements and gates. | generated_from_v2_requirements |
| D-018 | {"path": "contracts/requirements.yaml"} | REGENERATE | Rejected requirements and ownership mappings. | v2_schema_valid, complete_requirement_coverage |
| D-019 | {"path": "contracts/work-packets.yaml"} | REGENERATE | Rejected work packets. | v2_schema_valid, graph_valid |
| D-020 | {"path": "contracts/schemas/capability-package.schema.json"} | DELETE_AND_REBUILD | Brand- and domain-specific execution kinds. | canonical_execution_profiles_only, negative_fixture_pass |
| D-021 | {"path": "contracts/schemas/effect.schema.json"} | DELETE_AND_REBUILD | Rejected consequence model. | canonical_effect_classes_only, negative_fixture_pass |
| D-022 | {"path": "contracts/proto/habitat_authority_effect_v1.proto"} | DELETE_AND_REBUILD | v1-major interface contains rejected semantics. | v2_namespace, descriptor_digest, v1_rejection_test |
| D-023 | {"glob": "generated/**/*"} | REGENERATE | Generated output must derive only from v2. | clean_regeneration_byte_match |
| D-024 | {"glob": "evidence/**/*"} | REGENERATE | Passing evidence must be produced by v2 qualification. | runner_attribution, evidence_digest |
| D-025 | {"path": "flake.nix"} | DELETE_AND_REBUILD | Build graph contains rejected component and packet outputs. | deleted_output_absent, v2_apps_only, V-CONTRACT |
| D-026 | {"path": "Cargo.toml"} | DELETE_AND_REBUILD | Workspace contains rejected component. | deleted_member_absent, retained_member_audit |
| D-027 | {"path": "Cargo.lock"} | REGENERATE | Dependency lock derives from changed workspace. | clean_cargo_generate_lockfile, dependency_ownership_complete |
| D-028 | {"semantic": "domain_or_vendor_fixture_in_core_test"} | DELETE_AND_REBUILD | Fixtures cannot import application semantics into core behavior. | opaque_fixture_only, semantic_scope_report |
| D-029 | {"semantic": "unmapped_public_semantic"} | DELETE_AND_REBUILD | Every retained semantic requires v2 authority. | retention_ledger_mapping |
| D-030 | {"semantic": "remaining_repository_unit"} | AUDIT_FOR_RETENTION | No unit is trusted solely because no keyword matched. | all_retention_predicates_true |
