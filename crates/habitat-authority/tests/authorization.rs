use habitat_authority::*;
use std::os::unix::net::UnixStream;

#[test]
fn every_request_is_authenticated_and_mediated_against_all_grant_bounds() {
    let mut authority = Authority::new("policy:v2", "generation:01", "state:7", 150);
    let grant = Grant::builder("grant:01", "service:issuer", "activation:01", "StoreCap")
        .caller("machine:01", "service:runtime")
        .operations(["read"])
        .target_prefix("bucket/evidence/")
        .valid_between(100, 200)
        .generation("generation:01")
        .build()
        .unwrap();
    let request = Invocation::new(
        "command:01",
        MachineId::new("machine:01").unwrap(),
        ServiceId::new("service:runtime").unwrap(),
        ActivationId::new("activation:01").unwrap(),
        "StoreCap",
        "read",
        "bucket/evidence/a",
        150,
        "state:7",
        "objective:01",
    );
    let (channel, _peer) = UnixStream::pair().unwrap();
    authority
        .bind_peer(
            &channel,
            &request.machine,
            &request.service,
            &request.activation,
        )
        .unwrap();
    authority
        .issue(grant, IndependentApproval::verified("operator:01"))
        .unwrap();
    assert_eq!(
        authority.bind_peer(
            &channel,
            &MachineId::new("machine:other").unwrap(),
            &ServiceId::new("service:other").unwrap(),
            &ActivationId::new("activation:other").unwrap()
        ),
        Err(AuthorityError::BindingLocked)
    );
    assert!(authority.evaluate_peer(&channel, &request).unwrap().allowed);
    let (forged_channel, _forged_peer) = UnixStream::pair().unwrap();
    assert_eq!(
        authority
            .evaluate_peer(&forged_channel, &request)
            .unwrap()
            .denial_code
            .as_deref(),
        Some("UNAUTHORIZED")
    );
    assert_eq!(
        authority
            .evaluate_peer(
                &channel,
                &Invocation {
                    machine: MachineId::new("machine:other").unwrap(),
                    ..request.clone()
                }
            )
            .unwrap()
            .denial_code
            .as_deref(),
        Some("UNAUTHORIZED")
    );
    assert_eq!(
        authority
            .evaluate_peer(
                &channel,
                &Invocation {
                    service: ServiceId::new("service:other").unwrap(),
                    ..request.clone()
                }
            )
            .unwrap()
            .denial_code
            .as_deref(),
        Some("UNAUTHORIZED")
    );
    assert_eq!(
        authority
            .evaluate_peer(
                &channel,
                &Invocation {
                    operation: "write".into(),
                    ..request.clone()
                }
            )
            .unwrap()
            .denial_code
            .as_deref(),
        Some("UNAUTHORIZED")
    );
    assert_eq!(
        authority
            .evaluate_peer(
                &channel,
                &Invocation {
                    generation: "generation:02".into(),
                    ..request.clone()
                }
            )
            .unwrap()
            .denial_code
            .as_deref(),
        Some("STALE")
    );
    assert_eq!(
        authority
            .evaluate_peer(
                &channel,
                &Invocation {
                    state_version: "state:stale".into(),
                    ..request
                }
            )
            .unwrap()
            .denial_code
            .as_deref(),
        Some("STALE")
    );
}

#[test]
fn caller_timestamp_cannot_replay_an_expired_grant() {
    let mut authority = Authority::new("policy:v2", "generation:01", "state:1", 250);
    let grant = Grant::builder("grant:expired", "service:issuer", "activation:1", "ReadCap")
        .caller("machine:1", "service:runtime")
        .operations(["read"])
        .target_prefix("resource/")
        .valid_between(100, 200)
        .generation("generation:01")
        .build()
        .unwrap();
    let request = Invocation::new(
        "command:1",
        MachineId::new("machine:1").unwrap(),
        ServiceId::new("service:runtime").unwrap(),
        ActivationId::new("activation:1").unwrap(),
        "ReadCap",
        "read",
        "resource/1",
        150,
        "state:1",
        "objective:1",
    );
    let (channel, _peer) = UnixStream::pair().unwrap();
    authority
        .bind_peer(
            &channel,
            &request.machine,
            &request.service,
            &request.activation,
        )
        .unwrap();
    authority
        .issue(grant, IndependentApproval::verified("operator:1"))
        .unwrap();
    assert_eq!(
        authority
            .evaluate_peer(&channel, &request)
            .unwrap()
            .denial_code
            .as_deref(),
        Some("STALE")
    );
}

#[test]
fn deployed_runtime_authority_is_versioned_identity_bound_and_default_deny() {
    let request = RuntimeAuthorityRequest {
        schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION.into(),
        request_id: "effect:objective:1".into(),
        caller_service_id: "service:runtime".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        objective_id: "objective:1".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target: "objective:1".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        requested_at: 100,
    };
    assert!(!evaluate_runtime_request(&[], &request, 100).allowed);
    let grant = RuntimeGrant {
        grant_id: "grant:runtime".into(),
        issuer: "service:operator".into(),
        independent_approver: "operator:1".into(),
        machine_id: request.machine_id.clone(),
        service_id: request.service_id.clone(),
        activation_id: request.activation_id.clone(),
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        target_prefix: "objective:".into(),
        generation: request.generation.clone(),
        state_version: request.state_version.clone(),
        quota: 8,
        remaining_delegation_depth: 1,
        parent_grant_id: None,
        not_before: 90,
        expires_at: 110,
    };
    assert!(evaluate_runtime_request(std::slice::from_ref(&grant), &request, 100).allowed);
    for denied in [
        RuntimeAuthorityRequest {
            schema_version: "1.0".into(),
            ..request.clone()
        },
        RuntimeAuthorityRequest {
            service_id: "service:peer".into(),
            ..request.clone()
        },
        RuntimeAuthorityRequest {
            generation: "generation:stale".into(),
            ..request.clone()
        },
        RuntimeAuthorityRequest {
            target: "other:1".into(),
            ..request.clone()
        },
        RuntimeAuthorityRequest {
            requested_at: 69,
            ..request.clone()
        },
    ] {
        assert!(!evaluate_runtime_request(std::slice::from_ref(&grant), &denied, 100).allowed);
    }
    assert!(!evaluate_runtime_request(&[grant], &request, 110).allowed);
}

#[test]
fn deployed_store_persists_revocation_rotation_ancestry_and_quota() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.json");
    let parent = RuntimeGrant {
        grant_id: "grant:parent".into(),
        issuer: "service:operator".into(),
        independent_approver: "operator:release".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target_prefix: "objective:".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        quota: 2,
        remaining_delegation_depth: 2,
        parent_grant_id: None,
        not_before: 90,
        expires_at: 200,
    };
    let child = RuntimeGrant {
        grant_id: "grant:child".into(),
        issuer: "service:runtime".into(),
        independent_approver: "operator:delegate".into(),
        target_prefix: "objective:child-".into(),
        quota: 1,
        remaining_delegation_depth: 1,
        parent_grant_id: Some(parent.grant_id.clone()),
        ..parent.clone()
    };
    let request = RuntimeAuthorityRequest {
        schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION.into(),
        request_id: "effect:child".into(),
        caller_service_id: "service:runtime".into(),
        machine_id: parent.machine_id.clone(),
        service_id: parent.service_id.clone(),
        activation_id: parent.activation_id.clone(),
        objective_id: "objective:child-1".into(),
        capability: parent.capability.clone(),
        operation: parent.operation.clone(),
        target: "objective:child-1".into(),
        generation: parent.generation.clone(),
        state_version: parent.state_version.clone(),
        requested_at: 100,
    };
    let mut store =
        RuntimeAuthorityStore::open(&path, vec![parent.clone(), child.clone()], "state:current")
            .unwrap();
    assert_eq!(
        store.evaluate(&request, 100).unwrap().grant_id.as_deref(),
        Some("grant:child")
    );
    assert!(
        store.evaluate(&request, 100).unwrap().allowed,
        "reservation and dispatch rechecks are idempotent"
    );
    assert!(
        !store.evaluate(&request, 200).unwrap().allowed,
        "an idempotent quota reservation must not replay authority past grant expiry"
    );
    let second_invocation = RuntimeAuthorityRequest {
        request_id: "effect:child-2".into(),
        objective_id: "objective:child-2".into(),
        target: "objective:child-2".into(),
        ..request.clone()
    };
    assert!(
        !store.evaluate(&second_invocation, 100).unwrap().allowed,
        "a distinct invocation cannot reuse consumed quota"
    );
    drop(store);
    let mut reopened =
        RuntimeAuthorityStore::open(&path, vec![parent.clone(), child], "state:current").unwrap();
    assert!(
        reopened.evaluate(&request, 100).unwrap().allowed,
        "the original quota reservation survives restart and replays"
    );
    assert!(
        !reopened.evaluate(&second_invocation, 100).unwrap().allowed,
        "quota consumption survives restart"
    );
    reopened.revoke("grant:parent").unwrap();
    assert!(
        !reopened.evaluate(&request, 100).unwrap().allowed,
        "ancestor revocation is current"
    );
    reopened.rotate_state("state:rotated").unwrap();
    assert!(
        !reopened.evaluate(&request, 100).unwrap().allowed,
        "rotation invalidates stale state"
    );
}

#[test]
fn grant_reload_preserves_security_history_and_admin_requires_separate_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.json");
    let grant = RuntimeGrant {
        grant_id: "grant:runtime".into(),
        issuer: "service:operator".into(),
        independent_approver: "operator:release".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target_prefix: "objective:".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        quota: 2,
        remaining_delegation_depth: 0,
        parent_grant_id: None,
        not_before: 1,
        expires_at: 200,
    };
    let request = RuntimeAuthorityRequest {
        schema_version: "2.0".into(),
        request_id: "effect:one".into(),
        caller_service_id: "service:runtime".into(),
        machine_id: grant.machine_id.clone(),
        service_id: grant.service_id.clone(),
        activation_id: grant.activation_id.clone(),
        objective_id: "objective:one".into(),
        capability: grant.capability.clone(),
        operation: grant.operation.clone(),
        target: "objective:one".into(),
        generation: grant.generation.clone(),
        state_version: grant.state_version.clone(),
        requested_at: 100,
    };
    let mut store =
        RuntimeAuthorityStore::open(&path, vec![grant.clone()], "state:current").unwrap();
    assert!(store.evaluate(&request, 100).unwrap().allowed);

    let mut admin = RuntimeAuthorityAdminRequest {
        schema_version: "2.0".into(),
        operation: "revoke".into(),
        request_id: "admin:revoke-runtime".into(),
        caller_service_id: "service:operator".into(),
        grant_id: Some(grant.grant_id.clone()),
        state_version: None,
        independent_approval: "approval:revoke-runtime".into(),
    };
    assert!(!store.apply_admin(&admin, "service:operator").unwrap());
    let approval = RuntimeAuthorityAdminRequest {
        schema_version: "2.0".into(),
        operation: "approve".into(),
        request_id: admin.independent_approval.clone(),
        caller_service_id: "service:reviewer".into(),
        grant_id: Some(admin.request_id.clone()),
        state_version: Some(runtime_admin_digest(&admin)),
        independent_approval: String::new(),
    };
    assert!(store
        .record_admin_approval(&approval, "service:reviewer")
        .unwrap());
    assert!(store.apply_admin(&admin, "service:operator").unwrap());
    assert!(
        store.apply_admin(&admin, "service:operator").unwrap(),
        "admin replay is idempotent"
    );
    admin.state_version = Some("state:tampered".into());
    assert!(!store.apply_admin(&admin, "service:operator").unwrap());
    drop(store);

    let mut changed = grant.clone();
    changed.quota = 3;
    let mut reopened = RuntimeAuthorityStore::open(&path, vec![changed], "state:current").unwrap();
    assert!(
        !reopened.evaluate(&request, 100).unwrap().allowed,
        "configuration changes cannot clear a durable revocation"
    );
    assert!(reopened.rotate_state("state:next").is_ok());
    assert_eq!(
        reopened.rotate_state("state:current"),
        Err(AuthorityError::InvalidGrant)
    );
}

#[test]
fn quota_reservation_rolls_back_when_durable_replace_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.json");
    let grant = RuntimeGrant {
        grant_id: "grant:durability".into(),
        issuer: "service:operator".into(),
        independent_approver: "operator:reviewer".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target_prefix: "objective:".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        quota: 1,
        remaining_delegation_depth: 0,
        parent_grant_id: None,
        not_before: 1,
        expires_at: 200,
    };
    let request = RuntimeAuthorityRequest {
        schema_version: "2.0".into(),
        request_id: "effect:durability".into(),
        caller_service_id: "service:runtime".into(),
        machine_id: grant.machine_id.clone(),
        service_id: grant.service_id.clone(),
        activation_id: grant.activation_id.clone(),
        objective_id: "objective:durability".into(),
        capability: grant.capability.clone(),
        operation: grant.operation.clone(),
        target: "objective:durability".into(),
        generation: grant.generation.clone(),
        state_version: grant.state_version.clone(),
        requested_at: 100,
    };
    let mut store =
        RuntimeAuthorityStore::open(&path, vec![grant.clone()], "state:current").unwrap();
    let blocker = path.with_extension("next");
    std::fs::create_dir(&blocker).unwrap();
    assert_eq!(store.evaluate(&request, 100), Err(AuthorityError::Storage));
    std::fs::remove_dir(blocker).unwrap();
    assert_eq!(
        store.evaluate(&request, 100),
        Err(AuthorityError::Storage),
        "a durability ambiguity must poison the in-process store until restart"
    );
    drop(store);
    let mut reopened = RuntimeAuthorityStore::open(&path, vec![grant], "state:current").unwrap();
    assert!(
        reopened.evaluate(&request, 100).unwrap().allowed,
        "failed persistence must not consume quota"
    );
}

#[test]
fn effect_prepare_commit_abort_is_durable_and_consumes_quota_only_on_commit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.json");
    let grant = RuntimeGrant {
        grant_id: "grant:saga".into(),
        issuer: "service:operator".into(),
        independent_approver: "operator:reviewer".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target_prefix: "objective:".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        quota: 1,
        remaining_delegation_depth: 0,
        parent_grant_id: None,
        not_before: 1,
        expires_at: 200,
    };
    let request = RuntimeAuthorityRequest {
        schema_version: "2.0".into(),
        request_id: "effect:saga".into(),
        caller_service_id: "service:effects".into(),
        machine_id: grant.machine_id.clone(),
        service_id: grant.service_id.clone(),
        activation_id: grant.activation_id.clone(),
        objective_id: "objective:saga".into(),
        capability: grant.capability.clone(),
        operation: grant.operation.clone(),
        target: "objective:saga".into(),
        generation: grant.generation.clone(),
        state_version: grant.state_version.clone(),
        requested_at: 100,
    };
    let mut store =
        RuntimeAuthorityStore::open(&path, vec![grant.clone()], "state:current").unwrap();
    assert!(store.prepare_effect(&request, 100).unwrap().allowed);
    // Crash after PREPARE (and equivalently before PostgreSQL RESERVED): a
    // fresh authority process reports PREPARED and quota remains unconsumed.
    drop(store);
    let mut store =
        RuntimeAuthorityStore::open(&path, vec![grant.clone()], "state:current").unwrap();
    let prepared = store
        .status_effect(
            &request,
            &format!("effect:sha256:{}", "f".repeat(64)),
            100,
            &format!("sha256:{}", "e".repeat(64)),
        )
        .unwrap();
    assert!(!prepared.allowed);
    assert_eq!(prepared.code, "PREPARED");
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        persisted["quota_usage"]["grant:saga"].as_u64().unwrap_or(0),
        0
    );
    let second = RuntimeAuthorityRequest {
        request_id: "effect:other".into(),
        objective_id: "objective:other".into(),
        target: "objective:other".into(),
        ..request.clone()
    };
    assert!(!store.prepare_effect(&second, 100).unwrap().allowed);
    assert!(store.abort_effect(&request).unwrap());
    assert!(store.prepare_effect(&second, 100).unwrap().allowed);
    assert!(store.abort_effect(&second).unwrap());
    assert!(store.prepare_effect(&request, 100).unwrap().allowed);
    let effect_id = format!("effect:sha256:{}", "a".repeat(64));
    assert!(
        store
            .commit_effect(&request, &effect_id, 100)
            .unwrap()
            .allowed
    );
    // Crash after COMMIT durability but before the response/provider dispatch:
    // restart returns the exact committed authorization and charges once.
    drop(store);
    let mut store = RuntimeAuthorityStore::open(&path, vec![grant], "state:current").unwrap();
    let committed = store
        .status_effect(
            &request,
            &effect_id,
            100,
            &format!("sha256:{}", "e".repeat(64)),
        )
        .unwrap();
    assert!(committed.allowed);
    assert_eq!(committed.code, "AUTHORIZED");
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["quota_usage"]["grant:saga"], 1);
    assert!(
        store
            .commit_effect(&request, &effect_id, 100)
            .unwrap()
            .allowed
    );
    assert!(!store.prepare_effect(&request, 200).unwrap().allowed);
    assert!(!store.prepare_effect(&second, 100).unwrap().allowed);
}

#[test]
fn runtime_forwarding_mac_binds_subject_and_complete_effect_proposal() {
    let request = RuntimeAuthorityRequest {
        schema_version: "2.0".into(),
        request_id: "effect:forwarded".into(),
        caller_service_id: "service:runtime".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        objective_id: "objective:forwarded".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target: "objective:forwarded".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        requested_at: 100,
    };
    let key = b"runtime-only-forwarding-key-32-bytes-minimum";
    let proof = runtime_forwarding_proof(
        key,
        &request,
        "habitat-state",
        &format!("sha256:{}", "a".repeat(64)),
        "effect:objective:forwarded",
    )
    .unwrap();
    assert_eq!(
        proof,
        runtime_forwarding_proof(
            key,
            &request,
            "habitat-state",
            &format!("sha256:{}", "a".repeat(64)),
            "effect:objective:forwarded",
        )
        .unwrap()
    );
    let mut tampered = request;
    tampered.target = "objective:other".into();
    assert_ne!(
        proof,
        runtime_forwarding_proof(
            key,
            &tampered,
            "habitat-state",
            &format!("sha256:{}", "a".repeat(64)),
            "effect:objective:forwarded",
        )
        .unwrap()
    );
}
