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
        machine_id: request.machine_id.clone(),
        service_id: request.service_id.clone(),
        activation_id: request.activation_id.clone(),
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        target_prefix: "objective:".into(),
        generation: request.generation.clone(),
        state_version: request.state_version.clone(),
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
    ] {
        assert!(!evaluate_runtime_request(std::slice::from_ref(&grant), &denied, 100).allowed);
    }
    assert!(!evaluate_runtime_request(&[grant], &request, 110).allowed);
}
