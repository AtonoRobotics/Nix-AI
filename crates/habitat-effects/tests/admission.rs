use habitat_authority::*;
use habitat_effects::*;
use std::os::unix::net::UnixStream;

fn forwarding() -> RuntimeForwardingEvidence {
    RuntimeForwardingEvidence {
        provider_id: "habitat-state".into(),
        parameters_digest: format!("sha256:{}", "a".repeat(64)),
        idempotency_key: "effect:test".into(),
        proof: format!("sha256:{}", "b".repeat(64)),
    }
}

fn proposal(key: &str) -> EffectProposal {
    EffectProposal::new(
        "command:1",
        "activation:1",
        "objective:1",
        "mail.send",
        "send",
        "recipient:1",
        "sha256:payload",
        key,
        ConsequenceClass::E2,
        200,
    )
}

fn authorization(proposal: &EffectProposal) -> (Authority, Invocation, UnixStream, UnixStream) {
    let mut authority = Authority::new("policy:v2", "generation:01", "state:1", 100);
    let grant = Grant::builder(
        "grant:effect",
        "service:issuer",
        "activation:1",
        &proposal.capability,
    )
    .caller("machine:1", "service:effects")
    .operations([proposal.operation.as_str()])
    .target_prefix(&proposal.target)
    .valid_between(1, 500)
    .generation("generation:01")
    .build()
    .unwrap();
    let invocation = Invocation::new(
        &proposal.command_id,
        MachineId::new("machine:1").unwrap(),
        ServiceId::new("service:effects").unwrap(),
        ActivationId::new("activation:1").unwrap(),
        &proposal.capability,
        &proposal.operation,
        &proposal.target,
        100,
        "state:1",
        &proposal.objective_id,
    )
    .with_enforcement(EnforcementProof::verified("lsm:generic"));
    let (channel, peer) = UnixStream::pair().unwrap();
    authority
        .bind_peer(
            &channel,
            &invocation.machine,
            &invocation.service,
            &invocation.activation,
        )
        .unwrap();
    authority
        .issue(grant, IndependentApproval::verified("operator:1"))
        .unwrap();
    (authority, invocation, channel, peer)
}

#[test]
fn admission_atomically_reserves_semantic_intent_and_deduplicates() {
    let mut ledger = EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable(
        "mail",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2,
    ));
    let first_proposal = proposal("intent:mail:recipient:payload");
    let (mut authority, invocation, channel, _peer) = authorization(&first_proposal);
    let first = ledger
        .propose_authorized(
            first_proposal.clone(),
            &mut authority,
            &channel,
            &invocation,
            true,
        )
        .unwrap();
    let duplicate = ledger
        .propose_authorized(first_proposal, &mut authority, &channel, &invocation, true)
        .unwrap();
    assert_eq!(first.effect_id, duplicate.effect_id);
    assert_eq!(first.state, EffectState::Reserved);
    assert_eq!(ledger.len(), 1);
    assert!(ledger
        .get(&first.effect_id)
        .unwrap()
        .admission
        .precondition_valid());

    let mut changed = proposal("intent:mail:recipient:payload");
    changed.parameters_digest = "sha256:different-payload".into();
    let (_, changed_invocation, _, _) = authorization(&changed);
    assert_eq!(
        ledger.propose_authorized(changed, &mut authority, &channel, &changed_invocation, true),
        Err(EffectError::IdempotencyConflict)
    );
}

#[test]
fn stale_revoked_or_mismatched_authority_cannot_reserve_an_effect() {
    let mut ledger = EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable(
        "mail",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2,
    ));
    let proposal = proposal("intent:denied");
    let (mut authority, invocation, channel, _peer) = authorization(&proposal);
    authority.revoke("grant:effect");
    assert_eq!(
        ledger.propose_authorized(
            proposal.clone(),
            &mut authority,
            &channel,
            &invocation,
            true
        ),
        Err(EffectError::AdmissionDenied)
    );
    let (mut current, mut mismatch, current_channel, _current_peer) = authorization(&proposal);
    mismatch.target = "recipient:other".into();
    assert_eq!(
        ledger.propose_authorized(proposal, &mut current, &current_channel, &mismatch, true),
        Err(EffectError::AdmissionDenied)
    );
    assert_eq!(ledger.len(), 0);
}

#[test]
fn revocation_between_reservation_and_dispatch_fails_closed() {
    let mut ledger = EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable(
        "mail",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2,
    ));
    let proposal = proposal("intent:revoked-before-dispatch");
    let (mut authority, invocation, channel, _peer) = authorization(&proposal);
    let effect = ledger
        .propose_authorized(proposal, &mut authority, &channel, &invocation, true)
        .unwrap();
    authority.revoke("grant:effect");
    assert_eq!(
        ledger.dispatch_authorized(
            &effect.effect_id,
            Attempt::new("sha256:req", 101, "mail", "transport:revoked"),
            &mut authority,
            &channel,
            &invocation
        ),
        Err(EffectError::AdmissionDenied)
    );
    assert_eq!(
        ledger.get(&effect.effect_id).unwrap().state,
        EffectState::Reserved
    );
    assert!(ledger.attempts(&effect.effect_id).is_empty());
}

#[test]
fn deployed_effect_envelope_requires_exact_current_authority_binding() {
    let authority_request = RuntimeAuthorityRequest {
        schema_version: "2.0".into(),
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
    let authority = RuntimeAuthorityDecision {
        schema_version: "2.0".into(),
        decision_id: "decision:1".into(),
        request_id: "effect:objective:1".into(),
        broker_service_id: "service:effects".into(),
        allowed: true,
        code: "AUTHORIZED".into(),
        grant_id: Some("grant:1".into()),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        objective_id: "objective:1".into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target: "objective:1".into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        evaluated_at: 100,
        requested_at: 100,
        revocation_epoch: 1,
        phase: "PREPARE".into(),
        request_digest: format!("sha256:{}", "c".repeat(64)),
        grant_chain: vec!["grant:1".into()],
        issuer_chain: vec!["service:operator".into()],
        policy_ref: "policy:runtime-v2-default-deny".into(),
        configuration_digest: format!("sha256:{}", "d".repeat(64)),
        provider_proof: Some(format!("sha256:{}", "e".repeat(64))),
        evidence_ref: format!("authority://decisions/sha256/{}", "f".repeat(64)),
    };
    let request = RuntimeEffectRequest {
        schema_version: RUNTIME_EFFECT_SCHEMA_VERSION.into(),
        caller_service_id: "service:runtime".into(),
        command_id: "effect:objective:1".into(),
        objective_id: "objective:1".into(),
        provider_id: "habitat-state".into(),
        parameters_digest: format!("sha256:{}", "a".repeat(64)),
        idempotency_key: "effect:objective:1".into(),
        execution_constraint_id: "constraint:effect:objective:1".into(),
        valid_from: 100,
        valid_until: 130,
        controller_ack_required: true,
        authority_request,
        forwarding_proof: format!("sha256:{}", "b".repeat(64)),
    };
    assert_eq!(admit_runtime_effect(&request, &authority).state, "RESERVED");
    for denied in [
        RuntimeEffectRequest {
            schema_version: "1.0".into(),
            ..request.clone()
        },
        RuntimeEffectRequest {
            objective_id: "objective:peer".into(),
            ..request.clone()
        },
        RuntimeEffectRequest {
            provider_id: "peer".into(),
            ..request.clone()
        },
        RuntimeEffectRequest {
            authority_request: RuntimeAuthorityRequest {
                objective_id: "objective:peer".into(),
                ..request.authority_request.clone()
            },
            ..request.clone()
        },
    ] {
        assert_eq!(admit_runtime_effect(&denied, &authority).state, "REJECTED");
    }
    let denied = RuntimeAuthorityDecision {
        allowed: false,
        ..authority
    };
    assert_eq!(admit_runtime_effect(&request, &denied).state, "REJECTED");
    let wrong_broker = RuntimeAuthorityDecision {
        allowed: true,
        broker_service_id: "service:runtime".into(),
        ..denied
    };
    assert_eq!(
        admit_runtime_effect(&request, &wrong_broker).state,
        "REJECTED"
    );
}

#[test]
fn reservation_rolls_back_when_durable_replace_cannot_start() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("effects.json");
    let mut ledger = EffectLedger::open(&path).unwrap();
    ledger.register_provider(ProviderContract::reconcilable(
        "habitat-state",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2,
    ));
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    let mut proposal = EffectProposal::new(
        "effect:objective:durability",
        "activation:runtime",
        "objective:durability",
        "runtime.effect",
        "commit",
        "objective:durability",
        &format!("sha256:{}", "a".repeat(64)),
        "effect:objective:durability",
        ConsequenceClass::E2,
        200,
    );
    proposal.provider_id = "habitat-state".into();
    let grant = RuntimeGrant {
        grant_id: "grant:runtime".into(),
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
        request_id: proposal.command_id.clone(),
        caller_service_id: "service:effects".into(),
        machine_id: grant.machine_id.clone(),
        service_id: grant.service_id.clone(),
        activation_id: grant.activation_id.clone(),
        objective_id: proposal.objective_id.clone(),
        capability: proposal.capability.clone(),
        operation: proposal.operation.clone(),
        target: proposal.target.clone(),
        generation: grant.generation.clone(),
        state_version: grant.state_version.clone(),
        requested_at: 100,
    };
    let decision = evaluate_runtime_request(&[grant], &request, 100);
    assert_eq!(
        ledger.reserve_runtime(proposal.clone(), &decision, forwarding(), 100),
        Err(EffectError::Storage)
    );
    assert!(
        ledger.is_empty(),
        "an uncommitted reservation must not remain in memory"
    );
    std::fs::remove_dir(path.with_extension("tmp")).unwrap();
    assert_eq!(
        ledger.reserve_runtime(proposal, &decision, forwarding(), 100),
        Err(EffectError::Storage),
        "a persistence ambiguity must poison the in-process ledger until restart"
    );
}

#[test]
fn terminal_runtime_retry_is_bound_and_available_for_guard_repair() {
    let mut ledger = EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable(
        "habitat-state",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2,
    ));
    let mut proposal = EffectProposal::new(
        "effect:objective:retry",
        "activation:runtime",
        "objective:retry",
        "runtime.effect",
        "commit",
        "objective:retry",
        &format!("sha256:{}", "a".repeat(64)),
        "effect:objective:retry",
        ConsequenceClass::E2,
        130,
    );
    proposal.provider_id = "habitat-state".into();
    let decision = RuntimeAuthorityDecision {
        schema_version: "2.0".into(),
        decision_id: "decision:retry".into(),
        request_id: proposal.command_id.clone(),
        broker_service_id: "service:effects".into(),
        allowed: true,
        code: "AUTHORIZED".into(),
        grant_id: Some("grant:runtime".into()),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: proposal.activation_id.clone(),
        objective_id: proposal.objective_id.clone(),
        capability: proposal.capability.clone(),
        operation: proposal.operation.clone(),
        target: proposal.target.clone(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        evaluated_at: 100,
        requested_at: 100,
        revocation_epoch: 0,
        phase: "PREPARE".into(),
        request_digest: format!("sha256:{}", "c".repeat(64)),
        grant_chain: vec!["grant:runtime".into()],
        issuer_chain: vec!["service:operator".into()],
        policy_ref: "policy:runtime-v2-default-deny".into(),
        configuration_digest: format!("sha256:{}", "d".repeat(64)),
        provider_proof: Some(format!("sha256:{}", "e".repeat(64))),
        evidence_ref: format!("authority://decisions/sha256/{}", "f".repeat(64)),
    };
    let effect = ledger
        .reserve_runtime(proposal.clone(), &decision, forwarding(), 100)
        .unwrap();
    ledger
        .dispatch_runtime(
            &effect.effect_id,
            Attempt::new(
                &proposal.parameters_digest,
                101,
                "habitat-state",
                "dispatch:retry",
            ),
            &decision,
        )
        .unwrap();
    ledger
        .observe(
            &effect.effect_id,
            Observation::independent("postgresql", "evidence:retry", true),
        )
        .unwrap();

    let mut retry = proposal.clone();
    retry.expires_at = 160;
    assert_eq!(
        ledger.runtime_replay(&retry).unwrap().unwrap().state,
        EffectState::ObservedSucceeded,
        "a terminal retry must remain available to repair a missing guard"
    );
    let mut wrong_provider = proposal.clone();
    wrong_provider.provider_id = "other-provider".into();
    let mut wrong_objective = proposal.clone();
    wrong_objective.objective_id = "objective:other".into();
    let mut wrong_operation = proposal;
    wrong_operation.operation = "compensate".into();
    for mismatched in [wrong_provider, wrong_objective, wrong_operation] {
        assert_eq!(
            ledger.runtime_replay(&mismatched),
            Err(EffectError::IdempotencyConflict)
        );
    }
}
