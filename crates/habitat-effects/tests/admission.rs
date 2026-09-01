use habitat_authority::*;
use habitat_effects::*;
use std::os::unix::net::UnixStream;

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
