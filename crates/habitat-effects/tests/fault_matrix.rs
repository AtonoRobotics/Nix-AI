use habitat_authority::*;
use habitat_effects::*;
use std::os::unix::net::UnixStream;

fn ledger() -> EffectLedger {
    let mut value = EffectLedger::new();
    value.register_provider(ProviderContract::reconcilable(
        "mail",
        ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E3,
    ));
    value
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
fn proposed(ledger: &mut EffectLedger, key: &str) -> EffectRecord {
    let proposal = EffectProposal::new(
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
    );
    let (mut authority, invocation, channel, _peer) = authorization(&proposal);
    ledger
        .propose_authorized(proposal, &mut authority, &channel, &invocation, true)
        .unwrap()
}
fn dispatch(
    ledger: &mut EffectLedger,
    effect: &EffectRecord,
    attempt: Attempt,
) -> Result<(), EffectError> {
    let (mut authority, invocation, channel, _peer) = authorization(&effect.proposal);
    ledger.dispatch_authorized(
        &effect.effect_id,
        attempt,
        &mut authority,
        &channel,
        &invocation,
    )
}

#[test]
fn disconnect_after_dispatch_becomes_unknown_and_reconciles_without_retry() {
    let mut ledger = ledger();
    let effect = proposed(&mut ledger, "intent:unknown:0001");
    dispatch(
        &mut ledger,
        &effect,
        Attempt::new("sha256:req", 100, "mail", "transport:7"),
    )
    .unwrap();
    ledger
        .transport_lost(&effect.effect_id, "disconnect")
        .unwrap();
    assert_eq!(
        ledger.get(&effect.effect_id).unwrap().state,
        EffectState::OutcomeUnknown
    );
    assert_eq!(ledger.attempts(&effect.effect_id).len(), 1);
    ledger
        .begin_reconciliation(
            &effect.effect_id,
            ReconciliationAttempt::new("sha256:lookup", 101, "mail", "lookup:7"),
        )
        .unwrap();
    ledger
        .resolve(
            &effect.effect_id,
            Observation::independent("provider-lookup", "message:7", true),
        )
        .unwrap();
    assert_eq!(
        ledger.get(&effect.effect_id).unwrap().state,
        EffectState::ResolvedSucceeded
    );
    assert_eq!(ledger.attempts(&effect.effect_id).len(), 1);
    assert_eq!(
        ledger.attempts(&effect.effect_id)[0].terminal_classification,
        Some(EffectState::OutcomeUnknown)
    );
    assert_eq!(ledger.reconciliations(&effect.effect_id).len(), 1);
    assert_eq!(
        ledger.reconciliations(&effect.effect_id)[0]
            .observation_source
            .as_deref(),
        Some("provider-lookup")
    );
    assert_eq!(
        ledger.reconciliations(&effect.effect_id)[0].terminal_classification,
        Some(EffectState::ResolvedSucceeded)
    );
}

#[test]
fn acknowledgement_is_not_success_without_the_declared_observation() {
    let mut ledger = ledger();
    let effect = proposed(&mut ledger, "intent:evidence:0001");
    dispatch(
        &mut ledger,
        &effect,
        Attempt::new("sha256:req", 100, "mail", "transport:8"),
    )
    .unwrap();
    assert_eq!(
        ledger.observe(&effect.effect_id, Observation::provider_ack("accepted")),
        Err(EffectError::IndependentEvidenceRequired)
    );
    ledger
        .observe(
            &effect.effect_id,
            Observation::independent("mailbox", "message:8", true),
        )
        .unwrap();
    assert_eq!(
        ledger.get(&effect.effect_id).unwrap().state,
        EffectState::ObservedSucceeded
    );
    assert_eq!(
        ledger.attempts(&effect.effect_id)[0].terminal_classification,
        Some(EffectState::ObservedSucceeded)
    );
}

#[test]
fn cancellation_and_compensation_preserve_truthful_distinct_histories() {
    let mut ledger = ledger();
    let before = proposed(&mut ledger, "intent:cancel:0001");
    ledger.cancel(&before.effect_id).unwrap();
    assert_eq!(
        ledger.get(&before.effect_id).unwrap().state,
        EffectState::Rejected
    );
    let original = proposed(&mut ledger, "intent:original:0001");
    dispatch(
        &mut ledger,
        &original,
        Attempt::new("sha256:o", 100, "mail", "transport:o"),
    )
    .unwrap();
    ledger
        .observe(
            &original.effect_id,
            Observation::independent("mailbox", "message:o", true),
        )
        .unwrap();
    let compensation_proposal = EffectProposal::new(
        "command:c",
        "activation:1",
        "objective:1",
        "mail.retract",
        "compensate",
        "recipient:1",
        "sha256:payload",
        "intent:unused",
        ConsequenceClass::E2,
        200,
    );
    let (
        mut compensation_authority,
        compensation_invocation,
        compensation_channel,
        _compensation_peer,
    ) = authorization(&compensation_proposal);
    let compensation = ledger
        .compensate(
            &original.effect_id,
            "command:c",
            "mail.retract",
            "intent:compensation:0001",
            &mut compensation_authority,
            &compensation_channel,
            &compensation_invocation,
        )
        .unwrap();
    dispatch(
        &mut ledger,
        &compensation,
        Attempt::new("sha256:c", 110, "mail", "transport:c"),
    )
    .unwrap();
    ledger
        .observe(
            &compensation.effect_id,
            Observation::independent("mailbox", "still-present", false),
        )
        .unwrap();
    assert_eq!(
        ledger.get(&original.effect_id).unwrap().state,
        EffectState::ObservedSucceeded
    );
    assert_eq!(
        ledger.get(&compensation.effect_id).unwrap().state,
        EffectState::ObservedFailed
    );
    assert_eq!(
        compensation.proposal.compensates_effect_id,
        Some(original.effect_id)
    );
}

#[test]
fn recovery_bounded_validity_ordering_and_completion_fail_closed() {
    let mut ledger = ledger();
    ledger.register_provider(ProviderContract::reconcilable(
        "service",
        ReconciliationMode::TargetState,
        ConsequenceClass::E3,
    ));
    let mut operation = EffectProposal::new(
        "command:m",
        "activation:1",
        "objective:change",
        "service.change",
        "apply",
        "resource:1",
        "sha256:change",
        "intent:change:0001",
        ConsequenceClass::E3,
        120,
    );
    operation = operation
        .bounded("constraint:7", 100, 120, true)
        .ordered("resource:1", 1);
    let (mut authority, invocation, channel, _peer) = authorization(&operation);
    let effect = ledger
        .propose_authorized_at(operation, &mut authority, &channel, &invocation, true, 110)
        .unwrap();
    assert_eq!(
        ledger.complete_objective("objective:change"),
        Err(EffectError::ObjectiveEffectsPending)
    );
    authority.advance_time(121).unwrap();
    assert_eq!(
        ledger.dispatch_authorized_at(
            &effect.effect_id,
            Attempt::new("sha256:m", 121, "service", "transport:m"),
            &mut authority,
            &channel,
            &invocation,
            121
        ),
        Err(EffectError::ExpiredCommand)
    );
    assert_eq!(ledger.recover(), vec![effect.effect_id]);
}

#[test]
fn restart_recovers_nonterminal_effects_and_enforces_declared_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("effects.json");
    let effect_id = {
        let mut ledger = EffectLedger::open(&path).unwrap();
        ledger.register_provider(ProviderContract::reconcilable(
            "mail",
            ReconciliationMode::IdempotencyKey,
            ConsequenceClass::E3,
        ));
        let mut proposal = EffectProposal::new(
            "command:2",
            "activation:1",
            "objective:ordered",
            "mail.send",
            "send",
            "recipient:1",
            "sha256:two",
            "intent:ordered:0002",
            ConsequenceClass::E2,
            200,
        )
        .ordered("recipient:1", 2);
        let (mut authority, invocation, channel, _peer) = authorization(&proposal);
        assert_eq!(
            ledger.propose_authorized(
                proposal.clone(),
                &mut authority,
                &channel,
                &invocation,
                true
            ),
            Err(EffectError::OrderingViolation)
        );
        proposal.ordering_sequence = Some(1);
        let (mut authority, invocation, channel, _peer) = authorization(&proposal);
        ledger
            .propose_authorized(proposal, &mut authority, &channel, &invocation, true)
            .unwrap()
            .effect_id
    };
    let recovered = EffectLedger::open(&path).unwrap();
    assert_eq!(recovered.recover(), vec![effect_id]);
}
