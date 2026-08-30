use habitat_effects::*;

fn ledger()->EffectLedger{ let mut value=EffectLedger::new(); value.register_provider(
    ProviderContract::reconcilable("mail",ReconciliationMode::IdempotencyKey,ConsequenceClass::E3)); value }
fn proposed(ledger:&mut EffectLedger,key:&str)->EffectRecord{ ledger.propose(
    EffectProposal::new("command:1","activation:1","objective:1","mail.send","send","recipient:1",
        "sha256:payload",key,ConsequenceClass::E2,200),Admission::allow("decision:1",true)).unwrap() }

#[test]
fn disconnect_after_dispatch_becomes_unknown_and_reconciles_without_retry(){
    let mut ledger=ledger(); let effect=proposed(&mut ledger,"intent:unknown:0001");
    ledger.dispatch(&effect.effect_id,Attempt::new("sha256:req",100,"mail","transport:7")).unwrap();
    ledger.transport_lost(&effect.effect_id,"disconnect").unwrap();
    assert_eq!(ledger.get(&effect.effect_id).unwrap().state,EffectState::OutcomeUnknown);
    assert_eq!(ledger.attempts(&effect.effect_id).len(),1);
    ledger.begin_reconciliation(&effect.effect_id).unwrap();
    ledger.resolve(&effect.effect_id,Observation::independent("provider-lookup","message:7",true)).unwrap();
    assert_eq!(ledger.get(&effect.effect_id).unwrap().state,EffectState::ResolvedSucceeded);
    assert_eq!(ledger.attempts(&effect.effect_id).len(),1);
}

#[test]
fn acknowledgement_is_not_success_without_the_declared_observation(){
    let mut ledger=ledger(); let effect=proposed(&mut ledger,"intent:evidence:0001");
    ledger.dispatch(&effect.effect_id,Attempt::new("sha256:req",100,"mail","transport:8")).unwrap();
    assert_eq!(ledger.observe(&effect.effect_id,Observation::provider_ack("accepted")),Err(EffectError::IndependentEvidenceRequired));
    ledger.observe(&effect.effect_id,Observation::independent("mailbox","message:8",true)).unwrap();
    assert_eq!(ledger.get(&effect.effect_id).unwrap().state,EffectState::ObservedSucceeded);
    assert_eq!(ledger.attempts(&effect.effect_id)[0].terminal_classification,Some(EffectState::ObservedSucceeded));
}

#[test]
fn cancellation_and_compensation_preserve_truthful_distinct_histories(){
    let mut ledger=ledger(); let before=proposed(&mut ledger,"intent:cancel:0001");
    ledger.cancel(&before.effect_id).unwrap(); assert_eq!(ledger.get(&before.effect_id).unwrap().state,EffectState::Cancelled);
    let original=proposed(&mut ledger,"intent:original:0001");
    ledger.dispatch(&original.effect_id,Attempt::new("sha256:o",100,"mail","transport:o")).unwrap();
    ledger.observe(&original.effect_id,Observation::independent("mailbox","message:o",true)).unwrap();
    let compensation=ledger.compensate(&original.effect_id,"command:c","mail.retract","intent:compensation:0001",
        Admission::allow("decision:c",true)).unwrap();
    ledger.dispatch(&compensation.effect_id,Attempt::new("sha256:c",110,"mail","transport:c")).unwrap();
    ledger.observe(&compensation.effect_id,Observation::independent("mailbox","still-present",false)).unwrap();
    assert_eq!(ledger.get(&original.effect_id).unwrap().state,EffectState::ObservedSucceeded);
    assert_eq!(ledger.get(&compensation.effect_id).unwrap().state,EffectState::ObservedFailed);
    assert_eq!(compensation.proposal.compensates_effect_id,Some(original.effect_id));
}

#[test]
fn recovery_bounded_validity_ordering_and_completion_fail_closed(){
    let mut ledger=ledger(); ledger.register_provider(ProviderContract::reconcilable(
        "service",ReconciliationMode::TargetState,ConsequenceClass::E3));
    let mut operation=EffectProposal::new("command:m","activation:1","objective:change","service.change","apply",
        "resource:1","sha256:change","intent:change:0001",ConsequenceClass::E3,120);
    operation=operation.bounded("constraint:7",100,120,true).ordered("resource:1",1);
    let effect=ledger.propose_at(operation,Admission::allow("decision:m",true),110).unwrap();
    assert_eq!(ledger.complete_objective("objective:change"),Err(EffectError::ObjectiveEffectsPending));
    assert_eq!(ledger.dispatch_at(&effect.effect_id,Attempt::new("sha256:m",121,"service","transport:m"),121),Err(EffectError::ExpiredCommand));
    assert_eq!(ledger.recover(),vec![effect.effect_id]);
}

#[test]
fn restart_recovers_nonterminal_effects_and_enforces_declared_order(){
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("effects.json");
    let effect_id={
        let mut ledger=EffectLedger::open(&path).unwrap();ledger.register_provider(
            ProviderContract::reconcilable("mail",ReconciliationMode::IdempotencyKey,ConsequenceClass::E3));
        let mut proposal=EffectProposal::new("command:2","activation:1","objective:ordered","mail.send","send",
            "recipient:1","sha256:two","intent:ordered:0002",ConsequenceClass::E2,200).ordered("recipient:1",2);
        assert_eq!(ledger.propose(proposal.clone(),Admission::allow("decision:2",true)),Err(EffectError::OrderingViolation));
        proposal.ordering_sequence=Some(1);
        ledger.propose(proposal,Admission::allow("decision:1",true)).unwrap().effect_id
    };
    let recovered=EffectLedger::open(&path).unwrap();
    assert_eq!(recovered.recover(),vec![effect_id]);
}
