use habitat_effects::*;

fn proposal(key:&str)->EffectProposal{
    EffectProposal::new("command:1","activation:1","objective:1","mail.send","send",
        "recipient:1","sha256:payload",key,ConsequenceClass::E2,200)
}

#[test]
fn admission_atomically_reserves_semantic_intent_and_deduplicates(){
    let mut ledger=EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable("mail",ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2));
    let first=ledger.propose(proposal("intent:mail:recipient:payload"),Admission::allow("decision:1",true)).unwrap();
    let duplicate=ledger.propose(proposal("intent:mail:recipient:payload"),Admission::allow("decision:2",true)).unwrap();
    assert_eq!(first.effect_id,duplicate.effect_id);
    assert_eq!(first.state,EffectState::Reserved);
    assert_eq!(ledger.len(),1);
    assert!(ledger.get(&first.effect_id).unwrap().admission.precondition_valid);
}
