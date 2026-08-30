use habitat_effects::*;
use habitat_authority::*;

fn proposal(key:&str)->EffectProposal{
    EffectProposal::new("command:1","activation:1","objective:1","mail.send","send",
        "recipient:1","sha256:payload",key,ConsequenceClass::E2,200)
}

fn authorization(proposal:&EffectProposal)->(Authority,Invocation){
    let mut authority=Authority::new("policy:v2","generation:01","state:1");
    let grant=Grant::builder("grant:effect","service:issuer","activation:1",&proposal.capability)
        .caller("machine:1","service:effects").operations([proposal.operation.as_str()])
        .target_prefix(&proposal.target).valid_between(1,500).generation("generation:01").build().unwrap();
    authority.issue(grant,IndependentApproval::verified("operator:1")).unwrap();
    let invocation=Invocation::new(&proposal.command_id,MachineId::new("machine:1").unwrap(),
        ServiceId::new("service:effects").unwrap(),ActivationId::new("activation:1").unwrap(),
        &proposal.capability,&proposal.operation,&proposal.target,100,"state:1",&proposal.objective_id)
        .with_enforcement(EnforcementProof::verified("lsm:generic"));
    (authority,invocation)
}

#[test]
fn admission_atomically_reserves_semantic_intent_and_deduplicates(){
    let mut ledger=EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable("mail",ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2));
    let first_proposal=proposal("intent:mail:recipient:payload");
    let (mut authority,invocation)=authorization(&first_proposal);
    let first=ledger.propose_authorized(first_proposal.clone(),&mut authority,&invocation,true).unwrap();
    let duplicate=ledger.propose_authorized(first_proposal,&mut authority,&invocation,true).unwrap();
    assert_eq!(first.effect_id,duplicate.effect_id);
    assert_eq!(first.state,EffectState::Reserved);
    assert_eq!(ledger.len(),1);
    assert!(ledger.get(&first.effect_id).unwrap().admission.precondition_valid());

    let mut changed=proposal("intent:mail:recipient:payload");
    changed.target="recipient:other".into();
    let (_,changed_invocation)=authorization(&changed);
    assert_eq!(ledger.propose_authorized(changed,&mut authority,&changed_invocation,true),
        Err(EffectError::IdempotencyConflict));
}

#[test]
fn stale_revoked_or_mismatched_authority_cannot_reserve_an_effect(){
    let mut ledger=EffectLedger::new();
    ledger.register_provider(ProviderContract::reconcilable("mail",ReconciliationMode::IdempotencyKey,
        ConsequenceClass::E2));
    let proposal=proposal("intent:denied");
    let (mut authority,invocation)=authorization(&proposal);
    authority.revoke("grant:effect");
    assert_eq!(ledger.propose_authorized(proposal.clone(),&mut authority,&invocation,true),
        Err(EffectError::AdmissionDenied));
    let (mut current,mut mismatch)=authorization(&proposal);
    mismatch.target="recipient:other".into();
    assert_eq!(ledger.propose_authorized(proposal,&mut current,&mismatch,true),
        Err(EffectError::AdmissionDenied));
    assert_eq!(ledger.len(),0);
}
