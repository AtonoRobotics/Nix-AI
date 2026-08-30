use habitat_models::*;
use serde_json::json;

fn envelope()->ActivationEnvelope{ActivationEnvelope{abi_version:"1.0".into(),activation_id:"activation:9".into(),
    agent_id:"agent:9".into(),objective_ids:vec!["objective:9".into()],context_bundle_id:"context:9".into(),
    visible_capabilities:vec![CapabilityDescriptor{id:"weather.read".into(),operations:vec!["read".into()]}],
    deadline:200,trace_id:"trace:9".into(),correlation_id:"correlation:9".into()}}
fn candidate(kind:DispositionKind,command:&str,payload:serde_json::Value)->CandidateOutput{CandidateOutput{
    disposition:Disposition{activation_id:"activation:9".into(),command_id:command.into(),kind,payload,
        decision:DecisionArtifact{summary:"bounded decision".into(),evidence_refs:vec!["evidence:9".into()]}},
    provider_request_id:"provider-request:9".into(),provider:"test".into(),model:"model:9".into(),
    input_tokens:10,output_tokens:4}}

#[test]
fn validator_rejects_missing_identity_and_invisible_capability_without_heuristics(){
    let validator=DispositionValidator::new(&envelope());
    assert_eq!(validator.validate(candidate(DispositionKind::Checkpoint,"",json!({}))),Err(ModelError::CommandIdRequired));
    assert_eq!(validator.validate(candidate(DispositionKind::CapabilityInvocation,"command:1",
        json!({"capability":"admin.root","operation":"write"}))),Err(ModelError::CapabilityInvisible));
    let prose=json!({"id":"resp","model":"gpt-5","output":[{"type":"message","content":[{
        "type":"output_text","text":"I completed the objective and sent the email"}]}],
        "usage":{"input_tokens":1,"output_tokens":1}});
    assert_eq!(OpenAiAdapter::translate(&prose),Err(ModelError::MissingDisposition));
}

#[test]
fn provider_stop_does_not_complete_but_validated_completion_claim_does(){
    let driver=ModelDriver::new(envelope());
    assert_eq!(driver.status(),ActivationStatus::Running);
    let checkpoint=driver.accept(candidate(DispositionKind::Checkpoint,"command:1",json!({"progress":"saved"})),100).unwrap();
    assert_eq!(checkpoint.status,ActivationStatus::Running);
    let completion=driver.accept(candidate(DispositionKind::CompletionClaim,"command:2",
        json!({"objective_id":"objective:9","evidence_refs":["evidence:result"]})),110).unwrap();
    assert_eq!(completion.status,ActivationStatus::CompletionClaimed);
}

#[test]
fn cancellation_and_deadline_are_classified_without_implicit_completion(){
    let mut driver=ModelDriver::new(envelope());
    assert_eq!(driver.check_deadline(201),Err(ModelError::LeaseExpired));
    driver.cancel("command:cancel","USER_REQUEST").unwrap();
    assert_eq!(driver.status(),ActivationStatus::Cancelled);
}

#[test]
fn cognition_evidence_is_digest_only_and_contains_no_transport_secret_or_prompt(){
    let evidence=ModelEvidence::record(&envelope(),"openai","gpt-5","provider-request:9",10,4,37,
        "sha256:0000000000000000000000000000000000000000000000000000000000000009");
    let encoded=serde_json::to_string(&evidence).unwrap();
    assert!(encoded.contains("trace:9")&&encoded.contains("correlation:9"));
    assert!(!encoded.contains("secret")&&!encoded.contains("private prompt"));
    assert!(evidence.request_digest.starts_with("sha256:"));
}
