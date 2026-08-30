use habitat_harnesses::*;
use habitat_models::{ActivationEnvelope,CapabilityDescriptor,DispositionKind};
use serde_json::json;

fn envelope()->ActivationEnvelope{ActivationEnvelope{abi_version:"1.0".into(),activation_id:"activation:11".into(),
    agent_id:"agent:durable".into(),objective_ids:vec!["objective:durable".into()],context_bundle_id:"context:11".into(),
    visible_capabilities:vec![CapabilityDescriptor{id:"weather.read".into(),operations:vec!["read".into()]}],
    deadline:200,trace_id:"trace:11".into(),correlation_id:"correlation:11".into()}}
fn prepared()->PreparedActivation{HarnessAdapter::prepare(&envelope(),"activation-set:sha256:pinned",&["grant:read"])}

#[test]
fn process_success_prose_and_session_completion_do_not_complete_objective(){
    let runtime=HarnessRuntime::new(prepared());
    assert_eq!(runtime.process_exit(0,None),RuntimeOutcome::AwaitingDisposition);
    assert_eq!(runtime.process_exit(0,Some(&json!({"type":"result","result":"done"}))),RuntimeOutcome::AwaitingDisposition);
    assert_eq!(runtime.status(),RuntimeStatus::Running);
}

#[test]
fn capability_proxy_allows_only_granted_habitat_endpoints_and_no_ambient_access(){
    let proxy=CapabilityProxy::new(&["habitat://capability/weather.read"]);
    assert!(proxy.invoke("habitat://capability/weather.read",json!({"operation":"read"})).is_ok());
    assert_eq!(proxy.invoke("https://api.provider.invalid",json!({})),Err(HarnessError::CapabilityDenied));
    assert_eq!(proxy.invoke("unix:///run/habitat/authority.sock",json!({})),Err(HarnessError::CapabilityDenied));
    assert!(proxy.environment().is_empty());
}

#[test]
fn only_typed_checkpoint_is_durable_and_transcript_is_disposable(){
    let mut store=HarnessCheckpoint::new();store.observe_transcript("private chain of thought");
    let event=json!({"type":"habitat.disposition","session_id":"codex:checkpoint","payload":{
        "activation_id":"activation:11","command_id":"command:checkpoint","kind":"CHECKPOINT",
        "payload":{"progress":"saved"},"decision":{"summary":"saved","evidence_refs":["evidence:checkpoint"]}}});
    let output=CodexAdapter::translate(&prepared(),&event).unwrap();store.commit(output.candidate).unwrap();
    assert_eq!(store.records().len(),1);assert_eq!(store.records()[0].kind,DispositionKind::Checkpoint);
    assert!(!serde_json::to_string(store.records()).unwrap().contains("chain of thought"));
}

#[test]
fn cancellation_deadline_and_backend_comparison_preserve_committed_truth(){
    let mut runtime=HarnessRuntime::new(prepared());runtime.commit_effect("effect:unknown");
    assert_eq!(runtime.check_deadline(201),Err(HarnessError::LeaseExpired));
    runtime.cancel("command:cancel","LEASE_EXPIRED").unwrap();
    assert_eq!(runtime.status(),RuntimeStatus::Cancelled);
    assert_eq!(runtime.committed_effects(),&["effect:unknown"]);
    let identity=prepared().identity;let state=BackendState{identity,effect_history:vec!["effect:unknown".into()],
        completion_contract:"evidence-contract:v1".into()};
    assert!(BackendConformance::compare(&state,&state,&state).is_ok());
}
