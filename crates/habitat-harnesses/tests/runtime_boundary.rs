use habitat_harnesses::*;
use habitat_models::{ActivationEnvelope, CapabilityDescriptor, DispositionKind};
use serde_json::json;

fn envelope() -> ActivationEnvelope {
    ActivationEnvelope {
        abi_version: "1.0".into(),
        activation_id: "activation:11".into(),
        agent_id: "agent:durable".into(),
        objective_ids: vec!["objective:durable".into()],
        context_bundle_id: "context:11".into(),
        visible_capabilities: vec![CapabilityDescriptor {
            id: "weather.read".into(),
            operations: vec!["read".into()],
        }],
        deadline: 200,
        trace_id: "trace:11".into(),
        correlation_id: "correlation:11".into(),
    }
}
fn prepared() -> PreparedActivation {
    HarnessAdapter::prepare(
        &envelope(),
        "activation-set:sha256:pinned",
        &["grant:weather.read"],
    )
}

#[test]
fn process_success_prose_and_session_completion_do_not_complete_objective() {
    let runtime = HarnessRuntime::new(prepared());
    assert_eq!(
        runtime.process_exit(0, None),
        RuntimeOutcome::AwaitingDisposition
    );
    assert_eq!(
        runtime.process_exit(0, Some(&json!({"type":"result","result":"done"}))),
        RuntimeOutcome::AwaitingDisposition
    );
    assert_eq!(runtime.status(), RuntimeStatus::Running);
}

#[test]
fn capability_requests_remain_typed_dispositions_for_current_authority_mediation() {
    let event = json!({"type":"habitat.disposition","session_id":"codex:capability","payload":{
        "activation_id":"activation:11","command_id":"command:capability","kind":"CAPABILITY_INVOCATION",
        "payload":{"capability":"weather.read","operation":"read"},
        "decision":{"summary":"request","evidence_refs":[]}}});
    let output = CodexAdapter::translate(&prepared(), &event).unwrap();
    assert_eq!(
        output.candidate.disposition.kind,
        DispositionKind::CapabilityInvocation
    );
}

#[test]
fn only_typed_checkpoint_is_durable_and_provider_diagnostics_are_not_state() {
    let mut store = HarnessCheckpoint::new();
    let event = json!({"type":"habitat.disposition","session_id":"codex:checkpoint","payload":{
        "activation_id":"activation:11","command_id":"command:checkpoint","kind":"CHECKPOINT",
        "payload":{"progress":"saved"},"decision":{"summary":"saved","evidence_refs":["evidence:checkpoint"]}}});
    let output = CodexAdapter::translate(&prepared(), &event).unwrap();
    store.commit(output.candidate).unwrap();
    assert_eq!(store.records().len(), 1);
    assert_eq!(store.records()[0].kind, DispositionKind::Checkpoint);
    assert!(!serde_json::to_string(store.records())
        .unwrap()
        .contains("chain of thought"));
}

#[test]
fn cancellation_deadline_and_backend_comparison_preserve_committed_truth() {
    let mut runtime = HarnessRuntime::new(prepared());
    assert_eq!(runtime.check_deadline(201), Err(HarnessError::LeaseExpired));
    runtime.cancel("command:cancel", "LEASE_EXPIRED").unwrap();
    assert_eq!(runtime.status(), RuntimeStatus::Cancelled);
    let identity = prepared().identity;
    let state = BackendState {
        identity,
        effect_history: vec!["effect:unknown".into()],
        completion_contract: "evidence-contract:v1".into(),
    };
    assert!(BackendConformance::compare(&state, &state, &state).is_ok());
}
