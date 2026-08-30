use habitat_harnesses::*;
use habitat_models::{DispositionKind,ActivationEnvelope,CapabilityDescriptor};
use serde_json::json;

fn envelope()->ActivationEnvelope{ActivationEnvelope{abi_version:"1.0".into(),activation_id:"activation:11".into(),
    agent_id:"agent:durable".into(),objective_ids:vec!["objective:durable".into()],context_bundle_id:"context:11".into(),
    visible_capabilities:vec![CapabilityDescriptor{id:"weather.read".into(),operations:vec!["read".into()]}],
    deadline:200,trace_id:"trace:11".into(),correlation_id:"correlation:11".into()}}
fn disposition()->serde_json::Value{json!({"activation_id":"activation:11","command_id":"command:11",
    "kind":"CHECKPOINT","payload":{"progress":"saved"},
    "decision":{"summary":"checkpoint","evidence_refs":["evidence:11"]}})}

#[test]
fn codex_and_claude_emit_the_same_semantic_abi_and_identity(){
    let prepared=HarnessAdapter::prepare(&envelope(),"activation-set:sha256:adapter",&["grant:read"]);
    let codex=json!({"type":"habitat.disposition","session_id":"codex:11","payload":disposition()});
    let claude=json!({"type":"result","session_id":"claude:11","structured_output":disposition()});
    let a=CodexAdapter::translate(&prepared,&codex).unwrap();
    let b=ClaudeCodeAdapter::translate(&prepared,&claude).unwrap();
    assert_eq!(a.candidate.disposition,b.candidate.disposition);
    assert_eq!(a.candidate.disposition.kind,DispositionKind::Checkpoint);
    assert_eq!(a.identity,b.identity);
    assert_eq!(a.identity.agent_id,"agent:durable");
    assert_eq!(a.identity.activation_set_id,"activation-set:sha256:adapter");
}
