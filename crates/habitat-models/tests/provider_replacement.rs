use habitat_models::*;

fn semantic_disposition()->serde_json::Value{serde_json::json!({
    "activation_id":"activation:9","command_id":"command:9","kind":"CHECKPOINT",
    "payload":{"progress":"bounded"},"decision":{"summary":"progress saved","evidence_refs":["evidence:9"]}
})}

#[test]
fn openai_and_anthropic_translate_to_identical_semantic_disposition(){
    let disposition=semantic_disposition();
    let openai=serde_json::json!({"id":"resp_9","model":"gpt-5","output":[{
        "type":"function_call","name":"submit_disposition","arguments":disposition.to_string()}],
        "usage":{"input_tokens":20,"output_tokens":10}});
    let anthropic=serde_json::json!({"id":"msg_9","model":"claude-sonnet-4-5","content":[{
        "type":"tool_use","name":"submit_disposition","input":disposition}],
        "usage":{"input_tokens":20,"output_tokens":10}});
    let a=OpenAiAdapter::translate(&openai).unwrap();
    let b=AnthropicAdapter::translate(&anthropic).unwrap();
    assert_eq!(a.disposition,b.disposition);
    assert_eq!(a.disposition.kind,DispositionKind::Checkpoint);
    assert_ne!(a.provider_request_id,b.provider_request_id);
}
