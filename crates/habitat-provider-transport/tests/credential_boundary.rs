use habitat_provider_transport::CredentialBroker;

#[test]
fn credential_exists_only_in_transport_request_and_never_in_activation_or_digest(){
    let broker=CredentialBroker::new("provider-a","opaque-secret-value");
    let request=broker.prepare("https://provider.invalid/v1","activation:9",
        &serde_json::json!({"input":"private prompt"}));
    assert_eq!(request.authorization,"Bearer opaque-secret-value");
    assert_eq!(request.activation,"activation:9");
    assert!(!request.activation.contains("opaque-secret-value"));
    assert!(!request.body_digest.contains("opaque-secret-value"));
    assert!(!request.body_digest.contains("private prompt"));
    assert_eq!(broker.provider(),"provider-a");
}
