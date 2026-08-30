use habitat_provider_transport::{CredentialBroker, ProviderTransport};

#[derive(Default)]
struct RecordingTransport {
    received_secret: bool,
}
impl ProviderTransport for RecordingTransport {
    type Output = ();
    fn send(
        &mut self,
        _endpoint: &str,
        authorization: &str,
        _activation: &str,
        _body: &serde_json::Value,
    ) {
        self.received_secret = authorization == "Bearer opaque-secret-value";
    }
}

#[test]
fn credential_is_consumed_inside_transport_and_never_returned_as_evidence() {
    let broker = CredentialBroker::new("provider-a", "opaque-secret-value");
    let mut transport = RecordingTransport::default();
    let (_, evidence) = broker.dispatch(
        &mut transport,
        "https://provider.invalid/v1",
        "activation:9",
        &serde_json::json!({"input":"private prompt"}),
    );
    assert!(transport.received_secret);
    assert_eq!(evidence.activation, "activation:9");
    assert!(!evidence.activation.contains("opaque-secret-value"));
    assert!(!evidence.body_digest.contains("opaque-secret-value"));
    assert!(!evidence.body_digest.contains("private prompt"));
    assert_eq!(broker.provider(), "provider-a");
}
