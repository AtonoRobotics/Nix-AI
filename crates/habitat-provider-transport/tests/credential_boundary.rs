use habitat_provider_transport::{CredentialBroker, ProviderTransport, TransportError};

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
    let broker = CredentialBroker::new("provider-a", "opaque-secret-value").unwrap();
    let mut transport = RecordingTransport::default();
    let (_, evidence) = broker
        .dispatch(
            &mut transport,
            "https://provider.invalid/v1",
            "activation:9",
            &serde_json::json!({"input":"private prompt"}),
        )
        .unwrap();
    assert!(transport.received_secret);
    assert_eq!(evidence.activation(), "activation:9");
    assert_eq!(evidence.provider(), "provider-a");
    assert!(!evidence.activation().contains("opaque-secret-value"));
    assert!(!evidence.endpoint_digest().contains("opaque-secret-value"));
    assert!(!evidence.body_digest().contains("opaque-secret-value"));
    assert!(!evidence.body_digest().contains("private prompt"));
    assert_eq!(broker.provider(), "provider-a");
}

#[test]
fn secret_bearing_evidence_identifiers_are_rejected_and_endpoint_is_digest_only() {
    assert!(matches!(
        CredentialBroker::new("provider?key=secret", "credential"),
        Err(TransportError::UnsafeProvider)
    ));
    let broker = CredentialBroker::new("provider-a", "credential").unwrap();
    let mut transport = RecordingTransport::default();
    assert!(matches!(
        broker.dispatch(
            &mut transport,
            "https://user:secret@provider.invalid",
            "activation?secret",
            &serde_json::json!({})
        ),
        Err(TransportError::UnsafeActivation)
    ));
    assert!(matches!(
        broker.dispatch(
            &mut transport,
            "https://user:secret@provider.invalid",
            "activation:9",
            &serde_json::json!({}),
        ),
        Err(TransportError::UnsafeEndpoint)
    ));
    assert!(matches!(
        broker.dispatch(
            &mut transport,
            "https://provider.invalid/path?key=secret",
            "activation:9",
            &serde_json::json!({})
        ),
        Err(TransportError::UnsafeEndpoint)
    ));
    assert!(matches!(
        broker.dispatch(
            &mut transport,
            "https://provider.invalid/v1/sk-secret",
            "activation:9",
            &serde_json::json!({})
        ),
        Err(TransportError::UnsafeEndpoint)
    ));
}
