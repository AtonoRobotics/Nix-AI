use habitat_provider_transport::{ProviderEndpoint, RequestEvidence, TransportError};

#[test]
fn provider_metadata_is_secret_free_and_has_no_dispatch_authority() {
    let endpoint = ProviderEndpoint::admit("https://provider.invalid/v1").unwrap();
    let evidence = RequestEvidence::record(
        "provider-a",
        &endpoint,
        "activation:9",
        &serde_json::json!({"input":"private prompt"}),
    )
    .unwrap();
    assert_eq!(evidence.activation(), "activation:9");
    assert_eq!(evidence.provider(), "provider-a");
    assert!(!evidence.endpoint_digest().contains("provider.invalid"));
    assert!(!evidence.body_digest().contains("private prompt"));
}

#[test]
fn secret_bearing_provider_metadata_and_endpoints_are_rejected() {
    let endpoint = ProviderEndpoint::admit("https://provider.invalid/v1").unwrap();
    assert!(matches!(
        RequestEvidence::record(
            "provider?key=secret",
            &endpoint,
            "activation:9",
            &serde_json::json!({})
        ),
        Err(TransportError::UnsafeProvider)
    ));
    assert!(matches!(
        RequestEvidence::record(
            "provider-a",
            &endpoint,
            "activation?secret",
            &serde_json::json!({})
        ),
        Err(TransportError::UnsafeActivation)
    ));
    for unsafe_endpoint in [
        "https://user:secret@provider.invalid/v1",
        "https://provider.invalid/v1?key=secret",
        "https://provider.invalid/v1#secret",
        "https://provider.invalid/v1/sk-secret",
    ] {
        assert!(matches!(
            ProviderEndpoint::admit(unsafe_endpoint),
            Err(TransportError::UnsafeEndpoint)
        ));
    }
}
