//! Secret-free provider request metadata.
//!
//! This module deliberately has no credential, network, or dispatch capability. A caller may
//! construct evidence only after the authority/effect boundary has admitted the operation.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct ProviderEndpoint(String);
pub struct RequestEvidence {
    provider: String,
    endpoint_digest: String,
    activation: String,
    body_digest: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    UnsafeProvider,
    UnsafeActivation,
    UnsafeEndpoint,
}
impl ProviderEndpoint {
    pub fn admit(value: &str) -> Result<Self, TransportError> {
        if !safe_endpoint(value) {
            return Err(TransportError::UnsafeEndpoint);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl RequestEvidence {
    pub fn record(
        provider: &str,
        endpoint: &ProviderEndpoint,
        activation: &str,
        body: &Value,
    ) -> Result<Self, TransportError> {
        if !safe_identifier(provider) {
            return Err(TransportError::UnsafeProvider);
        }
        if !safe_identifier(activation) {
            return Err(TransportError::UnsafeActivation);
        }
        let bytes = serde_json::to_vec(body).expect("JSON provider request");
        Ok(Self {
            provider: provider.into(),
            endpoint_digest: format!("sha256:{:x}", Sha256::digest(endpoint.as_str().as_bytes())),
            activation: activation.into(),
            body_digest: format!("sha256:{:x}", Sha256::digest(bytes)),
        })
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn endpoint_digest(&self) -> &str {
        &self.endpoint_digest
    }
    pub fn activation(&self) -> &str {
        &self.activation
    }
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
}
fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn safe_endpoint(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let mut parts = rest.splitn(2, '/');
    let authority = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    !authority.is_empty()
        && !authority.contains('@')
        && !value.contains('?')
        && !value.contains('#')
        && matches!(path, "v1" | "v1/responses" | "v1/messages")
}
