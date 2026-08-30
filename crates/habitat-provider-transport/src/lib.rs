//! Credential-bearing provider transport adapter, isolated from cognition and harness modules.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct CredentialBroker {
    provider: String,
    credential: String,
}
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
    MissingCredential,
}
pub trait ProviderTransport {
    type Output;
    fn send(
        &mut self,
        endpoint: &str,
        authorization: &str,
        activation: &str,
        body: &Value,
    ) -> Self::Output;
}
impl CredentialBroker {
    pub fn new(provider: &str, credential: &str) -> Result<Self, TransportError> {
        if !safe_identifier(provider) {
            return Err(TransportError::UnsafeProvider);
        }
        if credential.is_empty() {
            return Err(TransportError::MissingCredential);
        }
        Ok(Self {
            provider: provider.into(),
            credential: credential.into(),
        })
    }
    pub fn dispatch<T: ProviderTransport>(
        &self,
        transport: &mut T,
        endpoint: &str,
        activation: &str,
        body: &Value,
    ) -> Result<(T::Output, RequestEvidence), TransportError> {
        if !safe_identifier(activation) {
            return Err(TransportError::UnsafeActivation);
        }
        if !safe_endpoint(endpoint) {
            return Err(TransportError::UnsafeEndpoint);
        }
        let bytes = serde_json::to_vec(body).expect("JSON provider request");
        let output = transport.send(
            endpoint,
            &format!("Bearer {}", self.credential),
            activation,
            body,
        );
        Ok((
            output,
            RequestEvidence {
                provider: self.provider.clone(),
                endpoint_digest: format!("sha256:{:x}", Sha256::digest(endpoint.as_bytes())),
                activation: activation.into(),
                body_digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            },
        ))
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
}
impl RequestEvidence {
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
