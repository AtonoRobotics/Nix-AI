//! Credential-bearing provider transport adapter, isolated from cognition and harness modules.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct CredentialBroker {
    provider: String,
    credential: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestEvidence {
    pub provider: String,
    pub endpoint: String,
    pub activation: String,
    pub body_digest: String,
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
    pub fn new(provider: &str, credential: &str) -> Self {
        Self {
            provider: provider.into(),
            credential: credential.into(),
        }
    }
    pub fn dispatch<T: ProviderTransport>(
        &self,
        transport: &mut T,
        endpoint: &str,
        activation: &str,
        body: &Value,
    ) -> (T::Output, RequestEvidence) {
        let bytes = serde_json::to_vec(body).expect("JSON provider request");
        let output = transport.send(
            endpoint,
            &format!("Bearer {}", self.credential),
            activation,
            body,
        );
        (
            output,
            RequestEvidence {
                provider: self.provider.clone(),
                endpoint: endpoint.into(),
                activation: activation.into(),
                body_digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            },
        )
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
}
