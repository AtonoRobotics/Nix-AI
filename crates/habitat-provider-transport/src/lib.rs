//! Credential-bearing provider transport adapter, isolated from cognition and harness modules.
use serde_json::Value;
use sha2::{Digest,Sha256};

pub struct CredentialBroker { provider:String,credential:String }
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct TransportRequest { pub endpoint:String,pub authorization:String,pub activation:String,
    pub body_digest:String }
impl CredentialBroker {
    pub fn new(provider:&str,credential:&str)->Self{Self{provider:provider.into(),credential:credential.into()}}
    pub fn prepare(&self,endpoint:&str,activation:&str,body:&Value)->TransportRequest{
        let bytes=serde_json::to_vec(body).expect("JSON provider request");
        TransportRequest{endpoint:endpoint.into(),authorization:format!("Bearer {}",self.credential),
            activation:activation.into(),body_digest:format!("sha256:{:x}",Sha256::digest(bytes))}
    }
    pub fn provider(&self)->&str{&self.provider}
}
