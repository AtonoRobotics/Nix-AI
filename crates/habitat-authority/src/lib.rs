//! Deterministic, default-deny capability authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeSet, HashMap, HashSet}, fs, path::{Path, PathBuf}};

macro_rules! identity {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, AuthorityError> {
                if value.starts_with($prefix) && value.len() > $prefix.len() {
                    Ok(Self(value.into()))
                } else { Err(AuthorityError::IdentityInvalid) }
            }
            pub fn as_str(&self) -> &str { &self.0 }
        }
    }
}
identity!(MachineId, "machine:");
identity!(ServiceId, "service:");
identity!(ActivationId, "activation:");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    IdentityInvalid, InvalidGrant, SelfAuthority, ParentMissing, ParentInactive, AttenuationViolation, Storage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String, pub schema_version: String, pub issuer: String, pub subject: String,
    pub capability: String, pub capability_version: String, pub operations: BTreeSet<String>,
    pub target_prefix: String, pub quota: u64, pub issued_at: u64, pub not_before: u64,
    pub expires_at: u64, pub remaining_delegation_depth: u32, pub generation: String,
    pub activation: String, pub revocation_handle: String, pub policy_ref: String,
    pub evidence_refs: Vec<String>, pub issuance_proof: String,
}

pub struct GrantBuilder(Grant);
impl Grant {
    pub fn builder(id: &str, issuer: &str, subject: &str, capability: &str) -> GrantBuilder {
        GrantBuilder(Grant { id:id.into(), schema_version:"2.0".into(), issuer:issuer.into(),
            subject:subject.into(), capability:capability.into(), capability_version:"2.0".into(),
            operations:BTreeSet::new(), target_prefix:String::new(), quota:1, issued_at:0,
            not_before:0, expires_at:0, remaining_delegation_depth:0, generation:String::new(),
            activation:subject.into(), revocation_handle:format!("revoke:{id}"),
            policy_ref:"policy:v2".into(), evidence_refs:vec![], issuance_proof:String::new() })
    }
}
impl GrantBuilder {
    pub fn operations<const N: usize>(mut self, values: [&str; N]) -> Self {
        self.0.operations = values.into_iter().map(Into::into).collect(); self
    }
    pub fn target_prefix(mut self, value: &str) -> Self { self.0.target_prefix=value.into(); self }
    pub fn valid_between(mut self, start:u64,end:u64)->Self{
        self.0.issued_at=start; self.0.not_before=start; self.0.expires_at=end; self
    }
    pub fn generation(mut self,value:&str)->Self{self.0.generation=value.into();self}
    pub fn delegation_depth(mut self,value:u32)->Self{self.0.remaining_delegation_depth=value;self}
    pub fn quota(mut self,value:u64)->Self{self.0.quota=value;self}
    pub fn build(mut self)->Result<Grant,AuthorityError>{
        if self.0.id.is_empty() || self.0.issuer.is_empty() || !self.0.subject.starts_with("activation:")
            || self.0.operations.is_empty() || self.0.target_prefix.is_empty()
            || self.0.not_before >= self.0.expires_at || self.0.generation.is_empty() {
            return Err(AuthorityError::InvalidGrant)
        }
        self.0.issuance_proof = format!("sha256:{:x}",Sha256::digest(serde_json::to_vec(&self.0).unwrap()));
        Ok(self.0)
    }
}

#[derive(Clone, Debug)]
pub struct IndependentApproval { approver:String, verified:bool }
impl IndependentApproval {
    pub fn verified(approver:&str)->Self{Self{approver:approver.into(),verified:true}}
}

#[derive(Clone, Debug)]
pub struct EnforcementProof { provider:String, verified:bool }
impl EnforcementProof {
    pub fn verified(provider:&str)->Self{Self{provider:provider.into(),verified:true}}
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub command_id:String, pub machine:MachineId, pub service:ServiceId,
    pub activation:ActivationId, pub capability:String, pub operation:String,
    pub target:String, pub at:u64, pub state_version:String, pub objective:String,
    pub generation:String, pub enforcement:Option<EnforcementProof>,
}
impl Invocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(command:&str,machine:MachineId,service:ServiceId,activation:ActivationId,
        capability:&str,operation:&str,target:&str,at:u64,state:&str,objective:&str)->Self{
        Self{command_id:command.into(),machine,service,activation,capability:capability.into(),
            operation:operation.into(),target:target.into(),at,state_version:state.into(),
            objective:objective.into(),generation:"generation:01".into(),enforcement:None}
    }
    pub fn with_enforcement(mut self,proof:EnforcementProof)->Self{self.enforcement=Some(proof);self}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id:String, pub allowed:bool, pub grant_id:Option<String>,
    pub denial_code:Option<String>, pub subject:String, pub issuer_chain:Vec<String>,
    pub activation:String, pub objective:String, pub target:String, pub operation:String,
    pub policy_version:String, pub revocation_epoch:u64, pub evaluated_state_version:String,
    pub result_evidence:String,
    pub enforcement_provider:Option<String>,
    pub denial_reason:Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Authority {
    policy:String, generation:String, state_version:String, grants:HashMap<String,Grant>, revoked:HashSet<String>,
    epoch:u64, available:bool, decisions:Vec<Decision>, #[serde(skip)] path:Option<PathBuf>,
}
impl Authority {
    pub fn new(policy:&str,generation:&str,state_version:&str)->Self{Self{policy:policy.into(),generation:generation.into(),state_version:state_version.into(),
        grants:HashMap::new(),revoked:HashSet::new(),epoch:0,available:true,decisions:vec![],path:None}}
    pub fn open(path:impl AsRef<Path>,policy:&str,generation:&str,state_version:&str)->Result<Self,AuthorityError>{
        let path=path.as_ref().to_owned();
        if path.exists(){
            let mut value:Self=serde_json::from_slice(&fs::read(&path).map_err(|_|AuthorityError::Storage)?)
                .map_err(|_|AuthorityError::Storage)?;
            value.path=Some(path); value.available=true; Ok(value)
        }else{
            let mut value=Self::new(policy,generation,state_version); value.path=Some(path); Ok(value)
        }
    }
    fn persist(&self)->Result<(),AuthorityError>{
        if let Some(path)=&self.path{
            let temp=path.with_extension("tmp");
            fs::write(&temp,serde_json::to_vec(self).map_err(|_|AuthorityError::Storage)?)
                .and_then(|_|fs::rename(temp,path)).map_err(|_|AuthorityError::Storage)?;
        } Ok(())
    }
    pub fn issue(&mut self,grant:Grant,approval:IndependentApproval)->Result<(),AuthorityError>{
        if !approval.verified || approval.approver==grant.subject || grant.issuer==grant.subject {
            return Err(AuthorityError::SelfAuthority)
        }
        self.grants.insert(grant.id.clone(),grant); self.persist()
    }
    pub fn set_available(&mut self,value:bool){self.available=value}
    pub fn update_state_version(&mut self,value:&str)->Result<(),AuthorityError>{
        self.state_version=value.into();self.persist()
    }
    pub fn revoke(&mut self,grant_id:&str)->bool{
        self.epoch+=1; let changed=self.revoked.insert(grant_id.into());
        if self.persist().is_err(){self.available=false;} changed
    }
    pub fn delegate(&mut self,parent_id:&str,child:Grant)->Result<(),AuthorityError>{
        let parent=self.grants.get(parent_id).ok_or(AuthorityError::ParentMissing)?;
        if self.revoked.contains(parent_id){return Err(AuthorityError::ParentInactive)}
        if child.issuer!=parent.subject || child.operations.is_empty()
            || !child.operations.is_subset(&parent.operations)
            || !child.target_prefix.starts_with(&parent.target_prefix)
            || child.not_before<parent.not_before || child.expires_at>parent.expires_at
            || child.quota>parent.quota
            || child.remaining_delegation_depth>=parent.remaining_delegation_depth
            || child.generation!=parent.generation {
            return Err(AuthorityError::AttenuationViolation)
        }
        self.grants.insert(child.id.clone(),child); self.persist()
    }
    pub fn evaluate(&mut self,request:&Invocation)->Decision{
        let denial = if !self.available { Some(("UNAVAILABLE","authority state unavailable")) }
            else if request.command_id.is_empty() || request.objective.is_empty() { Some(("INVALID","identity or objective missing")) }
            else if request.generation!=self.generation { Some(("STALE","generation mismatch")) }
            else if request.state_version!=self.state_version { Some(("STALE","authority state version mismatch")) }
            else { None };
        let mut candidates=self.grants.values().filter(|g|g.subject==request.activation.as_str()
            &&g.capability==request.capability).collect::<Vec<_>>();
        candidates.sort_by(|left,right|left.id.cmp(&right.id));
        let (mut grant,mut code)=(None,denial);
        if code.is_none(){
            for candidate in candidates{
                let reason=if self.revoked.contains(&candidate.id){Some(("UNAUTHORIZED","grant revoked"))}
                    else if request.at<candidate.not_before||request.at>=candidate.expires_at{Some(("STALE","grant outside validity interval"))}
                    else if candidate.generation!=request.generation{Some(("STALE","grant generation mismatch"))}
                    else if !candidate.operations.contains(&request.operation){Some(("UNAUTHORIZED","operation outside grant scope"))}
                    else if !request.target.starts_with(&candidate.target_prefix){Some(("UNAUTHORIZED","target outside grant scope"))}
                    else if !request.enforcement.as_ref().map(|p|p.verified).unwrap_or(false)
                        &&request.operation!="read"{Some(("UNAUTHORIZED","enforcement proof unverified"))}
                    else{None};
                if grant.is_none(){grant=Some(candidate);code=reason}
                if reason.is_none(){grant=Some(candidate);code=None;break}
            }
            if grant.is_none(){code=Some(("UNAUTHORIZED","no current scoped grant"))}
        }
        let mut decision=Decision{decision_id:String::new(),allowed:code.is_none(),
            grant_id:grant.map(|g|g.id.clone()),denial_code:code.map(|value|value.0.into()),
            subject:request.activation.as_str().into(),
            issuer_chain:grant.map(|g|vec![g.issuer.clone()]).unwrap_or_default(),
            activation:request.activation.as_str().into(),objective:request.objective.clone(),
            target:request.target.clone(),operation:request.operation.clone(),policy_version:self.policy.clone(),
            revocation_epoch:self.epoch,evaluated_state_version:request.state_version.clone(),
            result_evidence:String::new(),
            enforcement_provider:request.enforcement.as_ref().map(|p|p.provider.clone()),
            denial_reason:code.map(|value|value.1.into())};
        decision.decision_id=format!("decision:sha256:{:x}",Sha256::digest(serde_json::to_vec(&decision).unwrap()));
        decision.result_evidence=format!("evidence:{}",decision.decision_id);
        self.decisions.push(decision.clone()); decision
    }
    pub fn audit(&self)->&[Decision]{&self.decisions}
}
