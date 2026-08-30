//! Deterministic, default-deny capability authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeSet, HashMap, HashSet}, fs, mem, os::fd::AsRawFd,
    os::unix::{fs::MetadataExt,net::UnixStream}, path::{Path, PathBuf}};

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
    IdentityInvalid, InvalidGrant, SelfAuthority, ParentMissing, ParentInactive, AttenuationViolation,
    BindingLocked, PeerCredential, TimeRollback, Storage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String, pub schema_version: String, pub issuer: String, pub subject: String,
    pub capability: String, pub capability_version: String, pub operations: BTreeSet<String>,
    pub target_prefix: String, pub quota: u64, pub issued_at: u64, pub not_before: u64,
    pub expires_at: u64, pub remaining_delegation_depth: u32, pub generation: String,
    pub activation: String, pub revocation_handle: String, pub policy_ref: String,
    pub evidence_refs: Vec<String>, pub issuance_proof: String,
    pub machine:String,pub service:String,pub parent_grant_id:Option<String>,
}

pub struct GrantBuilder(Grant);
impl Grant {
    pub fn builder(id: &str, issuer: &str, subject: &str, capability: &str) -> GrantBuilder {
        GrantBuilder(Grant { id:id.into(), schema_version:"2.0".into(), issuer:issuer.into(),
            subject:subject.into(), capability:capability.into(), capability_version:"2.0".into(),
            operations:BTreeSet::new(), target_prefix:String::new(), quota:1, issued_at:0,
            not_before:0, expires_at:0, remaining_delegation_depth:0, generation:String::new(),
            activation:subject.into(), revocation_handle:format!("revoke:{id}"),
            policy_ref:"policy:v2".into(), evidence_refs:vec![], issuance_proof:String::new(),
            machine:String::new(),service:String::new(),parent_grant_id:None })
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
    pub fn caller(mut self,machine:&str,service:&str)->Self{
        self.0.machine=machine.into();self.0.service=service.into();self
    }
    pub fn build(mut self)->Result<Grant,AuthorityError>{
        if self.0.id.is_empty() || self.0.issuer.is_empty() || !self.0.subject.starts_with("activation:")
            || self.0.operations.is_empty() || self.0.target_prefix.is_empty()
            || self.0.not_before >= self.0.expires_at || self.0.generation.is_empty()
            || !self.0.machine.starts_with("machine:") || !self.0.service.starts_with("service:") {
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
    pub target:String, pub requested_at:u64, pub state_version:String, pub objective:String,
    pub generation:String, pub enforcement:Option<EnforcementProof>,
}
impl Invocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(command:&str,machine:MachineId,service:ServiceId,activation:ActivationId,
        capability:&str,operation:&str,target:&str,at:u64,state:&str,objective:&str)->Self{
        Self{command_id:command.into(),machine,service,activation,capability:capability.into(),
            operation:operation.into(),target:target.into(),requested_at:at,state_version:state.into(),
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
impl Decision{
    pub fn is_allowed(&self)->bool{self.allowed}
    pub fn id(&self)->&str{&self.decision_id}
}

#[derive(Serialize, Deserialize)]
pub struct Authority {
    policy:String,generation:String,state_version:String,current_time:u64,
    trusted_peer:Option<TrustedPeer>,#[serde(skip)] peer_binding:Option<PeerBinding>,
    grants:HashMap<String,Grant>,revoked:HashSet<String>,
    epoch:u64, available:bool, decisions:Vec<Decision>, #[serde(skip)] path:Option<PathBuf>,
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)] struct TrustedPeer { uid:u32,gid:u32,
    executable:(u64,u64),machine:String,service:String,activation:String }
#[derive(Clone,Debug)] struct PeerBinding { channel:(u64,u64),pid:i32,uid:u32,gid:u32,
    machine:String,service:String,activation:String }
impl Authority {
    pub fn new(policy:&str,generation:&str,state_version:&str,current_time:u64)->Self{Self{policy:policy.into(),generation:generation.into(),state_version:state_version.into(),current_time,
        trusted_peer:None,peer_binding:None,grants:HashMap::new(),revoked:HashSet::new(),epoch:0,available:true,decisions:vec![],path:None}}
    pub fn open(path:impl AsRef<Path>,policy:&str,generation:&str,state_version:&str,current_time:u64)->Result<Self,AuthorityError>{
        let path=path.as_ref().to_owned();
        if path.exists(){
            let mut value:Self=serde_json::from_slice(&fs::read(&path).map_err(|_|AuthorityError::Storage)?)
                .map_err(|_|AuthorityError::Storage)?;
            value.path=Some(path);value.policy=policy.into();value.generation=generation.into();
            value.state_version=state_version.into();value.current_time=value.current_time.max(current_time);
            value.available=true;value.persist()?;Ok(value)
        }else{
            let mut value=Self::new(policy,generation,state_version,current_time);value.path=Some(path);
            value.persist()?;Ok(value)
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
    fn peer_credentials(channel:&UnixStream)->Result<((u64,u64),libc::ucred),AuthorityError>{
        let fd=channel.as_raw_fd();
        let mut stat=mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe{libc::fstat(fd,stat.as_mut_ptr())}!=0{return Err(AuthorityError::PeerCredential)}
        let stat=unsafe{stat.assume_init()};
        let mut credential=mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length=mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),&mut length)}!=0||length as usize!=mem::size_of::<libc::ucred>(){
            return Err(AuthorityError::PeerCredential)
        }
        Ok(((stat.st_dev as u64,stat.st_ino as u64),unsafe{credential.assume_init()}))
    }
    pub fn bind_peer(&mut self,channel:&UnixStream,machine:&MachineId,service:&ServiceId,
        activation:&ActivationId)->Result<(),AuthorityError>{
        if self.peer_binding.is_some(){return Err(AuthorityError::BindingLocked)}
        let (identity,credential)=Self::peer_credentials(channel)?;
        let executable=fs::metadata(format!("/proc/{}/exe",credential.pid))
            .map_err(|_|AuthorityError::PeerCredential)?;
        let observed=TrustedPeer{uid:credential.uid,gid:credential.gid,
            executable:(executable.dev(),executable.ino()),machine:machine.as_str().into(),
            service:service.as_str().into(),activation:activation.as_str().into()};
        match &self.trusted_peer{
            Some(trusted) if trusted!=&observed=>return Err(AuthorityError::PeerCredential),
            None if !self.grants.is_empty()=>return Err(AuthorityError::BindingLocked),
            None=>{self.trusted_peer=Some(observed);self.persist()?},
            Some(_)=>{}
        }
        self.peer_binding=Some(PeerBinding{channel:identity,pid:credential.pid,uid:credential.uid,gid:credential.gid,
            machine:machine.as_str().into(),service:service.as_str().into(),activation:activation.as_str().into()});Ok(())
    }
    pub fn advance_time(&mut self,value:u64)->Result<(),AuthorityError>{
        if value<self.current_time{return Err(AuthorityError::TimeRollback)}
        self.current_time=value;self.persist()
    }
    pub fn update_state_version(&mut self,value:&str)->Result<(),AuthorityError>{
        self.state_version=value.into();self.persist()
    }
    pub fn revoke(&mut self,grant_id:&str)->bool{
        self.epoch+=1; let changed=self.revoked.insert(grant_id.into());
        if self.persist().is_err(){self.available=false;} changed
    }
    pub fn delegate(&mut self,parent_id:&str,mut child:Grant)->Result<(),AuthorityError>{
        let parent=self.grants.get(parent_id).ok_or(AuthorityError::ParentMissing)?;
        if self.revoked.contains(parent_id){return Err(AuthorityError::ParentInactive)}
        if child.issuer!=parent.subject || child.operations.is_empty()
            || !child.operations.is_subset(&parent.operations)
            || !child.target_prefix.starts_with(&parent.target_prefix)
            || child.not_before<parent.not_before || child.expires_at>parent.expires_at
            || child.quota>parent.quota
            || child.remaining_delegation_depth>=parent.remaining_delegation_depth
            || child.generation!=parent.generation || child.machine!=parent.machine
            || child.service!=parent.service {
            return Err(AuthorityError::AttenuationViolation)
        }
        child.parent_grant_id=Some(parent_id.into());
        self.grants.insert(child.id.clone(),child); self.persist()
    }
    fn chain_denial(&self,grant:&Grant,request:&Invocation)->Option<(&'static str,&'static str)>{
        let mut current=grant;
        loop{
            if self.revoked.contains(&current.id){return Some(("UNAUTHORIZED","grant chain revoked"))}
            if self.current_time<current.not_before||self.current_time>=current.expires_at{return Some(("STALE","grant chain outside validity interval"))}
            if current.generation!=request.generation{return Some(("STALE","grant chain generation mismatch"))}
            match &current.parent_grant_id{
                Some(parent)=>match self.grants.get(parent){Some(value)=>current=value,None=>return Some(("STALE","grant parent missing"))},
                None=>return None,
            }
        }
    }
    pub fn evaluate_peer(&mut self,channel:&UnixStream,request:&Invocation)->Result<Decision,AuthorityError>{
        let observed=Self::peer_credentials(channel)?;
        let executable=fs::metadata(format!("/proc/{}/exe",observed.1.pid))
            .map_err(|_|AuthorityError::PeerCredential)?;
        let executable_identity=(executable.dev(),executable.ino());
        let authenticated=self.peer_binding.as_ref().map(|value|value.channel==observed.0
            &&value.pid==observed.1.pid&&value.uid==observed.1.uid&&value.gid==observed.1.gid
            &&value.machine==request.machine.as_str()&&value.service==request.service.as_str()
            &&value.activation==request.activation.as_str()
            &&self.trusted_peer.as_ref().map(|trusted|trusted.executable==executable_identity)
                .unwrap_or(false)).unwrap_or(false);
        let denial = if !self.available { Some(("UNAVAILABLE","authority state unavailable")) }
            else if !authenticated { Some(("UNAUTHORIZED","kernel peer identity is not bound to invocation")) }
            else if request.command_id.is_empty() || request.objective.is_empty() { Some(("INVALID","identity or objective missing")) }
            else if request.generation!=self.generation { Some(("STALE","generation mismatch")) }
            else if request.state_version!=self.state_version { Some(("STALE","authority state version mismatch")) }
            else { None };
        let mut candidates=self.grants.values().filter(|g|g.subject==request.activation.as_str()
            &&g.capability==request.capability&&g.machine==request.machine.as_str()
            &&g.service==request.service.as_str()).collect::<Vec<_>>();
        candidates.sort_by(|left,right|left.id.cmp(&right.id));
        let (mut grant,mut code)=(None,denial);
        if code.is_none(){
            for candidate in candidates{
                let reason=if let Some(reason)=self.chain_denial(candidate,request){Some(reason)}
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
        self.decisions.push(decision.clone());self.persist()?;Ok(decision)
    }
    pub fn audit(&self)->&[Decision]{&self.decisions}
}
