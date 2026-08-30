//! Durable effect admission, evidence, observation, and reconciliation.
use habitat_authority::{Authority,Invocation};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::HashMap,fs,os::unix::net::UnixStream,path::{Path,PathBuf}};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize)]
pub enum ConsequenceClass { E0,E1,E2,E3 }

#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub enum ReconciliationMode { IdempotencyKey,ExternalIdentifier,TargetState,None }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ProviderContract { pub id:String,pub reconciliation:ReconciliationMode,pub max_class:ConsequenceClass }
impl ProviderContract {
    pub fn reconcilable(id:&str,mode:ReconciliationMode,max_class:ConsequenceClass)->Self{
        Self{id:id.into(),reconciliation:mode,max_class}
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct EffectProposal { pub command_id:String,pub activation_id:String,pub objective_id:String,
    pub capability:String,pub operation:String,pub target:String,pub parameters_digest:String,
    pub idempotency_key:String,pub consequence_class:ConsequenceClass,pub expires_at:u64,
    pub provider_id:String,pub compensates_effect_id:Option<String>,pub execution_constraint_id:Option<String>,
    pub valid_from:Option<u64>,pub valid_until:Option<u64>,pub controller_ack_required:bool,
    pub ordering_group:Option<String>,pub ordering_sequence:Option<u64> }
impl EffectProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(command:&str,activation:&str,objective:&str,capability:&str,operation:&str,target:&str,
        digest:&str,key:&str,class:ConsequenceClass,expires_at:u64)->Self{
        Self{command_id:command.into(),activation_id:activation.into(),objective_id:objective.into(),
            capability:capability.into(),operation:operation.into(),target:target.into(),
            parameters_digest:digest.into(),idempotency_key:key.into(),consequence_class:class,
            expires_at,provider_id:capability.split('.').next().unwrap_or(capability).into(),
            compensates_effect_id:None,execution_constraint_id:None,valid_from:None,valid_until:None,
            controller_ack_required:false,ordering_group:None,ordering_sequence:None}
    }
    pub fn bounded(mut self,constraint:&str,valid_from:u64,valid_until:u64,ack:bool)->Self{
        self.execution_constraint_id=Some(constraint.into());self.valid_from=Some(valid_from);
        self.valid_until=Some(valid_until);self.controller_ack_required=ack;self
    }
    pub fn ordered(mut self,group:&str,sequence:u64)->Self{
        self.ordering_group=Some(group.into());self.ordering_sequence=Some(sequence);self
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct Admission { authority_decision:String,allowed:bool,precondition_valid:bool }
impl Admission {
    fn from_authority(authority:&mut Authority,channel:&UnixStream,invocation:&Invocation,precondition_valid:bool)->Self{
        let decision=authority.evaluate_peer(channel,invocation);
        match decision{Ok(value)=>Self{authority_decision:value.id().into(),allowed:value.is_allowed(),precondition_valid},
            Err(_)=>Self{authority_decision:String::new(),allowed:false,precondition_valid}}
    }
    pub fn precondition_valid(&self)->bool{self.precondition_valid}
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub enum EffectState { Proposed,Rejected,Reserved,Executing,ObservedSucceeded,ObservedFailed,
    OutcomeUnknown,Reconciling,ResolvedSucceeded,ResolvedFailed,AuthorityRequired }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct EffectRecord { pub effect_id:String,pub proposal:EffectProposal,pub admission:Admission,
    pub state:EffectState }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct Attempt { pub request_digest:String,pub dispatched_at:u64,pub provider_id:String,
    pub transport_id:String,pub response:Option<String>,pub observation_source:Option<String>,
    pub terminal_classification:Option<EffectState> }
impl Attempt { pub fn new(digest:&str,at:u64,provider:&str,transport:&str)->Self{Self{
    request_digest:digest.into(),dispatched_at:at,provider_id:provider.into(),transport_id:transport.into(),
    response:None,observation_source:None,terminal_classification:None}}
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ReconciliationAttempt { pub request_digest:String,pub requested_at:u64,pub provider_id:String,
    pub transport_id:String,pub response:Option<String>,pub observation_source:Option<String>,
    pub terminal_classification:Option<EffectState> }
impl ReconciliationAttempt { pub fn new(digest:&str,at:u64,provider:&str,transport:&str)->Self{Self{
    request_digest:digest.into(),requested_at:at,provider_id:provider.into(),transport_id:transport.into(),
    response:None,observation_source:None,terminal_classification:None}}
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct Observation { pub source:String,pub evidence:String,pub succeeded:bool,pub independent:bool }
impl Observation {
    pub fn independent(source:&str,evidence:&str,succeeded:bool)->Self{Self{source:source.into(),evidence:evidence.into(),succeeded,independent:true}}
    pub fn provider_ack(response:&str)->Self{Self{source:"provider-ack".into(),evidence:response.into(),succeeded:true,independent:false}}
}

#[derive(Debug,PartialEq,Eq)] pub enum EffectError { AdmissionDenied,ProviderMissing,ConsequenceUnsupported,
    EffectMissing,InvalidTransition,IndependentEvidenceRequired,ExpiredCommand,
    ExecutionContractIncomplete,ObjectiveEffectsPending,OrderingViolation,IdempotencyConflict,
    InvalidAttempt,Storage }

#[derive(Default,Serialize,Deserialize)] pub struct EffectLedger { effects:HashMap<String,EffectRecord>,by_key:HashMap<String,String>,
    providers:HashMap<String,ProviderContract>,attempts:HashMap<String,Vec<Attempt>>,
    reconciliations:HashMap<String,Vec<ReconciliationAttempt>>,
    #[serde(skip)] path:Option<PathBuf> }
impl EffectLedger {
    pub fn new()->Self{Self::default()}
    pub fn open(path:impl AsRef<Path>)->Result<Self,EffectError>{
        let path=path.as_ref().to_owned();let mut ledger=if path.exists(){
            serde_json::from_slice(&fs::read(&path).map_err(|_|EffectError::Storage)?).map_err(|_|EffectError::Storage)?
        }else{Self::new()};ledger.path=Some(path);Ok(ledger)
    }
    fn persist(&self)->Result<(),EffectError>{if let Some(path)=&self.path{
        let temp=path.with_extension("tmp");fs::write(&temp,serde_json::to_vec(self).map_err(|_|EffectError::Storage)?)
            .and_then(|_|fs::rename(temp,path)).map_err(|_|EffectError::Storage)?;}Ok(())}
    pub fn register_provider(&mut self,provider:ProviderContract){self.providers.insert(provider.id.clone(),provider);let _=self.persist();}
    pub fn propose_authorized(&mut self,proposal:EffectProposal,authority:&mut Authority,channel:&UnixStream,
        invocation:&Invocation,precondition_valid:bool)->Result<EffectRecord,EffectError>{
        self.propose_authorized_at(proposal,authority,channel,invocation,precondition_valid,0)
    }
    pub fn propose_authorized_at(&mut self,proposal:EffectProposal,authority:&mut Authority,channel:&UnixStream,
        invocation:&Invocation,precondition_valid:bool,now:u64)->Result<EffectRecord,EffectError>{
        if proposal.command_id!=invocation.command_id
            ||proposal.activation_id!=invocation.activation.as_str()
            ||proposal.objective_id!=invocation.objective||proposal.capability!=invocation.capability
            ||proposal.operation!=invocation.operation||proposal.target!=invocation.target{
            return Err(EffectError::AdmissionDenied)
        }
        let admission=Admission::from_authority(authority,channel,invocation,precondition_valid);
        if !admission.allowed||!admission.precondition_valid||admission.authority_decision.is_empty(){return Err(EffectError::AdmissionDenied)}
        if let Some(id)=self.by_key.get(&proposal.idempotency_key){
            let existing=&self.effects[id];
            return if existing.proposal==proposal{Ok(existing.clone())}
                else{Err(EffectError::IdempotencyConflict)}
        }
        let provider=self.providers.get(&proposal.provider_id).ok_or(EffectError::ProviderMissing)?;
        if proposal.consequence_class>provider.max_class||
            (proposal.consequence_class>=ConsequenceClass::E2&&provider.reconciliation==ReconciliationMode::None){
            return Err(EffectError::ConsequenceUnsupported)
        }
        if proposal.consequence_class==ConsequenceClass::E3 && (proposal.execution_constraint_id.is_none()
            ||proposal.valid_from.map(|v|now<v).unwrap_or(true)||proposal.valid_until.map(|v|now>=v).unwrap_or(true)
            ||!proposal.controller_ack_required){return Err(EffectError::ExecutionContractIncomplete)}
        if let (Some(group),Some(sequence))=(&proposal.ordering_group,proposal.ordering_sequence){
            let next=self.effects.values().filter(|e|e.proposal.ordering_group.as_ref()==Some(group))
                .filter_map(|e|e.proposal.ordering_sequence).max().unwrap_or(0)+1;
            if sequence!=next{return Err(EffectError::OrderingViolation)}
        }
        let id=format!("effect:sha256:{:x}",Sha256::digest(serde_json::to_vec(&proposal).unwrap()));
        let record=EffectRecord{effect_id:id.clone(),proposal,admission,state:EffectState::Reserved};
        self.by_key.insert(record.proposal.idempotency_key.clone(),id.clone());
        self.effects.insert(id,record.clone());self.persist()?;Ok(record)
    }
    pub fn len(&self)->usize{self.effects.len()}
    pub fn get(&self,id:&str)->Option<&EffectRecord>{self.effects.get(id)}
    pub fn attempts(&self,id:&str)->&[Attempt]{self.attempts.get(id).map(Vec::as_slice).unwrap_or(&[])}
    pub fn reconciliations(&self,id:&str)->&[ReconciliationAttempt]{
        self.reconciliations.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn dispatch_authorized(&mut self,id:&str,attempt:Attempt,authority:&mut Authority,channel:&UnixStream,
        invocation:&Invocation)->Result<(),EffectError>{
        let at=attempt.dispatched_at;self.dispatch_authorized_at(id,attempt,authority,channel,invocation,at)
    }
    pub fn dispatch_authorized_at(&mut self,id:&str,attempt:Attempt,authority:&mut Authority,channel:&UnixStream,
        invocation:&Invocation,now:u64)->Result<(),EffectError>{
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state!=EffectState::Reserved{return Err(EffectError::InvalidTransition)}
        if effect.proposal.command_id!=invocation.command_id
            ||effect.proposal.activation_id!=invocation.activation.as_str()
            ||effect.proposal.objective_id!=invocation.objective||effect.proposal.capability!=invocation.capability
            ||effect.proposal.operation!=invocation.operation||effect.proposal.target!=invocation.target{
            return Err(EffectError::AdmissionDenied)
        }
        let decision=authority.evaluate_peer(channel,invocation).map_err(|_|EffectError::AdmissionDenied)?;
        if !decision.is_allowed(){return Err(EffectError::AdmissionDenied)}
        if attempt.request_digest.is_empty()||attempt.provider_id!=effect.proposal.provider_id
            ||attempt.transport_id.is_empty(){return Err(EffectError::InvalidAttempt)}
        if effect.proposal.consequence_class==ConsequenceClass::E3&&effect.proposal.valid_until.map(|v|now>=v).unwrap_or(true){
            return Err(EffectError::ExpiredCommand)
        }
        effect.state=EffectState::Executing;self.attempts.entry(id.into()).or_default().push(attempt);self.persist()
    }
    pub fn transport_lost(&mut self,id:&str,response:&str)->Result<(),EffectError>{
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state!=EffectState::Executing{return Err(EffectError::InvalidTransition)}
        effect.state=EffectState::OutcomeUnknown;
        if let Some(last)=self.attempts.get_mut(id).and_then(|v|v.last_mut()){last.response=Some(response.into());last.terminal_classification=Some(EffectState::OutcomeUnknown)}
        self.persist()
    }
    pub fn observe(&mut self,id:&str,observation:Observation)->Result<(),EffectError>{
        if !observation.independent{return Err(EffectError::IndependentEvidenceRequired)}
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state!=EffectState::Executing{return Err(EffectError::InvalidTransition)}
        effect.state=if observation.succeeded{EffectState::ObservedSucceeded}else{EffectState::ObservedFailed};
        if let Some(last)=self.attempts.get_mut(id).and_then(|v|v.last_mut()){
            last.response=Some(observation.evidence);last.observation_source=Some(observation.source);
            last.terminal_classification=Some(effect.state)
        } self.persist()
    }
    pub fn begin_reconciliation(&mut self,id:&str,attempt:ReconciliationAttempt)->Result<(),EffectError>{
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state!=EffectState::OutcomeUnknown{return Err(EffectError::InvalidTransition)}
        if attempt.request_digest.is_empty()||attempt.provider_id!=effect.proposal.provider_id
            ||attempt.transport_id.is_empty(){return Err(EffectError::InvalidAttempt)}
        effect.state=EffectState::Reconciling;
        self.reconciliations.entry(id.into()).or_default().push(attempt);self.persist()
    }
    pub fn resolve(&mut self,id:&str,observation:Observation)->Result<(),EffectError>{
        if !observation.independent{return Err(EffectError::IndependentEvidenceRequired)}
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state!=EffectState::Reconciling{return Err(EffectError::InvalidTransition)}
        effect.state=if observation.succeeded{EffectState::ResolvedSucceeded}else{EffectState::ResolvedFailed};
        if let Some(last)=self.reconciliations.get_mut(id).and_then(|value|value.last_mut()){
            last.response=Some(observation.evidence);last.observation_source=Some(observation.source);
            last.terminal_classification=Some(effect.state)
        }
        self.persist()
    }
    pub fn cancel(&mut self,id:&str)->Result<(),EffectError>{
        let effect=self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        effect.state=match effect.state{EffectState::Reserved=>EffectState::Rejected,
            EffectState::Executing=>EffectState::OutcomeUnknown,_=>return Err(EffectError::InvalidTransition)};self.persist()
    }
    pub fn compensate(&mut self,original_id:&str,command:&str,capability:&str,key:&str,
        authority:&mut Authority,channel:&UnixStream,invocation:&Invocation)->Result<EffectRecord,EffectError>{
        let original=self.effects.get(original_id).ok_or(EffectError::EffectMissing)?.clone();
        if !matches!(original.state,EffectState::ObservedSucceeded|EffectState::ResolvedSucceeded){return Err(EffectError::InvalidTransition)}
        let mut proposal=EffectProposal::new(command,&original.proposal.activation_id,&original.proposal.objective_id,
            capability,"compensate",&original.proposal.target,&original.proposal.parameters_digest,key,
            original.proposal.consequence_class,original.proposal.expires_at);
        proposal.compensates_effect_id=Some(original_id.into());
        self.propose_authorized(proposal,authority,channel,invocation,true)
    }
    pub fn complete_objective(&self,objective:&str)->Result<(),EffectError>{
        let pending=self.effects.values().any(|e|e.proposal.objective_id==objective&&!matches!(e.state,
            EffectState::ObservedSucceeded|EffectState::ObservedFailed|EffectState::ResolvedSucceeded|
            EffectState::ResolvedFailed|EffectState::Rejected));
        if pending{Err(EffectError::ObjectiveEffectsPending)}else{Ok(())}
    }
    pub fn recover(&self)->Vec<String>{
        let mut ids=self.effects.values().filter(|e|!matches!(e.state,EffectState::ObservedSucceeded|
            EffectState::ObservedFailed|EffectState::ResolvedSucceeded|EffectState::ResolvedFailed|
            EffectState::Rejected)).map(|e|e.effect_id.clone()).collect::<Vec<_>>();
        ids.sort();ids
    }
}
