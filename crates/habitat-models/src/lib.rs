//! Provider-neutral model activation and structured disposition validation.
use serde::{Deserialize,Serialize};
use serde_json::Value;
use sha2::{Digest,Sha256};

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum DispositionKind { ContextRequest,CapabilityInvocation,EffectProposal,Delegation,Message,
    Checkpoint,Sleep,CompletionClaim,ActivationFailure }

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
pub struct DecisionArtifact { pub summary:String,pub evidence_refs:Vec<String> }

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
pub struct Disposition { pub activation_id:String,pub command_id:String,pub kind:DispositionKind,
    pub payload:Value,pub decision:DecisionArtifact }

#[derive(Clone,Debug,PartialEq)]
pub struct CandidateOutput { pub disposition:Disposition,pub provider_request_id:String,
    pub provider:String,pub model:String,pub input_tokens:u64,pub output_tokens:u64 }

#[derive(Debug,PartialEq,Eq)] pub enum ModelError { InvalidEnvelope,MissingDisposition,MalformedDisposition,
    CommandIdRequired,ActivationMismatch,CapabilityInvisible,InvalidCompletion,LeaseExpired,Cancelled }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct CapabilityDescriptor { pub id:String,pub operations:Vec<String> }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ActivationEnvelope { pub abi_version:String,pub activation_id:String,pub agent_id:String,
    pub objective_ids:Vec<String>,pub context_bundle_id:String,pub visible_capabilities:Vec<CapabilityDescriptor>,
    pub deadline:u64,pub trace_id:String,pub correlation_id:String }

pub struct DispositionValidator { envelope:ActivationEnvelope }
impl DispositionValidator {
    pub fn new(envelope:&ActivationEnvelope)->Self{Self{envelope:envelope.clone()}}
    pub fn validate(&self,candidate:CandidateOutput)->Result<CandidateOutput,ModelError>{
        let disposition=&candidate.disposition;
        if disposition.command_id.trim().is_empty(){return Err(ModelError::CommandIdRequired)}
        if disposition.activation_id!=self.envelope.activation_id{return Err(ModelError::ActivationMismatch)}
        if disposition.kind==DispositionKind::CapabilityInvocation{
            let capability=disposition.payload.get("capability").and_then(Value::as_str).ok_or(ModelError::CapabilityInvisible)?;
            let operation=disposition.payload.get("operation").and_then(Value::as_str).ok_or(ModelError::CapabilityInvisible)?;
            if !self.envelope.visible_capabilities.iter().any(|c|c.id==capability&&c.operations.iter().any(|o|o==operation)){
                return Err(ModelError::CapabilityInvisible)
            }
        }
        if disposition.kind==DispositionKind::CompletionClaim{
            let objective=disposition.payload.get("objective_id").and_then(Value::as_str);
            let evidence=disposition.payload.get("evidence_refs").and_then(Value::as_array);
            if !objective.map(|o|self.envelope.objective_ids.iter().any(|known|known==o)).unwrap_or(false)
                ||evidence.map(|e|e.is_empty()).unwrap_or(true){return Err(ModelError::InvalidCompletion)}
        }
        Ok(candidate)
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub enum ActivationStatus { Running,CompletionClaimed,Cancelled }
#[derive(Clone,Debug,PartialEq)] pub struct DriverResult { pub disposition:Disposition,pub status:ActivationStatus }
pub struct ModelDriver { envelope:ActivationEnvelope,status:ActivationStatus }
impl ModelDriver {
    pub fn new(envelope:ActivationEnvelope)->Self{Self{envelope,status:ActivationStatus::Running}}
    pub fn status(&self)->ActivationStatus{self.status}
    pub fn accept(&self,candidate:CandidateOutput,now:u64)->Result<DriverResult,ModelError>{
        self.check_deadline(now)?;if self.status==ActivationStatus::Cancelled{return Err(ModelError::Cancelled)}
        let candidate=DispositionValidator::new(&self.envelope).validate(candidate)?;
        let status=if candidate.disposition.kind==DispositionKind::CompletionClaim{
            ActivationStatus::CompletionClaimed}else{ActivationStatus::Running};
        Ok(DriverResult{disposition:candidate.disposition,status})
    }
    pub fn check_deadline(&self,now:u64)->Result<(),ModelError>{if now>self.envelope.deadline{
        Err(ModelError::LeaseExpired)}else{Ok(())}}
    pub fn cancel(&mut self,command:&str,reason:&str)->Result<(),ModelError>{if command.is_empty()||reason.is_empty(){
        return Err(ModelError::InvalidEnvelope)}self.status=ActivationStatus::Cancelled;Ok(())}
}

pub struct CredentialBroker { provider:String,credential:String }
pub struct TransportRequest { pub endpoint:String,pub authorization:String,pub activation:String,
    body_digest:String }
impl CredentialBroker {
    pub fn new(provider:&str,credential:&str)->Self{Self{provider:provider.into(),credential:credential.into()}}
    pub fn prepare(&self,endpoint:&str,envelope:&ActivationEnvelope,body:Value)->TransportRequest{
        let bytes=serde_json::to_vec(&body).unwrap();TransportRequest{endpoint:endpoint.into(),
            authorization:format!("Bearer {}",self.credential),activation:serde_json::to_string(envelope).unwrap(),
            body_digest:format!("sha256:{:x}",Sha256::digest(bytes))}
    }
    pub fn provider(&self)->&str{&self.provider}
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ModelEvidence { pub activation_id:String,pub trace_id:String,pub correlation_id:String,
    pub provider:String,pub model:String,pub provider_request_id:String,pub input_tokens:u64,
    pub output_tokens:u64,pub latency_ms:u64,pub request_digest:String }
impl ModelEvidence { #[allow(clippy::too_many_arguments)]
    pub fn record(envelope:&ActivationEnvelope,provider:&str,model:&str,request_id:&str,input:u64,
        output:u64,latency:u64,request:&TransportRequest)->Self{Self{activation_id:envelope.activation_id.clone(),
        trace_id:envelope.trace_id.clone(),correlation_id:envelope.correlation_id.clone(),provider:provider.into(),
        model:model.into(),provider_request_id:request_id.into(),input_tokens:input,output_tokens:output,
        latency_ms:latency,request_digest:request.body_digest.clone()}}
}

pub struct OpenAiAdapter;
impl OpenAiAdapter { pub fn translate(response:&Value)->Result<CandidateOutput,ModelError>{
    let call=response.get("output").and_then(Value::as_array).and_then(|items|items.iter().find(|item|
        item.get("type").and_then(Value::as_str)==Some("function_call")&&
        item.get("name").and_then(Value::as_str)==Some("submit_disposition"))).ok_or(ModelError::MissingDisposition)?;
    let raw=call.get("arguments").and_then(Value::as_str).ok_or(ModelError::MalformedDisposition)?;
    let disposition=serde_json::from_str(raw).map_err(|_|ModelError::MalformedDisposition)?;
    Ok(candidate(response,disposition,"openai")?)
}}

pub struct AnthropicAdapter;
impl AnthropicAdapter { pub fn translate(response:&Value)->Result<CandidateOutput,ModelError>{
    let call=response.get("content").and_then(Value::as_array).and_then(|items|items.iter().find(|item|
        item.get("type").and_then(Value::as_str)==Some("tool_use")&&
        item.get("name").and_then(Value::as_str)==Some("submit_disposition"))).ok_or(ModelError::MissingDisposition)?;
    let disposition=serde_json::from_value(call.get("input").cloned().ok_or(ModelError::MalformedDisposition)?)
        .map_err(|_|ModelError::MalformedDisposition)?;
    candidate(response,disposition,"anthropic")
}}

fn candidate(response:&Value,disposition:Disposition,provider:&str)->Result<CandidateOutput,ModelError>{
    let usage=response.get("usage").ok_or(ModelError::InvalidEnvelope)?;
    Ok(CandidateOutput{disposition,provider_request_id:string(response,"id")?,provider:provider.into(),
        model:string(response,"model")?,input_tokens:number(usage,"input_tokens")?,
        output_tokens:number(usage,"output_tokens")?})
}
fn string(value:&Value,key:&str)->Result<String,ModelError>{value.get(key).and_then(Value::as_str)
    .filter(|v|!v.is_empty()).map(Into::into).ok_or(ModelError::InvalidEnvelope)}
fn number(value:&Value,key:&str)->Result<u64,ModelError>{value.get(key).and_then(Value::as_u64)
    .ok_or(ModelError::InvalidEnvelope)}
