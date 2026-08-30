//! Immutable context compilation and semantic context-fault resolution.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub enum TruthClass { AuthoritativeState, RawObservation, InterpretedClaim,
    ModelSuggestion, UnresolvedUncertainty, UntrustedExternalData }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct Provenance {
    pub source:String,pub source_version:String,pub observed_at:u64,
    pub compiled_at:u64,pub fresh_until:u64,
}
impl Provenance {
    pub fn new(source:&str,version:&str,observed:u64,fresh_until:u64)->Self{
        Self{source:source.into(),source_version:version.into(),observed_at:observed,
             compiled_at:0,fresh_until}
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ContextItem {
    pub id:String,pub truth_class:TruthClass,pub content:String,
    pub provenance:Provenance,pub consequential:bool,pub original_evidence_ref:Option<String>,
}
impl ContextItem {
    pub fn new(id:&str,class:TruthClass,content:&str,provenance:Provenance,consequential:bool)->Self{
        Self{id:id.into(),truth_class:class,content:content.into(),provenance,consequential,
             original_evidence_ref:None}
    }
    pub fn original(mut self,evidence_ref:&str)->Self{
        self.original_evidence_ref=Some(evidence_ref.into());self
    }
    pub fn source_access(&self,max_bytes:usize,expires_at:u64)->Option<SourceAccess>{
        self.original_evidence_ref.as_ref().filter(|_|self.consequential).map(|reference|SourceAccess{
            evidence_ref:reference.clone(),max_bytes,expires_at
        })
    }
    pub fn contradiction(id:&str,claims:&[&str],provenance:Provenance)->Self{
        Self::new(id,TruthClass::UnresolvedUncertainty,&claims.join(" | "),provenance,true)
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct SourceAccess { pub evidence_ref:String,pub max_bytes:usize,pub expires_at:u64 }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct SecurityObservation { pub item_id:String,pub attempted_directive:bool,pub isolated:bool }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct Omission { pub item_id:String,pub reason:String,pub resulting_uncertainty:String }

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ContextBundle {
    pub id:String,pub activation_id:String,pub objective_id:String,
    pub predecessor_id:Option<String>,pub resolved_request_id:Option<String>,
    pub items:Vec<ContextItem>,pub omissions:Vec<Omission>,pub budget_bytes:usize,
}

#[derive(Debug,PartialEq,Eq)]
pub enum ContextError { InvalidIdentity, RequiredContextUnavailable, InvalidRequest,
    NonMaterial, RecursionBound, SourceForbidden, StaleRequired }

pub struct Compiler { budget:usize,compiled_at:u64 }
impl Compiler {
    pub fn new(budget:usize,compiled_at:u64)->Self{Self{budget,compiled_at}}
    pub fn compile(&self,activation:&str,objective:&str,predecessor:Option<&str>,
                   mut items:Vec<ContextItem>)->Result<ContextBundle,ContextError>{
        if !activation.starts_with("activation:")||!objective.starts_with("objective:"){
            return Err(ContextError::InvalidIdentity)
        }
        items.sort_by(|a,b|a.id.cmp(&b.id));
        for item in &mut items { item.provenance.compiled_at=self.compiled_at; }
        let mut kept=Vec::new();let mut omissions=Vec::new();let mut used=0;
        for item in items {
            let size=serde_json::to_vec(&item).unwrap().len();
            if used+size<=self.budget {used+=size;kept.push(item)}
            else {omissions.push(Omission{item_id:item.id,reason:"CONTEXT_BUDGET".into(),
                resulting_uncertainty:"required detail omitted; action may require a context request".into()})}
        }
        let mut bundle=ContextBundle{id:String::new(),activation_id:activation.into(),
            objective_id:objective.into(),predecessor_id:predecessor.map(Into::into),
            resolved_request_id:None,items:kept,omissions,budget_bytes:self.budget};
        bundle.id=format!("context:sha256:{:x}",Sha256::digest(serde_json::to_vec(&bundle).unwrap()));
        Ok(bundle)
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub enum RequestedKind { Fact,Evidence,Procedure,CapabilityDocumentation,Precedent,FreshObservation }
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct ContextRequest {
    pub id:String,pub deficiency:String,pub materiality:String,pub requested_kind:RequestedKind,
    pub resolution_condition:String,pub allowed_sources:Vec<String>,pub freshness_deadline:u64,pub depth:u8,
}
impl ContextRequest {
    pub fn validate(&self,max_depth:u8)->Result<(),ContextError>{
        if self.deficiency.trim().is_empty()||self.resolution_condition.trim().is_empty(){
            return Err(ContextError::InvalidRequest)
        }
        if self.materiality.trim().is_empty(){return Err(ContextError::NonMaterial)}
        if self.depth>max_depth{return Err(ContextError::RecursionBound)}
        Ok(())
    }
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct SkillDescriptor {
    pub id:String,pub use_when:String,pub do_not_use_when:String,
    pub inputs:Vec<String>,pub outputs:Vec<String>,pub termination_conditions:Vec<String>,
    pub procedure_ref:String,
}
impl SkillDescriptor {
    pub fn applicable(&self,condition:&str)->bool{
        !self.use_when.is_empty()&&!self.do_not_use_when.is_empty()&&
        !self.inputs.is_empty()&&!self.outputs.is_empty()&&!self.termination_conditions.is_empty()&&
        condition.contains(&self.use_when)&&!condition.contains(&self.do_not_use_when)
    }
}

pub struct Broker { pub max_depth:u8 }
impl Broker {
    pub fn resolve(&self,compiler:&Compiler,predecessor:&ContextBundle,request:&ContextRequest,
                   item:ContextItem)->Result<ContextBundle,ContextError>{
        request.validate(self.max_depth)?;
        if !request.allowed_sources.is_empty()&&!request.allowed_sources.contains(&item.provenance.source){
            return Err(ContextError::SourceForbidden)
        }
        if item.provenance.fresh_until<request.freshness_deadline{return Err(ContextError::StaleRequired)}
        let mut bundle=compiler.compile(&predecessor.activation_id,&predecessor.objective_id,
                                        Some(&predecessor.id),vec![item])?;
        bundle.resolved_request_id=Some(request.id.clone());
        bundle.id=format!("context:sha256:{:x}",Sha256::digest(serde_json::to_vec(&bundle).unwrap()));
        Ok(bundle)
    }
}

pub fn isolate_external_content(id:&str,content:&str,source:&str,version:&str,observed:u64)
    ->ContextItem{
    ContextItem::new(id,TruthClass::UntrustedExternalData,content,
                     Provenance::new(source,version,observed,observed),false)
}

pub fn ingest_external_content(id:&str,content:&str,source:&str,version:&str,observed:u64)
    ->(ContextItem,SecurityObservation){
    let normalized=content.to_ascii_lowercase();
    let attempted=["system:","change policy","grant admin","ignore previous"]
        .iter().any(|marker|normalized.contains(marker));
    (isolate_external_content(id,content,source,version,observed),SecurityObservation{
        item_id:id.into(),attempted_directive:attempted,isolated:true
    })
}
