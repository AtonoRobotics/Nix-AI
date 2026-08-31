//! Durable effect admission, evidence, observation, and reconciliation.
use habitat_authority::{Authority, Invocation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

pub const RUNTIME_EFFECT_SCHEMA_VERSION: &str = "2.0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEffectRequest {
    pub schema_version: String,
    pub caller_service_id: String,
    pub command_id: String,
    pub objective_id: String,
    pub provider_id: String,
    pub parameters_digest: String,
    pub idempotency_key: String,
    pub authority_request: habitat_authority::RuntimeAuthorityRequest,
    pub forwarding_proof: String,
    pub execution_constraint_id: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub controller_ack_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEffectAdmission {
    pub schema_version: String,
    pub command_id: String,
    pub objective_id: String,
    pub state: String,
    pub code: String,
}

pub fn admit_runtime_effect(
    request: &RuntimeEffectRequest,
    authority: &habitat_authority::RuntimeAuthorityDecision,
) -> RuntimeEffectAdmission {
    let is_commit = authority.operation == "commit" && authority.target == request.objective_id;
    let is_compensation =
        authority.operation == "compensate" && authority.target.starts_with("effect:sha256:");
    let authority_matches = authority.schema_version == "2.0"
        && authority.allowed
        && authority.code == "AUTHORIZED"
        && authority.broker_service_id == "service:effects"
        && authority.objective_id == request.objective_id
        && (is_commit || is_compensation)
        && authority.capability == "runtime.effect"
        && authority.request_id == request.command_id;
    let valid = runtime_effect_request_valid(request) && authority_matches;
    RuntimeEffectAdmission {
        schema_version: RUNTIME_EFFECT_SCHEMA_VERSION.into(),
        command_id: request.command_id.clone(),
        objective_id: request.objective_id.clone(),
        state: if valid { "RESERVED" } else { "REJECTED" }.into(),
        code: if valid {
            "AUTHORIZED"
        } else {
            "ADMISSION_DENIED"
        }
        .into(),
    }
}

pub fn runtime_effect_request_valid(request: &RuntimeEffectRequest) -> bool {
    let digest_valid = request
        .parameters_digest
        .strip_prefix("sha256:")
        .is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    let is_commit = request.authority_request.operation == "commit"
        && request.authority_request.target == request.objective_id
        && request.idempotency_key == format!("effect:{}", request.objective_id);
    let is_compensation = request.authority_request.operation == "compensate"
        && request
            .authority_request
            .target
            .starts_with("effect:sha256:")
        && request.idempotency_key == format!("compensation:{}", request.authority_request.target);
    request.schema_version == RUNTIME_EFFECT_SCHEMA_VERSION
        && request.caller_service_id.starts_with("service:")
        && request.caller_service_id == request.authority_request.caller_service_id
        && !request.command_id.is_empty()
        && request.objective_id.starts_with("objective:")
        && request.provider_id == "habitat-offline-provider"
        && digest_valid
        && request.authority_request.schema_version == "2.0"
        && request.authority_request.request_id == request.command_id
        && request.authority_request.objective_id == request.objective_id
        && request.authority_request.capability == "runtime.effect"
        && request.forwarding_proof.starts_with("sha256:")
        && request.forwarding_proof.len() == 71
        && request.execution_constraint_id == format!("constraint:{}", request.command_id)
        && request.valid_from == request.authority_request.requested_at
        && request.valid_until == request.valid_from.saturating_add(30)
        && request.valid_from < request.valid_until
        && request.controller_ack_required
        && (is_commit || is_compensation)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConsequenceClass {
    E0,
    E1,
    E2,
    E3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconciliationMode {
    IdempotencyKey,
    ExternalIdentifier,
    TargetState,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContract {
    pub id: String,
    pub reconciliation: ReconciliationMode,
    pub max_class: ConsequenceClass,
}
impl ProviderContract {
    pub fn reconcilable(id: &str, mode: ReconciliationMode, max_class: ConsequenceClass) -> Self {
        Self {
            id: id.into(),
            reconciliation: mode,
            max_class,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectProposal {
    pub command_id: String,
    pub activation_id: String,
    pub objective_id: String,
    pub capability: String,
    pub operation: String,
    pub target: String,
    pub parameters_digest: String,
    pub idempotency_key: String,
    pub consequence_class: ConsequenceClass,
    pub expires_at: u64,
    pub provider_id: String,
    pub compensates_effect_id: Option<String>,
    pub execution_constraint_id: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    pub controller_ack_required: bool,
    pub ordering_group: Option<String>,
    pub ordering_sequence: Option<u64>,
}
impl EffectProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: &str,
        activation: &str,
        objective: &str,
        capability: &str,
        operation: &str,
        target: &str,
        digest: &str,
        key: &str,
        class: ConsequenceClass,
        expires_at: u64,
    ) -> Self {
        Self {
            command_id: command.into(),
            activation_id: activation.into(),
            objective_id: objective.into(),
            capability: capability.into(),
            operation: operation.into(),
            target: target.into(),
            parameters_digest: digest.into(),
            idempotency_key: key.into(),
            consequence_class: class,
            expires_at,
            provider_id: capability.split('.').next().unwrap_or(capability).into(),
            compensates_effect_id: None,
            execution_constraint_id: None,
            valid_from: None,
            valid_until: None,
            controller_ack_required: false,
            ordering_group: None,
            ordering_sequence: None,
        }
    }
    pub fn bounded(
        mut self,
        constraint: &str,
        valid_from: u64,
        valid_until: u64,
        ack: bool,
    ) -> Self {
        self.execution_constraint_id = Some(constraint.into());
        self.valid_from = Some(valid_from);
        self.valid_until = Some(valid_until);
        self.controller_ack_required = ack;
        self
    }
    pub fn ordered(mut self, group: &str, sequence: u64) -> Self {
        self.ordering_group = Some(group.into());
        self.ordering_sequence = Some(sequence);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    authority_decision: String,
    allowed: bool,
    precondition_valid: bool,
}
impl Admission {
    fn from_runtime(
        decision: &habitat_authority::RuntimeAuthorityDecision,
        precondition_valid: bool,
    ) -> Self {
        Self {
            authority_decision: decision.decision_id.clone(),
            allowed: decision.allowed && decision.code == "AUTHORIZED",
            precondition_valid,
        }
    }
    fn from_authority(
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
        precondition_valid: bool,
    ) -> Self {
        let decision = authority.evaluate_peer(channel, invocation);
        match decision {
            Ok(value) => Self {
                authority_decision: value.id().into(),
                allowed: value.is_allowed(),
                precondition_valid,
            },
            Err(_) => Self {
                authority_decision: String::new(),
                allowed: false,
                precondition_valid,
            },
        }
    }
    pub fn precondition_valid(&self) -> bool {
        self.precondition_valid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectState {
    Proposed,
    Rejected,
    Reserved,
    Executing,
    ObservedSucceeded,
    ObservedFailed,
    OutcomeUnknown,
    Reconciling,
    ResolvedSucceeded,
    ResolvedFailed,
    AuthorityRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectRecord {
    pub effect_id: String,
    pub proposal: EffectProposal,
    pub admission: Admission,
    pub state: EffectState,
    #[serde(default)]
    pub runtime_authority_request: Option<habitat_authority::RuntimeAuthorityRequest>,
    #[serde(default)]
    pub runtime_forwarding: Option<habitat_authority::RuntimeForwardingEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub request_digest: String,
    pub dispatched_at: u64,
    pub provider_id: String,
    pub transport_id: String,
    pub response: Option<String>,
    pub observation_source: Option<String>,
    pub terminal_classification: Option<EffectState>,
}
impl Attempt {
    pub fn new(digest: &str, at: u64, provider: &str, transport: &str) -> Self {
        Self {
            request_digest: digest.into(),
            dispatched_at: at,
            provider_id: provider.into(),
            transport_id: transport.into(),
            response: None,
            observation_source: None,
            terminal_classification: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationAttempt {
    pub request_digest: String,
    pub requested_at: u64,
    pub provider_id: String,
    pub transport_id: String,
    pub response: Option<String>,
    pub observation_source: Option<String>,
    pub terminal_classification: Option<EffectState>,
}
impl ReconciliationAttempt {
    pub fn new(digest: &str, at: u64, provider: &str, transport: &str) -> Self {
        Self {
            request_digest: digest.into(),
            requested_at: at,
            provider_id: provider.into(),
            transport_id: transport.into(),
            response: None,
            observation_source: None,
            terminal_classification: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub source: String,
    pub evidence: String,
    pub succeeded: bool,
    pub independent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectTransition {
    pub state: EffectState,
    pub evidence: String,
}
impl Observation {
    pub fn independent(source: &str, evidence: &str, succeeded: bool) -> Self {
        Self {
            source: source.into(),
            evidence: evidence.into(),
            succeeded,
            independent: true,
        }
    }
    pub fn provider_ack(response: &str) -> Self {
        Self {
            source: "provider-ack".into(),
            evidence: response.into(),
            succeeded: true,
            independent: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EffectError {
    AdmissionDenied,
    ProviderMissing,
    ConsequenceUnsupported,
    EffectMissing,
    InvalidTransition,
    IndependentEvidenceRequired,
    ExpiredCommand,
    ExecutionContractIncomplete,
    ObjectiveEffectsPending,
    OrderingViolation,
    IdempotencyConflict,
    InvalidAttempt,
    Storage,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EffectLedger {
    effects: HashMap<String, EffectRecord>,
    by_key: HashMap<String, String>,
    providers: HashMap<String, ProviderContract>,
    attempts: HashMap<String, Vec<Attempt>>,
    reconciliations: HashMap<String, Vec<ReconciliationAttempt>>,
    #[serde(default)]
    history: HashMap<String, Vec<EffectTransition>>,
    #[serde(default)]
    pending_guards: std::collections::HashSet<String>,
    #[serde(skip)]
    path: Option<PathBuf>,
    #[serde(skip, default = "ledger_available")]
    available: bool,
    #[serde(skip)]
    fault_after_rename: bool,
}
fn ledger_available() -> bool {
    true
}
impl EffectLedger {
    pub fn new() -> Self {
        Self {
            available: true,
            ..Self::default()
        }
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EffectError> {
        let path = path.as_ref().to_owned();
        let mut ledger = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| EffectError::Storage)?)
                .map_err(|_| EffectError::Storage)?
        } else {
            Self::new()
        };
        ledger.path = Some(path);
        ledger.available = true;
        Ok(ledger)
    }
    /// Replace the local cache from PostgreSQL-owned canonical records.
    /// The state service is the sole production recovery authority.
    pub fn restore_authoritative(
        &mut self,
        snapshots: &[serde_json::Value],
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        self.effects.clear();
        self.by_key.clear();
        self.attempts.clear();
        self.reconciliations.clear();
        self.history.clear();
        for snapshot in snapshots {
            let record: EffectRecord = serde_json::from_value(
                snapshot
                    .get("record")
                    .cloned()
                    .ok_or(EffectError::Storage)?,
            )
            .map_err(|_| EffectError::Storage)?;
            let attempts: Vec<Attempt> = serde_json::from_value(
                snapshot
                    .get("attempts")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )
            .map_err(|_| EffectError::Storage)?;
            let reconciliations: Vec<ReconciliationAttempt> = serde_json::from_value(
                snapshot
                    .get("reconciliations")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )
            .map_err(|_| EffectError::Storage)?;
            let history: Vec<EffectTransition> = serde_json::from_value(
                snapshot
                    .get("history")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )
            .map_err(|_| EffectError::Storage)?;
            self.by_key.insert(
                record.proposal.idempotency_key.clone(),
                record.effect_id.clone(),
            );
            self.attempts.insert(record.effect_id.clone(), attempts);
            self.reconciliations
                .insert(record.effect_id.clone(), reconciliations);
            self.history.insert(record.effect_id.clone(), history);
            self.effects.insert(record.effect_id.clone(), record);
        }
        self.commit_or_restore(previous)
    }
    fn persist(&self) -> Result<(), EffectError> {
        if !self.available {
            return Err(EffectError::Storage);
        }
        if let Some(path) = &self.path {
            let temp = path.with_extension("tmp");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)
                .map_err(|_| EffectError::Storage)?;
            file.write_all(&serde_json::to_vec(self).map_err(|_| EffectError::Storage)?)
                .and_then(|_| file.sync_all())
                .and_then(|_| fs::rename(&temp, path))
                .map_err(|_| EffectError::Storage)?;
            if cfg!(test) && self.fault_after_rename {
                return Err(EffectError::Storage);
            }
            File::open(path.parent().unwrap_or_else(|| Path::new(".")))
                .and_then(|directory| directory.sync_all())
                .map_err(|_| EffectError::Storage)?;
        }
        Ok(())
    }
    #[cfg(test)]
    fn inject_fault_after_rename(&mut self) {
        self.fault_after_rename = true;
    }
    fn commit_or_restore(&mut self, previous: Self) -> Result<(), EffectError> {
        if let Err(error) = self.persist() {
            *self = previous;
            self.available = false;
            return Err(error);
        }
        Ok(())
    }
    fn transition(&mut self, id: &str, state: EffectState, evidence: &str) {
        self.history
            .entry(id.into())
            .or_default()
            .push(EffectTransition {
                state,
                evidence: evidence.into(),
            });
    }
    pub fn register_provider(&mut self, provider: ProviderContract) {
        self.providers.insert(provider.id.clone(), provider);
        let _ = self.persist();
    }
    pub fn register_provider_durable(
        &mut self,
        provider: ProviderContract,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        self.providers.insert(provider.id.clone(), provider);
        self.commit_or_restore(previous)
    }
    pub fn reserve_runtime(
        &mut self,
        proposal: EffectProposal,
        decision: &habitat_authority::RuntimeAuthorityDecision,
        forwarding: habitat_authority::RuntimeForwardingEvidence,
        now: u64,
    ) -> Result<EffectRecord, EffectError> {
        let previous = self.clone();
        if decision.request_id != proposal.command_id
            || decision.broker_service_id != "service:effects"
            || decision.activation_id != proposal.activation_id
            || decision.objective_id != proposal.objective_id
            || decision.capability != proposal.capability
            || decision.operation != proposal.operation
            || decision.target != proposal.target
        {
            return Err(EffectError::AdmissionDenied);
        }
        let admission = Admission::from_runtime(decision, now < proposal.expires_at);
        if !admission.allowed
            || !admission.precondition_valid
            || admission.authority_decision.is_empty()
        {
            return Err(EffectError::AdmissionDenied);
        }
        if let Some(existing) = self.runtime_replay(&proposal)? {
            return Ok(existing);
        }
        if let Some(original_id) = proposal.compensates_effect_id.as_deref() {
            let original = self
                .effects
                .get(original_id)
                .ok_or(EffectError::AdmissionDenied)?;
            let expected_digest = format!("sha256:{:x}", Sha256::digest(original_id.as_bytes()));
            if original.proposal.objective_id != proposal.objective_id
                || original.proposal.activation_id != proposal.activation_id
                || original.proposal.compensates_effect_id.is_some()
                || !matches!(
                    original.state,
                    EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded
                )
                || proposal.parameters_digest != expected_digest
                || self.effects.values().any(|effect| {
                    effect.proposal.compensates_effect_id.as_deref() == Some(original_id)
                })
            {
                return Err(EffectError::AdmissionDenied);
            }
        }
        self.validate_provider_and_ordering(&proposal, now)?;
        let id = format!(
            "effect:sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&proposal).map_err(|_| EffectError::Storage)?)
        );
        let record = EffectRecord {
            effect_id: id.clone(),
            proposal,
            admission,
            state: EffectState::Reserved,
            runtime_authority_request: Some(habitat_authority::RuntimeAuthorityRequest {
                schema_version: "2.0".into(),
                request_id: decision.request_id.clone(),
                // The broker identity is separately bound by the authenticated
                // effects socket and decision.  The HMAC-covered request was
                // issued by runtime; changing this field to the broker makes
                // durable STATUS/COMMIT recovery unverifiable.
                caller_service_id: "service:runtime".into(),
                machine_id: decision.machine_id.clone(),
                service_id: decision.service_id.clone(),
                activation_id: decision.activation_id.clone(),
                objective_id: decision.objective_id.clone(),
                capability: decision.capability.clone(),
                operation: decision.operation.clone(),
                target: decision.target.clone(),
                generation: decision.generation.clone(),
                state_version: decision.state_version.clone(),
                requested_at: decision.requested_at,
            }),
            runtime_forwarding: Some(forwarding),
        };
        self.by_key
            .insert(record.proposal.idempotency_key.clone(), id.clone());
        self.effects.insert(id, record.clone());
        self.transition(
            &record.effect_id,
            EffectState::Reserved,
            &record.admission.authority_decision,
        );
        self.commit_or_restore(previous)?;
        Ok(record)
    }

    pub fn runtime_replay(
        &self,
        proposal: &EffectProposal,
    ) -> Result<Option<EffectRecord>, EffectError> {
        let Some(id) = self.by_key.get(&proposal.idempotency_key) else {
            return Ok(None);
        };
        let existing = &self.effects[id];
        let mut normalized = proposal.clone();
        normalized.expires_at = existing.proposal.expires_at;
        if existing.proposal == normalized {
            Ok(Some(existing.clone()))
        } else {
            Err(EffectError::IdempotencyConflict)
        }
    }

    fn validate_provider_and_ordering(
        &self,
        proposal: &EffectProposal,
        now: u64,
    ) -> Result<(), EffectError> {
        let provider = self
            .providers
            .get(&proposal.provider_id)
            .ok_or(EffectError::ProviderMissing)?;
        if proposal.consequence_class > provider.max_class
            || (proposal.consequence_class >= ConsequenceClass::E2
                && provider.reconciliation == ReconciliationMode::None)
        {
            return Err(EffectError::ConsequenceUnsupported);
        }
        if proposal.consequence_class == ConsequenceClass::E3
            && (proposal.execution_constraint_id.is_none()
                || proposal.valid_from.map(|value| now < value).unwrap_or(true)
                || proposal
                    .valid_until
                    .map(|value| now >= value)
                    .unwrap_or(true)
                || !proposal.controller_ack_required)
        {
            return Err(EffectError::ExecutionContractIncomplete);
        }
        if let (Some(group), Some(sequence)) =
            (&proposal.ordering_group, proposal.ordering_sequence)
        {
            let next = self
                .effects
                .values()
                .filter(|effect| effect.proposal.ordering_group.as_ref() == Some(group))
                .filter_map(|effect| effect.proposal.ordering_sequence)
                .max()
                .unwrap_or(0)
                + 1;
            if sequence != next {
                return Err(EffectError::OrderingViolation);
            }
        }
        Ok(())
    }
    pub fn propose_authorized(
        &mut self,
        proposal: EffectProposal,
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
        precondition_valid: bool,
    ) -> Result<EffectRecord, EffectError> {
        self.propose_authorized_at(
            proposal,
            authority,
            channel,
            invocation,
            precondition_valid,
            0,
        )
    }
    pub fn propose_authorized_at(
        &mut self,
        proposal: EffectProposal,
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
        precondition_valid: bool,
        now: u64,
    ) -> Result<EffectRecord, EffectError> {
        if proposal.command_id != invocation.command_id
            || proposal.activation_id != invocation.activation.as_str()
            || proposal.objective_id != invocation.objective
            || proposal.capability != invocation.capability
            || proposal.operation != invocation.operation
            || proposal.target != invocation.target
        {
            return Err(EffectError::AdmissionDenied);
        }
        let admission =
            Admission::from_authority(authority, channel, invocation, precondition_valid);
        if !admission.allowed
            || !admission.precondition_valid
            || admission.authority_decision.is_empty()
        {
            return Err(EffectError::AdmissionDenied);
        }
        if let Some(id) = self.by_key.get(&proposal.idempotency_key) {
            let existing = &self.effects[id];
            return if existing.proposal == proposal {
                Ok(existing.clone())
            } else {
                Err(EffectError::IdempotencyConflict)
            };
        }
        let provider = self
            .providers
            .get(&proposal.provider_id)
            .ok_or(EffectError::ProviderMissing)?;
        if proposal.consequence_class > provider.max_class
            || (proposal.consequence_class >= ConsequenceClass::E2
                && provider.reconciliation == ReconciliationMode::None)
        {
            return Err(EffectError::ConsequenceUnsupported);
        }
        if proposal.consequence_class == ConsequenceClass::E3
            && (proposal.execution_constraint_id.is_none()
                || proposal.valid_from.map(|v| now < v).unwrap_or(true)
                || proposal.valid_until.map(|v| now >= v).unwrap_or(true)
                || !proposal.controller_ack_required)
        {
            return Err(EffectError::ExecutionContractIncomplete);
        }
        if let (Some(group), Some(sequence)) =
            (&proposal.ordering_group, proposal.ordering_sequence)
        {
            let next = self
                .effects
                .values()
                .filter(|e| e.proposal.ordering_group.as_ref() == Some(group))
                .filter_map(|e| e.proposal.ordering_sequence)
                .max()
                .unwrap_or(0)
                + 1;
            if sequence != next {
                return Err(EffectError::OrderingViolation);
            }
        }
        let id = format!(
            "effect:sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&proposal).unwrap())
        );
        let previous = self.clone();
        let record = EffectRecord {
            effect_id: id.clone(),
            proposal,
            admission,
            state: EffectState::Reserved,
            runtime_authority_request: None,
            runtime_forwarding: None,
        };
        self.by_key
            .insert(record.proposal.idempotency_key.clone(), id.clone());
        self.effects.insert(id, record.clone());
        self.transition(
            &record.effect_id,
            EffectState::Reserved,
            &record.admission.authority_decision,
        );
        self.commit_or_restore(previous)?;
        Ok(record)
    }
    pub fn len(&self) -> usize {
        self.effects.len()
    }
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }
    pub fn get(&self, id: &str) -> Option<&EffectRecord> {
        self.effects.get(id)
    }
    pub fn attempts(&self, id: &str) -> &[Attempt] {
        self.attempts.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn reconciliations(&self, id: &str) -> &[ReconciliationAttempt] {
        self.reconciliations
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
    pub fn history(&self, id: &str) -> &[EffectTransition] {
        self.history.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn pending_guard_objectives(&self) -> Vec<String> {
        let mut objectives = self.pending_guards.iter().cloned().collect::<Vec<_>>();
        objectives.sort();
        objectives
    }

    /// Objectives whose provider outcome is already authoritative but whose
    /// state-side completion guard may have been lost across a process crash.
    /// This is deliberately derived from PostgreSQL-restored effect records;
    /// the retry obligation is therefore never an alternate in-memory truth.
    pub fn successful_objectives(&self) -> Vec<String> {
        let mut objectives = self
            .effects
            .values()
            .filter(|effect| {
                matches!(
                    effect.state,
                    EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded
                )
            })
            .map(|effect| effect.proposal.objective_id.clone())
            .collect::<Vec<_>>();
        objectives.sort();
        objectives.dedup();
        objectives
    }
    pub fn mark_guard_pending(&mut self, objective: &str) -> Result<(), EffectError> {
        let previous = self.clone();
        self.pending_guards.insert(objective.into());
        self.commit_or_restore(previous)
    }
    pub fn clear_guard_pending(&mut self, objective: &str) -> Result<(), EffectError> {
        let previous = self.clone();
        self.pending_guards.remove(objective);
        self.commit_or_restore(previous)
    }
    pub fn reject_reserved(&mut self, id: &str, evidence: &str) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Reserved {
            return Err(EffectError::InvalidTransition);
        }
        effect.state = EffectState::Rejected;
        self.transition(id, EffectState::Rejected, evidence);
        self.commit_or_restore(previous)
    }
    pub fn dispatch_authorized(
        &mut self,
        id: &str,
        attempt: Attempt,
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
    ) -> Result<(), EffectError> {
        let at = attempt.dispatched_at;
        self.dispatch_authorized_at(id, attempt, authority, channel, invocation, at)
    }
    pub fn dispatch_runtime(
        &mut self,
        id: &str,
        attempt: Attempt,
        decision: &habitat_authority::RuntimeAuthorityDecision,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Reserved
            || !decision.allowed
            || decision.code != "AUTHORIZED"
            || decision.broker_service_id != "service:effects"
            || decision.request_id != effect.proposal.command_id
            || decision.activation_id != effect.proposal.activation_id
            || decision.objective_id != effect.proposal.objective_id
            || decision.capability != effect.proposal.capability
            || decision.operation != effect.proposal.operation
            || decision.target != effect.proposal.target
        {
            return Err(EffectError::AdmissionDenied);
        }
        if attempt.request_digest != effect.proposal.parameters_digest
            || attempt.provider_id != effect.proposal.provider_id
            || attempt.transport_id.is_empty()
        {
            return Err(EffectError::InvalidAttempt);
        }
        effect.state = EffectState::Executing;
        self.attempts.entry(id.into()).or_default().push(attempt);
        self.transition(id, EffectState::Executing, "provider dispatch persisted");
        self.commit_or_restore(previous)
    }
    pub fn dispatch_authorized_at(
        &mut self,
        id: &str,
        attempt: Attempt,
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
        now: u64,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Reserved {
            return Err(EffectError::InvalidTransition);
        }
        if effect.proposal.command_id != invocation.command_id
            || effect.proposal.activation_id != invocation.activation.as_str()
            || effect.proposal.objective_id != invocation.objective
            || effect.proposal.capability != invocation.capability
            || effect.proposal.operation != invocation.operation
            || effect.proposal.target != invocation.target
        {
            return Err(EffectError::AdmissionDenied);
        }
        let decision = authority
            .evaluate_peer(channel, invocation)
            .map_err(|_| EffectError::AdmissionDenied)?;
        if !decision.is_allowed() {
            return Err(EffectError::AdmissionDenied);
        }
        if attempt.request_digest != effect.proposal.parameters_digest
            || attempt.provider_id != effect.proposal.provider_id
            || attempt.transport_id.is_empty()
        {
            return Err(EffectError::InvalidAttempt);
        }
        if effect.proposal.consequence_class == ConsequenceClass::E3
            && effect
                .proposal
                .valid_until
                .map(|v| now >= v)
                .unwrap_or(true)
        {
            return Err(EffectError::ExpiredCommand);
        }
        effect.state = EffectState::Executing;
        self.attempts.entry(id.into()).or_default().push(attempt);
        self.transition(id, EffectState::Executing, "provider dispatch persisted");
        self.commit_or_restore(previous)
    }
    pub fn transport_lost(&mut self, id: &str, response: &str) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Executing {
            return Err(EffectError::InvalidTransition);
        }
        effect.state = EffectState::OutcomeUnknown;
        if let Some(last) = self.attempts.get_mut(id).and_then(|v| v.last_mut()) {
            last.response = Some(response.into());
            last.observation_source = Some("transport".into());
            last.terminal_classification = Some(EffectState::OutcomeUnknown)
        }
        self.transition(id, EffectState::OutcomeUnknown, response);
        self.commit_or_restore(previous)
    }
    pub fn record_provider_response(
        &mut self,
        id: &str,
        response: &str,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        if self.effects.get(id).map(|effect| effect.state) != Some(EffectState::Executing) {
            return Err(EffectError::InvalidTransition);
        }
        let attempt = self
            .attempts
            .get_mut(id)
            .and_then(|attempts| attempts.last_mut())
            .ok_or(EffectError::InvalidAttempt)?;
        attempt.response = Some(response.into());
        self.commit_or_restore(previous)
    }
    pub fn observe(&mut self, id: &str, observation: Observation) -> Result<(), EffectError> {
        let previous = self.clone();
        if !observation.independent {
            return Err(EffectError::IndependentEvidenceRequired);
        }
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Executing {
            return Err(EffectError::InvalidTransition);
        }
        effect.state = if observation.succeeded {
            EffectState::ObservedSucceeded
        } else {
            EffectState::ObservedFailed
        };
        if let Some(last) = self.attempts.get_mut(id).and_then(|v| v.last_mut()) {
            last.observation_source = Some(observation.source);
            last.terminal_classification = Some(effect.state)
        }
        let state = effect.state;
        self.transition(id, state, &observation.evidence);
        self.commit_or_restore(previous)
    }
    pub fn begin_reconciliation(
        &mut self,
        id: &str,
        attempt: ReconciliationAttempt,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if !matches!(
            effect.state,
            EffectState::OutcomeUnknown | EffectState::Reconciling
        ) {
            return Err(EffectError::InvalidTransition);
        }
        if attempt.request_digest != effect.proposal.parameters_digest
            || attempt.provider_id != effect.proposal.provider_id
            || attempt.transport_id.is_empty()
        {
            return Err(EffectError::InvalidAttempt);
        }
        if self.reconciliations.get(id).map(Vec::len).unwrap_or(0) >= 8 {
            return Err(EffectError::InvalidAttempt);
        }
        effect.state = EffectState::Reconciling;
        self.reconciliations
            .entry(id.into())
            .or_default()
            .push(attempt);
        self.transition(id, EffectState::Reconciling, "reconciliation dispatched");
        self.commit_or_restore(previous)
    }
    pub fn reconciliation_inconclusive(
        &mut self,
        id: &str,
        source: &str,
        evidence: &str,
    ) -> Result<(), EffectError> {
        let previous = self.clone();
        if self.effects.get(id).map(|effect| effect.state) != Some(EffectState::Reconciling) {
            return Err(EffectError::InvalidTransition);
        }
        let last = self
            .reconciliations
            .get_mut(id)
            .and_then(|attempts| attempts.last_mut())
            .ok_or(EffectError::InvalidAttempt)?;
        last.response = Some(evidence.into());
        last.observation_source = Some(source.into());
        last.terminal_classification = None;
        self.transition(id, EffectState::Reconciling, evidence);
        self.commit_or_restore(previous)
    }
    pub fn resolve(&mut self, id: &str, observation: Observation) -> Result<(), EffectError> {
        let previous = self.clone();
        if !observation.independent {
            return Err(EffectError::IndependentEvidenceRequired);
        }
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        if effect.state != EffectState::Reconciling {
            return Err(EffectError::InvalidTransition);
        }
        effect.state = if observation.succeeded {
            EffectState::ResolvedSucceeded
        } else {
            EffectState::ResolvedFailed
        };
        if let Some(last) = self
            .reconciliations
            .get_mut(id)
            .and_then(|value| value.last_mut())
        {
            last.response = Some(observation.evidence.clone());
            last.observation_source = Some(observation.source);
            last.terminal_classification = Some(effect.state)
        }
        let state = effect.state;
        self.transition(id, state, &observation.evidence);
        self.commit_or_restore(previous)
    }
    pub fn cancel(&mut self, id: &str) -> Result<(), EffectError> {
        let previous = self.clone();
        let effect = self.effects.get_mut(id).ok_or(EffectError::EffectMissing)?;
        effect.state = match effect.state {
            EffectState::Reserved => EffectState::Rejected,
            EffectState::Executing => EffectState::OutcomeUnknown,
            _ => return Err(EffectError::InvalidTransition),
        };
        self.commit_or_restore(previous)
    }
    #[allow(clippy::too_many_arguments, reason = "stable effect compensation ABI")]
    pub fn compensate(
        &mut self,
        original_id: &str,
        command: &str,
        capability: &str,
        key: &str,
        authority: &mut Authority,
        channel: &UnixStream,
        invocation: &Invocation,
    ) -> Result<EffectRecord, EffectError> {
        let original = self
            .effects
            .get(original_id)
            .ok_or(EffectError::EffectMissing)?
            .clone();
        if !matches!(
            original.state,
            EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded
        ) {
            return Err(EffectError::InvalidTransition);
        }
        let mut proposal = EffectProposal::new(
            command,
            &original.proposal.activation_id,
            &original.proposal.objective_id,
            capability,
            "compensate",
            &original.proposal.target,
            &original.proposal.parameters_digest,
            key,
            original.proposal.consequence_class,
            original.proposal.expires_at,
        );
        proposal.compensates_effect_id = Some(original_id.into());
        self.propose_authorized(proposal, authority, channel, invocation, true)
    }
    pub fn complete_objective(&self, objective: &str) -> Result<(), EffectError> {
        let pending = self.effects.values().any(|e| {
            e.proposal.objective_id == objective
                && !matches!(
                    e.state,
                    EffectState::ObservedSucceeded
                        | EffectState::ObservedFailed
                        | EffectState::ResolvedSucceeded
                        | EffectState::ResolvedFailed
                        | EffectState::Rejected
                )
        });
        if pending {
            Err(EffectError::ObjectiveEffectsPending)
        } else {
            Ok(())
        }
    }
    pub fn objective_effects(&self, objective: &str) -> Vec<String> {
        let mut ids = self
            .effects
            .values()
            .filter(|effect| effect.proposal.objective_id == objective)
            .map(|effect| effect.effect_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
    pub fn recover(&self) -> Vec<String> {
        let mut ids = self
            .effects
            .values()
            .filter(|e| {
                !matches!(
                    e.state,
                    EffectState::ObservedSucceeded
                        | EffectState::ObservedFailed
                        | EffectState::ResolvedSucceeded
                        | EffectState::ResolvedFailed
                        | EffectState::Rejected
                )
            })
            .map(|e| e.effect_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;

    #[test]
    fn post_rename_sync_ambiguity_poison_stops_in_process_and_restart_reads_complete_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("effects.json");
        let mut ledger = EffectLedger::open(&path).unwrap();
        ledger.inject_fault_after_rename();
        assert_eq!(
            ledger.register_provider_durable(ProviderContract::reconcilable(
                "provider",
                ReconciliationMode::IdempotencyKey,
                ConsequenceClass::E1,
            )),
            Err(EffectError::Storage)
        );
        assert_eq!(
            ledger.register_provider_durable(ProviderContract::reconcilable(
                "other",
                ReconciliationMode::IdempotencyKey,
                ConsequenceClass::E1,
            )),
            Err(EffectError::Storage)
        );
        let reopened = EffectLedger::open(&path).unwrap();
        assert!(reopened.providers.contains_key("provider"));
        assert!(!reopened.providers.contains_key("other"));
    }
}
