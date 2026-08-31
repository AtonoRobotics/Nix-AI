//! Deterministic, default-deny capability authority.
use habitat_uds::PeerPrincipal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    mem,
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

pub const RUNTIME_AUTHORITY_SCHEMA_VERSION: &str = "2.0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeGrant {
    pub grant_id: String,
    pub issuer: String,
    pub independent_approver: String,
    pub machine_id: String,
    pub service_id: String,
    pub activation_id: String,
    pub capability: String,
    pub operation: String,
    pub target_prefix: String,
    pub generation: String,
    pub state_version: String,
    pub quota: u64,
    pub remaining_delegation_depth: u32,
    pub parent_grant_id: Option<String>,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePeer {
    pub service_id: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuthorityAdminRequest {
    pub schema_version: String,
    pub operation: String,
    pub request_id: String,
    pub caller_service_id: String,
    pub grant_id: Option<String>,
    pub state_version: Option<String>,
    pub independent_approval: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuthorityRequest {
    pub schema_version: String,
    pub request_id: String,
    pub caller_service_id: String,
    pub machine_id: String,
    pub service_id: String,
    pub activation_id: String,
    pub objective_id: String,
    pub capability: String,
    pub operation: String,
    pub target: String,
    pub generation: String,
    pub state_version: String,
    pub requested_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuthorityEffectRequest {
    pub schema_version: String,
    pub phase: String,
    pub request: RuntimeAuthorityRequest,
    pub effect_id: Option<String>,
    pub forwarding: RuntimeForwardingEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeForwardingEvidence {
    pub provider_id: String,
    pub parameters_digest: String,
    pub idempotency_key: String,
    pub proof: String,
}

pub fn runtime_forwarding_proof(
    key: &[u8],
    request: &RuntimeAuthorityRequest,
    provider_id: &str,
    parameters_digest: &str,
    idempotency_key: &str,
) -> Result<String, AuthorityError> {
    if key.len() < 32 {
        return Err(AuthorityError::InvalidGrant);
    }
    let bytes = serde_json::to_vec(&(request, provider_id, parameters_digest, idempotency_key))
        .map_err(|_| AuthorityError::Storage)?;
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(bytes)
        .finalize();
    Ok(format!(
        "sha256:{:x}",
        Sha256::new()
            .chain_update(outer_pad)
            .chain_update(inner)
            .finalize()
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuthorityDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub request_id: String,
    pub broker_service_id: String,
    pub allowed: bool,
    pub code: String,
    pub grant_id: Option<String>,
    pub machine_id: String,
    pub service_id: String,
    pub activation_id: String,
    pub objective_id: String,
    pub capability: String,
    pub operation: String,
    pub target: String,
    pub generation: String,
    pub state_version: String,
    pub evaluated_at: u64,
    pub requested_at: u64,
    pub revocation_epoch: u64,
    pub phase: String,
    pub request_digest: String,
    pub grant_chain: Vec<String>,
    pub issuer_chain: Vec<String>,
    pub policy_ref: String,
    pub configuration_digest: String,
    pub provider_proof: Option<String>,
    pub evidence_ref: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuntimeAuthorityStore {
    grants: HashMap<String, RuntimeGrant>,
    revoked: HashSet<String>,
    quota_usage: HashMap<String, u64>,
    revocation_epoch: u64,
    state_version: String,
    configuration_digest: String,
    decisions: Vec<RuntimeAuthorityDecision>,
    #[serde(default)]
    decisions_by_request: HashMap<String, StoredRuntimeDecision>,
    #[serde(default)]
    quota_reservations: HashMap<String, Vec<String>>,
    #[serde(default)]
    effect_reservations: HashMap<String, RuntimeEffectReservation>,
    #[serde(default)]
    state_version_history: HashSet<String>,
    #[serde(default)]
    admin_approvals: HashMap<String, RuntimeAdminApproval>,
    #[serde(default)]
    admin_results: HashMap<String, RuntimeAdminResult>,
    #[serde(skip)]
    path: Option<PathBuf>,
    #[serde(skip, default = "available")]
    available: bool,
    #[serde(skip)]
    fault_after_rename: bool,
}

fn available() -> bool {
    true
}

fn runtime_effect_request_digest(
    request: &RuntimeAuthorityRequest,
) -> Result<String, AuthorityError> {
    let semantic = (
        &request.schema_version,
        &request.request_id,
        &request.caller_service_id,
        &request.machine_id,
        &request.service_id,
        &request.activation_id,
        &request.objective_id,
        &request.capability,
        &request.operation,
        &request.target,
        &request.generation,
        &request.state_version,
        request.requested_at,
    );
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&semantic).map_err(|_| AuthorityError::Storage)?)
    ))
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredRuntimeDecision {
    request_digest: String,
    decision: RuntimeAuthorityDecision,
}

#[derive(Clone, Serialize, Deserialize)]
struct RuntimeAdminApproval {
    target_request_id: String,
    request_digest: String,
    approver_service_id: String,
    used_by: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RuntimeAdminResult {
    request_digest: String,
    applied: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct RuntimeEffectReservation {
    request_digest: String,
    chain: Vec<String>,
    #[serde(default)]
    revocation_epoch: u64,
    #[serde(default)]
    configuration_digest: String,
    #[serde(default)]
    state_version: String,
    #[serde(default)]
    prepared_at: u64,
    effect_id: Option<String>,
    committed: bool,
}

pub fn runtime_admin_digest(request: &RuntimeAuthorityAdminRequest) -> String {
    let canonical = (
        &request.schema_version,
        &request.operation,
        &request.request_id,
        &request.caller_service_id,
        &request.grant_id,
        &request.state_version,
    );
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).expect("admin request serializes"))
    )
}

fn durable_replace(path: &Path, bytes: &[u8], fault_after_rename: bool) -> std::io::Result<()> {
    let temporary = path.with_extension("next");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if cfg!(test) && fault_after_rename {
        return Err(std::io::Error::other("injected post-rename sync failure"));
    }
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

impl RuntimeAuthorityStore {
    pub fn from_snapshot(
        snapshot: Option<serde_json::Value>,
        grants: Vec<RuntimeGrant>,
        state_version: &str,
    ) -> Result<Self, AuthorityError> {
        validate_runtime_grants(&grants)?;
        let configuration_digest = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_json::to_vec(&(state_version, &grants))
                    .map_err(|_| AuthorityError::Storage)?,
            )
        );
        let mut store = match snapshot {
            Some(value) => serde_json::from_value(value).map_err(|_| AuthorityError::Storage)?,
            None => Self {
                grants: HashMap::new(),
                revoked: HashSet::new(),
                quota_usage: HashMap::new(),
                revocation_epoch: 0,
                state_version: state_version.into(),
                configuration_digest: String::new(),
                decisions: Vec::new(),
                decisions_by_request: HashMap::new(),
                quota_reservations: HashMap::new(),
                effect_reservations: HashMap::new(),
                state_version_history: HashSet::new(),
                admin_approvals: HashMap::new(),
                admin_results: HashMap::new(),
                path: None,
                available: true,
                fault_after_rename: false,
            },
        };
        store.path = None;
        store.available = true;
        store
            .state_version_history
            .insert(store.state_version.clone());
        if store.configuration_digest != configuration_digest {
            if store.state_version != state_version
                && store.state_version_history.contains(state_version)
            {
                return Err(AuthorityError::InvalidGrant);
            }
            store.grants = grants
                .into_iter()
                .map(|grant| (grant.grant_id.clone(), grant))
                .collect();
            store.revocation_epoch = store.revocation_epoch.saturating_add(1);
            store.state_version = state_version.into();
            store.state_version_history.insert(state_version.into());
            store.configuration_digest = configuration_digest;
        }
        Ok(store)
    }

    pub fn snapshot(&self) -> Result<serde_json::Value, AuthorityError> {
        serde_json::to_value(self).map_err(|_| AuthorityError::Storage)
    }

    fn enrich_decision(
        &self,
        mut decision: RuntimeAuthorityDecision,
        phase: &str,
        provider_proof: Option<&str>,
    ) -> RuntimeAuthorityDecision {
        decision.phase = phase.into();
        decision.configuration_digest = self.configuration_digest.clone();
        if provider_proof.is_some() {
            decision.broker_service_id = "service:effects".into();
        }
        decision.provider_proof = provider_proof
            .map(|proof| format!("proof-digest:sha256:{:x}", Sha256::digest(proof.as_bytes())));
        if let Some(grant_id) = decision.grant_id.as_deref() {
            decision.grant_chain = self.grant_chain(grant_id);
            decision.issuer_chain = decision
                .grant_chain
                .iter()
                .rev()
                .filter_map(|id| self.grants.get(id).map(|grant| grant.issuer.clone()))
                .collect();
        }
        decision.decision_id.clear();
        decision.evidence_ref.clear();
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&decision).unwrap_or_default())
        );
        decision.decision_id = format!("decision:sha256:{digest}");
        decision.evidence_ref = format!("authority://decisions/sha256/{digest}");
        decision
    }

    fn persist_phase_decision(
        &mut self,
        mut decision: RuntimeAuthorityDecision,
        phase: &str,
        request_digest: String,
        provider_proof: Option<&str>,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        decision.request_digest = request_digest;
        decision = self.enrich_decision(decision, phase, provider_proof);
        self.decisions.push(decision.clone());
        if let Err(error) = self.persist() {
            self.decisions.pop();
            self.available = false;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn open(
        path: impl AsRef<Path>,
        grants: Vec<RuntimeGrant>,
        state_version: &str,
    ) -> Result<Self, AuthorityError> {
        validate_runtime_grants(&grants)?;
        let path = path.as_ref().to_owned();
        let configuration_digest = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_json::to_vec(&(state_version, &grants))
                    .map_err(|_| AuthorityError::Storage)?
            )
        );
        let mut store = if path.exists() {
            serde_json::from_slice::<Self>(&fs::read(&path).map_err(|_| AuthorityError::Storage)?)
                .map_err(|_| AuthorityError::Storage)?
        } else {
            Self {
                grants: HashMap::new(),
                revoked: HashSet::new(),
                quota_usage: HashMap::new(),
                revocation_epoch: 0,
                state_version: state_version.into(),
                configuration_digest: String::new(),
                decisions: Vec::new(),
                decisions_by_request: HashMap::new(),
                quota_reservations: HashMap::new(),
                effect_reservations: HashMap::new(),
                state_version_history: HashSet::new(),
                admin_approvals: HashMap::new(),
                admin_results: HashMap::new(),
                path: None,
                available: true,
                fault_after_rename: false,
            }
        };
        store.path = Some(path);
        store.available = true;
        store
            .state_version_history
            .insert(store.state_version.clone());
        if store.configuration_digest != configuration_digest {
            if store.state_version != state_version
                && store.state_version_history.contains(state_version)
            {
                return Err(AuthorityError::InvalidGrant);
            }
            store.grants = grants
                .into_iter()
                .map(|grant| (grant.grant_id.clone(), grant))
                .collect();
            store.revocation_epoch = store.revocation_epoch.saturating_add(1);
            store.state_version = state_version.into();
            store.state_version_history.insert(state_version.into());
            store.configuration_digest = configuration_digest;
        }
        store.persist()?;
        Ok(store)
    }

    fn persist(&self) -> Result<(), AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let Some(path) = &self.path else {
            return Ok(());
        };
        durable_replace(
            path,
            &serde_json::to_vec(self).map_err(|_| AuthorityError::Storage)?,
            self.fault_after_rename,
        )
        .map_err(|_| AuthorityError::Storage)
    }

    #[cfg(test)]
    fn inject_fault_after_rename(&mut self) {
        self.fault_after_rename = true;
    }

    pub fn revoke(&mut self, grant_id: &str) -> Result<bool, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        if !self.grants.contains_key(grant_id) {
            return Ok(false);
        }
        let changed = self.revoked.insert(grant_id.into());
        if changed {
            let previous_epoch = self.revocation_epoch;
            self.revocation_epoch = self.revocation_epoch.saturating_add(1);
            if let Err(error) = self.persist() {
                self.revoked.remove(grant_id);
                self.revocation_epoch = previous_epoch;
                self.available = false;
                return Err(error);
            }
        }
        Ok(changed)
    }

    pub fn rotate_state(&mut self, state_version: &str) -> Result<(), AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        if !state_version.starts_with("state:")
            || self.state_version_history.contains(state_version)
        {
            return Err(AuthorityError::InvalidGrant);
        }
        let previous = self.state_version.clone();
        let previous_epoch = self.revocation_epoch;
        self.state_version = state_version.into();
        self.state_version_history.insert(state_version.into());
        self.revocation_epoch = self.revocation_epoch.saturating_add(1);
        if let Err(error) = self.persist() {
            self.state_version = previous;
            self.state_version_history.remove(state_version);
            self.revocation_epoch = previous_epoch;
            self.available = false;
            return Err(error);
        }
        Ok(())
    }

    pub fn evaluate(
        &mut self,
        request: &RuntimeAuthorityRequest,
        now: u64,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let request_digest = runtime_effect_request_digest(request)?;
        if let Some(stored) = self.decisions_by_request.get(&request.request_id) {
            if stored.request_digest != request_digest {
                let mut denied = evaluate_runtime_request(&[], request, now);
                denied.code = "REQUEST_ID_CONFLICT".into();
                return Ok(denied);
            }
        }
        let had_quota_reservation = self.quota_reservations.contains_key(&request.request_id);
        let grants = self.grants.values().cloned().collect::<Vec<_>>();
        let mut decision = evaluate_runtime_request(&grants, request, now);
        decision.revocation_epoch = self.revocation_epoch;
        let selected = decision.grant_id.as_deref();
        if decision.allowed {
            let grant_id = selected.expect("allowed decision has grant");
            let chain = self.grant_chain(grant_id);
            let reservation = self.quota_reservations.get(&request.request_id).cloned();
            if self.chain_inactive(grant_id)
                || request.state_version != self.state_version
                || reservation
                    .as_ref()
                    .is_some_and(|reserved| reserved != &chain)
                || (reservation.is_none()
                    && chain.iter().any(|id| {
                        self.quota_usage.get(id).copied().unwrap_or(0) >= self.grants[id].quota
                    }))
            {
                decision.allowed = false;
                decision.code = "UNAUTHORIZED".into();
                decision.grant_id = None;
            } else {
                if reservation.is_none() {
                    for id in &chain {
                        *self.quota_usage.entry(id.clone()).or_default() += 1;
                    }
                    self.quota_reservations
                        .insert(request.request_id.clone(), chain);
                }
            }
        }
        decision.request_digest = request_digest.clone();
        decision = self.enrich_decision(decision, "EVALUATE", None);
        self.decisions.push(decision.clone());
        self.decisions_by_request.insert(
            request.request_id.clone(),
            StoredRuntimeDecision {
                request_digest,
                decision: decision.clone(),
            },
        );
        if let Err(error) = self.persist() {
            self.decisions.pop();
            self.decisions_by_request.remove(&request.request_id);
            if decision.allowed
                && !had_quota_reservation
                && self
                    .quota_reservations
                    .remove(&request.request_id)
                    .is_some()
            {
                for id in self.grant_chain(decision.grant_id.as_deref().unwrap_or_default()) {
                    if let Some(used) = self.quota_usage.get_mut(&id) {
                        *used = used.saturating_sub(1);
                    }
                }
            }
            self.available = false;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn prepare_effect(
        &mut self,
        request: &RuntimeAuthorityRequest,
        now: u64,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        self.prepare_effect_with_proof(request, now, None)
    }

    pub fn prepare_effect_proven(
        &mut self,
        request: &RuntimeAuthorityRequest,
        now: u64,
        provider_proof: &str,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        self.prepare_effect_with_proof(request, now, Some(provider_proof))
    }

    fn prepare_effect_with_proof(
        &mut self,
        request: &RuntimeAuthorityRequest,
        now: u64,
        provider_proof: Option<&str>,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let previous_reservations = self.effect_reservations.clone();
        let request_digest = runtime_effect_request_digest(request)?;
        if let Some(existing) = self.effect_reservations.get(&request.request_id) {
            if existing.request_digest != request_digest {
                let mut denied = evaluate_runtime_request(&[], request, now);
                denied.code = "REQUEST_ID_CONFLICT".into();
                return self.persist_phase_decision(
                    denied,
                    "PREPARE",
                    request_digest,
                    provider_proof,
                );
            }
        }
        let grants = self.grants.values().cloned().collect::<Vec<_>>();
        let mut decision = evaluate_runtime_request(&grants, request, now);
        decision.revocation_epoch = self.revocation_epoch;
        if decision.allowed {
            let grant_id = decision.grant_id.as_deref().expect("allowed grant");
            let chain = self.grant_chain(grant_id);
            let existing = self.effect_reservations.get(&request.request_id);
            let capacity_available = chain.iter().all(|id| {
                let prepared = self
                    .effect_reservations
                    .values()
                    .filter(|reservation| !reservation.committed && reservation.chain.contains(id))
                    .count() as u64;
                self.quota_usage.get(id).copied().unwrap_or(0) + prepared < self.grants[id].quota
            });
            if self.chain_inactive(grant_id)
                || request.state_version != self.state_version
                || (existing.is_none() && !capacity_available)
            {
                decision.allowed = false;
                decision.code = "UNAUTHORIZED".into();
                decision.grant_id = None;
            } else if existing.is_none() {
                self.effect_reservations.insert(
                    request.request_id.clone(),
                    RuntimeEffectReservation {
                        request_digest: request_digest.clone(),
                        chain,
                        revocation_epoch: self.revocation_epoch,
                        configuration_digest: self.configuration_digest.clone(),
                        state_version: self.state_version.clone(),
                        prepared_at: now,
                        effect_id: None,
                        committed: false,
                    },
                );
            }
        }
        decision.request_digest = request_digest;
        decision = self.enrich_decision(decision, "PREPARE", provider_proof);
        self.decisions.push(decision.clone());
        if let Err(error) = self.persist() {
            self.effect_reservations = previous_reservations;
            self.decisions.pop();
            self.available = false;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn commit_effect(
        &mut self,
        request: &RuntimeAuthorityRequest,
        effect_id: &str,
        now: u64,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        self.commit_effect_with_proof(request, effect_id, now, None)
    }

    pub fn commit_effect_proven(
        &mut self,
        request: &RuntimeAuthorityRequest,
        effect_id: &str,
        now: u64,
        provider_proof: &str,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        self.commit_effect_with_proof(request, effect_id, now, Some(provider_proof))
    }

    fn commit_effect_with_proof(
        &mut self,
        request: &RuntimeAuthorityRequest,
        effect_id: &str,
        now: u64,
        provider_proof: Option<&str>,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let previous_reservations = self.effect_reservations.clone();
        let previous_usage = self.quota_usage.clone();
        let request_digest = runtime_effect_request_digest(request)?;
        let grants = self.grants.values().cloned().collect::<Vec<_>>();
        let mut decision = evaluate_runtime_request(&grants, request, now);
        decision.revocation_epoch = self.revocation_epoch;
        let Some(reservation) = self.effect_reservations.get(&request.request_id).cloned() else {
            decision.allowed = false;
            decision.code = "UNAUTHORIZED".into();
            decision.grant_id = None;
            return self.persist_phase_decision(decision, "COMMIT", request_digest, provider_proof);
        };
        if reservation.request_digest != request_digest
            || !effect_id.starts_with("effect:sha256:")
            || reservation
                .effect_id
                .as_deref()
                .is_some_and(|bound| bound != effect_id)
            || decision
                .grant_id
                .as_deref()
                .is_none_or(|grant| self.chain_inactive(grant))
            || decision
                .grant_id
                .as_deref()
                .is_none_or(|grant| self.grant_chain(grant) != reservation.chain)
            || reservation.revocation_epoch != self.revocation_epoch
            || reservation.configuration_digest != self.configuration_digest
            || reservation.state_version != self.state_version
            || request.state_version != self.state_version
        {
            decision.allowed = false;
            decision.code = "UNAUTHORIZED".into();
            decision.grant_id = None;
            return self.persist_phase_decision(decision, "COMMIT", request_digest, provider_proof);
        }
        if decision.allowed && !reservation.committed {
            for id in &reservation.chain {
                *self.quota_usage.entry(id.clone()).or_default() += 1;
            }
            let bound = self
                .effect_reservations
                .get_mut(&request.request_id)
                .unwrap();
            bound.effect_id = Some(effect_id.into());
            bound.committed = true;
        }
        decision.request_digest = request_digest;
        decision = self.enrich_decision(decision, "COMMIT", provider_proof);
        self.decisions.push(decision.clone());
        if let Err(error) = self.persist() {
            self.effect_reservations = previous_reservations;
            self.quota_usage = previous_usage;
            self.decisions.pop();
            self.available = false;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn abort_effect(
        &mut self,
        request: &RuntimeAuthorityRequest,
    ) -> Result<bool, AuthorityError> {
        self.abort_effect_with_proof(request, None)
            .map(|decision| decision.code == "ABORTED")
    }

    pub fn abort_effect_decision(
        &mut self,
        request: &RuntimeAuthorityRequest,
        provider_proof: &str,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        self.abort_effect_with_proof(request, Some(provider_proof))
    }

    fn abort_effect_with_proof(
        &mut self,
        request: &RuntimeAuthorityRequest,
        provider_proof: Option<&str>,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let request_digest = runtime_effect_request_digest(request)?;
        let grants = self.grants.values().cloned().collect::<Vec<_>>();
        let mut decision = evaluate_runtime_request(&grants, request, request.requested_at);
        decision.revocation_epoch = self.revocation_epoch;
        let previous = self.effect_reservations.clone();
        let abortable = self
            .effect_reservations
            .get(&request.request_id)
            .is_none_or(|reservation| {
                reservation.request_digest == request_digest && !reservation.committed
            });
        if abortable {
            self.effect_reservations.remove(&request.request_id);
            decision.allowed = true;
            decision.code = "ABORTED".into();
        } else {
            decision.allowed = false;
            decision.code = "UNAUTHORIZED".into();
            decision.grant_id = None;
        }
        decision.request_digest = request_digest;
        decision = self.enrich_decision(decision, "ABORT", provider_proof);
        self.decisions.push(decision.clone());
        if let Err(error) = self.persist() {
            self.effect_reservations = previous;
            self.decisions.pop();
            self.available = false;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn status_effect(
        &mut self,
        request: &RuntimeAuthorityRequest,
        effect_id: &str,
        now: u64,
        provider_proof: &str,
    ) -> Result<RuntimeAuthorityDecision, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let request_digest = runtime_effect_request_digest(request)?;
        let grants = self.grants.values().cloned().collect::<Vec<_>>();
        let mut decision = evaluate_runtime_request(&grants, request, now);
        decision.revocation_epoch = self.revocation_epoch;
        match self.effect_reservations.get(&request.request_id) {
            Some(reservation)
                if reservation.request_digest == request_digest
                    && reservation.effect_id.as_deref() == Some(effect_id)
                    && reservation.committed
                    && reservation.revocation_epoch == self.revocation_epoch
                    && reservation.configuration_digest == self.configuration_digest
                    && reservation.state_version == self.state_version =>
            {
                // AUTHORIZED is an exact replay of the already durable COMMIT,
                // allowing effects recovery to persist EXECUTING before the
                // one and only provider dispatch.
                decision.allowed = true;
                decision.code = "AUTHORIZED".into();
                decision.grant_id = reservation.chain.last().cloned();
            }
            Some(reservation)
                if reservation.request_digest == request_digest && !reservation.committed =>
            {
                decision.allowed = false;
                decision.code = "PREPARED".into();
                decision.grant_id = None;
            }
            _ => {
                decision.allowed = false;
                decision.code = "UNAUTHORIZED".into();
                decision.grant_id = None;
            }
        }
        self.persist_phase_decision(decision, "STATUS", request_digest, Some(provider_proof))
    }

    pub fn reap_expired_prepares(&mut self, now: u64) -> Result<usize, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let previous = self.effect_reservations.clone();
        self.effect_reservations.retain(|_, reservation| {
            reservation.committed
                || reservation.prepared_at == 0
                || now < reservation.prepared_at.saturating_add(30)
        });
        let removed = previous
            .len()
            .saturating_sub(self.effect_reservations.len());
        if removed > 0 {
            if let Err(error) = self.persist() {
                self.effect_reservations = previous;
                self.available = false;
                return Err(error);
            }
        }
        Ok(removed)
    }

    fn chain_inactive(&self, grant_id: &str) -> bool {
        let mut current = Some(grant_id);
        let mut seen = HashSet::new();
        while let Some(id) = current {
            if !seen.insert(id) || self.revoked.contains(id) {
                return true;
            }
            current = self
                .grants
                .get(id)
                .and_then(|grant| grant.parent_grant_id.as_deref());
        }
        false
    }

    fn grant_chain(&self, grant_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = Some(grant_id);
        while let Some(id) = current {
            result.push(id.into());
            current = self
                .grants
                .get(id)
                .and_then(|grant| grant.parent_grant_id.as_deref());
        }
        result
    }

    pub fn epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub fn record_admin_approval(
        &mut self,
        approval: &RuntimeAuthorityAdminRequest,
        authenticated_service: &str,
    ) -> Result<bool, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        if approval.schema_version != RUNTIME_AUTHORITY_SCHEMA_VERSION
            || approval.operation != "approve"
            || approval.caller_service_id != authenticated_service
            || authenticated_service != "service:reviewer"
        {
            return Ok(false);
        }
        let Some(target_request_id) = approval.grant_id.as_deref() else {
            return Ok(false);
        };
        let Some(request_digest) = approval.state_version.as_deref() else {
            return Ok(false);
        };
        if !request_digest.starts_with("sha256:") {
            return Ok(false);
        }
        let artifact = RuntimeAdminApproval {
            target_request_id: target_request_id.into(),
            request_digest: request_digest.into(),
            approver_service_id: authenticated_service.into(),
            used_by: None,
        };
        if let Some(existing) = self.admin_approvals.get(&approval.request_id) {
            return Ok(existing.target_request_id == artifact.target_request_id
                && existing.request_digest == artifact.request_digest
                && existing.approver_service_id == artifact.approver_service_id);
        }
        self.admin_approvals
            .insert(approval.request_id.clone(), artifact);
        if let Err(error) = self.persist() {
            self.admin_approvals.remove(&approval.request_id);
            self.available = false;
            return Err(error);
        }
        Ok(true)
    }

    pub fn apply_admin(
        &mut self,
        request: &RuntimeAuthorityAdminRequest,
        authenticated_service: &str,
    ) -> Result<bool, AuthorityError> {
        if !self.available {
            return Err(AuthorityError::Storage);
        }
        let digest = runtime_admin_digest(request);
        if let Some(existing) = self.admin_results.get(&request.request_id) {
            return if existing.request_digest == digest {
                Ok(existing.applied)
            } else {
                Ok(false)
            };
        }
        if request.schema_version != RUNTIME_AUTHORITY_SCHEMA_VERSION
            || request.caller_service_id != authenticated_service
            || authenticated_service != "service:operator"
        {
            return Ok(false);
        }
        let Some(approval) = self.admin_approvals.get(&request.independent_approval) else {
            return Ok(false);
        };
        if approval.target_request_id != request.request_id
            || approval.request_digest != digest
            || approval.approver_service_id == authenticated_service
            || approval.used_by.is_some()
        {
            return Ok(false);
        }
        let old_revoked = self.revoked.clone();
        let old_epoch = self.revocation_epoch;
        let old_state = self.state_version.clone();
        let old_history = self.state_version_history.clone();
        let applied = match request.operation.as_str() {
            "revoke" => request
                .grant_id
                .as_deref()
                .is_some_and(|id| self.grants.contains_key(id) && self.revoked.insert(id.into())),
            "rotate_state" => request.state_version.as_deref().is_some_and(|state| {
                if !state.starts_with("state:") || self.state_version_history.contains(state) {
                    false
                } else {
                    self.state_version = state.into();
                    self.state_version_history.insert(state.into());
                    true
                }
            }),
            _ => false,
        };
        if !applied {
            return Ok(false);
        }
        self.revocation_epoch = self.revocation_epoch.saturating_add(1);
        self.admin_approvals
            .get_mut(&request.independent_approval)
            .unwrap()
            .used_by = Some(request.request_id.clone());
        self.admin_results.insert(
            request.request_id.clone(),
            RuntimeAdminResult {
                request_digest: digest,
                applied: true,
            },
        );
        if let Err(error) = self.persist() {
            self.revoked = old_revoked;
            self.revocation_epoch = old_epoch;
            self.state_version = old_state;
            self.state_version_history = old_history;
            self.admin_approvals
                .get_mut(&request.independent_approval)
                .unwrap()
                .used_by = None;
            self.admin_results.remove(&request.request_id);
            self.available = false;
            return Err(error);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod runtime_durability_tests {
    use super::*;

    #[test]
    fn post_rename_sync_ambiguity_poison_stops_authority_until_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.json");
        let mut store = RuntimeAuthorityStore::open(&path, Vec::new(), "state:none").unwrap();
        store.inject_fault_after_rename();
        assert_eq!(
            store.rotate_state("state:next"),
            Err(AuthorityError::Storage)
        );
        assert_eq!(
            store.rotate_state("state:later"),
            Err(AuthorityError::Storage)
        );
        let disk: RuntimeAuthorityStore = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.state_version, "state:next");
    }
}

fn validate_runtime_grants(grants: &[RuntimeGrant]) -> Result<(), AuthorityError> {
    let by_id = grants
        .iter()
        .map(|grant| (grant.grant_id.as_str(), grant))
        .collect::<HashMap<_, _>>();
    for grant in grants {
        if grant.grant_id.is_empty()
            || !grant.issuer.starts_with("service:")
            || !grant.independent_approver.starts_with("operator:")
            || grant.independent_approver == grant.activation_id
            || grant.quota == 0
            || grant.not_before >= grant.expires_at
        {
            return Err(AuthorityError::InvalidGrant);
        }
        if let Some(parent_id) = &grant.parent_grant_id {
            let parent = by_id
                .get(parent_id.as_str())
                .ok_or(AuthorityError::ParentMissing)?;
            if grant.issuer != parent.service_id
                || grant.machine_id != parent.machine_id
                || grant.service_id != parent.service_id
                || grant.activation_id != parent.activation_id
                || grant.capability != parent.capability
                || grant.operation != parent.operation
                || !grant.target_prefix.starts_with(&parent.target_prefix)
                || grant.not_before < parent.not_before
                || grant.expires_at > parent.expires_at
                || grant.quota > parent.quota
                || grant.remaining_delegation_depth >= parent.remaining_delegation_depth
                || grant.generation != parent.generation
                || grant.state_version != parent.state_version
            {
                return Err(AuthorityError::AttenuationViolation);
            }
        }
    }
    Ok(())
}

pub fn evaluate_runtime_request(
    grants: &[RuntimeGrant],
    request: &RuntimeAuthorityRequest,
    now: u64,
) -> RuntimeAuthorityDecision {
    let structurally_valid = request.schema_version == RUNTIME_AUTHORITY_SCHEMA_VERSION
        && !request.request_id.is_empty()
        && (request.caller_service_id == request.service_id
            || (request.caller_service_id == "service:effects"
                && request.capability == "runtime.effect"
                && request.service_id == "service:runtime"))
        && request.machine_id.starts_with("machine:")
        && request.service_id.starts_with("service:")
        && request.activation_id.starts_with("activation:")
        && request.objective_id.starts_with("objective:")
        && !request.capability.is_empty()
        && !request.operation.is_empty()
        && !request.target.is_empty()
        && request.generation.starts_with("generation:")
        && request.state_version.starts_with("state:")
        && request.requested_at <= now
        && now.saturating_sub(request.requested_at) <= 30;
    let grant = structurally_valid
        .then(|| {
            grants
                .iter()
                .filter(|grant| {
                    grant.machine_id == request.machine_id
                        && grant.service_id == request.service_id
                        && grant.activation_id == request.activation_id
                        && grant.capability == request.capability
                        && grant.operation == request.operation
                        && request.target.starts_with(&grant.target_prefix)
                        && grant.generation == request.generation
                        && grant.state_version == request.state_version
                        && now >= grant.not_before
                        && now < grant.expires_at
                })
                .max_by_key(|grant| (grant.target_prefix.len(), grant.parent_grant_id.is_some()))
        })
        .flatten();
    let (allowed, code) = if structurally_valid && grant.is_some() {
        (true, "AUTHORIZED")
    } else {
        (false, "UNAUTHORIZED")
    };
    let mut decision = RuntimeAuthorityDecision {
        schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION.into(),
        decision_id: String::new(),
        request_id: request.request_id.clone(),
        broker_service_id: request.caller_service_id.clone(),
        allowed,
        code: code.into(),
        grant_id: grant.map(|value| value.grant_id.clone()),
        machine_id: request.machine_id.clone(),
        service_id: request.service_id.clone(),
        activation_id: request.activation_id.clone(),
        objective_id: request.objective_id.clone(),
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        target: request.target.clone(),
        generation: request.generation.clone(),
        state_version: request.state_version.clone(),
        evaluated_at: now,
        requested_at: request.requested_at,
        revocation_epoch: 0,
        phase: "EVALUATE".into(),
        request_digest: runtime_effect_request_digest(request).unwrap_or_default(),
        grant_chain: Vec::new(),
        issuer_chain: Vec::new(),
        policy_ref: "policy:runtime-v2-default-deny".into(),
        configuration_digest: String::new(),
        provider_proof: None,
        evidence_ref: String::new(),
    };
    decision.decision_id = format!(
        "decision:sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&decision).expect("decision serializes"))
    );
    decision
}

macro_rules! identity {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, AuthorityError> {
                if value.starts_with($prefix) && value.len() > $prefix.len() {
                    Ok(Self(value.into()))
                } else {
                    Err(AuthorityError::IdentityInvalid)
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
identity!(MachineId, "machine:");
identity!(ServiceId, "service:");
identity!(ActivationId, "activation:");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    IdentityInvalid,
    InvalidGrant,
    SelfAuthority,
    ParentMissing,
    ParentInactive,
    AttenuationViolation,
    BindingLocked,
    PeerCredential,
    TimeRollback,
    Storage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub schema_version: String,
    pub issuer: String,
    pub subject: String,
    pub capability: String,
    pub capability_version: String,
    pub operations: BTreeSet<String>,
    pub target_prefix: String,
    pub quota: u64,
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub remaining_delegation_depth: u32,
    pub generation: String,
    pub activation: String,
    pub revocation_handle: String,
    pub policy_ref: String,
    pub evidence_refs: Vec<String>,
    pub issuance_proof: String,
    pub machine: String,
    pub service: String,
    pub parent_grant_id: Option<String>,
}

pub struct GrantBuilder(Grant);
impl Grant {
    pub fn builder(id: &str, issuer: &str, subject: &str, capability: &str) -> GrantBuilder {
        GrantBuilder(Grant {
            id: id.into(),
            schema_version: "2.0".into(),
            issuer: issuer.into(),
            subject: subject.into(),
            capability: capability.into(),
            capability_version: "2.0".into(),
            operations: BTreeSet::new(),
            target_prefix: String::new(),
            quota: 1,
            issued_at: 0,
            not_before: 0,
            expires_at: 0,
            remaining_delegation_depth: 0,
            generation: String::new(),
            activation: subject.into(),
            revocation_handle: format!("revoke:{id}"),
            policy_ref: "policy:v2".into(),
            evidence_refs: vec![],
            issuance_proof: String::new(),
            machine: String::new(),
            service: String::new(),
            parent_grant_id: None,
        })
    }
}
impl GrantBuilder {
    pub fn operations<const N: usize>(mut self, values: [&str; N]) -> Self {
        self.0.operations = values.into_iter().map(Into::into).collect();
        self
    }
    pub fn target_prefix(mut self, value: &str) -> Self {
        self.0.target_prefix = value.into();
        self
    }
    pub fn valid_between(mut self, start: u64, end: u64) -> Self {
        self.0.issued_at = start;
        self.0.not_before = start;
        self.0.expires_at = end;
        self
    }
    pub fn generation(mut self, value: &str) -> Self {
        self.0.generation = value.into();
        self
    }
    pub fn delegation_depth(mut self, value: u32) -> Self {
        self.0.remaining_delegation_depth = value;
        self
    }
    pub fn quota(mut self, value: u64) -> Self {
        self.0.quota = value;
        self
    }
    pub fn caller(mut self, machine: &str, service: &str) -> Self {
        self.0.machine = machine.into();
        self.0.service = service.into();
        self
    }
    pub fn build(mut self) -> Result<Grant, AuthorityError> {
        if self.0.id.is_empty()
            || self.0.issuer.is_empty()
            || !self.0.subject.starts_with("activation:")
            || self.0.operations.is_empty()
            || self.0.target_prefix.is_empty()
            || self.0.not_before >= self.0.expires_at
            || self.0.generation.is_empty()
            || !self.0.machine.starts_with("machine:")
            || !self.0.service.starts_with("service:")
        {
            return Err(AuthorityError::InvalidGrant);
        }
        self.0.issuance_proof = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&self.0).unwrap())
        );
        Ok(self.0)
    }
}

#[derive(Clone, Debug)]
pub struct IndependentApproval {
    approver: String,
    verified: bool,
}
impl IndependentApproval {
    pub fn verified(approver: &str) -> Self {
        Self {
            approver: approver.into(),
            verified: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnforcementProof {
    provider: String,
    verified: bool,
}
impl EnforcementProof {
    pub fn verified(provider: &str) -> Self {
        Self {
            provider: provider.into(),
            verified: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub command_id: String,
    pub machine: MachineId,
    pub service: ServiceId,
    pub activation: ActivationId,
    pub capability: String,
    pub operation: String,
    pub target: String,
    pub requested_at: u64,
    pub state_version: String,
    pub objective: String,
    pub generation: String,
    pub enforcement: Option<EnforcementProof>,
}
impl Invocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: &str,
        machine: MachineId,
        service: ServiceId,
        activation: ActivationId,
        capability: &str,
        operation: &str,
        target: &str,
        at: u64,
        state: &str,
        objective: &str,
    ) -> Self {
        Self {
            command_id: command.into(),
            machine,
            service,
            activation,
            capability: capability.into(),
            operation: operation.into(),
            target: target.into(),
            requested_at: at,
            state_version: state.into(),
            objective: objective.into(),
            generation: "generation:01".into(),
            enforcement: None,
        }
    }
    pub fn with_enforcement(mut self, proof: EnforcementProof) -> Self {
        self.enforcement = Some(proof);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: String,
    pub allowed: bool,
    pub grant_id: Option<String>,
    pub denial_code: Option<String>,
    pub subject: String,
    pub issuer_chain: Vec<String>,
    pub activation: String,
    pub objective: String,
    pub target: String,
    pub operation: String,
    pub policy_version: String,
    pub revocation_epoch: u64,
    pub evaluated_state_version: String,
    pub result_evidence: String,
    pub enforcement_provider: Option<String>,
    pub denial_reason: Option<String>,
}
impl Decision {
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }
    pub fn id(&self) -> &str {
        &self.decision_id
    }
}

#[derive(Serialize, Deserialize)]
pub struct Authority {
    policy: String,
    generation: String,
    state_version: String,
    current_time: u64,
    trusted_peer: Option<TrustedPeer>,
    #[serde(skip)]
    peer_binding: Option<PeerBinding>,
    grants: HashMap<String, Grant>,
    revoked: HashSet<String>,
    epoch: u64,
    available: bool,
    decisions: Vec<Decision>,
    #[serde(skip)]
    path: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TrustedPeer {
    uid: u32,
    gid: u32,
    machine: String,
    service: String,
    activation: String,
}
#[derive(Clone, Debug)]
struct PeerBinding {
    channel: (u64, u64),
    pid: i32,
    uid: u32,
    gid: u32,
    machine: String,
    service: String,
    activation: String,
}
impl Authority {
    pub fn new(policy: &str, generation: &str, state_version: &str, current_time: u64) -> Self {
        Self {
            policy: policy.into(),
            generation: generation.into(),
            state_version: state_version.into(),
            current_time,
            trusted_peer: None,
            peer_binding: None,
            grants: HashMap::new(),
            revoked: HashSet::new(),
            epoch: 0,
            available: true,
            decisions: vec![],
            path: None,
        }
    }
    pub fn open(
        path: impl AsRef<Path>,
        policy: &str,
        generation: &str,
        state_version: &str,
        current_time: u64,
    ) -> Result<Self, AuthorityError> {
        let path = path.as_ref().to_owned();
        if path.exists() {
            let mut value: Self =
                serde_json::from_slice(&fs::read(&path).map_err(|_| AuthorityError::Storage)?)
                    .map_err(|_| AuthorityError::Storage)?;
            value.path = Some(path);
            value.policy = policy.into();
            value.generation = generation.into();
            value.state_version = state_version.into();
            value.current_time = value.current_time.max(current_time);
            value.available = true;
            value.persist()?;
            Ok(value)
        } else {
            let mut value = Self::new(policy, generation, state_version, current_time);
            value.path = Some(path);
            value.persist()?;
            Ok(value)
        }
    }
    fn persist(&self) -> Result<(), AuthorityError> {
        if let Some(path) = &self.path {
            durable_replace(
                path,
                &serde_json::to_vec(self).map_err(|_| AuthorityError::Storage)?,
                false,
            )
            .map_err(|_| AuthorityError::Storage)?;
        }
        Ok(())
    }
    pub fn issue(
        &mut self,
        grant: Grant,
        approval: IndependentApproval,
    ) -> Result<(), AuthorityError> {
        if !approval.verified || approval.approver == grant.subject || grant.issuer == grant.subject
        {
            return Err(AuthorityError::SelfAuthority);
        }
        self.grants.insert(grant.id.clone(), grant);
        self.persist()
    }
    pub fn set_available(&mut self, value: bool) {
        self.available = value
    }
    fn peer_credentials(
        channel: &UnixStream,
    ) -> Result<((u64, u64), PeerPrincipal), AuthorityError> {
        let fd = channel.as_raw_fd();
        let mut stat = mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(AuthorityError::PeerCredential);
        }
        let stat = unsafe { stat.assume_init() };
        let credential =
            PeerPrincipal::from_stream(channel).map_err(|_| AuthorityError::PeerCredential)?;
        Ok(((stat.st_dev, stat.st_ino), credential))
    }
    pub fn bind_peer(
        &mut self,
        channel: &UnixStream,
        machine: &MachineId,
        service: &ServiceId,
        activation: &ActivationId,
    ) -> Result<(), AuthorityError> {
        if self.peer_binding.is_some() {
            return Err(AuthorityError::BindingLocked);
        }
        let (identity, credential) = Self::peer_credentials(channel)?;
        let peer_pid = credential.pid;
        let observed = TrustedPeer {
            uid: credential.uid,
            gid: credential.gid,
            machine: machine.as_str().into(),
            service: service.as_str().into(),
            activation: activation.as_str().into(),
        };
        match &self.trusted_peer {
            Some(trusted) if trusted != &observed => return Err(AuthorityError::PeerCredential),
            None if !self.grants.is_empty() => return Err(AuthorityError::BindingLocked),
            None => {
                self.trusted_peer = Some(observed);
                self.persist()?
            }
            Some(_) => {}
        }
        self.peer_binding = Some(PeerBinding {
            channel: identity,
            pid: peer_pid,
            uid: credential.uid,
            gid: credential.gid,
            machine: machine.as_str().into(),
            service: service.as_str().into(),
            activation: activation.as_str().into(),
        });
        Ok(())
    }
    pub fn advance_time(&mut self, value: u64) -> Result<(), AuthorityError> {
        if value < self.current_time {
            return Err(AuthorityError::TimeRollback);
        }
        self.current_time = value;
        self.persist()
    }
    pub fn update_state_version(&mut self, value: &str) -> Result<(), AuthorityError> {
        self.state_version = value.into();
        self.persist()
    }
    pub fn revoke(&mut self, grant_id: &str) -> bool {
        self.epoch += 1;
        let changed = self.revoked.insert(grant_id.into());
        if self.persist().is_err() {
            self.available = false;
        }
        changed
    }
    pub fn delegate(&mut self, parent_id: &str, mut child: Grant) -> Result<(), AuthorityError> {
        let parent = self
            .grants
            .get(parent_id)
            .ok_or(AuthorityError::ParentMissing)?;
        if self.revoked.contains(parent_id) {
            return Err(AuthorityError::ParentInactive);
        }
        if child.issuer != parent.subject
            || child.operations.is_empty()
            || !child.operations.is_subset(&parent.operations)
            || !child.target_prefix.starts_with(&parent.target_prefix)
            || child.not_before < parent.not_before
            || child.expires_at > parent.expires_at
            || child.quota > parent.quota
            || child.remaining_delegation_depth >= parent.remaining_delegation_depth
            || child.generation != parent.generation
            || child.machine != parent.machine
            || child.service != parent.service
        {
            return Err(AuthorityError::AttenuationViolation);
        }
        child.parent_grant_id = Some(parent_id.into());
        self.grants.insert(child.id.clone(), child);
        self.persist()
    }
    fn chain_denial(
        &self,
        grant: &Grant,
        request: &Invocation,
    ) -> Option<(&'static str, &'static str)> {
        let mut current = grant;
        loop {
            if self.revoked.contains(&current.id) {
                return Some(("UNAUTHORIZED", "grant chain revoked"));
            }
            if self.current_time < current.not_before || self.current_time >= current.expires_at {
                return Some(("STALE", "grant chain outside validity interval"));
            }
            if current.generation != request.generation {
                return Some(("STALE", "grant chain generation mismatch"));
            }
            {
                let parent = current.parent_grant_id.as_ref()?;
                match self.grants.get(parent) {
                    Some(value) => current = value,
                    None => return Some(("STALE", "grant parent missing")),
                }
            }
        }
    }
    pub fn evaluate_peer(
        &mut self,
        channel: &UnixStream,
        request: &Invocation,
    ) -> Result<Decision, AuthorityError> {
        let observed = Self::peer_credentials(channel)?;
        let observed_pid = observed.1.pid;
        let authenticated = self
            .peer_binding
            .as_ref()
            .map(|value| {
                value.channel == observed.0
                    && value.pid == observed_pid
                    && value.uid == observed.1.uid
                    && value.gid == observed.1.gid
                    && value.machine == request.machine.as_str()
                    && value.service == request.service.as_str()
                    && value.activation == request.activation.as_str()
                    && self.trusted_peer.is_some()
            })
            .unwrap_or(false);
        let denial = if !self.available {
            Some(("UNAVAILABLE", "authority state unavailable"))
        } else if !authenticated {
            Some((
                "UNAUTHORIZED",
                "kernel peer identity is not bound to invocation",
            ))
        } else if request.command_id.is_empty() || request.objective.is_empty() {
            Some(("INVALID", "identity or objective missing"))
        } else if request.generation != self.generation {
            Some(("STALE", "generation mismatch"))
        } else if request.state_version != self.state_version {
            Some(("STALE", "authority state version mismatch"))
        } else {
            None
        };
        let mut candidates = self
            .grants
            .values()
            .filter(|g| {
                g.subject == request.activation.as_str()
                    && g.capability == request.capability
                    && g.machine == request.machine.as_str()
                    && g.service == request.service.as_str()
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.id.cmp(&right.id));
        let (mut grant, mut code) = (None, denial);
        if code.is_none() {
            for candidate in candidates {
                let reason = if let Some(reason) = self.chain_denial(candidate, request) {
                    Some(reason)
                } else if !candidate.operations.contains(&request.operation) {
                    Some(("UNAUTHORIZED", "operation outside grant scope"))
                } else if !request.target.starts_with(&candidate.target_prefix) {
                    Some(("UNAUTHORIZED", "target outside grant scope"))
                } else if !request
                    .enforcement
                    .as_ref()
                    .map(|p| p.verified)
                    .unwrap_or(false)
                    && request.operation != "read"
                {
                    Some(("UNAUTHORIZED", "enforcement proof unverified"))
                } else {
                    None
                };
                if grant.is_none() {
                    grant = Some(candidate);
                    code = reason
                }
                if reason.is_none() {
                    grant = Some(candidate);
                    code = None;
                    break;
                }
            }
            if grant.is_none() {
                code = Some(("UNAUTHORIZED", "no current scoped grant"))
            }
        }
        let mut decision = Decision {
            decision_id: String::new(),
            allowed: code.is_none(),
            grant_id: grant.map(|g| g.id.clone()),
            denial_code: code.map(|value| value.0.into()),
            subject: request.activation.as_str().into(),
            issuer_chain: grant.map(|g| vec![g.issuer.clone()]).unwrap_or_default(),
            activation: request.activation.as_str().into(),
            objective: request.objective.clone(),
            target: request.target.clone(),
            operation: request.operation.clone(),
            policy_version: self.policy.clone(),
            revocation_epoch: self.epoch,
            evaluated_state_version: request.state_version.clone(),
            result_evidence: String::new(),
            enforcement_provider: request.enforcement.as_ref().map(|p| p.provider.clone()),
            denial_reason: code.map(|value| value.1.into()),
        };
        decision.decision_id = format!(
            "decision:sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&decision).unwrap())
        );
        decision.result_evidence = format!("evidence:{}", decision.decision_id);
        self.decisions.push(decision.clone());
        self.persist()?;
        Ok(decision)
    }
    pub fn audit(&self) -> &[Decision] {
        &self.decisions
    }
}
