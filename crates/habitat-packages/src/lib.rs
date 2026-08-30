//! Signed capability packages and immutable activation sets.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityVersion {
    pub id: String,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChain {
    pub source: String,
    pub lock: String,
    pub build_environment: String,
    pub sbom: String,
    pub vulnerability_result: String,
    pub reproducibility: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    pub id: String,
    pub version: String,
    pub publisher: String,
    pub content_digest: String,
    pub artifact_ref: String,
    pub provides: Vec<CapabilityVersion>,
    pub requires: Vec<CapabilityVersion>,
    pub hardware: Vec<String>,
    pub isolation: Vec<String>,
    pub state_schema: String,
    pub supply_chain: SupplyChain,
}
pub struct ManifestBuilder(PackageManifest);
impl PackageManifest {
    pub fn builder(id: &str, version: &str, publisher: &str, digest: &str) -> ManifestBuilder {
        ManifestBuilder(Self {
            id: id.into(),
            version: version.into(),
            publisher: publisher.into(),
            content_digest: digest.into(),
            artifact_ref: String::new(),
            provides: vec![],
            requires: vec![],
            hardware: vec![],
            isolation: vec![],
            state_schema: "stateless".into(),
            supply_chain: SupplyChain {
                source: String::new(),
                lock: String::new(),
                build_environment: String::new(),
                sbom: String::new(),
                vulnerability_result: String::new(),
                reproducibility: String::new(),
            },
        })
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable manifest")
    }
    pub fn requires(mut self, id: &str, version: &str) -> Self {
        self.requires.push(CapabilityVersion {
            id: id.into(),
            version: version.into(),
        });
        self
    }
    pub fn requirements(
        mut self,
        hardware: &[&str],
        isolation: &[&str],
        state_schema: &str,
    ) -> Self {
        self.hardware = hardware.iter().map(|v| (*v).into()).collect();
        self.isolation = isolation.iter().map(|v| (*v).into()).collect();
        self.state_schema = state_schema.into();
        self
    }
}
impl ManifestBuilder {
    pub fn artifact(mut self, value: &str) -> Self {
        self.0.artifact_ref = value.into();
        self
    }
    pub fn provides(mut self, id: &str, version: &str) -> Self {
        self.0.provides.push(CapabilityVersion {
            id: id.into(),
            version: version.into(),
        });
        self
    }
    pub fn requires(mut self, id: &str, version: &str) -> Self {
        self.0.requires.push(CapabilityVersion {
            id: id.into(),
            version: version.into(),
        });
        self
    }
    pub fn supply_chain(
        mut self,
        source: &str,
        lock: &str,
        build: &str,
        sbom: &str,
        vuln: &str,
        repro: &str,
    ) -> Self {
        self.0.supply_chain = SupplyChain {
            source: source.into(),
            lock: lock.into(),
            build_environment: build.into(),
            sbom: sbom.into(),
            vulnerability_result: vuln.into(),
            reproducibility: repro.into(),
        };
        self
    }
    pub fn build(self) -> PackageManifest {
        self.0
    }
}

#[derive(Default)]
pub struct TrustStore {
    keys: HashMap<String, VerifyingKey>,
    revoked: HashSet<String>,
}
impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn trust(&mut self, publisher: &str, key: VerifyingKey) {
        self.keys.insert(publisher.into(), key);
    }
    pub fn revoke(&mut self, publisher: &str) {
        self.revoked.insert(publisher.into());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderState {
    Discovered,
    Admitted,
    Staged,
    Starting,
    Verifying,
    Active,
    Degraded,
    Unavailable,
    Quarantined,
    Draining,
    Revoked,
    Retired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRecord {
    pub manifest: PackageManifest,
    pub state: ProviderState,
    pub provider_authority: bool,
    pub agent_authority: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum PackageError {
    PublisherUntrusted,
    PublisherRevoked,
    SignatureInvalid,
    MutableArtifact,
    SupplyChainIncomplete,
    PackageMissing,
    DependencyUnresolved,
    HostRequirementMissing,
    LiveVerificationRequired,
    BehavioralProbeFailed,
    NoActiveSet,
    NoRollback,
    DestructiveMigrationUnproven,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProfile {
    hardware: BTreeSet<String>,
    isolation: BTreeSet<String>,
}
impl HostProfile {
    pub fn new(hardware: &[&str], isolation: &[&str]) -> Self {
        Self {
            hardware: hardware.iter().map(|v| (*v).into()).collect(),
            isolation: isolation.iter().map(|v| (*v).into()).collect(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSet {
    packages: Vec<String>,
    key: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BehavioralProbe {
    contract: String,
    evidence: String,
    passed: bool,
}
impl BehavioralProbe {
    pub fn passed(contract: &str, evidence: &str) -> Self {
        Self {
            contract: contract.into(),
            evidence: evidence.into(),
            passed: true,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationEntry {
    pub package_id: String,
    pub version: String,
    pub artifact_ref: String,
    pub configuration_digest: String,
    pub state_schema: String,
    pub grants: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationSet {
    pub id: String,
    pub entries: Vec<ActivationEntry>,
    pub verification_evidence: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkBinding {
    pub activation_id: String,
    pub activation_set_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub unresolved_effects: Vec<String>,
    pub recovery_wakes: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationDirection {
    ForwardOnly,
    Bidirectional,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationContract {
    pub from: String,
    pub to: String,
    pub direction: MigrationDirection,
    pub interruption: String,
    pub rollback_limit: String,
    pub destructive: bool,
    pub evidence: Option<String>,
}
pub struct PackageController {
    trust: TrustStore,
    packages: BTreeMap<String, PackageRecord>,
    verified: HashMap<String, String>,
    current: Option<ActivationSet>,
    history: Vec<ActivationSet>,
    bindings: HashMap<String, WorkBinding>,
}
impl PackageController {
    pub fn new(trust: TrustStore) -> Self {
        Self {
            trust,
            packages: BTreeMap::new(),
            verified: HashMap::new(),
            current: None,
            history: vec![],
            bindings: HashMap::new(),
        }
    }
    pub fn admit(
        &mut self,
        manifest: PackageManifest,
        signature: [u8; 64],
    ) -> Result<PackageRecord, PackageError> {
        if self.trust.revoked.contains(&manifest.publisher) {
            return Err(PackageError::PublisherRevoked);
        }
        let key = self
            .trust
            .keys
            .get(&manifest.publisher)
            .ok_or(PackageError::PublisherUntrusted)?;
        key.verify(
            &manifest.signing_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| PackageError::SignatureInvalid)?;
        if !valid_digest(&manifest.content_digest)
            || !manifest.artifact_ref.contains("@sha256:")
            || manifest
                .artifact_ref
                .rsplit("@sha256:")
                .next()
                .map(|v| v.len() != 64)
                .unwrap_or(true)
        {
            return Err(PackageError::MutableArtifact);
        }
        let supply = &manifest.supply_chain;
        if [
            &supply.source,
            &supply.lock,
            &supply.build_environment,
            &supply.sbom,
            &supply.vulnerability_result,
            &supply.reproducibility,
        ]
        .iter()
        .any(|v| v.is_empty())
        {
            return Err(PackageError::SupplyChainIncomplete);
        }
        let record = PackageRecord {
            manifest: manifest.clone(),
            state: ProviderState::Admitted,
            provider_authority: false,
            agent_authority: false,
        };
        self.packages.insert(manifest.id.clone(), record.clone());
        Ok(record)
    }
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }
    pub fn resolve(&self, roots: &[&str], host: &HostProfile) -> Result<ResolvedSet, PackageError> {
        let mut selected = BTreeSet::new();
        let mut pending = roots.iter().map(|v| (*v).to_string()).collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if !selected.insert(id.clone()) {
                continue;
            }
            let record = self.packages.get(&id).ok_or(PackageError::PackageMissing)?;
            if !record
                .manifest
                .hardware
                .iter()
                .all(|v| host.hardware.contains(v))
                || !record
                    .manifest
                    .isolation
                    .iter()
                    .all(|v| host.isolation.contains(v))
            {
                return Err(PackageError::HostRequirementMissing);
            }
            for requirement in &record.manifest.requires {
                let provider = self
                    .packages
                    .values()
                    .find(|p| {
                        p.manifest.provides.iter().any(|provided| {
                            provided.id == requirement.id && provided.version == requirement.version
                        })
                    })
                    .ok_or(PackageError::DependencyUnresolved)?;
                pending.push(provider.manifest.id.clone());
            }
        }
        let packages = selected.into_iter().collect::<Vec<_>>();
        let key = activation_set_digest(&packages);
        Ok(ResolvedSet { packages, key })
    }
    pub fn stage(&mut self, resolved: &ResolvedSet) -> Result<(), PackageError> {
        for id in &resolved.packages {
            self.packages
                .get_mut(id)
                .ok_or(PackageError::PackageMissing)?
                .state = ProviderState::Staged;
        }
        Ok(())
    }
    pub fn verify(
        &mut self,
        resolved: &ResolvedSet,
        probe: BehavioralProbe,
    ) -> Result<(), PackageError> {
        if !probe.passed || probe.contract.is_empty() || probe.evidence.is_empty() {
            return Err(PackageError::BehavioralProbeFailed);
        }
        for id in &resolved.packages {
            self.packages
                .get_mut(id)
                .ok_or(PackageError::PackageMissing)?
                .state = ProviderState::Verifying;
        }
        self.verified.insert(resolved.key.clone(), probe.evidence);
        Ok(())
    }
    pub fn activate(&mut self, resolved: &ResolvedSet) -> Result<ActivationSet, PackageError> {
        let evidence = self
            .verified
            .get(&resolved.key)
            .ok_or(PackageError::LiveVerificationRequired)?
            .clone();
        let mut entries = resolved
            .packages
            .iter()
            .map(|id| {
                let p = &self.packages[id].manifest;
                ActivationEntry {
                    package_id: p.id.clone(),
                    version: p.version.clone(),
                    artifact_ref: p.artifact_ref.clone(),
                    configuration_digest: format!(
                        "sha256:{:x}",
                        Sha256::digest(format!("{}:{}", p.id, p.version))
                    ),
                    state_schema: p.state_schema.clone(),
                    grants: vec![],
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.package_id.cmp(&b.package_id));
        let mut set = ActivationSet {
            id: String::new(),
            entries,
            verification_evidence: vec![evidence],
        };
        set.id = activation_set_digest(&set);
        if let Some(current) = self.current.replace(set.clone()) {
            self.history.push(current)
        }
        for id in &resolved.packages {
            self.packages.get_mut(id).unwrap().state = ProviderState::Active;
        }
        Ok(set)
    }
    pub fn qualify_and_activate(
        &mut self,
        roots: &[&str],
        host: &HostProfile,
        evidence: &str,
    ) -> Result<ActivationSet, PackageError> {
        let resolved = self.resolve(roots, host)?;
        self.stage(&resolved)?;
        self.verify(
            &resolved,
            BehavioralProbe::passed("declared-capability-contract", evidence),
        )?;
        self.activate(&resolved)
    }
    pub fn bind(&mut self, activation: &str) -> Result<WorkBinding, PackageError> {
        let set = self.current.as_ref().ok_or(PackageError::NoActiveSet)?;
        let binding = WorkBinding {
            activation_id: activation.into(),
            activation_set_id: set.id.clone(),
        };
        self.bindings.insert(activation.into(), binding.clone());
        Ok(binding)
    }
    pub fn binding(&self, activation: &str) -> Option<&WorkBinding> {
        self.bindings.get(activation)
    }
    pub fn drain(&mut self, package: &str) -> Result<(), PackageError> {
        self.packages
            .get_mut(package)
            .ok_or(PackageError::PackageMissing)?
            .state = ProviderState::Draining;
        Ok(())
    }
    pub fn rollback(&mut self) -> Result<ActivationSet, PackageError> {
        let prior = self.history.pop().ok_or(PackageError::NoRollback)?;
        self.current = Some(prior.clone());
        Ok(prior)
    }
    pub fn revoke(
        &mut self,
        package: &str,
        effects: &[&str],
        objectives: &[&str],
    ) -> Result<RecoveryPlan, PackageError> {
        self.packages
            .get_mut(package)
            .ok_or(PackageError::PackageMissing)?
            .state = ProviderState::Revoked;
        Ok(RecoveryPlan {
            unresolved_effects: effects.iter().map(|v| (*v).into()).collect(),
            recovery_wakes: objectives
                .iter()
                .map(|v| format!("recovery-wake:{v}"))
                .collect(),
        })
    }
    pub fn migrate(
        &mut self,
        package: &str,
        contract: MigrationContract,
    ) -> Result<String, PackageError> {
        if !self.packages.contains_key(package) {
            return Err(PackageError::PackageMissing);
        }
        if contract.destructive && contract.evidence.is_none() {
            return Err(PackageError::DestructiveMigrationUnproven);
        }
        Ok(contract
            .evidence
            .unwrap_or_else(|| "evidence:non-destructive-migration".into()))
    }
}
fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .map(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

pub fn activation_set_digest<T: Serialize>(value: &T) -> String {
    format!(
        "activation-set:sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).unwrap())
    )
}
