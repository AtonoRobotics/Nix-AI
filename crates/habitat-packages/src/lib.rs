//! Content-bound package admission, immutable activation sets, and governed change.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const CONTRACT_VERSION: &str = "V2.0.1";

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
    pub requested_authority: Vec<String>,
    pub memory_limit_bytes: u64,
    pub cpu_limit_millis: u32,
    pub execution_profile: String,
    pub abi_version: String,
    pub migration_contract: String,
    pub live_verification_contract: String,
}
pub struct ManifestBuilder(PackageManifest);
pub struct PackagePolicy<'a> {
    pub authority: &'a [&'a str],
    pub memory_limit_bytes: u64,
    pub cpu_limit_millis: u32,
    pub execution_profile: &'a str,
    pub abi_version: &'a str,
    pub migration_contract: &'a str,
    pub live_verification_contract: &'a str,
}
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
            requested_authority: vec![],
            memory_limit_bytes: 64 * 1024 * 1024,
            cpu_limit_millis: 1_000,
            execution_profile: "isolated".into(),
            abi_version: CONTRACT_VERSION.into(),
            migration_contract: "migration:stateless".into(),
            live_verification_contract: "probe:default".into(),
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
    pub fn artifact(mut self, v: &str) -> Self {
        self.0.artifact_ref = v.into();
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
    pub fn policy(mut self, policy: PackagePolicy<'_>) -> Self {
        self.0.requested_authority = policy.authority.iter().map(|v| (*v).into()).collect();
        self.0.memory_limit_bytes = policy.memory_limit_bytes;
        self.0.cpu_limit_millis = policy.cpu_limit_millis;
        self.0.execution_profile = policy.execution_profile.into();
        self.0.abi_version = policy.abi_version.into();
        self.0.migration_contract = policy.migration_contract.into();
        self.0.live_verification_contract = policy.live_verification_contract.into();
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
    pub fn trust(&mut self, p: &str, k: VerifyingKey) {
        self.keys.insert(p.into(), k);
    }
    pub fn revoke(&mut self, p: &str) {
        self.revoked.insert(p.into());
    }
}

#[derive(Clone, Debug)]
pub struct BundleSubmission {
    pub manifest: PackageManifest,
    pub bundle: Vec<u8>,
    pub signature: [u8; 64],
    pub provenance: Vec<u8>,
    pub sbom: Vec<u8>,
    pub dependency_closure: Vec<String>,
}
impl BundleSubmission {
    pub fn signing_bytes(
        m: &PackageManifest,
        b: &[u8],
        p: &[u8],
        s: &[u8],
        c: &[String],
    ) -> Vec<u8> {
        serde_json::to_vec(&(m, digest(b), digest(p), digest(s), c))
            .expect("serializable submission")
    }
    pub fn unsigned(
        manifest: PackageManifest,
        bundle: Vec<u8>,
        provenance: Vec<u8>,
        sbom: Vec<u8>,
        dependency_closure: Vec<String>,
    ) -> Self {
        Self {
            manifest,
            bundle,
            signature: [0; 64],
            provenance,
            sbom,
            dependency_closure,
        }
    }
    pub fn bytes_to_sign(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.manifest,
            &self.bundle,
            &self.provenance,
            &self.sbom,
            &self.dependency_closure,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub allowed_authority: BTreeSet<String>,
    pub max_memory_bytes: u64,
    pub max_cpu_millis: u32,
    pub execution_profiles: BTreeSet<String>,
    pub abi_version: String,
}
impl AdmissionPolicy {
    pub fn strict(a: &[&str], m: u64, c: u32, p: &[&str]) -> Self {
        Self {
            allowed_authority: a.iter().map(|v| (*v).into()).collect(),
            max_memory_bytes: m,
            max_cpu_millis: c,
            execution_profiles: p.iter().map(|v| (*v).into()).collect(),
            abi_version: CONTRACT_VERSION.into(),
        }
    }
}
pub trait ProbeExecutor {
    fn execute(&mut self, contract: &str, bundle: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct ExecutableProbe {
    root: PathBuf,
    timeout: Duration,
}

impl ExecutableProbe {
    pub fn new(root: impl AsRef<Path>, timeout: Duration) -> Result<Self, String> {
        if timeout.is_zero() {
            return Err("probe timeout must be positive".into());
        }
        fs::create_dir_all(root.as_ref()).map_err(|error| error.to_string())?;
        Ok(Self {
            root: root.as_ref().to_owned(),
            timeout,
        })
    }
}

impl ProbeExecutor for ExecutableProbe {
    fn execute(&mut self, contract: &str, bundle: &[u8]) -> Result<Vec<u8>, String> {
        let identity = format!("{:x}", Sha256::digest(bundle));
        let path = self.root.join(format!("probe-{identity}"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(bundle)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500))
            .map_err(|error| error.to_string())?;
        let mut child = Command::new(&path)
            .arg(contract)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        loop {
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(_) => break,
                None if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(10))
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(&path);
                    return Err("behavioral probe deadline exceeded".into());
                }
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;
        let _ = fs::remove_file(&path);
        if !output.status.success() || !output.stderr.is_empty() {
            return Err("behavioral probe failed".into());
        }
        let observation: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| "behavioral probe output is not JSON".to_string())?;
        if observation["contract"].as_str() != Some(contract)
            || observation["passed"].as_bool() != Some(true)
        {
            return Err("behavioral probe did not satisfy its contract".into());
        }
        Ok(output.stdout)
    }
}

#[derive(Deserialize)]
struct ProvenanceStatement {
    source: String,
    lock: String,
    builder: String,
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
    pub admission_evidence: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageError {
    PublisherUntrusted,
    PublisherRevoked,
    SignatureInvalid,
    ContentDigestMismatch,
    MutableArtifact,
    ProvenanceInvalid,
    SbomInvalid,
    ClosureMismatch,
    AuthorityExceeded,
    ResourcesExceeded,
    ExecutionProfileDenied,
    AbiIncompatible,
    MigrationContractMissing,
    LiveContractMissing,
    PackageMissing,
    DependencyUnresolved,
    HostRequirementMissing,
    LiveVerificationRequired,
    BehavioralProbeFailed,
    NoActiveSet,
    NoRollback,
    DestructiveMigrationUnproven,
    StagingRace,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProfile {
    hardware: BTreeSet<String>,
    isolation: BTreeSet<String>,
}
impl HostProfile {
    pub fn new(h: &[&str], i: &[&str]) -> Self {
        Self {
            hardware: h.iter().map(|v| (*v).into()).collect(),
            isolation: i.iter().map(|v| (*v).into()).collect(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSet {
    packages: Vec<String>,
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
    current: Option<ActivationSet>,
    history: Vec<ActivationSet>,
    bindings: HashMap<String, WorkBinding>,
}
impl PackageController {
    pub fn new(trust: TrustStore) -> Self {
        Self {
            trust,
            packages: BTreeMap::new(),
            current: None,
            history: vec![],
            bindings: HashMap::new(),
        }
    }
    pub fn admit_bundle(
        &mut self,
        s: BundleSubmission,
        policy: &AdmissionPolicy,
        probe: &mut dyn ProbeExecutor,
    ) -> Result<PackageRecord, PackageError> {
        let m = &s.manifest;
        if self.trust.revoked.contains(&m.publisher) {
            return Err(PackageError::PublisherRevoked);
        }
        let k = self
            .trust
            .keys
            .get(&m.publisher)
            .ok_or(PackageError::PublisherUntrusted)?;
        k.verify(&s.bytes_to_sign(), &Signature::from_bytes(&s.signature))
            .map_err(|_| PackageError::SignatureInvalid)?;
        if m.content_digest != digest(&s.bundle) {
            return Err(PackageError::ContentDigestMismatch);
        }
        if m.artifact_ref.rsplit_once("@sha256:").map(|(_, v)| v)
            != m.content_digest.strip_prefix("sha256:")
        {
            return Err(PackageError::MutableArtifact);
        }
        let provenance: ProvenanceStatement =
            serde_json::from_slice(&s.provenance).map_err(|_| PackageError::ProvenanceInvalid)?;
        if provenance.source != m.supply_chain.source
            || provenance.lock != m.supply_chain.lock
            || provenance.builder != m.supply_chain.build_environment
            || m.supply_chain.reproducibility.is_empty()
        {
            return Err(PackageError::ProvenanceInvalid);
        }
        if s.sbom.is_empty()
            || m.supply_chain.sbom != digest(&s.sbom)
            || m.supply_chain.vulnerability_result != "vuln:passed"
        {
            return Err(PackageError::SbomInvalid);
        }
        let expected = m
            .requires
            .iter()
            .map(|r| format!("{}@{}", r.id, r.version))
            .collect::<BTreeSet<_>>();
        if expected != s.dependency_closure.iter().cloned().collect() {
            return Err(PackageError::ClosureMismatch);
        }
        if !m
            .requested_authority
            .iter()
            .all(|v| policy.allowed_authority.contains(v))
        {
            return Err(PackageError::AuthorityExceeded);
        }
        if m.memory_limit_bytes > policy.max_memory_bytes
            || m.cpu_limit_millis > policy.max_cpu_millis
        {
            return Err(PackageError::ResourcesExceeded);
        }
        if !policy.execution_profiles.contains(&m.execution_profile) {
            return Err(PackageError::ExecutionProfileDenied);
        }
        if m.abi_version != policy.abi_version {
            return Err(PackageError::AbiIncompatible);
        }
        if m.migration_contract.is_empty() {
            return Err(PackageError::MigrationContractMissing);
        }
        if m.live_verification_contract.is_empty() {
            return Err(PackageError::LiveContractMissing);
        }
        let out = probe
            .execute(&m.live_verification_contract, &s.bundle)
            .map_err(|_| PackageError::BehavioralProbeFailed)?;
        if out.is_empty() {
            return Err(PackageError::BehavioralProbeFailed);
        }
        if self.packages.contains_key(&m.id) {
            return Err(PackageError::StagingRace);
        }
        let ev = digest(&serde_json::to_vec(&(s.bytes_to_sign(), out)).expect("evidence"));
        let r = PackageRecord {
            manifest: m.clone(),
            state: ProviderState::Admitted,
            provider_authority: false,
            agent_authority: false,
            admission_evidence: ev,
        };
        self.packages.insert(m.id.clone(), r.clone());
        Ok(r)
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
            let r = self.packages.get(&id).ok_or(PackageError::PackageMissing)?;
            if !r
                .manifest
                .hardware
                .iter()
                .all(|v| host.hardware.contains(v))
                || !r
                    .manifest
                    .isolation
                    .iter()
                    .all(|v| host.isolation.contains(v))
            {
                return Err(PackageError::HostRequirementMissing);
            }
            for req in &r.manifest.requires {
                let p = self
                    .packages
                    .values()
                    .find(|p| {
                        p.manifest
                            .provides
                            .iter()
                            .any(|x| x.id == req.id && x.version == req.version)
                    })
                    .ok_or(PackageError::DependencyUnresolved)?;
                pending.push(p.manifest.id.clone())
            }
        }
        Ok(ResolvedSet {
            packages: selected.into_iter().collect(),
        })
    }
    pub fn stage(&mut self, r: &ResolvedSet) -> Result<(), PackageError> {
        for id in &r.packages {
            self.packages
                .get_mut(id)
                .ok_or(PackageError::PackageMissing)?
                .state = ProviderState::Staged
        }
        Ok(())
    }
    pub fn activate(&mut self, r: &ResolvedSet) -> Result<ActivationSet, PackageError> {
        let mut entries = vec![];
        let mut evidence = vec![];
        for id in &r.packages {
            let x = self.packages.get(id).ok_or(PackageError::PackageMissing)?;
            if x.admission_evidence.is_empty() {
                return Err(PackageError::LiveVerificationRequired);
            }
            let p = &x.manifest;
            entries.push(ActivationEntry {
                package_id: p.id.clone(),
                version: p.version.clone(),
                artifact_ref: p.artifact_ref.clone(),
                configuration_digest: digest(format!("{}:{}", p.id, p.version).as_bytes()),
                state_schema: p.state_schema.clone(),
                grants: p.requested_authority.clone(),
            });
            evidence.push(x.admission_evidence.clone())
        }
        entries.sort_by(|a, b| a.package_id.cmp(&b.package_id));
        evidence.sort();
        let mut set = ActivationSet {
            id: String::new(),
            entries,
            verification_evidence: evidence,
        };
        set.id = activation_set_digest(&set);
        if let Some(c) = self.current.replace(set.clone()) {
            self.history.push(c)
        }
        for id in &r.packages {
            self.packages.get_mut(id).expect("resolved").state = ProviderState::Active
        }
        Ok(set)
    }
    pub fn qualify_and_activate(
        &mut self,
        roots: &[&str],
        host: &HostProfile,
        _: &str,
    ) -> Result<ActivationSet, PackageError> {
        let r = self.resolve(roots, host)?;
        self.stage(&r)?;
        self.activate(&r)
    }
    pub fn bind(&mut self, a: &str) -> Result<WorkBinding, PackageError> {
        let s = self.current.as_ref().ok_or(PackageError::NoActiveSet)?;
        let b = WorkBinding {
            activation_id: a.into(),
            activation_set_id: s.id.clone(),
        };
        self.bindings.insert(a.into(), b.clone());
        Ok(b)
    }
    pub fn binding(&self, a: &str) -> Option<&WorkBinding> {
        self.bindings.get(a)
    }
    pub fn drain(&mut self, p: &str) -> Result<(), PackageError> {
        self.packages
            .get_mut(p)
            .ok_or(PackageError::PackageMissing)?
            .state = ProviderState::Draining;
        Ok(())
    }
    pub fn rollback(&mut self) -> Result<ActivationSet, PackageError> {
        let p = self.history.pop().ok_or(PackageError::NoRollback)?;
        self.current = Some(p.clone());
        Ok(p)
    }
    pub fn revoke(
        &mut self,
        p: &str,
        e: &[&str],
        o: &[&str],
    ) -> Result<RecoveryPlan, PackageError> {
        self.packages
            .get_mut(p)
            .ok_or(PackageError::PackageMissing)?
            .state = ProviderState::Revoked;
        Ok(RecoveryPlan {
            unresolved_effects: e.iter().map(|v| (*v).into()).collect(),
            recovery_wakes: o.iter().map(|v| format!("recovery-wake:{v}")).collect(),
        })
    }
    pub fn migrate(&mut self, p: &str, c: MigrationContract) -> Result<String, PackageError> {
        if !self.packages.contains_key(p) {
            return Err(PackageError::PackageMissing);
        }
        if c.destructive && c.evidence.is_none() {
            return Err(PackageError::DestructiveMigrationUnproven);
        }
        Ok(c.evidence
            .unwrap_or_else(|| "evidence:non-destructive-migration".into()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeState {
    Proposed,
    Built,
    Evaluated,
    Signed,
    Staged,
    Activated,
    Confirmed,
    Rejected,
    Quarantined,
    RolledBack,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeProposal {
    pub id: String,
    pub source_digest: String,
    pub dependency_closure_digest: String,
    pub contract_version: String,
    pub tests_digest: String,
    pub threshold: u32,
    pub evaluator: String,
    pub evaluator_closure: String,
    pub target_generation: u64,
    pub rollback_generation: u64,
    pub requested_authority: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub proposal: ChangeProposal,
    pub state: ChangeState,
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError {
    Duplicate,
    Missing,
    InvalidTransition,
    EvaluatorCapture,
    SelfConfirmation,
    AuthorityWidened,
    RollbackTargetMissing,
    EvaluationFailed,
    HealthGateFailed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeJournal {
    records: BTreeMap<String, ChangeRecord>,
    protected_evaluator: String,
    protected_closure: String,
    allowed_authority: BTreeSet<String>,
    generations: BTreeSet<u64>,
}
impl ChangeJournal {
    pub fn new(e: &str, c: &str, a: &[&str], g: &[u64]) -> Self {
        Self {
            records: BTreeMap::new(),
            protected_evaluator: e.into(),
            protected_closure: c.into(),
            allowed_authority: a.iter().map(|v| (*v).into()).collect(),
            generations: g.iter().copied().collect(),
        }
    }
    pub fn propose(&mut self, p: ChangeProposal) -> Result<(), ChangeError> {
        if self.records.contains_key(&p.id) {
            return Err(ChangeError::Duplicate);
        }
        if p.contract_version != CONTRACT_VERSION
            || p.evaluator != self.protected_evaluator
            || p.evaluator_closure != self.protected_closure
        {
            return Err(ChangeError::EvaluatorCapture);
        }
        if !p.requested_authority.is_subset(&self.allowed_authority) {
            return Err(ChangeError::AuthorityWidened);
        }
        if !self.generations.contains(&p.rollback_generation)
            || p.rollback_generation == p.target_generation
        {
            return Err(ChangeError::RollbackTargetMissing);
        }
        self.records.insert(
            p.id.clone(),
            ChangeRecord {
                proposal: p,
                state: ChangeState::Proposed,
                evidence: vec![],
            },
        );
        Ok(())
    }
    fn transition(
        &mut self,
        id: &str,
        from: ChangeState,
        to: ChangeState,
        e: &str,
    ) -> Result<(), ChangeError> {
        let r = self.records.get_mut(id).ok_or(ChangeError::Missing)?;
        if r.state != from {
            return Err(ChangeError::InvalidTransition);
        }
        if e.is_empty() {
            return Err(ChangeError::EvaluationFailed);
        }
        r.state = to;
        r.evidence.push(digest(e.as_bytes()));
        Ok(())
    }
    pub fn built(&mut self, id: &str, e: &str) -> Result<(), ChangeError> {
        self.transition(id, ChangeState::Proposed, ChangeState::Built, e)
    }
    pub fn evaluated(
        &mut self,
        id: &str,
        evaluator: &str,
        closure: &str,
        score: u32,
        e: &str,
    ) -> Result<(), ChangeError> {
        let r = self.records.get(id).ok_or(ChangeError::Missing)?;
        if evaluator != self.protected_evaluator
            || closure != self.protected_closure
            || evaluator != r.proposal.evaluator
            || closure != r.proposal.evaluator_closure
        {
            return Err(ChangeError::EvaluatorCapture);
        }
        if score < r.proposal.threshold {
            return self.transition(id, ChangeState::Built, ChangeState::Rejected, e);
        }
        self.transition(id, ChangeState::Built, ChangeState::Evaluated, e)
    }
    pub fn signed(&mut self, id: &str, e: &str) -> Result<(), ChangeError> {
        self.transition(id, ChangeState::Evaluated, ChangeState::Signed, e)
    }
    pub fn staged(&mut self, id: &str, e: &str) -> Result<(), ChangeError> {
        self.transition(id, ChangeState::Signed, ChangeState::Staged, e)
    }
    pub fn activated(&mut self, id: &str, e: &str) -> Result<(), ChangeError> {
        let t = self
            .records
            .get(id)
            .ok_or(ChangeError::Missing)?
            .proposal
            .target_generation;
        self.generations.insert(t);
        self.transition(id, ChangeState::Staged, ChangeState::Activated, e)
    }
    pub fn confirmed(
        &mut self,
        id: &str,
        actor: &str,
        recovered: bool,
        healthy: bool,
        e: &str,
    ) -> Result<(), ChangeError> {
        let evaluator = self
            .records
            .get(id)
            .ok_or(ChangeError::Missing)?
            .proposal
            .evaluator
            .clone();
        if actor == evaluator {
            return Err(ChangeError::SelfConfirmation);
        }
        if !recovered || !healthy {
            return Err(ChangeError::HealthGateFailed);
        }
        self.transition(id, ChangeState::Activated, ChangeState::Confirmed, e)
    }
    pub fn quarantine(&mut self, id: &str, e: &str) -> Result<(), ChangeError> {
        let s = self.records.get(id).ok_or(ChangeError::Missing)?.state;
        if !matches!(
            s,
            ChangeState::Built
                | ChangeState::Evaluated
                | ChangeState::Signed
                | ChangeState::Staged
                | ChangeState::Activated
        ) {
            return Err(ChangeError::InvalidTransition);
        }
        let r = self.records.get_mut(id).expect("checked");
        r.state = ChangeState::Quarantined;
        r.evidence.push(digest(e.as_bytes()));
        Ok(())
    }
    pub fn rollback(&mut self, id: &str, e: &str) -> Result<u64, ChangeError> {
        let r = self.records.get_mut(id).ok_or(ChangeError::Missing)?;
        if !matches!(r.state, ChangeState::Activated | ChangeState::Quarantined) {
            return Err(ChangeError::InvalidTransition);
        }
        if !self.generations.contains(&r.proposal.rollback_generation) {
            return Err(ChangeError::RollbackTargetMissing);
        }
        r.state = ChangeState::RolledBack;
        r.evidence.push(digest(e.as_bytes()));
        Ok(r.proposal.rollback_generation)
    }
    pub fn record(&self, id: &str) -> Option<&ChangeRecord> {
        self.records.get(id)
    }
    pub fn snapshot(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("journal serializes")
    }
    pub fn restore(b: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(b)
    }
}
fn digest(v: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(v))
}
pub fn activation_set_digest<T: Serialize>(v: &T) -> String {
    format!(
        "activation-set:{}",
        digest(&serde_json::to_vec(v).expect("serializable"))
    )
}
