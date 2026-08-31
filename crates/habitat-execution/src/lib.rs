//! Execution-profile admission and default-deny backend specifications.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Runtime {
    Native,
    Wasi,
    Oci,
    MicroVm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    RuntimeUnsupported,
    CapacityExceeded,
    InvalidLimit,
}

#[derive(Clone, Debug, Serialize)]
pub struct IsolationRequest {
    pub runtime: Runtime,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub storage_mib: u64,
    pub process_limit: u32,
    pub timeout_seconds: u64,
}
impl IsolationRequest {
    pub fn new(
        runtime: Runtime,
        cpu: u32,
        memory: u64,
        storage: u64,
        processes: u32,
        timeout: u64,
    ) -> Self {
        Self {
            runtime,
            cpu_cores: cpu,
            memory_mib: memory,
            storage_mib: storage,
            process_limit: processes,
            timeout_seconds: timeout,
        }
    }
}

#[derive(Serialize)]
pub struct HardwareProfile {
    pub id: &'static str,
    pub runtimes: Vec<Runtime>,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub storage_mib: u64,
    pub process_limit: u32,
    pub timeout_seconds: u64,
}
impl HardwareProfile {
    pub fn qemu_conformance() -> Self {
        Self {
            id: "qemu-x86_64-conformance",
            runtimes: vec![Runtime::Native],
            cpu_cores: 2,
            memory_mib: 2048,
            storage_mib: 8192,
            process_limit: 64,
            timeout_seconds: 300,
        }
    }
    pub fn admit(&self, r: &IsolationRequest) -> Result<(), AdmissionError> {
        if !self.runtimes.contains(&r.runtime) {
            return Err(AdmissionError::RuntimeUnsupported);
        }
        if r.cpu_cores == 0
            || r.memory_mib == 0
            || r.storage_mib == 0
            || r.process_limit == 0
            || r.timeout_seconds == 0
        {
            return Err(AdmissionError::InvalidLimit);
        }
        if r.cpu_cores > self.cpu_cores
            || r.memory_mib > self.memory_mib
            || r.storage_mib > self.storage_mib
            || r.process_limit > self.process_limit
            || r.timeout_seconds > self.timeout_seconds
        {
            return Err(AdmissionError::CapacityExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SandboxSpec {
    pub executable: String,
    pub workspace: String,
    pub writable_paths: Vec<String>,
    pub mounts: Vec<String>,
    pub device_allowlist: Vec<String>,
    pub unshare_network: bool,
    pub clear_environment: bool,
    pub read_only_nix_store: bool,
    pub cpu_cores: u32,
    pub memory_mib: u64,
    pub storage_mib: u64,
    pub process_limit: u32,
    pub timeout_seconds: u64,
}
pub struct NativeSandbox {
    workspace: String,
}
impl NativeSandbox {
    pub fn new(workspace: &str) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }
    pub fn command(&self, executable: &str, admitted: &IsolationRequest) -> SandboxSpec {
        SandboxSpec {
            executable: executable.into(),
            workspace: self.workspace.clone(),
            writable_paths: vec![self.workspace.clone()],
            mounts: vec!["/nix/store".into()],
            device_allowlist: vec![],
            unshare_network: true,
            clear_environment: true,
            read_only_nix_store: true,
            cpu_cores: admitted.cpu_cores,
            memory_mib: admitted.memory_mib,
            storage_mib: admitted.storage_mib,
            process_limit: admitted.process_limit,
            timeout_seconds: admitted.timeout_seconds,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OciImage(String);
#[derive(Debug, PartialEq, Eq)]
pub enum ImageError {
    DigestRequired,
}
impl OciImage {
    pub fn parse(value: &str) -> Result<Self, ImageError> {
        let valid = value
            .rsplit_once("@sha256:")
            .map(|(_, d)| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false);
        if valid {
            Ok(Self(value.into()))
        } else {
            Err(ImageError::DigestRequired)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FeatureDeclaration {
    pub runtime: Runtime,
    pub status: &'static str,
    pub reason: &'static str,
}
pub fn qemu_feature_declarations() -> Vec<FeatureDeclaration> {
    vec![
        FeatureDeclaration {
            runtime: Runtime::Native,
            status: "qualified",
            reason: "live bwrap namespace qualification",
        },
        FeatureDeclaration {
            runtime: Runtime::Wasi,
            status: "absent",
            reason: "not declared by profile",
        },
        FeatureDeclaration {
            runtime: Runtime::Oci,
            status: "absent",
            reason: "not declared by profile",
        },
        FeatureDeclaration {
            runtime: Runtime::MicroVm,
            status: "absent",
            reason: "KVM not declared by profile",
        },
    ]
}

#[derive(Serialize)]
pub struct ExecutionDeclaration {
    pub profile: HardwareProfile,
    pub admitted_request: IsolationRequest,
    pub sandbox: SandboxSpec,
    pub qualification_request: IsolationRequest,
    pub qualification_sandbox: SandboxSpec,
    pub features: Vec<FeatureDeclaration>,
}

pub fn qemu_execution_declaration() -> ExecutionDeclaration {
    let profile = HardwareProfile::qemu_conformance();
    let admitted_request = IsolationRequest::new(
        Runtime::Native,
        profile.cpu_cores,
        profile.memory_mib,
        profile.storage_mib,
        profile.process_limit,
        profile.timeout_seconds,
    );
    profile
        .admit(&admitted_request)
        .expect("declared profile capacity must admit itself");
    let sandbox = NativeSandbox::new("/activation/work")
        .command("/nix/store/tool/bin/worker", &admitted_request);
    let qualification_request = IsolationRequest::new(Runtime::Native, 1, 64, 1, 8, 1);
    profile
        .admit(&qualification_request)
        .expect("qualification request must be within profile capacity");
    let qualification_sandbox = NativeSandbox::new("/activation/work")
        .command("/nix/store/tool/bin/worker", &qualification_request);
    ExecutionDeclaration {
        profile,
        admitted_request,
        sandbox,
        qualification_request,
        qualification_sandbox,
        features: qemu_feature_declarations(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderCommand {
    Execute {
        effect_id: String,
        command_id: String,
        idempotency_key: String,
        request_digest: String,
        operation: String,
        payload: serde_json::Value,
    },
    Observe {
        effect_id: String,
        request_digest: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderObservation {
    pub effect_id: String,
    pub command_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub operation: String,
    pub payload: serde_json::Value,
    pub transport_id: String,
    pub record_digest: String,
    pub outcome: String,
    pub postcondition_digest: String,
}

#[derive(Debug)]
pub enum ProviderError {
    Invalid,
    Conflict,
    NotFound,
    Storage(io::Error),
}
impl From<io::Error> for ProviderError {
    fn from(value: io::Error) -> Self {
        Self::Storage(value)
    }
}

pub struct OfflineProvider {
    root: PathBuf,
}
impl OfflineProvider {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ProviderError> {
        fs::create_dir_all(root.as_ref())?;
        fs::create_dir_all(root.as_ref().join("records"))?;
        fs::create_dir_all(root.as_ref().join("world"))?;
        File::open(root.as_ref())?.sync_all()?;
        Ok(Self {
            root: root.as_ref().to_owned(),
        })
    }
    fn path(&self, effect_id: &str) -> Result<PathBuf, ProviderError> {
        let digest = effect_id
            .strip_prefix("effect:sha256:")
            .ok_or(ProviderError::Invalid)?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProviderError::Invalid);
        }
        Ok(self.root.join("records").join(format!("{digest}.json")))
    }
    fn world_path(&self, effect_id: &str) -> Result<PathBuf, ProviderError> {
        let digest = effect_id
            .strip_prefix("effect:sha256:")
            .ok_or(ProviderError::Invalid)?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProviderError::Invalid);
        }
        Ok(self.root.join("world").join(format!("{digest}.applied")))
    }
    fn verify_postcondition(&self, value: &ProviderObservation) -> Result<(), ProviderError> {
        let path = if value.operation == "compensate" {
            let original = value.payload["compensates_effect_id"]
                .as_str()
                .ok_or(ProviderError::Invalid)?;
            self.world_path(original)?
        } else {
            self.world_path(&value.effect_id)?
        };
        let postcondition = if value.operation == "compensate" {
            if path.exists() {
                return Err(ProviderError::Invalid);
            }
            format!("absent:{}", path.file_name().and_then(|v| v.to_str()).unwrap_or(""))
        } else {
            let bytes = fs::read(path).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    ProviderError::NotFound
                } else {
                    ProviderError::Storage(error)
                }
            })?;
            format!("present:sha256:{:x}", Sha256::digest(bytes))
        };
        if format!("sha256:{:x}", Sha256::digest(postcondition.as_bytes()))
            != value.postcondition_digest
        {
            return Err(ProviderError::Invalid);
        }
        Ok(())
    }
    fn read(&self, path: &Path) -> Result<ProviderObservation, ProviderError> {
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ProviderError::NotFound
            } else {
                ProviderError::Storage(e)
            }
        })?;
        let value: ProviderObservation =
            serde_json::from_slice(&bytes).map_err(|_| ProviderError::Invalid)?;
        let claimed = value.record_digest.clone();
        let mut unsigned = value.clone();
        unsigned.record_digest.clear();
        let actual = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&unsigned).map_err(|_| ProviderError::Invalid)?)
        );
        if claimed != actual {
            return Err(ProviderError::Invalid);
        }
        self.verify_postcondition(&value)?;
        Ok(value)
    }
    pub fn execute(
        &self,
        command: &ProviderCommand,
        fault: Option<&str>,
    ) -> Result<ProviderObservation, ProviderError> {
        let ProviderCommand::Execute {
            effect_id,
            command_id,
            idempotency_key,
            request_digest,
            operation,
            payload,
        } = command
        else {
            return Err(ProviderError::Invalid);
        };
        if !request_digest.starts_with("sha256:")
            || !payload.is_object()
            || operation.is_empty()
            || command_id.is_empty()
            || idempotency_key.is_empty()
        {
            return Err(ProviderError::Invalid);
        }
        let path = self.path(effect_id)?;
        if path.exists() {
            let prior = self.read(&path)?;
            return if prior.request_digest == request_digest.as_str()
                && prior.command_id == command_id.as_str()
                && prior.idempotency_key == idempotency_key.as_str()
                && prior.operation == operation.as_str()
                && prior.payload == *payload
            {
                Ok(prior)
            } else {
                Err(ProviderError::Conflict)
            };
        }
        let transport_id = format!(
            "provider://offline/sha256/{:x}",
            Sha256::digest(format!("{effect_id}\0{idempotency_key}").as_bytes())
        );
        let mut observation = ProviderObservation {
            effect_id: effect_id.into(),
            command_id: command_id.into(),
            idempotency_key: idempotency_key.into(),
            request_digest: request_digest.into(),
            operation: operation.into(),
            payload: payload.clone(),
            transport_id,
            record_digest: String::new(),
            outcome: "SUCCEEDED".into(),
            postcondition_digest: String::new(),
        };
        let world_path = if operation == "compensate" {
            let original = payload["compensates_effect_id"]
                .as_str()
                .ok_or(ProviderError::Invalid)?;
            self.world_path(original)?
        } else {
            self.world_path(effect_id)?
        };
        let postcondition = if operation == "compensate" {
            format!("absent:{}", world_path.file_name().and_then(|v| v.to_str()).unwrap_or(""))
        } else {
            let applied = serde_json::to_vec(&serde_json::json!({
                "effect_id":effect_id,
                "operation":operation,
                "payload":payload,
                "request_digest":request_digest,
            }))
            .map_err(|_| ProviderError::Invalid)?;
            format!("present:sha256:{:x}", Sha256::digest(applied))
        };
        observation.postcondition_digest =
            format!("sha256:{:x}", Sha256::digest(postcondition.as_bytes()));
        observation.record_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&observation).map_err(|_| ProviderError::Invalid)?)
        );
        let bytes = serde_json::to_vec(&observation).map_err(|_| ProviderError::Invalid)?;
        let temporary = self.root.join(format!(
            ".pending-{}-{}",
            std::process::id(),
            &observation.record_digest[7..23]
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if fault == Some("before-commit") {
            return Err(ProviderError::Storage(io::Error::other(
                "injected before commit",
            )));
        }
        if operation == "compensate" {
            match fs::remove_file(&world_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(ProviderError::Storage(error)),
            }
        } else if !world_path.exists() {
            let applied = serde_json::to_vec(&serde_json::json!({
                "effect_id":effect_id,
                "operation":operation,
                "payload":payload,
                "request_digest":request_digest,
            }))
            .map_err(|_| ProviderError::Invalid)?;
            let mut world = OpenOptions::new().create_new(true).write(true).open(&world_path)?;
            world.write_all(&applied)?;
            world.sync_all()?;
        }
        File::open(self.root.join("world"))?.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(self.root.join("records"))?.sync_all()?;
        if fault == Some("after-commit") {
            return Err(ProviderError::Storage(io::Error::other(
                "injected after commit",
            )));
        }
        self.read(&path)
    }
    pub fn observe(
        &self,
        effect_id: &str,
        request_digest: &str,
    ) -> Result<ProviderObservation, ProviderError> {
        let value = self.read(&self.path(effect_id)?)?;
        if value.request_digest != request_digest {
            return Err(ProviderError::Conflict);
        }
        Ok(value)
    }
}
