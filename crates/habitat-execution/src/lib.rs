//! Execution-profile admission and default-deny backend specifications.
use serde::{Deserialize, Serialize};

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
    ExecutionDeclaration {
        profile,
        admitted_request,
        sandbox,
        features: qemu_feature_declarations(),
    }
}
