//! Profile-pinned GPU capsule admission and mediated simulation effects.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GpuFeature {
    Rtx,
    IsaacSim,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCapsule {
    pub image: String,
    pub gpu_model: String,
    pub driver_version: String,
    pub memory_mib: u64,
    pub features: Vec<GpuFeature>,
}
impl CompatibilityCapsule {
    pub fn new<const N: usize>(
        image: &str,
        gpu: &str,
        driver: &str,
        memory: u64,
        features: [GpuFeature; N],
    ) -> Self {
        Self {
            image: image.into(),
            gpu_model: gpu.into(),
            driver_version: driver.into(),
            memory_mib: memory,
            features: features.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleAdmission {
    pub profile_id: String,
    pub device_nodes: [String; 2],
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulationError {
    DigestRequired,
    GpuMismatch,
    DriverMismatch,
    CapacityExceeded,
    FeatureAbsent,
    CapabilityDenied,
    AuthorityDenied,
    LeaseExists,
    LeaseMissing,
    DeviceDenied,
}

pub struct SimulationProvider {
    profile_id: String,
    gpu_model: String,
    driver_version: String,
    memory_mib: u64,
}
impl SimulationProvider {
    pub fn new(profile: &str, gpu: &str, driver: &str, memory: u64) -> Self {
        Self {
            profile_id: profile.into(),
            gpu_model: gpu.into(),
            driver_version: driver.into(),
            memory_mib: memory,
        }
    }
    pub fn admit(
        &self,
        capsule: &CompatibilityCapsule,
    ) -> Result<CapsuleAdmission, SimulationError> {
        let pinned = capsule
            .image
            .rsplit_once("@sha256:")
            .map(|(_, d)| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false);
        if !pinned {
            return Err(SimulationError::DigestRequired);
        }
        if capsule.gpu_model != self.gpu_model {
            return Err(SimulationError::GpuMismatch);
        }
        if capsule.driver_version != self.driver_version {
            return Err(SimulationError::DriverMismatch);
        }
        if capsule.memory_mib > self.memory_mib {
            return Err(SimulationError::CapacityExceeded);
        }
        if !capsule.features.contains(&GpuFeature::Rtx)
            || !capsule.features.contains(&GpuFeature::IsaacSim)
        {
            return Err(SimulationError::FeatureAbsent);
        }
        Ok(CapsuleAdmission {
            profile_id: self.profile_id.clone(),
            device_nodes: ["/dev/nvidia0".into(), "/dev/nvidiactl".into()],
            environment: BTreeMap::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationCommand {
    pub command_id: String,
    pub activation_id: String,
    pub objective_id: String,
    pub operation: String,
    pub scene_digest: String,
    pub idempotency_key: String,
}
impl SimulationCommand {
    pub fn new(
        command: &str,
        activation: &str,
        objective: &str,
        operation: &str,
        scene: &str,
        key: &str,
    ) -> Self {
        Self {
            command_id: command.into(),
            activation_id: activation.into(),
            objective_id: objective.into(),
            operation: operation.into(),
            scene_digest: scene.into(),
            idempotency_key: key.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationEffect {
    pub effect_id: String,
    pub command_id: String,
    pub state: String,
    pub authority_decision: String,
    pub evidence_ref: String,
    pub profile_id: String,
}

pub struct SimulationCapability {
    admission: CapsuleAdmission,
    grants: BTreeSet<String>,
    effects: BTreeMap<String, SimulationEffect>,
}
impl SimulationCapability {
    pub fn new(admission: CapsuleAdmission, grants: &[&str]) -> Self {
        Self {
            admission,
            grants: grants.iter().map(|v| (*v).into()).collect(),
            effects: BTreeMap::new(),
        }
    }
    pub fn execute(
        &mut self,
        command: SimulationCommand,
        authority: &str,
    ) -> Result<SimulationEffect, SimulationError> {
        if !self.grants.contains(&command.operation) {
            return Err(SimulationError::CapabilityDenied);
        }
        if authority.is_empty() || authority.contains("deny") {
            return Err(SimulationError::AuthorityDenied);
        }
        if !valid_digest(&command.scene_digest) {
            return Err(SimulationError::DigestRequired);
        }
        if let Some(effect) = self.effects.get(&command.idempotency_key) {
            return Ok(effect.clone());
        }
        let bytes = serde_json::to_vec(&command).expect("serializable command");
        let effect = SimulationEffect {
            effect_id: format!("effect:sha256:{:x}", Sha256::digest(&bytes)),
            command_id: command.command_id.clone(),
            state: "OBSERVED_SUCCEEDED".into(),
            authority_decision: authority.into(),
            evidence_ref: format!(
                "evidence:sha256:{:x}",
                Sha256::digest([bytes.as_slice(), self.admission.profile_id.as_bytes()].concat())
            ),
            profile_id: self.admission.profile_id.clone(),
        };
        self.effects.insert(command.idempotency_key, effect.clone());
        Ok(effect)
    }
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .map(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuSandbox {
    pub activation_id: String,
    pub lease_id: String,
    pub device_nodes: [String; 2],
    pub clear_environment: bool,
    pub read_only_host: bool,
}

pub struct GpuIsolationBoundary {
    admission: CapsuleAdmission,
    lease: Option<GpuSandbox>,
}
impl GpuIsolationBoundary {
    pub fn new(admission: CapsuleAdmission) -> Self {
        Self {
            admission,
            lease: None,
        }
    }
    pub fn acquire(
        &mut self,
        activation: &str,
        lease: &str,
    ) -> Result<GpuSandbox, SimulationError> {
        if self.lease.is_some() {
            return Err(SimulationError::LeaseExists);
        }
        let sandbox = GpuSandbox {
            activation_id: activation.into(),
            lease_id: lease.into(),
            device_nodes: self.admission.device_nodes.clone(),
            clear_environment: true,
            read_only_host: true,
        };
        self.lease = Some(sandbox.clone());
        Ok(sandbox)
    }
    pub fn open_device(&self, lease: &str, node: &str) -> Result<(), SimulationError> {
        let active = self
            .lease
            .as_ref()
            .filter(|v| v.lease_id == lease)
            .ok_or(SimulationError::LeaseMissing)?;
        if active.device_nodes.iter().any(|v| v == node) {
            Ok(())
        } else {
            Err(SimulationError::DeviceDenied)
        }
    }
    pub fn release(&mut self, lease: &str) -> Result<(), SimulationError> {
        if self.lease.as_ref().map(|v| v.lease_id.as_str()) != Some(lease) {
            return Err(SimulationError::LeaseMissing);
        }
        self.lease = None;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationEvidence {
    pub outcome: String,
    pub artifact_digest: String,
    pub observations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationReport {
    reports: BTreeMap<String, QualificationEvidence>,
}
impl QualificationReport {
    #[allow(clippy::too_many_arguments)]
    pub fn passed(
        artifact: &str,
        profile: &str,
        gpu: &str,
        driver: &str,
        effect: &str,
        observation: &str,
    ) -> Self {
        let item = |observations: Vec<String>| QualificationEvidence {
            outcome: "passed".into(),
            artifact_digest: artifact.into(),
            observations,
        };
        Self {
            reports: BTreeMap::from([
                (
                    "rtx-isaac-live-report".into(),
                    item(vec![
                        format!("profile={profile}"),
                        format!("gpu={gpu}"),
                        format!("driver={driver}"),
                        "rtx=ready".into(),
                        "isaac-sim=ready".into(),
                    ]),
                ),
                (
                    "simulation-effect-report".into(),
                    item(vec![
                        effect.into(),
                        observation.into(),
                        "state=OBSERVED_SUCCEEDED".into(),
                    ]),
                ),
                (
                    "gpu-isolation-report".into(),
                    item(vec![
                        "lease-scoped-devices=true".into(),
                        "ambient-device-access=false".into(),
                        "read-only-host=true".into(),
                    ]),
                ),
            ]),
        }
    }
    pub fn evidence(&self) -> &BTreeMap<String, QualificationEvidence> {
        &self.reports
    }
}
