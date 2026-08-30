//! Optional harness adapters over the provider-neutral Habitat semantic ABI.
use habitat_models::{
    ActivationEnvelope, CandidateOutput, Disposition, DispositionValidator, ModelError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableIdentity {
    pub agent_id: String,
    pub objective_ids: Vec<String>,
    pub activation_id: String,
    pub grant_ids: Vec<String>,
    pub activation_set_id: String,
    pub context_bundle_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreparedActivation {
    pub envelope: ActivationEnvelope,
    pub identity: DurableIdentity,
    pub adapter_artifact: String,
    pub adapter_configuration_digest: String,
}
pub struct HarnessAdapter;
impl HarnessAdapter {
    pub fn prepare(
        envelope: &ActivationEnvelope,
        activation_set: &str,
        grants: &[&str],
    ) -> PreparedActivation {
        PreparedActivation{envelope:envelope.clone(),identity:DurableIdentity{agent_id:envelope.agent_id.clone(),
        objective_ids:envelope.objective_ids.clone(),activation_id:envelope.activation_id.clone(),
        grant_ids:grants.iter().map(|v|(*v).into()).collect(),activation_set_id:activation_set.into(),
        context_bundle_id:envelope.context_bundle_id.clone()},
        adapter_artifact:"harness-adapter@sha256:0000000000000000000000000000000000000000000000000000000000000011".into(),
        adapter_configuration_digest:"sha256:1111111111111111111111111111111111111111111111111111111111111111".into()}
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HarnessOutput {
    pub candidate: CandidateOutput,
    pub identity: DurableIdentity,
    pub session_id: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum HarnessError {
    MissingStructuredDisposition,
    MalformedDisposition,
    Model(ModelError),
    TypedCheckpointRequired,
    LeaseExpired,
    InvalidCancellation,
    BackendDivergence,
}
impl From<ModelError> for HarnessError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub struct CodexAdapter;
impl CodexAdapter {
    pub fn translate(
        prepared: &PreparedActivation,
        event: &Value,
    ) -> Result<HarnessOutput, HarnessError> {
        if event.get("type").and_then(Value::as_str) != Some("habitat.disposition") {
            return Err(HarnessError::MissingStructuredDisposition);
        }
        translate(
            prepared,
            event.get("payload"),
            event.get("session_id"),
            "codex-cli",
        )
    }
}
pub struct ClaudeCodeAdapter;
impl ClaudeCodeAdapter {
    pub fn translate(
        prepared: &PreparedActivation,
        event: &Value,
    ) -> Result<HarnessOutput, HarnessError> {
        if event.get("type").and_then(Value::as_str) != Some("result") {
            return Err(HarnessError::MissingStructuredDisposition);
        }
        translate(
            prepared,
            event.get("structured_output"),
            event.get("session_id"),
            "claude-code",
        )
    }
}
fn translate(
    prepared: &PreparedActivation,
    payload: Option<&Value>,
    session: Option<&Value>,
    provider: &str,
) -> Result<HarnessOutput, HarnessError> {
    let disposition: Disposition = serde_json::from_value(
        payload
            .cloned()
            .ok_or(HarnessError::MissingStructuredDisposition)?,
    )
    .map_err(|_| HarnessError::MalformedDisposition)?;
    let session_id = session
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(HarnessError::MalformedDisposition)?;
    let candidate = CandidateOutput {
        disposition,
        provider_request_id: session_id.into(),
        provider: provider.into(),
        model: "harness-managed".into(),
        input_tokens: 0,
        output_tokens: 0,
    };
    let candidate = DispositionValidator::new(&prepared.envelope).validate(candidate)?;
    Ok(HarnessOutput {
        candidate,
        identity: prepared.identity.clone(),
        session_id: session_id.into(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeStatus {
    Running,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeOutcome {
    AwaitingDisposition,
    DispositionAccepted,
}
pub struct HarnessRuntime {
    prepared: PreparedActivation,
    status: RuntimeStatus,
}
impl HarnessRuntime {
    pub fn new(prepared: PreparedActivation) -> Self {
        Self {
            prepared,
            status: RuntimeStatus::Running,
        }
    }
    pub fn process_exit(&self, _code: i32, _event: Option<&Value>) -> RuntimeOutcome {
        RuntimeOutcome::AwaitingDisposition
    }
    pub fn status(&self) -> RuntimeStatus {
        self.status
    }
    pub fn check_deadline(&self, now: u64) -> Result<(), HarnessError> {
        if now > self.prepared.envelope.deadline {
            Err(HarnessError::LeaseExpired)
        } else {
            Ok(())
        }
    }
    pub fn cancel(&mut self, command: &str, reason: &str) -> Result<(), HarnessError> {
        if command.is_empty() || reason.is_empty() {
            return Err(HarnessError::InvalidCancellation);
        }
        self.status = RuntimeStatus::Cancelled;
        Ok(())
    }
}

#[derive(Default)]
pub struct HarnessCheckpoint {
    records: Vec<Disposition>,
}
impl HarnessCheckpoint {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn commit(&mut self, candidate: CandidateOutput) -> Result<(), HarnessError> {
        if candidate.disposition.kind != habitat_models::DispositionKind::Checkpoint {
            return Err(HarnessError::TypedCheckpointRequired);
        }
        self.records.push(candidate.disposition);
        Ok(())
    }
    pub fn records(&self) -> &[Disposition] {
        &self.records
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendState {
    pub identity: DurableIdentity,
    pub effect_history: Vec<String>,
    pub completion_contract: String,
}
pub struct BackendConformance;
impl BackendConformance {
    pub fn compare(
        direct: &BackendState,
        codex: &BackendState,
        claude: &BackendState,
    ) -> Result<(), HarnessError> {
        if direct == codex && codex == claude {
            Ok(())
        } else {
            Err(HarnessError::BackendDivergence)
        }
    }
}
