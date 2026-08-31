//! Versioned Habitat Agent ABI transport and durable command ledger.

use habitat_uds::{connect_with_timeouts, FrameConfig, TransportError};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("nix_ai.agent.v2");
}

pub const ABI_VERSION: &str = "2.0";
pub const MAX_COMMAND_BYTES: usize = 1024 * 1024;
pub const CONTRACT_VERSION: &str = "2.0.1";

#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    pub expected_peer_uid: u32,
    pub activation_id: String,
    pub activation_credential: String,
    pub minimum_lease_fence: u64,
    pub system_generation_id: String,
    pub capability_activation_set_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    Invalid,
    UnsupportedMajor,
}

pub fn negotiate_version(requested: &str) -> Result<&'static str, VersionError> {
    let (major, minor) = requested.split_once('.').ok_or(VersionError::Invalid)?;
    major.parse::<u32>().map_err(|_| VersionError::Invalid)?;
    minor.parse::<u32>().map_err(|_| VersionError::Invalid)?;
    if major != "2" {
        return Err(VersionError::UnsupportedMajor);
    }
    Ok(ABI_VERSION)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    Unavailable(String),
    Corrupt(String),
    DigestMismatch(Box<proto::CommandResult>),
}

pub trait CommandLedger: Send + Sync + std::fmt::Debug {
    fn commit(
        &self,
        activation_id: &str,
        command_id: &str,
        request_digest: &str,
        proposed: &proto::CommandResult,
    ) -> Result<proto::CommandResult, LedgerError>;

    fn get(
        &self,
        activation_id: &str,
        command_id: &str,
    ) -> Result<Option<proto::CommandResult>, LedgerError>;
}

/// Fail-closed client for the PostgreSQL-owned habitat state service.
///
/// Each operation uses a fresh authenticated-by-filesystem Unix connection. The
/// service performs the compare-and-insert in one PostgreSQL transaction; this
/// process deliberately retains no replay cache that could survive a state
/// service outage and permit semantic execution.
#[derive(Clone, Debug)]
pub struct StateServiceLedger {
    socket: Arc<std::path::PathBuf>,
}

impl StateServiceLedger {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: Arc::new(socket.as_ref().to_owned()),
        }
    }

    fn request(&self, request: serde_json::Value) -> Result<serde_json::Value, LedgerError> {
        let frames = FrameConfig::new(2 * MAX_COMMAND_BYTES)
            .map_err(|error| LedgerError::Corrupt(error.to_string()))?;
        let mut transport = connect_with_timeouts::<serde_json::Value, serde_json::Value>(
            self.socket.as_path(),
            frames,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .map_err(ledger_transport_error)?;
        transport
            .send_request(&request)
            .map_err(ledger_transport_error)?;
        let response = transport
            .receive_response()
            .map_err(ledger_transport_error)?;
        match response.get("status").and_then(|value| value.as_str()) {
            Some("ok") => Ok(response),
            Some("digest_mismatch") => {
                let result =
                    serde_json::from_value(response.get("result").cloned().ok_or_else(|| {
                        LedgerError::Corrupt("digest mismatch omitted committed result".into())
                    })?)
                    .map_err(|error| LedgerError::Corrupt(error.to_string()))?;
                Err(LedgerError::DigestMismatch(Box::new(result)))
            }
            Some("corrupt") => Err(LedgerError::Corrupt(
                response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ledger corrupt")
                    .into(),
            )),
            Some("unavailable") => Err(LedgerError::Unavailable(
                response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ledger unavailable")
                    .into(),
            )),
            _ => Err(LedgerError::Corrupt(
                "invalid state-service response".into(),
            )),
        }
    }
}

fn ledger_transport_error(error: TransportError) -> LedgerError {
    if matches!(error, TransportError::Io(_)) {
        LedgerError::Unavailable(error.to_string())
    } else {
        LedgerError::Corrupt(error.to_string())
    }
}

impl CommandLedger for StateServiceLedger {
    fn commit(
        &self,
        activation_id: &str,
        command_id: &str,
        request_digest: &str,
        proposed: &proto::CommandResult,
    ) -> Result<proto::CommandResult, LedgerError> {
        let evidence = self.request(serde_json::json!({
            "operation":"evidence_put",
            "command_id":format!("evidence:{activation_id}:{command_id}"),
            "envelope":{
                "schema_version":"1",
                "producer":"service:abi",
                "subject":command_id,
                "operation":"command.commit",
                "source":request_digest,
                "payload":{
                    "disposition":proposed.state,
                    "activation_id":activation_id,
                    "command_id":command_id,
                    "request_digest":request_digest,
                }
            }
        }))?;
        let evidence_ref = evidence
            .get("result")
            .and_then(|result| result.get("evidence_ref"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| LedgerError::Corrupt("evidence response omitted reference".into()))?;
        let mut committed = proposed.clone();
        committed.durable_record_id = evidence_ref.into();
        if !committed
            .evidence_refs
            .iter()
            .any(|reference| reference == evidence_ref)
        {
            committed.evidence_refs.push(evidence_ref.into());
        }
        let response = self.request(serde_json::json!({"operation":"commit_command",
            "activation_id":activation_id,"command_id":command_id,
            "request_digest":request_digest,"result":committed}))?;
        serde_json::from_value(
            response
                .get("result")
                .cloned()
                .ok_or_else(|| LedgerError::Corrupt("commit response omitted result".into()))?,
        )
        .map_err(|error| LedgerError::Corrupt(error.to_string()))
    }

    fn get(
        &self,
        activation_id: &str,
        command_id: &str,
    ) -> Result<Option<proto::CommandResult>, LedgerError> {
        let response = self.request(serde_json::json!({"operation":"get_command",
            "activation_id":activation_id,"command_id":command_id}))?;
        match response.get("result") {
            Some(value) if !value.is_null() => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|error| LedgerError::Corrupt(error.to_string())),
            _ => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct AgentAbi {
    ledger: Arc<dyn CommandLedger>,
    policy: SecurityPolicy,
}

impl AgentAbi {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let credential = std::env::var("HABITAT_ABI_ACTIVATION_CREDENTIAL").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "HABITAT_ABI_ACTIVATION_CREDENTIAL is required",
            )
        })?;
        let peer_uid = std::env::var("HABITAT_ABI_PEER_UID")
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "HABITAT_ABI_PEER_UID is required",
                )
            })?
            .parse()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HABITAT_ABI_PEER_UID must be a u32",
                )
            })?;
        Self::open_with_security(
            path,
            SecurityPolicy {
                expected_peer_uid: peer_uid,
                activation_id: std::env::var("HABITAT_ABI_ACTIVATION_ID")
                    .unwrap_or_else(|_| "activation:01".into()),
                activation_credential: credential,
                minimum_lease_fence: std::env::var("HABITAT_ABI_LEASE_FENCE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1),
                system_generation_id: std::env::var("HABITAT_ABI_SYSTEM_GENERATION")
                    .unwrap_or_else(|_| "generation:01".into()),
                capability_activation_set_id: std::env::var("HABITAT_ABI_CAPABILITY_SET")
                    .unwrap_or_else(|_| "capability-set:01".into()),
            },
        )
    }

    pub fn open_with_security(
        path: impl AsRef<Path>,
        policy: SecurityPolicy,
    ) -> std::io::Result<Self> {
        if policy.activation_id.is_empty()
            || policy.activation_credential.is_empty()
            || policy.system_generation_id.is_empty()
            || policy.capability_activation_set_id.is_empty()
            || policy.minimum_lease_fence == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "security policy identifiers, credential, and lease fence are required",
            ));
        }
        Ok(Self {
            ledger: Arc::new(StateServiceLedger::new(path)),
            policy,
        })
    }

    pub fn with_repository(
        ledger: Arc<dyn CommandLedger>,
        policy: SecurityPolicy,
    ) -> std::io::Result<Self> {
        if policy.activation_id.is_empty()
            || policy.activation_credential.is_empty()
            || policy.system_generation_id.is_empty()
            || policy.capability_activation_set_id.is_empty()
            || policy.minimum_lease_fence == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "security policy identifiers, credential, and lease fence are required",
            ));
        }
        Ok(Self { ledger, policy })
    }

    fn version<T>(request: &Request<T>) -> Result<(), Status> {
        let requested = request
            .metadata()
            .get("x-habitat-abi-version")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                structured_status(
                    "UNSUPPORTED_ABI_VERSION",
                    "missing ABI version",
                    false,
                    "UNCHANGED",
                    "send x-habitat-abi-version=2.x",
                )
            })?;
        negotiate_version(requested).map_err(|_| {
            structured_status(
                "UNSUPPORTED_ABI_VERSION",
                "unsupported ABI version",
                false,
                "UNCHANGED",
                "use a supported 2.x client",
            )
        })?;
        Ok(())
    }

    fn authenticate<T>(
        &self,
        request: &Request<T>,
        binding: Option<&proto::RequestBinding>,
        activation: &str,
        command: Option<&str>,
    ) -> Result<u32, Status> {
        let uid = request
            .extensions()
            .get::<UdsConnectInfo>()
            .and_then(|info| info.peer_cred.as_ref())
            .map(|cred| cred.uid())
            .ok_or_else(|| {
                structured_status(
                    "IDENTITY_INVALID",
                    "Unix peer credentials unavailable",
                    false,
                    "UNCHANGED",
                    "connect through the protected Agent ABI Unix socket",
                )
            })?;
        if uid != self.policy.expected_peer_uid {
            return Err(unauthorized_status(
                "PEER_IDENTITY_MISMATCH",
                "Unix peer is not authorized for this activation",
            ));
        }
        let binding = binding
            .ok_or_else(|| invalid_status("MISSING_BINDING", "request binding is required"))?;
        let required = [
            ("schema_version", binding.schema_version.as_str()),
            ("command_id", binding.command_id.as_str()),
            ("machine_id", binding.machine_id.as_str()),
            ("agent_id", binding.agent_id.as_str()),
            ("objective_id", binding.objective_id.as_str()),
            ("activation_id", binding.activation_id.as_str()),
            (
                "system_generation_id",
                binding.system_generation_id.as_str(),
            ),
            (
                "capability_activation_set_id",
                binding.capability_activation_set_id.as_str(),
            ),
            ("trace_id", binding.trace_id.as_str()),
            (
                "activation_credential",
                binding.activation_credential.as_str(),
            ),
        ];
        if let Some((name, _)) = required.iter().find(|(_, value)| value.is_empty()) {
            return Err(invalid_status(
                "MISSING_BINDING",
                &format!("{name} is required"),
            ));
        }
        if binding.schema_version != CONTRACT_VERSION {
            return Err(invalid_status(
                "SCHEMA_VERSION_MISMATCH",
                "binding must use V2.0.1",
            ));
        }
        if activation != self.policy.activation_id || binding.activation_id != activation {
            return Err(unauthorized_status(
                "ACTIVATION_ID_MISMATCH",
                "activation binding does not match",
            ));
        }
        if binding.activation_credential != self.policy.activation_credential {
            return Err(unauthorized_status(
                "ACTIVATION_CREDENTIAL_INVALID",
                "activation credential is invalid",
            ));
        }
        if binding.lease_fence < self.policy.minimum_lease_fence {
            return Err(invalid_status("STALE_LEASE_FENCE", "lease fence is stale"));
        }
        if binding.system_generation_id != self.policy.system_generation_id
            || binding.capability_activation_set_id != self.policy.capability_activation_set_id
        {
            return Err(unauthorized_status(
                "ACTIVATION_SCOPE_MISMATCH",
                "generation or capability set does not match",
            ));
        }
        if let Some(command) = command {
            if binding.command_id != command {
                return Err(invalid_status(
                    "COMMAND_ID_MISMATCH",
                    "command binding does not match",
                ));
            }
        }
        let deadline = binding
            .deadline
            .as_ref()
            .ok_or_else(|| invalid_status("MISSING_BINDING", "deadline is required"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock unavailable"))?;
        if !(0..1_000_000_000).contains(&deadline.nanos)
            || deadline.seconds < 0
            || (deadline.seconds as u64, deadline.nanos)
                <= (now.as_secs(), now.subsec_nanos() as i32)
        {
            return Err(invalid_status(
                "DEADLINE_EXPIRED",
                "request deadline has expired",
            ));
        }
        Ok(uid)
    }

    fn commit(
        &self,
        activation: &str,
        command: &str,
        fingerprint: String,
        state: &str,
    ) -> Result<proto::CommandResult, Status> {
        if activation.is_empty() || command.is_empty() {
            return Err(structured_status(
                "INVALID_REQUEST",
                "typed identifiers are required",
                false,
                "UNCHANGED",
                "provide activation_id and command_id",
            ));
        }
        let result = proto::CommandResult {
            command_id: command.into(),
            committed: true,
            durable_record_id: format!("command:sha256:{fingerprint}"),
            state: state.into(),
            error: None,
            evidence_refs: vec![],
        };
        self.ledger
            .commit(activation, command, &fingerprint, &result)
            .map_err(ledger_status)
    }
}

fn ledger_status(error: LedgerError) -> Status {
    match error {
        LedgerError::Unavailable(_) => internal_status(
            "COMMAND_LEDGER_UNAVAILABLE",
            "authoritative command ledger is unavailable",
            "UNKNOWN",
            "restore the state service before retrying",
        ),
        LedgerError::Corrupt(_) => internal_status(
            "COMMAND_LEDGER_CORRUPT",
            "authoritative command ledger returned corrupt data",
            "UNKNOWN",
            "repair the ledger under recovery authority",
        ),
        LedgerError::DigestMismatch(result) => internal_status(
            "REPLAY_DIGEST_MISMATCH",
            "idempotency key reused for another command",
            &result.state,
            "fetch the committed command result",
        ),
    }
}

fn fingerprint<T: prost::Message>(message: &T) -> Result<String, Status> {
    if message.encoded_len() > MAX_COMMAND_BYTES {
        return Err(structured_status(
            "RESOURCE_EXHAUSTED",
            "command exceeds payload limit",
            false,
            "UNCHANGED",
            "reduce the disposition payload",
        ));
    }
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(message.encode_to_vec())
    ))
}

fn structured_status(
    code: &str,
    message: &str,
    retryable: bool,
    state: &str,
    action: &str,
) -> Status {
    let detail = serde_json::json!({"code":code,"message":message,"retryable":retryable,
        "authority_impact":"NONE","current_durable_state":state,"safe_next_action":action});
    Status::failed_precondition(detail.to_string())
}

fn internal_status(code: &str, message: &str, state: &str, action: &str) -> Status {
    let detail = serde_json::json!({"code":code,"message":message,"retryable":false,
        "authority_impact":"NONE","current_durable_state":state,"safe_next_action":action});
    Status::internal(detail.to_string())
}

fn invalid_status(code: &str, message: &str) -> Status {
    let detail = serde_json::json!({"code":code,"message":message,"retryable":false,
        "authority_impact":"NONE","current_durable_state":"UNCHANGED","safe_next_action":"submit a valid, current activation binding"});
    Status::invalid_argument(detail.to_string())
}

fn unauthorized_status(code: &str, message: &str) -> Status {
    let detail = serde_json::json!({"code":code,"message":message,"retryable":false,
        "authority_impact":"NONE","current_durable_state":"UNCHANGED","safe_next_action":"obtain a fresh activation from the trusted scheduler"});
    Status::unauthenticated(detail.to_string())
}

#[tonic::async_trait]
impl proto::agent_runtime_server::AgentRuntime for AgentAbi {
    async fn get_activation(
        &self,
        request: Request<proto::GetActivationRequest>,
    ) -> Result<Response<proto::ActivationEnvelope>, Status> {
        Self::version(&request)?;
        let body = request.get_ref();
        let uid = self.authenticate(&request, body.binding.as_ref(), &body.activation_id, None)?;
        if body.activation_credential != self.policy.activation_credential {
            return Err(unauthorized_status(
                "ACTIVATION_CREDENTIAL_INVALID",
                "activation credential is invalid",
            ));
        }
        let id = request.into_inner().activation_id;
        if id.is_empty() {
            return Err(Status::invalid_argument("activation_id required"));
        }
        let mut response = Response::new(proto::ActivationEnvelope {
            abi_version: ABI_VERSION.into(),
            activation_id: id,
            ..Default::default()
        });
        response
            .metadata_mut()
            .insert("x-habitat-peer-uid", uid.to_string().parse().unwrap());
        Ok(response)
    }

    async fn submit_disposition(
        &self,
        request: Request<proto::SubmitDispositionRequest>,
    ) -> Result<Response<proto::CommandResult>, Status> {
        Self::version(&request)?;
        let body = request.get_ref();
        self.authenticate(
            &request,
            body.binding.as_ref(),
            &body.activation_id,
            Some(&body.command_id),
        )?;
        let command = request.into_inner();
        if command.kind == 0 {
            return Err(structured_status(
                "INVALID_REQUEST",
                "a structured disposition kind is required",
                false,
                "UNCHANGED",
                "submit one declared DispositionKind",
            ));
        }
        let digest = fingerprint(&command)?;
        Ok(Response::new(self.commit(
            &command.activation_id,
            &command.command_id,
            digest,
            "DISPOSITION_COMMITTED",
        )?))
    }

    async fn get_command_result(
        &self,
        request: Request<proto::GetCommandResultRequest>,
    ) -> Result<Response<proto::CommandResult>, Status> {
        Self::version(&request)?;
        let body = request.get_ref();
        self.authenticate(
            &request,
            body.binding.as_ref(),
            &body.activation_id,
            Some(&body.command_id),
        )?;
        let query = request.into_inner();
        self.ledger
            .get(&query.activation_id, &query.command_id)
            .map_err(ledger_status)?
            .map(Response::new)
            .ok_or_else(|| Status::not_found("command result not found"))
    }

    async fn cancel_activation(
        &self,
        request: Request<proto::CancelActivationRequest>,
    ) -> Result<Response<proto::CommandResult>, Status> {
        Self::version(&request)?;
        let body = request.get_ref();
        self.authenticate(
            &request,
            body.binding.as_ref(),
            &body.activation_id,
            Some(&body.command_id),
        )?;
        let command = request.into_inner();
        let digest = fingerprint(&command)?;
        Ok(Response::new(self.commit(
            &command.activation_id,
            &command.command_id,
            digest,
            "CANCELLED",
        )?))
    }
}
