//! Versioned Habitat Agent ABI transport and durable command ledger.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
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

#[derive(Clone, Serialize, Deserialize)]
struct LedgerEntry {
    fingerprint: String,
    result: proto::CommandResult,
}

#[derive(Clone)]
pub struct AgentAbi {
    ledger_path: PathBuf,
    entries: Arc<Mutex<HashMap<String, LedgerEntry>>>,
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
        let ledger_path = path.as_ref().to_owned();
        let entries = if ledger_path.exists() {
            serde_json::from_slice(&fs::read(&ledger_path)?).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("command ledger is corrupt: {error}"),
                )
            })?
        } else {
            HashMap::new()
        };
        Ok(Self {
            ledger_path,
            entries: Arc::new(Mutex::new(entries)),
            policy,
        })
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
        let key = format!("{activation}:{command}");
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Status::internal("ledger lock poisoned"))?;
        if let Some(entry) = entries.get(&key) {
            if entry.fingerprint != fingerprint {
                return Err(internal_status(
                    "REPLAY_DIGEST_MISMATCH",
                    "idempotency key reused for another command",
                    &entry.result.state,
                    "fetch the committed command result",
                ));
            }
            return Ok(entry.result.clone());
        }
        let result = proto::CommandResult {
            command_id: command.into(),
            committed: true,
            durable_record_id: format!("command:sha256:{fingerprint}"),
            state: state.into(),
            error: None,
            evidence_refs: vec![],
        };
        let mut committed_entries = entries.clone();
        committed_entries.insert(
            key,
            LedgerEntry {
                fingerprint,
                result: result.clone(),
            },
        );
        let bytes = serde_json::to_vec(&committed_entries)
            .map_err(|_| Status::internal("ledger serialization failed"))?;
        let temporary = self.ledger_path.with_extension("tmp");
        let mut file =
            fs::File::create(&temporary).map_err(|_| Status::unavailable("ledger unavailable"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Status::unavailable("ledger persistence failed"))?;
        fs::rename(temporary, &self.ledger_path)
            .map_err(|_| Status::unavailable("ledger commit failed"))?;
        if let Some(parent) = self.ledger_path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| Status::unavailable("ledger directory sync failed"))?;
        }
        *entries = committed_entries;
        Ok(result)
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
    Ok(format!("{:x}", Sha256::digest(message.encode_to_vec())))
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
        let key = format!("{}:{}", query.activation_id, query.command_id);
        let entries = self
            .entries
            .lock()
            .map_err(|_| Status::internal("ledger lock poisoned"))?;
        entries
            .get(&key)
            .map(|entry| Response::new(entry.result.clone()))
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
