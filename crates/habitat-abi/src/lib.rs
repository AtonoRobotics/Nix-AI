//! Versioned Habitat Agent ABI transport and durable command ledger.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("nix_ai.agent.v2");
}

pub const ABI_VERSION: &str = "2.0";
pub const MAX_COMMAND_BYTES: usize = 1024 * 1024;

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
}

impl AgentAbi {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let ledger_path = path.as_ref().to_owned();
        let entries = if ledger_path.exists() {
            serde_json::from_slice(&fs::read(&ledger_path)?).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self {
            ledger_path,
            entries: Arc::new(Mutex::new(entries)),
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

    fn peer_uid<T>(request: &Request<T>) -> Result<u32, Status> {
        request
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
            })
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
                return Err(structured_status(
                    "CONFLICT",
                    "idempotency key reused for another command",
                    false,
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
        entries.insert(
            key,
            LedgerEntry {
                fingerprint,
                result: result.clone(),
            },
        );
        let bytes = serde_json::to_vec(&*entries)
            .map_err(|_| Status::internal("ledger serialization failed"))?;
        let temporary = self.ledger_path.with_extension("tmp");
        let mut file =
            fs::File::create(&temporary).map_err(|_| Status::unavailable("ledger unavailable"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Status::unavailable("ledger persistence failed"))?;
        fs::rename(temporary, &self.ledger_path)
            .map_err(|_| Status::unavailable("ledger commit failed"))?;
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

#[tonic::async_trait]
impl proto::agent_runtime_server::AgentRuntime for AgentAbi {
    async fn get_activation(
        &self,
        request: Request<proto::GetActivationRequest>,
    ) -> Result<Response<proto::ActivationEnvelope>, Status> {
        Self::version(&request)?;
        let uid = Self::peer_uid(&request)?;
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
        Self::peer_uid(&request)?;
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
        Self::peer_uid(&request)?;
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
        Self::peer_uid(&request)?;
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
