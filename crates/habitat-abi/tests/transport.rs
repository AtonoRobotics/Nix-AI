use habitat_abi::{
    proto::{
        agent_runtime_client::AgentRuntimeClient, agent_runtime_server::AgentRuntimeServer,
        DispositionKind, GetActivationRequest, RequestBinding, SubmitDispositionRequest,
    },
    AgentAbi, CommandLedger, LedgerError, SecurityPolicy, StateServiceLedger, CONTRACT_VERSION,
};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    os::unix::fs::MetadataExt,
    os::unix::net::UnixListener as StdUnixListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{
    transport::{Channel, Endpoint, Server},
    Request,
};
use tower::service_fn;

#[test]
fn state_service_repository_uses_authoritative_response_and_rejects_malformed_data() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("state.sock");
    let listener = StdUnixListener::bind(&socket).unwrap();
    let responder = std::thread::spawn(move || {
        for response in [
            serde_json::json!({"status":"ok","result":{"command_id":"command:01",
                "committed":true,"durable_record_id":"record:01","state":"COMMITTED",
                "error":null,"evidence_refs":[]}})
            .to_string()
                + "\n",
            "not-json\n".into(),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            assert!(request.contains("commit_command"));
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    let ledger = StateServiceLedger::new(&socket);
    let proposed = habitat_abi::proto::CommandResult {
        command_id: "command:01".into(),
        committed: true,
        durable_record_id: "proposed:01".into(),
        state: "PROPOSED".into(),
        error: None,
        evidence_refs: vec![],
    };
    let committed = ledger
        .commit("activation:01", "command:01", &"a".repeat(64), &proposed)
        .unwrap();
    assert_eq!(committed.durable_record_id, "record:01");
    assert!(matches!(
        ledger.commit("activation:01", "command:02", &"b".repeat(64), &proposed),
        Err(LedgerError::Corrupt(_))
    ));
    responder.join().unwrap();
}

fn policy(root: &Path) -> SecurityPolicy {
    SecurityPolicy {
        expected_peer_uid: std::fs::metadata(root).unwrap().uid(),
        activation_id: "activation:01".into(),
        activation_credential: "secret-credential".into(),
        minimum_lease_fence: 7,
        system_generation_id: "generation:01".into(),
        capability_activation_set_id: "capability-set:01".into(),
    }
}

#[derive(Debug, Default)]
struct TestLedger(Mutex<HashMap<(String, String), (String, habitat_abi::proto::CommandResult)>>);

impl CommandLedger for TestLedger {
    fn commit(
        &self,
        activation: &str,
        command: &str,
        digest: &str,
        proposed: &habitat_abi::proto::CommandResult,
    ) -> Result<habitat_abi::proto::CommandResult, LedgerError> {
        let mut rows = self
            .0
            .lock()
            .map_err(|_| LedgerError::Corrupt("poisoned".into()))?;
        let key = (activation.into(), command.into());
        if let Some((recorded, result)) = rows.get(&key) {
            return if recorded == digest {
                Ok(result.clone())
            } else {
                Err(LedgerError::DigestMismatch(Box::new(result.clone())))
            };
        }
        rows.insert(key, (digest.into(), proposed.clone()));
        Ok(proposed.clone())
    }

    fn get(
        &self,
        activation: &str,
        command: &str,
    ) -> Result<Option<habitat_abi::proto::CommandResult>, LedgerError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| LedgerError::Corrupt("poisoned".into()))?
            .get(&(activation.into(), command.into()))
            .map(|(_, result)| result.clone()))
    }
}

async fn start(
    socket: &Path,
    ledger: Arc<dyn CommandLedger>,
    policy: SecurityPolicy,
) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    let service = AgentAbi::with_repository(ledger, policy).unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(
                AgentRuntimeServer::new(service)
                    .max_decoding_message_size(habitat_abi::MAX_COMMAND_BYTES * 2),
            )
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
            .unwrap();
    })
}

async fn connect(socket: PathBuf) -> AgentRuntimeClient<Channel> {
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let path = socket.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    AgentRuntimeClient::new(channel)
}

fn request<T>(message: T, version: &'static str) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("x-habitat-abi-version", version.parse().unwrap());
    request
}

fn disposition(command: &str, kind: DispositionKind) -> SubmitDispositionRequest {
    SubmitDispositionRequest {
        activation_id: "activation:01".into(),
        command_id: command.into(),
        kind: kind as i32,
        payload: None,
        decision_record: None,
        binding: Some(binding(command)),
    }
}

fn binding(command: &str) -> RequestBinding {
    RequestBinding {
        schema_version: CONTRACT_VERSION.into(),
        command_id: command.into(),
        machine_id: "machine:01".into(),
        agent_id: "agent:01".into(),
        objective_id: "objective:01".into(),
        activation_id: "activation:01".into(),
        lease_fence: 7,
        system_generation_id: "generation:01".into(),
        capability_activation_set_id: "capability-set:01".into(),
        deadline: Some(prost_types::Timestamp {
            seconds: 4_102_444_800,
            nanos: 0,
        }),
        trace_id: "trace:01".into(),
        evidence_refs: vec!["evidence:sha256:01".into()],
        activation_credential: "secret-credential".into(),
    }
}

#[tokio::test]
async fn unix_peer_version_and_durable_duplicate_semantics() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("agent.sock");
    let repository: Arc<dyn CommandLedger> = Arc::new(TestLedger::default());
    let security = policy(temp.path());
    let server = start(&socket, repository.clone(), security.clone()).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket.clone()).await;
    let activation = client
        .get_activation(request(
            GetActivationRequest {
                activation_id: "activation:01".into(),
                activation_credential: "secret-credential".into(),
                binding: Some(binding("get-activation:01")),
            },
            "2.8",
        ))
        .await
        .unwrap();
    assert_eq!(activation.get_ref().abi_version, "2.0");
    assert_eq!(
        activation.metadata().get("x-habitat-peer-uid").unwrap(),
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .unwrap()
            .stdout
            .strip_suffix(b"\n")
            .unwrap()
    );

    let first = client
        .submit_disposition(request(
            disposition("command:01", DispositionKind::Checkpoint),
            "2.8",
        ))
        .await
        .unwrap()
        .into_inner();
    let duplicate = client
        .submit_disposition(request(
            disposition("command:01", DispositionKind::Checkpoint),
            "2.8",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first, duplicate);
    assert!(client
        .submit_disposition(request(
            disposition("command:01", DispositionKind::Sleep),
            "2.8"
        ))
        .await
        .unwrap_err()
        .message()
        .contains("REPLAY_DIGEST_MISMATCH"));

    server.abort();
    drop(client);
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::remove_file(&socket).unwrap();
    let restarted = start(&socket, repository, security).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut restarted_client = connect(socket).await;
    assert_eq!(
        restarted_client
            .submit_disposition(request(
                disposition("command:01", DispositionKind::Checkpoint),
                "2.0"
            ))
            .await
            .unwrap()
            .into_inner(),
        first
    );
    restarted.abort();
}

#[tokio::test]
async fn unknown_major_unstructured_and_oversized_commands_fail_closed() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("agent.sock");
    let server = start(
        &socket,
        Arc::new(TestLedger::default()),
        policy(temp.path()),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut incompatible = connect(socket.clone()).await;
    assert!(incompatible
        .get_activation(request(GetActivationRequest::default(), "1.0"))
        .await
        .unwrap_err()
        .message()
        .contains("UNSUPPORTED_ABI_VERSION"));
    let mut compatible = connect(socket).await;
    assert!(compatible
        .submit_disposition(request(
            disposition("command:invalid", DispositionKind::Unspecified),
            "2.0"
        ))
        .await
        .unwrap_err()
        .message()
        .contains("INVALID_REQUEST"));
    let mut huge = disposition("command:huge", DispositionKind::Message);
    huge.payload = Some(prost_types::Struct {
        fields: [(
            "content".into(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "x".repeat(habitat_abi::MAX_COMMAND_BYTES),
                )),
            },
        )]
        .into(),
    });
    assert!(compatible
        .submit_disposition(request(huge, "2.0"))
        .await
        .unwrap_err()
        .message()
        .contains("RESOURCE_EXHAUSTED"));
    server.abort();
}

#[tokio::test]
async fn invalid_bindings_fail_before_ledger_mutation() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("agent.sock");
    let ledger = temp.path().join("ledger.json");
    let server = start(
        &socket,
        Arc::new(TestLedger::default()),
        policy(temp.path()),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket).await;

    let mut cases = Vec::new();
    let mut missing = disposition("command:missing", DispositionKind::Checkpoint);
    missing.binding = None;
    cases.push((missing, "MISSING_BINDING"));
    for field in [
        "schema_version",
        "command_id",
        "machine_id",
        "agent_id",
        "objective_id",
        "activation_id",
        "system_generation_id",
        "capability_activation_set_id",
        "trace_id",
        "activation_credential",
    ] {
        let mut message = disposition(
            &format!("command:missing-{field}"),
            DispositionKind::Checkpoint,
        );
        let binding = message.binding.as_mut().unwrap();
        match field {
            "schema_version" => binding.schema_version.clear(),
            "command_id" => binding.command_id.clear(),
            "machine_id" => binding.machine_id.clear(),
            "agent_id" => binding.agent_id.clear(),
            "objective_id" => binding.objective_id.clear(),
            "activation_id" => binding.activation_id.clear(),
            "system_generation_id" => binding.system_generation_id.clear(),
            "capability_activation_set_id" => binding.capability_activation_set_id.clear(),
            "trace_id" => binding.trace_id.clear(),
            "activation_credential" => binding.activation_credential.clear(),
            _ => unreachable!(),
        }
        cases.push((message, "MISSING_BINDING"));
    }
    let mut no_deadline = disposition("command:no-deadline", DispositionKind::Checkpoint);
    no_deadline.binding.as_mut().unwrap().deadline = None;
    cases.push((no_deadline, "MISSING_BINDING"));
    let mut forged = disposition("command:forged", DispositionKind::Checkpoint);
    forged.binding.as_mut().unwrap().activation_credential = "forged".into();
    cases.push((forged, "ACTIVATION_CREDENTIAL_INVALID"));
    let mut expired = disposition("command:expired", DispositionKind::Checkpoint);
    expired.binding.as_mut().unwrap().deadline = Some(prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    });
    cases.push((expired, "DEADLINE_EXPIRED"));
    let mut stale = disposition("command:stale", DispositionKind::Checkpoint);
    stale.binding.as_mut().unwrap().lease_fence = 6;
    cases.push((stale, "STALE_LEASE_FENCE"));
    let mut wrong_command = disposition("command:outer", DispositionKind::Checkpoint);
    wrong_command.binding.as_mut().unwrap().command_id = "command:inner".into();
    cases.push((wrong_command, "COMMAND_ID_MISMATCH"));
    let mut wrong_activation = disposition("command:activation", DispositionKind::Checkpoint);
    wrong_activation.binding.as_mut().unwrap().activation_id = "activation:other".into();
    cases.push((wrong_activation, "ACTIVATION_ID_MISMATCH"));
    let mut wrong_generation = disposition("command:generation", DispositionKind::Checkpoint);
    wrong_generation
        .binding
        .as_mut()
        .unwrap()
        .system_generation_id = "generation:other".into();
    cases.push((wrong_generation, "ACTIVATION_SCOPE_MISMATCH"));
    let mut wrong_capabilities = disposition("command:capabilities", DispositionKind::Checkpoint);
    wrong_capabilities
        .binding
        .as_mut()
        .unwrap()
        .capability_activation_set_id = "capability-set:other".into();
    cases.push((wrong_capabilities, "ACTIVATION_SCOPE_MISMATCH"));

    for (message, code) in cases {
        let error = client
            .submit_disposition(request(message, "2.0"))
            .await
            .unwrap_err();
        assert!(error.message().contains(code), "{error:?}");
    }
    assert!(
        std::fs::metadata(&ledger).is_err(),
        "rejected requests must not create local state"
    );
    server.abort();
}

#[tokio::test]
async fn peer_mismatch_and_unavailable_ledger_fail_closed() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("peer.sock");
    let mut wrong_peer = policy(temp.path());
    wrong_peer.expected_peer_uid = wrong_peer.expected_peer_uid.saturating_add(1);
    let server = start(&socket, Arc::new(TestLedger::default()), wrong_peer).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket).await;
    let error = client
        .submit_disposition(request(
            disposition("command:peer", DispositionKind::Checkpoint),
            "2.0",
        ))
        .await
        .unwrap_err();
    assert!(error.message().contains("PEER_IDENTITY_MISMATCH"));
    server.abort();

    #[derive(Debug)]
    struct FailedLedger(LedgerError);
    impl CommandLedger for FailedLedger {
        fn commit(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &habitat_abi::proto::CommandResult,
        ) -> Result<habitat_abi::proto::CommandResult, LedgerError> {
            Err(self.0.clone())
        }
        fn get(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<habitat_abi::proto::CommandResult>, LedgerError> {
            Err(self.0.clone())
        }
    }
    let socket = temp.path().join("unavailable.sock");
    let server = start(
        &socket,
        Arc::new(FailedLedger(LedgerError::Unavailable("down".into()))),
        policy(temp.path()),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket).await;
    let error = client
        .submit_disposition(request(
            disposition("command:unavailable", DispositionKind::Checkpoint),
            "2.0",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.message().contains("COMMAND_LEDGER_UNAVAILABLE"));
    server.abort();

    let socket = temp.path().join("corrupt.sock");
    let server = start(
        &socket,
        Arc::new(FailedLedger(LedgerError::Corrupt("bad row".into()))),
        policy(temp.path()),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket).await;
    let error = client
        .submit_disposition(request(
            disposition("command:corrupt", DispositionKind::Checkpoint),
            "2.0",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.message().contains("COMMAND_LEDGER_CORRUPT"));
    server.abort();
}
