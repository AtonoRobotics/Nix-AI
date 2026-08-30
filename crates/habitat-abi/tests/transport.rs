use std::{path::{Path, PathBuf}, time::Duration};
use habitat_abi::{proto::{agent_runtime_client::AgentRuntimeClient,
    agent_runtime_server::AgentRuntimeServer, DispositionKind, GetActivationRequest,
    SubmitDispositionRequest}, AgentAbi};
use tempfile::TempDir;
use tokio::{net::{UnixListener, UnixStream}, task::JoinHandle};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::{Channel, Endpoint, Server}, Request};
use tower::service_fn;
use hyper_util::rt::TokioIo;

async fn start(socket: &Path, ledger: &Path) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    let service = AgentAbi::open(ledger).unwrap();
    tokio::spawn(async move {
        Server::builder().add_service(AgentRuntimeServer::new(service)
            .max_decoding_message_size(habitat_abi::MAX_COMMAND_BYTES * 2))
            .serve_with_incoming(UnixListenerStream::new(listener)).await.unwrap();
    })
}

async fn connect(socket: PathBuf) -> AgentRuntimeClient<Channel> {
    let channel = Endpoint::try_from("http://[::]:50051").unwrap()
        .connect_with_connector(service_fn(move |_| {
            let path = socket.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await.unwrap();
    AgentRuntimeClient::new(channel)
}

fn request<T>(message: T, version: &'static str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert("x-habitat-abi-version", version.parse().unwrap());
    request
}

fn disposition(command: &str, kind: DispositionKind) -> SubmitDispositionRequest {
    SubmitDispositionRequest { activation_id: "activation:01".into(), command_id: command.into(),
        kind: kind as i32, payload: None, decision_record: None }
}

#[tokio::test]
async fn unix_peer_version_and_durable_duplicate_semantics() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("agent.sock");
    let ledger = temp.path().join("commands.json");
    let server = start(&socket, &ledger).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut client = connect(socket.clone()).await;
    let activation = client.get_activation(request(GetActivationRequest {
        activation_id: "activation:01".into(), activation_credential: "ephemeral".into()
    }, "2.8")).await.unwrap();
    assert_eq!(activation.get_ref().abi_version, "2.0");
    assert_eq!(activation.metadata().get("x-habitat-peer-uid").unwrap(),
               std::process::Command::new("id").arg("-u").output().unwrap()
                   .stdout.strip_suffix(b"\n").unwrap());

    let first = client.submit_disposition(request(disposition("command:01", DispositionKind::Checkpoint), "2.8"))
        .await.unwrap().into_inner();
    let duplicate = client.submit_disposition(request(disposition("command:01", DispositionKind::Checkpoint), "2.8"))
        .await.unwrap().into_inner();
    assert_eq!(first, duplicate);
    assert!(client.submit_disposition(request(disposition("command:01", DispositionKind::Sleep), "2.8"))
        .await.unwrap_err().message().contains("CONFLICT"));

    server.abort();
    drop(client);
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::remove_file(&socket).unwrap();
    let restarted = start(&socket, &ledger).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut restarted_client = connect(socket).await;
    assert_eq!(restarted_client.submit_disposition(request(disposition("command:01", DispositionKind::Checkpoint), "2.0"))
        .await.unwrap().into_inner(), first);
    restarted.abort();
}

#[tokio::test]
async fn unknown_major_unstructured_and_oversized_commands_fail_closed() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("agent.sock");
    let server = start(&socket, &temp.path().join("ledger.json")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut incompatible = connect(socket.clone()).await;
    assert!(incompatible.get_activation(request(GetActivationRequest::default(), "1.0")).await
        .unwrap_err().message().contains("UNSUPPORTED_ABI_VERSION"));
    let mut compatible = connect(socket).await;
    assert!(compatible.submit_disposition(request(disposition("command:invalid",
        DispositionKind::Unspecified), "2.0")).await.unwrap_err().message().contains("INVALID_REQUEST"));
    let mut huge = disposition("command:huge", DispositionKind::Message);
    huge.payload = Some(prost_types::Struct { fields: [(
        "content".into(), prost_types::Value { kind: Some(prost_types::value::Kind::StringValue(
            "x".repeat(habitat_abi::MAX_COMMAND_BYTES))) })].into() });
    assert!(compatible.submit_disposition(request(huge, "2.0")).await.unwrap_err().message()
        .contains("RESOURCE_EXHAUSTED"));
    server.abort();
}
