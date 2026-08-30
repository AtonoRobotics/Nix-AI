use habitat_abi::{proto::agent_runtime_server::AgentRuntimeServer, AgentAbi};
use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let socket = PathBuf::from(
        args.next()
            .ok_or("usage: habitat-abi-server SOCKET STATE_SERVICE_SOCKET")?,
    );
    let state_service_socket = PathBuf::from(
        args.next()
            .ok_or("usage: habitat-abi-server SOCKET STATE_SERVICE_SOCKET")?,
    );
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    let service = AgentAbi::open(state_service_socket)?;
    Server::builder()
        .add_service(
            AgentRuntimeServer::new(service)
                .max_decoding_message_size(habitat_abi::MAX_COMMAND_BYTES * 2),
        )
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let _ = fs::remove_file(socket);
    Ok(())
}
