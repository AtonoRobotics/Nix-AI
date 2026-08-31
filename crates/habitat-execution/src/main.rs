use habitat_execution::{OfflineProvider, ProviderCommand, ProviderError};
use habitat_uds::{
    FrameConfig, ServiceAllowlist, ServiceListener, ServicePrincipal, SocketPermissions,
    StreamTimeouts, DEFAULT_MAX_PAYLOAD,
};
use serde::Deserialize;
use std::{env, fs, io, path::PathBuf};
#[derive(Deserialize)]
struct Peer {
    service_id: String,
    uid: u32,
    gid: u32,
}
fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let Some(socket) = args.next() else {
        println!(
            "{}",
            serde_json::to_string(&habitat_execution::qemu_execution_declaration()).unwrap()
        );
        return Ok(());
    };
    let root = PathBuf::from(args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing provider state directory",
        )
    })?);
    let peers: Vec<Peer> =
        serde_json::from_slice(&fs::read(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing peers")
        })?)?)
        .map_err(io::Error::other)?;
    if args.next().is_some() || peers.len() != 1 || peers[0].service_id != "service:effects" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider requires exactly service:effects",
        ));
    }
    let principal = ServicePrincipal::new("service:effects", peers[0].uid, peers[0].gid)
        .map_err(io::Error::other)?;
    let listener = ServiceListener::bind(
        socket,
        SocketPermissions::new(0o660).map_err(io::Error::other)?,
        ServiceAllowlist::new(vec![principal]),
        StreamTimeouts::new(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let provider = OfflineProvider::open(root)
        .map_err(|_| io::Error::other("provider storage unavailable"))?;
    loop {
        let authenticated = match listener.accept() {
            Ok(v) => v,
            Err(e) if e.is_peer_rejection() => continue,
            Err(e) => return Err(io::Error::other(e)),
        };
        let mut transport = authenticated.into_transport::<ProviderCommand, serde_json::Value>(
            FrameConfig::new(DEFAULT_MAX_PAYLOAD).map_err(io::Error::other)?,
        );
        let command = match transport.receive_request() {
            Ok(v) => v,
            Err(e) if e.is_connection_fault() => continue,
            Err(e) => return Err(io::Error::other(e)),
        };
        let fault = env::var("HABITAT_PROVIDER_FAULT").ok();
        let result = match command {
            ProviderCommand::Execute {
                effect_id,
                command_id,
                idempotency_key,
                request_digest,
                operation,
                payload,
            } => provider.execute(
                &ProviderCommand::Execute {
                    effect_id,
                    command_id,
                    idempotency_key,
                    request_digest,
                    operation,
                    payload,
                },
                fault.as_deref(),
            ),
            ProviderCommand::Observe {
                effect_id,
                request_digest,
            } => provider.observe(&effect_id, &request_digest),
        };
        let response = match result {
            Ok(observation) => serde_json::json!({"status":"ok","observation":observation}),
            Err(ProviderError::Conflict) => serde_json::json!({"status":"conflict"}),
            Err(ProviderError::NotFound) => serde_json::json!({"status":"not_found"}),
            Err(ProviderError::Invalid) => serde_json::json!({"status":"corrupt"}),
            Err(ProviderError::Storage(_)) => serde_json::json!({"status":"unavailable"}),
        };
        transport
            .send_response(&response)
            .map_err(io::Error::other)?;
    }
}
