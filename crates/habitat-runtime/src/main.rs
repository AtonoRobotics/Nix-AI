use habitat_authority::RuntimePeer;
use habitat_runtime::{
    component_socket, dependencies_operational, query_state,
    serve_deployed_component_service_listener, RecoveryReport, COMPONENTS,
};
use habitat_uds::{
    publish_readiness as publish_readiness_atomic, FrameConfig, Readiness, ServiceAllowlist,
    ServiceListener, ServicePrincipal, SocketPermissions, StreamTimeouts, DEFAULT_MAX_PAYLOAD,
};
use std::{env, fs, io, path::PathBuf, thread, time::Duration};

fn publish_readiness(path: &std::path::Path, readiness: Readiness) -> io::Result<()> {
    publish_readiness_atomic(
        path,
        readiness,
        FrameConfig::new(DEFAULT_MAX_PAYLOAD).expect("constant frame bound is valid"),
    )
    .map_err(io::Error::other)
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let component = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-runtime COMPONENT RUN_DIR STATE_DIR PEERS",
        )
    })?;
    let run_dir = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing run directory"))?,
    );
    let _state_dir =
        PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing state directory")
        })?);
    let peers_path = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing peers"))?,
    );
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected argument",
        ));
    }
    let peers: Vec<RuntimePeer> = serde_json::from_slice(&fs::read(peers_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !COMPONENTS.contains(&component.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown component",
        ));
    }
    fs::create_dir_all(&run_dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("create runtime root {}: {error}", run_dir.display()),
        )
    })?;
    if !matches!(component.as_str(), "scheduler" | "runtime") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "habitat-runtime only hosts scheduler or runtime",
        ));
    }
    let socket = component_socket(&run_dir, &component);
    let services = peers
        .iter()
        .map(|peer| ServicePrincipal::new(&peer.service_id, peer.uid, peer.gid))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let listener = ServiceListener::bind(
        &socket,
        SocketPermissions::new(0o660).map_err(io::Error::other)?,
        ServiceAllowlist::new(services),
        StreamTimeouts::new(Duration::from_secs(10), Duration::from_secs(10))
            .map_err(io::Error::other)?,
    )
    .map_err(|error| {
        io::Error::other(format!(
            "bind component socket {}: {error}",
            socket.display()
        ))
    })?;
    let readiness = socket
        .parent()
        .expect("component socket has parent")
        .join("readiness");
    if component == "runtime" {
        publish_readiness(
            &readiness,
            Readiness::Recovering {
                pid: std::process::id(),
            },
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("publish recovering state {}: {error}", readiness.display()),
            )
        })?;
    }
    while !dependencies_operational(&run_dir, &component)? {
        thread::sleep(Duration::from_millis(250));
    }
    let report = RecoveryReport::from_wire(&query_state(
        &component_socket(&run_dir, "state"),
        "STATUS",
    )?)?;
    if component == "runtime" {
        publish_readiness(
            &readiness,
            Readiness::Operational {
                pid: std::process::id(),
            },
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("publish operational state {}: {error}", readiness.display()),
            )
        })?;
    }
    serve_deployed_component_service_listener(
        &component,
        listener,
        report,
        socket.parent().expect("component socket has parent"),
    )
}
