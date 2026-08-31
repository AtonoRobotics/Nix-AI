use habitat_runtime::{
    bind_component, component_socket, dependencies_operational, query, serve_component_listener,
    DurableState, RecoveryReport, COMPONENTS,
};
use std::{
    env, fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

fn require_credential(name: &str) -> io::Result<()> {
    let path =
        PathBuf::from(env::var(name).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, format!("missing {name}"))
        })?);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("invalid {name}"),
        ));
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let component = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-runtime COMPONENT RUN_DIR STATE_DIR",
        )
    })?;
    let run_dir = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing run directory"))?,
    );
    let state_dir =
        PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing state directory")
        })?);
    if !COMPONENTS.contains(&component.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown component",
        ));
    }
    fs::create_dir_all(&run_dir)?;
    if component == "state" {
        require_credential("HABITAT_DATABASE_CREDENTIAL")?;
        require_credential("HABITAT_OBJECT_STORE_CREDENTIAL")?;
    }
    let socket = component_socket(&run_dir, &component);
    let listener = bind_component(&socket)?;
    let readiness = socket
        .parent()
        .expect("component socket has parent")
        .join("readiness");
    if component == "runtime" {
        fs::write(&readiness, b"RECOVERING\n")?;
    }
    let state = Arc::new(Mutex::new(DurableState::open(state_dir)?));
    while !dependencies_operational(&run_dir, &component)? {
        thread::sleep(Duration::from_millis(250));
    }
    let report = if component == "state" {
        state.lock().unwrap().recover()?
    } else {
        RecoveryReport::from_wire(&query(&component_socket(&run_dir, "state"), "STATUS")?)?
    };
    if component == "runtime" {
        fs::write(readiness, b"OPERATIONAL\n")?;
    }
    serve_component_listener(
        &component,
        listener,
        state,
        report,
        socket.parent().expect("component socket has parent"),
    )
}
