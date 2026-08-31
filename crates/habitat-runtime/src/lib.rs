use habitat_authority::{
    runtime_forwarding_proof, RuntimeAuthorityRequest, RUNTIME_AUTHORITY_SCHEMA_VERSION,
};
pub mod coordinator;
use coordinator::{
    ContextId, Coordinator, Effect, EffectState, GenerationId, ObjectiveId, ObjectiveSnapshot,
    ObjectiveState, PackageId,
};
use habitat_effects::{
    RuntimeEffectAdmission, RuntimeEffectRequest, RUNTIME_EFFECT_SCHEMA_VERSION,
};
use habitat_uds::{
    connect_with_timeouts, AuthenticatedListener, FrameConfig, JsonTransport, PeerAllowlist,
    PeerPrincipal, ServiceCommandPolicy, ServiceListener, SocketPermissions, StreamTimeouts,
    DEFAULT_MAX_PAYLOAD,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ComponentCommand {
    Status,
    Schedule,
    Tick,
    Inspect,
    Prepare,
    Resume,
    Compensate,
    Run,
}

fn component_command(request: &str) -> Option<ComponentCommand> {
    match request {
        "STATUS" => Some(ComponentCommand::Status),
        "TICK" => Some(ComponentCommand::Tick),
        value if value.starts_with("SCHEDULE ") => Some(ComponentCommand::Schedule),
        value if value.starts_with("INSPECT ") => Some(ComponentCommand::Inspect),
        value if value.starts_with("PREPARE ") => Some(ComponentCommand::Prepare),
        value if value.starts_with("RESUME ") => Some(ComponentCommand::Resume),
        value if value.starts_with("COMPENSATE ") => Some(ComponentCommand::Compensate),
        value if value.starts_with("RUN ") => Some(ComponentCommand::Run),
        _ => None,
    }
}

fn commands_for(component: &str, service: &str) -> Vec<ComponentCommand> {
    use ComponentCommand::*;
    match (component, service) {
        (_, "service:runtime-conformance") => {
            vec![
                Status, Schedule, Tick, Inspect, Prepare, Resume, Compensate, Run,
            ]
        }
        (_, "service:operator") => {
            vec![Status, Inspect, Prepare, Resume, Compensate, Run]
        }
        ("scheduler", "service:runtime") => vec![Status, Schedule, Tick],
        ("state", "service:scheduler") => vec![Status, Schedule, Tick],
        ("state", "service:runtime") => vec![Status, Inspect],
        (_, "service:runtime") => vec![Status],
        _ => vec![Status],
    }
}
#[cfg(test)]
use habitat_uds::ServicePrincipal;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(test)]
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

const DEPLOYMENT_GRAPH_JSON: &str = include_str!("deployment_graph.json");

fn readiness_dependencies(component: &str) -> io::Result<Vec<&'static str>> {
    static GRAPH: OnceLock<serde_json::Value> = OnceLock::new();
    let graph = GRAPH.get_or_init(|| {
        serde_json::from_str(DEPLOYMENT_GRAPH_JSON)
            .expect("generated deployment graph must be valid JSON")
    });
    graph["readiness"][component]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown component"))?
        .iter()
        .map(|name| {
            name.as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid readiness dependency")
            })
        })
        .collect()
}

pub const COMPONENTS: [&str; 6] = [
    "state",
    "scheduler",
    "authority",
    "effects",
    "abi",
    "runtime",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub migrations: bool,
    pub leases_fenced: bool,
    pub effects_classified: bool,
    pub wakes_redelivered: usize,
}

impl RecoveryReport {
    pub fn operational(&self) -> bool {
        self.migrations && self.leases_fenced && self.effects_classified
    }

    fn wire(&self) -> String {
        format!(
            "READY migrations={} leases_fenced={} effects_classified={} wakes_redelivered={}",
            self.migrations as u8,
            self.leases_fenced as u8,
            self.effects_classified as u8,
            self.wakes_redelivered
        )
    }

    pub fn from_wire(value: &str) -> io::Result<Self> {
        if !value.starts_with("READY ") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "state is not ready",
            ));
        }
        let field = |name: &str| {
            value.split_whitespace().find_map(|entry| {
                entry
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('='))
            })
        };
        let required = |name| match field(name) {
            Some("1") => Ok(true),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("state recovery predicate {name} is not satisfied"),
            )),
        };
        let wakes_redelivered = field("wakes_redelivered")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing wake count"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid wake count"))?;
        Ok(Self {
            migrations: required("migrations")?,
            leases_fenced: required("leases_fenced")?,
            effects_classified: required("effects_classified")?,
            wakes_redelivered,
        })
    }
}

#[cfg(test)]
pub struct DurableState {
    root: PathBuf,
}

#[cfg(test)]
impl DurableState {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    fn append(&self, name: &str, record: &str) -> io::Result<()> {
        let path = self.root.join(name);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", record.replace('\n', " "))?;
        file.sync_data()?;
        File::open(&self.root)?.sync_all()
    }

    fn rewrite_lines(&self, name: &str, transform: impl Fn(&str) -> String) -> io::Result<usize> {
        let path = self.root.join(name);
        if !path.exists() {
            File::create(path)?.sync_all()?;
            File::open(&self.root)?.sync_all()?;
            return Ok(0);
        }
        let lines: Vec<String> = BufReader::new(File::open(&path)?)
            .lines()
            .collect::<Result<_, _>>()?;
        let transformed: Vec<String> = lines.iter().map(|line| transform(line)).collect();
        let changed = lines
            .iter()
            .zip(&transformed)
            .filter(|(a, b)| a != b)
            .count();
        let temporary = path.with_extension("next");
        {
            let mut output = File::create(&temporary)?;
            for line in transformed {
                writeln!(output, "{line}")?;
            }
            output.sync_all()?;
        }
        fs::rename(temporary, path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(changed)
    }

    pub fn recover(&self) -> io::Result<RecoveryReport> {
        let schema = self.root.join("schema-version");
        fs::write(&schema, b"2\n")?;
        File::open(schema)?.sync_all()?;
        self.rewrite_lines("leases", |line| {
            if line.contains(" ACTIVE") {
                line.replace(" ACTIVE", " FENCED")
            } else {
                line.into()
            }
        })?;
        let redelivered = self.rewrite_lines("wakes", |line| {
            if line.contains(" COMMITTED") {
                line.replace(" COMMITTED", " REDELIVERED")
            } else {
                line.into()
            }
        })?;
        self.append(
            "events",
            &format!("{} RECOVERY_COMPLETE wakes={redelivered}", now()),
        )?;
        Ok(RecoveryReport {
            migrations: true,
            leases_fenced: true,
            effects_classified: true,
            wakes_redelivered: redelivered,
        })
    }

    pub fn schedule(&self, objective: &str) -> io::Result<()> {
        validate_id(objective)?;
        self.append("objectives", &format!("{} {objective} CLAIMED", now()))?;
        self.append("wakes", &format!("{} wake:{objective} COMMITTED", now()))
    }

    pub fn complete_next(&self) -> io::Result<bool> {
        let changed = self.rewrite_lines("wakes", |line| {
            if line.contains(" COMMITTED") || line.contains(" REDELIVERED") {
                line.replace(" COMMITTED", " ACKED")
                    .replace(" REDELIVERED", " ACKED")
            } else {
                line.into()
            }
        })?;
        if changed > 0 {
            self.append(
                "events",
                &format!("{} OBJECTIVE_COMPLETED count={changed}", now()),
            )?;
        }
        Ok(changed > 0)
    }

    pub fn read(&self, name: &str) -> io::Result<String> {
        fs::read_to_string(self.root.join(name))
    }
}

fn validate_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:/.".contains(&b))
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid identifier",
        ))
    } else {
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn forwarding_proof(
    request: &RuntimeAuthorityRequest,
    provider: &str,
    digest: &str,
    key: &str,
) -> Option<String> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    let secret = fs::read(PathBuf::from(directory).join("authority-forwarding-key")).ok()?;
    runtime_forwarding_proof(&secret, request, provider, digest, key).ok()
}

pub fn query(socket: &Path, request: &str) -> io::Result<String> {
    let mut transport: JsonTransport<UnixStream, String, String> = connect_with_timeouts(
        socket,
        frames(),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(10),
    )
    .map_err(io::Error::other)?;
    transport
        .send_request(&request.to_owned())
        .map_err(io::Error::other)?;
    transport.receive_response().map_err(io::Error::other)
}

pub fn query_state(socket: &Path, request: &str) -> io::Result<String> {
    let (wire, legacy) = if request == "STATUS" {
        (
            serde_json::json!({"operation":"runtime_status"}),
            Some("STATUS"),
        )
    } else if let Some(objective) = request.strip_prefix("INSPECT ") {
        (
            serde_json::json!({"operation":"runtime_inspect","objective_id":objective}),
            Some("INSPECT"),
        )
    } else if let Some(objective) = request.strip_prefix("SCHEDULE ") {
        (
            serde_json::json!({"operation":"runtime_schedule","objective_id":objective}),
            Some("SCHEDULE"),
        )
    } else if request == "TICK" {
        (
            serde_json::json!({"operation":"runtime_tick"}),
            Some("TICK"),
        )
    } else {
        (
            serde_json::from_str(request).map_err(io::Error::other)?,
            None,
        )
    };
    let mut transport: JsonTransport<UnixStream, serde_json::Value, serde_json::Value> =
        connect_with_timeouts(
            socket,
            frames(),
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(io::Error::other)?;
    transport.send_request(&wire).map_err(io::Error::other)?;
    let response = transport.receive_response().map_err(io::Error::other)?;
    if response["status"] != "ok" {
        return Err(io::Error::other("state request unavailable"));
    }
    Ok(match legacy {
        Some("STATUS") => format!(
            "{} migrations={} leases_fenced={} effects_classified={} wakes_redelivered={}",
            response["result"]["readiness"]
                .as_str()
                .unwrap_or("RECOVERING"),
            u8::from(response["result"]["migrations"] == true),
            u8::from(response["result"]["leases_fenced"] == true),
            u8::from(response["result"]["effects_classified"] == true),
            response["result"]["wakes_redelivered"]
                .as_u64()
                .unwrap_or(0)
        ),
        Some("INSPECT") => serde_json::to_string(&response["result"]).map_err(io::Error::other)?,
        Some("SCHEDULE") => "ACCEPTED".into(),
        Some("TICK") if !response["result"]["completion"].is_null() => "COMPLETED".into(),
        Some("TICK") => "IDLE".into(),
        _ => serde_json::to_string(&response).map_err(io::Error::other)?,
    })
}

fn query_state_protocol(socket: &Path, request: &str, deployed: bool) -> io::Result<String> {
    if deployed {
        query_state(socket, request)
    } else {
        query(socket, request)
    }
}

fn frames() -> FrameConfig {
    FrameConfig::new(DEFAULT_MAX_PAYLOAD).expect("constant frame bound is valid")
}

fn resume_objective(run_dir: &Path, objective: &str, deployed_state_protocol: bool) -> String {
    if validate_id(objective).is_err() {
        return "INVALID".into();
    }
    let state_socket = component_socket(run_dir, "state");
    let inspection = query_state_protocol(
        &state_socket,
        &format!("INSPECT {objective}"),
        deployed_state_protocol,
    );
    if inspection
        .as_deref()
        .is_ok_and(|wire| objective_is_satisfied(wire, objective))
    {
        return "COMPLETED".into();
    }
    if inspection
        .as_deref()
        .is_ok_and(|wire| objective_is_compensated(wire, objective))
    {
        return "COMPENSATED".into();
    }
    if inspection
        .as_deref()
        .is_ok_and(|wire| objective_is_guarded(wire, objective))
    {
        let _ = query(&component_socket(run_dir, "scheduler"), "TICK");
        if query_state_protocol(
            &state_socket,
            &format!("INSPECT {objective}"),
            deployed_state_protocol,
        )
        .as_deref()
        .is_ok_and(|wire| objective_is_satisfied(wire, objective))
        {
            return "COMPLETED".into();
        }
    }
    let command_id = format!("effect:{objective}");
    let authority_request = RuntimeAuthorityRequest {
        schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION.into(),
        request_id: command_id.clone(),
        caller_service_id: "service:runtime".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        objective_id: objective.into(),
        capability: "runtime.effect".into(),
        operation: "commit".into(),
        target: objective.into(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        requested_at: now(),
    };
    let parameters_digest = format!("sha256:{:x}", Sha256::digest(objective.as_bytes()));
    let idempotency_key = format!("effect:{objective}");
    let Some(proof) = forwarding_proof(
        &authority_request,
        "habitat-state",
        &parameters_digest,
        &idempotency_key,
    ) else {
        eprintln!("runtime effect unavailable: forwarding proof credential or binding failed");
        return "UNAVAILABLE".into();
    };
    let effect_request = RuntimeEffectRequest {
        schema_version: RUNTIME_EFFECT_SCHEMA_VERSION.into(),
        caller_service_id: "service:runtime".into(),
        command_id: command_id.clone(),
        objective_id: objective.into(),
        provider_id: "habitat-state".into(),
        parameters_digest,
        idempotency_key,
        execution_constraint_id: format!("constraint:{command_id}"),
        valid_from: authority_request.requested_at,
        valid_until: authority_request.requested_at.saturating_add(30),
        controller_ack_required: true,
        authority_request,
        forwarding_proof: proof,
    };
    let effect_wire = match serde_json::to_string(&effect_request) {
        Ok(value) => value,
        Err(_) => return "INVALID".into(),
    };
    let effect_response = match query(&component_socket(run_dir, "effects"), &effect_wire) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("runtime effect transport failed: {error}");
            return "UNAVAILABLE".into();
        }
    };
    let admission = effect_admission(&effect_response);
    if admission.is_none() {
        eprintln!("runtime effect response was not a canonical admission");
    }
    match admission {
        Some(applied) if applied.state == "COMMITTED" => {
            let scheduler = component_socket(run_dir, "scheduler");
            if query(&scheduler, "TICK").is_err() {
                return "UNAVAILABLE".into();
            }
            match query_state_protocol(
                &component_socket(run_dir, "state"),
                &format!("INSPECT {objective}"),
                deployed_state_protocol,
            ) {
                Ok(state) if objective_is_satisfied(&state, objective) => "COMPLETED".into(),
                Ok(_) => "IDLE".into(),
                Err(_) => "UNAVAILABLE".into(),
            }
        }
        Some(applied) => applied.code,
        None => "UNAVAILABLE".into(),
    }
}

fn effect_admission(wire: &str) -> Option<RuntimeEffectAdmission> {
    serde_json::from_str::<RuntimeEffectAdmission>(wire)
        .ok()
        .or_else(|| {
            let value = serde_json::from_str::<serde_json::Value>(wire).ok()?;
            Some(RuntimeEffectAdmission {
                schema_version: RUNTIME_EFFECT_SCHEMA_VERSION.into(),
                command_id: value["command_id"].as_str().unwrap_or_default().into(),
                objective_id: value["objective_id"].as_str().unwrap_or_default().into(),
                state: value["state"].as_str().unwrap_or("REJECTED").into(),
                code: value["code"].as_str()?.into(),
            })
        })
}

fn objective_is_satisfied(wire: &str, objective: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(wire)
        .ok()
        .is_some_and(|projection| {
            projection["objective_id"].as_str() == Some(objective)
                && projection["objective_state"].as_str() == Some("SATISFIED")
                && projection["guard"]["ready"].as_bool() == Some(true)
        })
}

fn objective_is_compensated(wire: &str, objective: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(wire)
        .ok()
        .is_some_and(|projection| {
            projection["objective_id"].as_str() == Some(objective)
                && projection["objective_state"].as_str() == Some("COMPENSATED")
                && projection["guard"]["ready"].as_bool() == Some(false)
        })
}

fn objective_is_guarded(wire: &str, objective: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(wire)
        .ok()
        .is_some_and(|projection| {
            projection["objective_id"].as_str() == Some(objective)
                && projection["guard"]["ready"].as_bool() == Some(true)
                && projection["effects"].as_array().is_some_and(|effects| {
                    let mut ids = effects
                        .iter()
                        .filter_map(|effect| effect["effect_id"].as_str())
                        .collect::<Vec<_>>();
                    ids.sort_unstable();
                    let digest = format!(
                        "sha256:{:x}",
                        Sha256::digest(serde_json::to_vec(&ids).unwrap_or_default())
                    );
                    !effects.is_empty()
                        && ids.len() == effects.len()
                        && ids.windows(2).all(|pair| pair[0] != pair[1])
                        && projection["guard"]["effect_count"].as_u64()
                            == Some(effects.len() as u64)
                        && projection["guard"]["effect_set_digest"].as_str()
                            == Some(digest.as_str())
                        && effects
                            .iter()
                            .all(|effect| effect["state"].as_str() == Some("COMMITTED"))
                })
        })
}

fn compensate_objective(run_dir: &Path, request: &str, deployed_state_protocol: bool) -> String {
    let mut fields = request.split_whitespace();
    let (Some(objective), Some(original), None) = (fields.next(), fields.next(), fields.next())
    else {
        return "INVALID".into();
    };
    if validate_id(objective).is_err()
        || validate_id(original).is_err()
        || !original.starts_with("effect:sha256:")
    {
        return "INVALID".into();
    }
    let inspection = match query_state_protocol(
        &component_socket(run_dir, "state"),
        &format!("INSPECT {objective}"),
        deployed_state_protocol,
    ) {
        Ok(value) => value,
        Err(_) => return "UNAVAILABLE".into(),
    };
    let original_is_member = serde_json::from_str::<serde_json::Value>(&inspection)
        .ok()
        .and_then(|value| value["effects"].as_array().cloned())
        .is_some_and(|effects| {
            effects.iter().any(|effect| {
                effect["effect_id"].as_str() == Some(original)
                    && effect["state"].as_str() == Some("COMMITTED")
            })
        });
    if !original_is_member {
        return "NOT_FOUND".into();
    }
    let original = original.to_owned();
    let command_id = format!("compensation:{original}");
    let authority_request = RuntimeAuthorityRequest {
        schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION.into(),
        request_id: command_id.clone(),
        caller_service_id: "service:runtime".into(),
        machine_id: "machine:local".into(),
        service_id: "service:runtime".into(),
        activation_id: "activation:runtime".into(),
        objective_id: objective.into(),
        capability: "runtime.effect".into(),
        operation: "compensate".into(),
        target: original.clone(),
        generation: "generation:current".into(),
        state_version: "state:current".into(),
        requested_at: now(),
    };
    let parameters_digest = format!("sha256:{:x}", Sha256::digest(original.as_bytes()));
    let idempotency_key = format!("compensation:{original}");
    let Some(proof) = forwarding_proof(
        &authority_request,
        "habitat-state",
        &parameters_digest,
        &idempotency_key,
    ) else {
        return "UNAVAILABLE".into();
    };
    let effect_request = RuntimeEffectRequest {
        schema_version: RUNTIME_EFFECT_SCHEMA_VERSION.into(),
        caller_service_id: "service:runtime".into(),
        command_id: command_id.clone(),
        objective_id: objective.into(),
        provider_id: "habitat-state".into(),
        parameters_digest,
        idempotency_key,
        execution_constraint_id: format!("constraint:{command_id}"),
        valid_from: authority_request.requested_at,
        valid_until: authority_request.requested_at.saturating_add(30),
        controller_ack_required: true,
        authority_request,
        forwarding_proof: proof,
    };
    serde_json::to_string(&effect_request)
        .ok()
        .and_then(|wire| query(&component_socket(run_dir, "effects"), &wire).ok())
        .and_then(|wire| effect_admission(&wire))
        .map(|result| {
            if result.state == "COMMITTED" {
                "COMPENSATED".into()
            } else {
                result.code
            }
        })
        .unwrap_or_else(|| "UNAVAILABLE".into())
}

pub fn component_socket(run_dir: &Path, component: &str) -> PathBuf {
    run_dir.join(component).join(format!("{component}.sock"))
}

pub fn bind_component(socket: &Path) -> io::Result<AuthenticatedListener> {
    AuthenticatedListener::bind(
        socket,
        SocketPermissions::new(0o660).map_err(io::Error::other)?,
        PeerAllowlist::principals([PeerPrincipal::current_process()]),
        StreamTimeouts::new(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)
}

#[cfg(test)]
pub fn serve_component(
    component: &str,
    socket: &Path,
    state: Arc<Mutex<DurableState>>,
    report: RecoveryReport,
) -> io::Result<()> {
    if !COMPONENTS.contains(&component) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown component",
        ));
    }
    let listener = bind_component(socket)?;
    serve_component_listener(
        component,
        listener,
        state,
        report,
        socket.parent().unwrap_or(Path::new("/run")),
    )
}

#[cfg(test)]
pub fn serve_component_listener(
    component: &str,
    listener: AuthenticatedListener,
    state: Arc<Mutex<DurableState>>,
    report: RecoveryReport,
    component_dir: &Path,
) -> io::Result<()> {
    let run_dir = component_dir.parent().unwrap_or(component_dir);
    loop {
        let authenticated = match listener.accept() {
            Ok(authenticated) => authenticated,
            Err(error) if error.is_peer_rejection() => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let peer = authenticated.principal();
        let service = ServicePrincipal::new("service:runtime-conformance", peer.uid, peer.gid)
            .map_err(io::Error::other)?;
        let mut transport = authenticated.into_transport::<String, String>(frames());
        if let Err(error) = serve_component_request(
            component,
            &service,
            &mut transport,
            &state,
            &report,
            run_dir,
            false,
        ) {
            if error.kind() != io::ErrorKind::InvalidData
                && error.kind() != io::ErrorKind::UnexpectedEof
            {
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
pub fn serve_component_service_listener(
    component: &str,
    listener: ServiceListener,
    state: Arc<Mutex<DurableState>>,
    report: RecoveryReport,
    component_dir: &Path,
) -> io::Result<()> {
    let run_dir = component_dir.parent().unwrap_or(component_dir);
    loop {
        let authenticated = match listener.accept() {
            Ok(authenticated) => authenticated,
            Err(error) if error.is_peer_rejection() => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let service = authenticated.service_principal().clone();
        let mut transport = authenticated.into_transport::<String, String>(frames());
        serve_component_request(
            component,
            &service,
            &mut transport,
            &state,
            &report,
            run_dir,
            true,
        )?;
    }
}

/// Deployed scheduler/runtime adapter. All lifecycle reads and mutations cross the state UDS.
pub fn serve_deployed_component_service_listener(
    component: &str,
    listener: ServiceListener,
    report: RecoveryReport,
    component_dir: &Path,
) -> io::Result<()> {
    if !matches!(component, "scheduler" | "runtime") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployed habitat-runtime only hosts scheduler or runtime",
        ));
    }
    let run_dir = component_dir.parent().unwrap_or(component_dir);
    loop {
        let authenticated = match listener.accept() {
            Ok(authenticated) => authenticated,
            Err(error) if error.is_peer_rejection() => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let service = authenticated.service_principal().clone();
        let mut transport = authenticated.into_transport::<String, String>(frames());
        let request = transport.receive_request().map_err(io::Error::other)?;
        let Some(command) = component_command(&request) else {
            transport
                .send_response(&"INVALID".into())
                .map_err(io::Error::other)?;
            continue;
        };
        let policy = ServiceCommandPolicy::new([(
            service.clone(),
            commands_for(component, &service.service_id),
        )]);
        if policy.authorize(&service, &command).is_err() {
            transport
                .send_response(&"UNAUTHORIZED".into())
                .map_err(io::Error::other)?;
            continue;
        }
        let response = deployed_response(component, &request, &report, run_dir);
        transport
            .send_response(&response)
            .map_err(io::Error::other)?;
    }
}

fn deployed_response(
    component: &str,
    request: &str,
    report: &RecoveryReport,
    run_dir: &Path,
) -> String {
    if request == "STATUS" {
        return report.wire();
    }
    if component == "scheduler" && (request.starts_with("SCHEDULE ") || request == "TICK") {
        return query_state(&component_socket(run_dir, "state"), request)
            .unwrap_or_else(|_| "UNAVAILABLE".into());
    }
    if component != "runtime" {
        return "INVALID".into();
    }
    if request.starts_with("INSPECT ") {
        query_state(&component_socket(run_dir, "state"), request)
            .unwrap_or_else(|_| "UNAVAILABLE".into())
    } else if let Some(objective) = request.strip_prefix("PREPARE ") {
        query(
            &component_socket(run_dir, "scheduler"),
            &format!("SCHEDULE {objective}"),
        )
        .unwrap_or_else(|_| "UNAVAILABLE".into())
    } else if let Some(objective) = request.strip_prefix("RESUME ") {
        match query_state(
            &component_socket(run_dir, "state"),
            &format!("INSPECT {objective}"),
        )
        .and_then(|wire| snapshot_from_state_projection(&wire))
        {
            Ok(snapshot) if snapshot.state == ObjectiveState::Compensated => "COMPENSATED".into(),
            Ok(snapshot) if Coordinator::new().resume(&snapshot).is_ok() => {
                resume_objective(run_dir, objective, true)
            }
            _ => "UNAVAILABLE".into(),
        }
    } else if let Some(compensation) = request.strip_prefix("COMPENSATE ") {
        compensate_objective(run_dir, compensation, true)
    } else if let Some(objective) = request.strip_prefix("RUN ") {
        match query(
            &component_socket(run_dir, "scheduler"),
            &format!("SCHEDULE {objective}"),
        ) {
            Ok(response) if response == "ACCEPTED" => resume_objective(run_dir, objective, true),
            Ok(response) => response,
            Err(_) => "UNAVAILABLE".into(),
        }
    } else {
        "INVALID".into()
    }
}

fn snapshot_from_state_projection(wire: &str) -> io::Result<ObjectiveSnapshot> {
    let value: serde_json::Value = serde_json::from_str(wire).map_err(io::Error::other)?;
    let text = |name: &str| {
        value[name]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {name}")))
    };
    let state = match text("objective_state")? {
        // PostgreSQL lifecycle calls its admitted, not-yet-executing state
        // PROPOSED; the coordinator's corresponding state is CLAIMED.
        "PROPOSED" | "CLAIMED" => ObjectiveState::Claimed,
        "PREPARING" => ObjectiveState::Preparing,
        "EXECUTING" => ObjectiveState::Executing,
        "VERIFYING" => ObjectiveState::Verifying,
        "SATISFIED" => ObjectiveState::Satisfied,
        "COMPENSATED" => ObjectiveState::Compensated,
        "FAILED" => ObjectiveState::Failed,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown objective state",
            ))
        }
    };
    let effects = value["effects"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing effects"))?
        .iter()
        .map(|item| {
            let effect_state = match item["state"].as_str() {
                Some("AUTHORIZED") => EffectState::Authorized,
                Some("DISPATCHED") => EffectState::Dispatched,
                Some("COMMITTED") => EffectState::Committed,
                Some("FAILED") => EffectState::Failed,
                Some("COMPENSATED") => EffectState::Compensated,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown effect state",
                    ))
                }
            };
            Effect::new(
                item["effect_id"].as_str().unwrap_or_default(),
                item["idempotency_key"]
                    .as_str()
                    .unwrap_or(item["effect_id"].as_str().unwrap_or_default()),
                effect_state,
            )
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid effect: {error:?}"),
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(ObjectiveSnapshot {
        id: ObjectiveId::new(text("objective_id")?).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid objective: {error:?}"),
            )
        })?,
        state,
        generation: GenerationId::new(value["generation"].as_str().unwrap_or("generation:current"))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid generation: {error:?}"),
                )
            })?,
        context: value["context_id"]
            .as_str()
            .map(ContextId::new)
            .transpose()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid context: {error:?}"),
                )
            })?,
        package: value["package_id"]
            .as_str()
            .map(PackageId::new)
            .transpose()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid package: {error:?}"),
                )
            })?,
        effects,
        completion_evidence: None,
    })
}

#[cfg(test)]
fn serve_component_request(
    component: &str,
    service: &ServicePrincipal,
    transport: &mut JsonTransport<UnixStream, String, String>,
    state: &Arc<Mutex<DurableState>>,
    report: &RecoveryReport,
    run_dir: &Path,
    deployed_state_protocol: bool,
) -> io::Result<()> {
    let request = transport.receive_request().map_err(io::Error::other)?;
    let request = request.as_str();
    let Some(command) = component_command(request) else {
        transport
            .send_response(&"INVALID".into())
            .map_err(io::Error::other)?;
        return Ok(());
    };
    let policy = ServiceCommandPolicy::new([(
        service.clone(),
        commands_for(component, &service.service_id),
    )]);
    if policy.authorize(service, &command).is_err() {
        transport
            .send_response(&"UNAUTHORIZED".into())
            .map_err(io::Error::other)?;
        return Ok(());
    }
    let response = if request == "STATUS" {
        report.wire()
    } else if component == "state" && request.starts_with("SCHEDULE ") {
        state
            .lock()
            .unwrap()
            .schedule(&request[9..])
            .map(|_| "ACCEPTED".into())
            .unwrap_or_else(|_| "INVALID".into())
    } else if component == "state" && request == "TICK" {
        if state.lock().unwrap().complete_next()? {
            "COMPLETED".into()
        } else {
            "IDLE".into()
        }
    } else if component == "scheduler" && (request.starts_with("SCHEDULE ") || request == "TICK") {
        if deployed_state_protocol {
            query_state(&component_socket(run_dir, "state"), request)
        } else {
            query(&component_socket(run_dir, "state"), request)
        }
        .unwrap_or_else(|_| "UNAVAILABLE".into())
    } else if component == "runtime" && request.starts_with("INSPECT ") {
        query_state(&component_socket(run_dir, "state"), request)
            .unwrap_or_else(|_| "UNAVAILABLE".into())
    } else if component == "runtime" && request.starts_with("PREPARE ") {
        query(
            &component_socket(run_dir, "scheduler"),
            &format!("SCHEDULE {}", &request[8..]),
        )
        .unwrap_or_else(|_| "UNAVAILABLE".into())
    } else if component == "runtime" && request.starts_with("RESUME ") {
        resume_objective(run_dir, &request[7..], deployed_state_protocol)
    } else if component == "runtime" && request.starts_with("COMPENSATE ") {
        compensate_objective(run_dir, &request[11..], deployed_state_protocol)
    } else if component == "runtime" && request.starts_with("RUN ") {
        let scheduler = component_socket(run_dir, "scheduler");
        match query(&scheduler, &format!("SCHEDULE {}", &request[4..])) {
            Ok(response) if response == "ACCEPTED" => {
                resume_objective(run_dir, &request[4..], deployed_state_protocol)
            }
            Ok(response) => response,
            Err(_) => "UNAVAILABLE".into(),
        }
    } else {
        "INVALID".into()
    };
    transport.send_response(&response).map_err(io::Error::other)
}

pub fn dependencies_operational(run_dir: &Path, component: &str) -> io::Result<bool> {
    let dependencies = readiness_dependencies(component)?;
    Ok(dependencies.iter().all(|name| {
        if *name == "abi" {
            return component_socket(run_dir, name)
                .metadata()
                .map(|metadata| metadata.file_type().is_socket())
                .unwrap_or(false);
        }
        let status = if *name == "state" {
            query_state(&component_socket(run_dir, name), "STATUS")
        } else {
            query(&component_socket(run_dir, name), "STATUS")
        };
        status
            .map(|s| {
                s.contains("migrations=1")
                    && s.contains("leases_fenced=1")
                    && s.contains("effects_classified=1")
            })
            .unwrap_or(false)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hr-{}-{nonce}-{sequence}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn cold_boot_recovers_and_scheduler_continues() {
        let root = temporary();
        let store = DurableState::open(root.join("state")).unwrap();
        store
            .append("leases", "activation:1 worker:old ACTIVE")
            .unwrap();
        store
            .append("wakes", "wake:lost objective:1 COMMITTED")
            .unwrap();
        let recovery = store.recover().unwrap();
        assert!(recovery.operational());
        assert_eq!(recovery.wakes_redelivered, 1);
        assert!(store.read("leases").unwrap().contains("FENCED"));
        assert!(store.complete_next().unwrap());
        store.schedule("objective:2").unwrap();
        assert!(store.complete_next().unwrap());
        assert!(
            store
                .read("events")
                .unwrap()
                .matches("OBJECTIVE_COMPLETED")
                .count()
                >= 2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_wire_is_fail_closed() {
        assert!(RecoveryReport::from_wire(
            "READY migrations=1 leases_fenced=1 effects_classified=1 wakes_redelivered=2"
        )
        .unwrap()
        .operational());
        for invalid in [
            "READY migrations=0 leases_fenced=1 effects_classified=1 wakes_redelivered=0",
            "READY migrations=1 leases_fenced=1 effects_classified=1",
            "UNAVAILABLE",
        ] {
            assert!(RecoveryReport::from_wire(invalid).is_err());
        }
    }

    #[test]
    fn postgres_proposed_projection_maps_to_claimed_coordinator_state() {
        let snapshot = snapshot_from_state_projection(
            r#"{"objective_id":"objective:proposed","objective_state":"PROPOSED","effects":[]}"#,
        )
        .unwrap();
        assert_eq!(snapshot.state, ObjectiveState::Claimed);
        assert!(Coordinator::new().resume(&snapshot).is_ok());
    }

    #[test]
    fn effect_rejection_preserves_authority_code_without_full_admission_body() {
        let admission = effect_admission(r#"{"status":"error","code":"UNAUTHORIZED"}"#)
            .expect("structured rejection must retain its code");
        assert_eq!(admission.code, "UNAUTHORIZED");
        assert_eq!(admission.state, "REJECTED");
    }

    #[test]
    fn terminal_projection_replays_only_the_matching_guarded_objective() {
        let projection = serde_json::json!({
            "objective_id": "objective:done",
            "objective_state": "SATISFIED",
            "guard": {"ready": true, "effect_count": 1,
                      "effect_set_digest": "sha256:c8ee5e4d736a4d07522a5384619ceaed83869199b0c53fee6e4f0e2d539be221"},
            "effects": [{"effect_id":"effect:one", "state": "COMMITTED"}]
        })
        .to_string();
        assert!(objective_is_satisfied(&projection, "objective:done"));
        assert!(objective_is_guarded(&projection, "objective:done"));
        assert!(!objective_is_satisfied(&projection, "objective:other"));
        assert!(!objective_is_guarded(&projection, "objective:other"));

        let unguarded = serde_json::json!({
            "objective_id": "objective:done",
            "objective_state": "SATISFIED",
            "guard": {"ready": false}
        })
        .to_string();
        assert!(!objective_is_satisfied(&unguarded, "objective:done"));
        assert!(!objective_is_guarded(&unguarded, "objective:done"));
        assert!(!objective_is_satisfied("UNAVAILABLE", "objective:done"));
        assert!(!objective_is_guarded("UNAVAILABLE", "objective:done"));
    }

    #[test]
    fn protected_socket_reports_recovery_and_rejects_bad_commands() {
        let root = temporary();
        let socket = root.join("state.sock");
        let state = Arc::new(Mutex::new(DurableState::open(root.join("data")).unwrap()));
        let report = state.lock().unwrap().recover().unwrap();
        let thread_socket = socket.clone();
        thread::spawn(move || {
            let _ = serve_component("state", &thread_socket, state, report);
        });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(query(&socket, "STATUS")
            .unwrap()
            .starts_with("READY migrations=1"));
        assert_eq!(
            query(&socket, "SCHEDULE objective:socket").unwrap(),
            "ACCEPTED"
        );
        assert_eq!(query(&socket, "TICK").unwrap(), "COMPLETED");
        fs::remove_file(socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scheduler_uses_authoritative_state_and_unconfigured_authority_fails_closed() {
        let root = temporary();
        for component in ["state", "scheduler", "authority", "effects", "runtime"] {
            fs::create_dir_all(root.join(component)).unwrap();
            let socket = component_socket(&root, component);
            let state = Arc::new(Mutex::new(
                DurableState::open(root.join(format!("data-{component}"))).unwrap(),
            ));
            let report = state.lock().unwrap().recover().unwrap();
            thread::spawn(move || {
                let _ = serve_component(component, &socket, state, report);
            });
        }
        for component in ["state", "scheduler", "authority", "effects", "runtime"] {
            let socket = component_socket(&root, component);
            for _ in 0..50 {
                if socket.exists() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(
            query(&component_socket(&root, "runtime"), "RUN objective:rpc").unwrap(),
            "UNAVAILABLE"
        );
        assert_eq!(
            query(
                &component_socket(&root, "runtime"),
                "PREPARE objective:interrupted"
            )
            .unwrap(),
            "ACCEPTED"
        );
        assert_eq!(
            query(
                &component_socket(&root, "runtime"),
                "RESUME objective:interrupted"
            )
            .unwrap(),
            "UNAVAILABLE"
        );
        assert!(fs::read_to_string(root.join("data-state/objectives"))
            .unwrap()
            .contains("objective:interrupted"));
        assert!(!root.join("data-state/effects").exists());
        assert!(!root.join("data-scheduler/objectives").exists());
        for component in ["state", "scheduler", "authority", "effects", "runtime"] {
            fs::remove_file(component_socket(&root, component)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}
