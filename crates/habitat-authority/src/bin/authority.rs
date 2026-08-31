use habitat_authority::{
    runtime_forwarding_proof, RuntimeAuthorityAdminRequest, RuntimeAuthorityEffectRequest,
    RuntimeAuthorityRequest, RuntimeAuthorityStore, RuntimeGrant, RuntimePeer,
};
use habitat_uds::{
    connect_with_timeouts, FrameConfig, JsonTransport, ServiceAllowlist, ServiceCommandPolicy,
    ServiceListener, ServicePrincipal, SocketPermissions, StreamTimeouts, DEFAULT_MAX_PAYLOAD,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AuthorityCommand {
    Status,
    Admin,
    Effect,
    Evaluate,
}
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn frames() -> FrameConfig {
    FrameConfig::new(DEFAULT_MAX_PAYLOAD).expect("constant frame bound is valid")
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-authority SOCKET GRANTS PEERS STATE FORWARDING_KEY",
        )
    })?;
    if first == "--client" {
        let socket = args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing client socket"))?;
        let request = args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing client request"))?;
        if args.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected client argument",
            ));
        }
        println!("{}", query_client(&socket, &request)?);
        return Ok(());
    }
    let socket = PathBuf::from(first);
    let grants_path = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing grants"))?;
    let peers_path = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing peers"))?;
    let state_socket = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing state"))?,
    );
    let forwarding_key =
        fs::read(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing forwarding key")
        })?)?;
    if forwarding_key.len() < 32 || args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected argument",
        ));
    }
    let grants: Vec<RuntimeGrant> = serde_json::from_slice(&fs::read(grants_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let peers: Vec<RuntimePeer> = serde_json::from_slice(&fs::read(peers_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let state_version = grants
        .first()
        .map(|grant| grant.state_version.clone())
        .unwrap_or_else(|| "state:none".into());
    let current = state_request(
        &state_socket,
        serde_json::json!({
            "operation":"authority_get", "binding_id":"authority:runtime"
        }),
    )?;
    let snapshot = current
        .get("result")
        .and_then(|result| result.get("snapshot"))
        .cloned();
    let mut state_version_number = current
        .get("result")
        .and_then(|result| result.get("version"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let mut authority = RuntimeAuthorityStore::from_snapshot(snapshot, grants, &state_version)
        .map_err(|_| io::Error::other("authority state unavailable"))?;
    commit_authority(
        &state_socket,
        &authority,
        &state_version,
        &mut state_version_number,
    )?;
    let services = peers
        .iter()
        .map(|peer| ServicePrincipal::new(&peer.service_id, peer.uid, peer.gid))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let command_policy = ServiceCommandPolicy::new(services.iter().cloned().map(|service| {
        let commands = match service.service_id.as_str() {
            "service:operator" | "service:reviewer" => {
                vec![AuthorityCommand::Status, AuthorityCommand::Admin]
            }
            "service:effects" => vec![AuthorityCommand::Status, AuthorityCommand::Effect],
            "service:runtime" => vec![AuthorityCommand::Status, AuthorityCommand::Evaluate],
            _ => vec![AuthorityCommand::Status],
        };
        (service, commands)
    }));
    let listener = ServiceListener::bind(
        &socket,
        SocketPermissions::new(0o660).map_err(io::Error::other)?,
        ServiceAllowlist::new(services),
        StreamTimeouts::new(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    loop {
        let authenticated = match listener.accept() {
            Ok(authenticated) => authenticated,
            Err(error) if error.is_peer_rejection() => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let service = authenticated.service_principal().clone();
        let service_id = service.service_id.clone();
        let mut transport = authenticated.into_transport::<String, String>(frames());
        let line = match transport.receive_request() {
            Ok(line) => line,
            Err(error) if error.is_connection_fault() => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        let request_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let reaped = authority
            .reap_expired_prepares(request_now)
            .map_err(|_| io::Error::other("authority persistence unavailable"))?;
        if reaped > 0 {
            commit_authority(
                &state_socket,
                &authority,
                &state_version,
                &mut state_version_number,
            )?;
        }
        if line.trim() == "STATUS" {
            if command_policy
                .authorize(&service, &AuthorityCommand::Status)
                .is_err()
            {
                continue;
            }
            transport
                .send_response(&format!(
                    "READY migrations=1 leases_fenced=1 effects_classified=1 authority_epoch={}",
                    authority.epoch()
                ))
                .map_err(io::Error::other)?;
            continue;
        }
        if let Ok(request) = serde_json::from_str::<RuntimeAuthorityAdminRequest>(&line) {
            if command_policy
                .authorize(&service, &AuthorityCommand::Admin)
                .is_err()
            {
                transport
                    .send_response(
                        &"{\"schema_version\":\"2.0\",\"outcome\":\"UNAUTHORIZED\"}".into(),
                    )
                    .map_err(io::Error::other)?;
                continue;
            }
            let changed = match service_id.as_str() {
                "service:reviewer" if request.operation == "approve" => authority
                    .record_admin_approval(&request, "service:reviewer")
                    .map_err(|_| io::Error::other("authority persistence unavailable"))?,
                "service:operator" => authority
                    .apply_admin(&request, "service:operator")
                    .map_err(|_| io::Error::other("authority persistence unavailable"))?,
                _ => false,
            };
            commit_authority(
                &state_socket,
                &authority,
                &state_version,
                &mut state_version_number,
            )?;
            transport
                .send_response(
                    &serde_json::json!({
                        "schema_version":"2.0", "request_id":request.request_id,
                        "outcome":if changed { "APPLIED" } else { "UNAUTHORIZED" },
                        "revocation_epoch":authority.epoch()
                    })
                    .to_string(),
                )
                .map_err(io::Error::other)?;
            continue;
        }
        if let Ok(protocol) = serde_json::from_str::<RuntimeAuthorityEffectRequest>(&line) {
            if command_policy
                .authorize(&service, &AuthorityCommand::Effect)
                .is_err()
            {
                transport
                    .send_response(
                        &"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}"
                            .into(),
                    )
                    .map_err(io::Error::other)?;
                continue;
            }
            let expected = runtime_forwarding_proof(
                &forwarding_key,
                &protocol.request,
                &protocol.forwarding.provider_id,
                &protocol.forwarding.parameters_digest,
                &protocol.forwarding.idempotency_key,
            )
            .unwrap_or_default();
            let proof_matches = expected.len() == protocol.forwarding.proof.len()
                && expected
                    .bytes()
                    .zip(protocol.forwarding.proof.bytes())
                    .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                    == 0;
            if protocol.schema_version != "2.0"
                || !proof_matches
                || service_id != "service:effects"
                || protocol.request.caller_service_id != "service:runtime"
            {
                transport
                    .send_response(
                        &"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}"
                            .into(),
                    )
                    .map_err(io::Error::other)?;
                continue;
            }
            let now = request_now;
            let decision = match protocol.phase.as_str() {
                "PREPARE" if protocol.effect_id.is_none() => authority.prepare_effect_proven(
                    &protocol.request,
                    now,
                    &protocol.forwarding.proof,
                ),
                "COMMIT" => protocol.effect_id.as_deref().map_or_else(
                    || Err(habitat_authority::AuthorityError::InvalidGrant),
                    |effect_id| {
                        authority.commit_effect_proven(
                            &protocol.request,
                            effect_id,
                            now,
                            &protocol.forwarding.proof,
                        )
                    },
                ),
                "STATUS" => protocol.effect_id.as_deref().map_or_else(
                    || Err(habitat_authority::AuthorityError::InvalidGrant),
                    |effect_id| {
                        authority.status_effect(
                            &protocol.request,
                            effect_id,
                            now,
                            &protocol.forwarding.proof,
                        )
                    },
                ),
                "ABORT" if protocol.effect_id.is_none() => {
                    authority.abort_effect_decision(&protocol.request, &protocol.forwarding.proof)
                }
                _ => Err(habitat_authority::AuthorityError::InvalidGrant),
            }
            .map_err(|_| io::Error::other("authority persistence unavailable"))?;
            commit_authority(
                &state_socket,
                &authority,
                &state_version,
                &mut state_version_number,
            )?;
            transport
                .send_response(&serde_json::to_string(&decision).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            continue;
        }
        let Ok(request) = serde_json::from_str::<RuntimeAuthorityRequest>(&line) else {
            transport
                .send_response(
                    &"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}"
                        .into(),
                )
                .map_err(io::Error::other)?;
            continue;
        };
        if command_policy
            .authorize(&service, &AuthorityCommand::Evaluate)
            .is_err()
        {
            transport
                .send_response(
                    &"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}"
                        .into(),
                )
                .map_err(io::Error::other)?;
            continue;
        }
        if service_id != request.caller_service_id {
            transport
                .send_response(
                    &"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}"
                        .into(),
                )
                .map_err(io::Error::other)?;
            continue;
        }
        let now = request_now;
        let decision = authority
            .evaluate(&request, now)
            .map_err(|_| io::Error::other("authority persistence unavailable"))?;
        commit_authority(
            &state_socket,
            &authority,
            &state_version,
            &mut state_version_number,
        )?;
        transport
            .send_response(&serde_json::to_string(&decision).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
}

fn state_request(
    socket: &std::path::Path,
    request: serde_json::Value,
) -> io::Result<serde_json::Value> {
    let mut transport: JsonTransport<_, serde_json::Value, serde_json::Value> =
        connect_with_timeouts(
            socket,
            frames(),
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
        )
        .map_err(io::Error::other)?;
    transport.send_request(&request).map_err(io::Error::other)?;
    transport.receive_response().map_err(io::Error::other)
}

fn commit_authority(
    socket: &std::path::Path,
    authority: &RuntimeAuthorityStore,
    generation: &str,
    version: &mut u64,
) -> io::Result<()> {
    let snapshot = authority
        .snapshot()
        .map_err(|_| io::Error::other("authority snapshot unavailable"))?;
    let canonical = serde_json::to_vec(&snapshot).map_err(io::Error::other)?;
    let digest = format!("sha256:{:x}", Sha256::digest(&canonical));
    let command_id = format!("authority-snapshot-{}-{}", *version, &digest[7..23]);
    let evidence = state_request(
        socket,
        serde_json::json!({
            "operation":"evidence_put",
            "command_id":format!("evidence:{command_id}"),
            "envelope": {"schema_version":"1", "producer":"service:authority",
                "subject":"authority:runtime", "operation":"authority.snapshot",
                "source":digest, "payload":{"expected_version":*version}}
        }),
    )?;
    let evidence_ref = evidence
        .get("result")
        .and_then(|result| result.get("evidence_ref"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::other("authority evidence unavailable"))?;
    let response = state_request(
        socket,
        serde_json::json!({
            "operation":"authority_commit", "binding_id":"authority:runtime",
            "command_id":command_id, "expected_version":*version, "generation":generation,
            "snapshot":snapshot, "snapshot_digest":digest, "evidence_ref":evidence_ref
        }),
    )?;
    *version = response
        .get("result")
        .and_then(|result| result.get("version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| io::Error::other("authority commit rejected"))?;
    Ok(())
}

fn query_client(socket: &str, request: &str) -> io::Result<String> {
    if socket.ends_with("/state.sock") {
        if request != "STATUS" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state client supports STATUS only",
            ));
        }
        let mut transport: JsonTransport<_, serde_json::Value, serde_json::Value> =
            connect_with_timeouts(
                socket,
                frames(),
                std::time::Duration::from_secs(10),
                std::time::Duration::from_secs(10),
            )
            .map_err(io::Error::other)?;
        transport
            .send_request(&serde_json::json!({"operation":"runtime_status"}))
            .map_err(io::Error::other)?;
        let response = transport.receive_response().map_err(io::Error::other)?;
        if response["status"] != "ok" {
            return Err(io::Error::other("state status unavailable"));
        }
        return Ok(format!(
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
        ));
    }
    let mut transport: JsonTransport<_, String, String> = connect_with_timeouts(
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
