use habitat_authority::{RuntimeAuthorityDecision, RuntimePeer};
use habitat_effects::{
    admit_runtime_effect, runtime_effect_request_valid, Attempt, ConsequenceClass, EffectLedger,
    EffectProposal, EffectState, Observation, ProviderContract, ReconciliationAttempt,
    ReconciliationMode, RuntimeEffectRequest,
};
use habitat_execution::{ProviderCommand, ProviderObservation};
use habitat_uds::{
    connect_with_timeouts, FrameConfig, JsonTransport, ServiceAllowlist, ServiceCommandPolicy,
    ServiceListener, ServicePrincipal, SocketPermissions, StreamTimeouts, DEFAULT_MAX_PAYLOAD,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EffectsCommand {
    Status,
    Submit,
}
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct PostgresEffectStore {
    database_name: String,
    socket_directory: String,
    psql: PathBuf,
}

fn parse_local_database_url(value: &str) -> io::Result<(String, String)> {
    let rest = value
        .strip_prefix("postgresql:///")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "database URL must be local"))?;
    let (database, socket) = rest
        .split_once("?host=")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "database socket missing"))?;
    if database.is_empty()
        || !database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || !socket.starts_with('/')
        || socket.contains('?')
        || socket.contains('&')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid local database URL",
        ));
    }
    Ok((database.into(), socket.into()))
}

fn sql_text(value: &str) -> String {
    let hex = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("convert_from(decode('{hex}','hex'),'UTF8')")
}

impl PostgresEffectStore {
    fn execute(&self, sql: &str) -> io::Result<String> {
        let mut child = Command::new(&self.psql)
            .args(["-X", "-qAt", "-v", "ON_ERROR_STOP=1"])
            // Use separate libpq environment fields. PGDATABASE does not
            // consistently interpret URI syntax across supported psql builds,
            // and credentials remain absent from /proc/*/cmdline.
            .env("PGDATABASE", &self.database_name)
            .env("PGHOST", &self.socket_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("psql stdin unavailable"))?
            .write_all(sql.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "PostgreSQL effect transaction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        String::from_utf8(output.stdout).map_err(io::Error::other)
    }

    fn recover(&self) -> io::Result<Vec<serde_json::Value>> {
        let output = self.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM effect_records r LEFT JOIN \
             (SELECT effect_id,max(effect_version) AS version FROM effect_transition_history \
              GROUP BY effect_id) h USING(effect_id) WHERE h.version IS NULL OR h.version<>r.version) \
             THEN RAISE EXCEPTION 'effect record/history version mismatch'; END IF; END $$; \
             SELECT h.canonical_event::text FROM effect_records r JOIN LATERAL \
             (SELECT canonical_event FROM effect_transition_history WHERE effect_id=r.effect_id \
              ORDER BY effect_version DESC LIMIT 1) h ON true ORDER BY r.effect_id;",
        )?;
        output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(io::Error::other))
            .collect()
    }
}

const MAX_RECONCILIATION_ATTEMPTS: usize = 8;
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(2);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn query(socket: &Path, request: &str) -> io::Result<String> {
    // A stopped service can leave its socket inode behind.  Bound both halves
    // of the exchange so reconciliation records an unavailable provider
    // instead of hanging forever after a successful connect to that inode.
    let mut transport: WireTransport = connect_with_timeouts(
        socket,
        frames(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .map_err(io::Error::other)?;
    transport
        .send_request(&request.to_owned())
        .map_err(io::Error::other)?;
    transport.receive_response().map_err(io::Error::other)
}

fn query_state(socket: &Path, request: &str) -> io::Result<String> {
    let (wire, inspect) = if let Some(objective) = request.strip_prefix("INSPECT ") {
        (
            serde_json::json!({"operation":"runtime_inspect","objective_id":objective}),
            true,
        )
    } else {
        (
            serde_json::from_str(request).map_err(io::Error::other)?,
            false,
        )
    };
    let mut transport: JsonTransport<UnixStream, serde_json::Value, serde_json::Value> =
        connect_with_timeouts(
            socket,
            frames(),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .map_err(io::Error::other)?;
    transport.send_request(&wire).map_err(io::Error::other)?;
    let response = transport.receive_response().map_err(io::Error::other)?;
    if inspect && response["status"] == "ok" {
        serde_json::to_string(&response["result"]).map_err(io::Error::other)
    } else {
        serde_json::to_string(&response).map_err(io::Error::other)
    }
}

type WireTransport = JsonTransport<UnixStream, String, String>;

fn frames() -> FrameConfig {
    FrameConfig::new(DEFAULT_MAX_PAYLOAD).expect("constant frame bound is valid")
}

fn authority_decision(
    socket: &Path,
    request: &habitat_authority::RuntimeAuthorityRequest,
    forwarding: &habitat_authority::RuntimeForwardingEvidence,
    phase: &str,
    effect_id: Option<&str>,
) -> Option<RuntimeAuthorityDecision> {
    let wire = serde_json::to_string(&habitat_authority::RuntimeAuthorityEffectRequest {
        schema_version: "2.0".into(),
        phase: phase.into(),
        request: request.clone(),
        effect_id: effect_id.map(str::to_owned),
        forwarding: forwarding.clone(),
    })
    .ok()?;
    let response = query(socket, &wire)
        .inspect_err(|error| eprintln!("authority {phase} transport failed: {error}"))
        .ok()?;
    serde_json::from_str(&response)
        .inspect_err(|error| eprintln!("authority {phase} response was invalid: {error}"))
        .ok()
}

fn state_request(socket: &Path, request: &serde_json::Value) -> Option<serde_json::Value> {
    serde_json::to_string(request)
        .ok()
        .and_then(|wire| query_state(socket, &wire).ok())
        .and_then(|wire| serde_json::from_str(&wire).ok())
}

fn provider_request(socket: &Path, command: &ProviderCommand) -> io::Result<ProviderObservation> {
    let mut transport: JsonTransport<UnixStream, ProviderCommand, serde_json::Value> =
        connect_with_timeouts(
            socket,
            frames(),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .map_err(io::Error::other)?;
    transport.send_request(command).map_err(io::Error::other)?;
    let response = transport.receive_response().map_err(io::Error::other)?;
    if response["status"] != "ok" {
        return Err(io::Error::other(format!(
            "provider rejected request: {}",
            response["status"].as_str().unwrap_or("invalid")
        )));
    }
    serde_json::from_value(response["observation"].clone()).map_err(io::Error::other)
}

fn execute_provider(
    socket: &Path,
    record: &habitat_effects::EffectRecord,
) -> io::Result<ProviderObservation> {
    provider_request(
        socket,
        &ProviderCommand::Execute {
            effect_id: record.effect_id.clone(),
            command_id: record.proposal.command_id.clone(),
            idempotency_key: record.proposal.idempotency_key.clone(),
            request_digest: record.proposal.parameters_digest.clone(),
            operation: record.proposal.operation.clone(),
            payload: serde_json::json!({
                "objective_id": record.proposal.objective_id,
                "capability": record.proposal.capability,
                "target": record.proposal.target,
                "compensates_effect_id": record.proposal.compensates_effect_id,
            }),
        },
    )
}

fn observe_provider(
    socket: &Path,
    record: &habitat_effects::EffectRecord,
) -> io::Result<ProviderObservation> {
    provider_request(
        socket,
        &ProviderCommand::Observe {
            effect_id: record.effect_id.clone(),
            request_digest: record.proposal.parameters_digest.clone(),
        },
    )
}

fn persist_provider_transition(
    state_socket: &Path,
    token: &str,
    record: &habitat_effects::EffectRecord,
    previous_state: Option<&str>,
    new_state: &str,
    external_ref: &str,
    provider_observation: Option<&ProviderObservation>,
) -> io::Result<String> {
    let transition_id = format!(
        "transition:sha256:{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                record.effect_id,
                previous_state.unwrap_or(""),
                new_state,
                record.proposal.parameters_digest,
                external_ref
            )
            .as_bytes()
        )
    );
    let payload = serde_json::json!({
        "transition_id": transition_id,
        "effect_id": record.effect_id,
        "objective_id": record.proposal.objective_id,
        "request_digest": record.proposal.parameters_digest,
        "previous_state": previous_state,
        "new_state": new_state,
        "disposition": new_state,
        "provider_id": record.proposal.provider_id,
        "attempt_identity": record.proposal.idempotency_key,
        "external_ref": external_ref,
        "provider_observation": provider_observation,
    });
    let evidence = state_request(
        state_socket,
        &serde_json::json!({
            "operation":"evidence_put",
            "command_id":format!("evidence:{transition_id}"),
            "envelope":{
                "schema_version":"1",
                "producer":"service:effects",
                "subject":record.effect_id,
                "operation":"effect.transition",
                "source":external_ref,
                "payload":payload,
            }
        }),
    )
    .filter(|response| response["status"] == "ok")
    .ok_or_else(|| io::Error::other("provider transition evidence unavailable"))?;
    let evidence_ref = evidence["result"]["evidence_ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("provider transition evidence reference missing"))?;
    let transition = state_request(
        state_socket,
        &serde_json::json!({
            "operation":"effect_transition", "admission_token":token,
            "transition_id":transition_id, "effect_id":record.effect_id,
            "objective_id":record.proposal.objective_id,
            "request_digest":record.proposal.parameters_digest,
            "previous_state":previous_state, "new_state":new_state,
            "evidence_ref":evidence_ref, "external_ref":external_ref,
        }),
    )
    .filter(|response| response["status"] == "ok")
    .ok_or_else(|| io::Error::other("provider transition persistence failed"))?;
    let _ = transition;
    Ok(evidence_ref.to_owned())
}

fn persist_dispatch_chain(
    state_socket: &Path,
    token: &str,
    record: &habitat_effects::EffectRecord,
    external_ref: &str,
) -> io::Result<()> {
    persist_provider_transition(
        state_socket,
        token,
        record,
        None,
        "PROPOSED",
        external_ref,
        None,
    )?;
    persist_provider_transition(
        state_socket,
        token,
        record,
        Some("PROPOSED"),
        "AUTHORIZED",
        external_ref,
        None,
    )?;
    persist_provider_transition(
        state_socket,
        token,
        record,
        Some("AUTHORIZED"),
        "DISPATCHED",
        external_ref,
        None,
    )?;
    Ok(())
}

fn resume_dispatch_chain(
    state_socket: &Path,
    token: &str,
    record: &habitat_effects::EffectRecord,
    external_ref: &str,
    provider_state: Option<&str>,
) -> io::Result<()> {
    match provider_state {
        None => persist_dispatch_chain(state_socket, token, record, external_ref),
        Some("PROPOSED") => {
            persist_provider_transition(
                state_socket,
                token,
                record,
                Some("PROPOSED"),
                "AUTHORIZED",
                external_ref,
                None,
            )?;
            persist_provider_transition(
                state_socket,
                token,
                record,
                Some("AUTHORIZED"),
                "DISPATCHED",
                external_ref,
                None,
            )?;
            Ok(())
        }
        Some("AUTHORIZED") => persist_provider_transition(
            state_socket,
            token,
            record,
            Some("AUTHORIZED"),
            "DISPATCHED",
            external_ref,
            None,
        )
        .map(|_| ()),
        Some(
            "DISPATCHED" | "UNCERTAIN" | "OBSERVED_SUCCEEDED" | "OBSERVED_FAILED"
            | "RESOLVED_SUCCEEDED" | "RESOLVED_FAILED",
        ) => Ok(()),
        Some(other) => Err(io::Error::other(format!(
            "unsupported durable provider state during recovery: {other}"
        ))),
    }
}

fn provider_transport_id(record: &habitat_effects::EffectRecord) -> String {
    format!(
        "provider://offline/sha256/{:x}",
        Sha256::digest(
            format!("{}\0{}", record.effect_id, record.proposal.idempotency_key).as_bytes()
        )
    )
}

fn execute_observe_and_persist(
    provider_socket: &Path,
    state_socket: &Path,
    token: &str,
    record: &habitat_effects::EffectRecord,
) -> io::Result<(ProviderObservation, String)> {
    if let Some(existing) = state_request(
        state_socket,
        &serde_json::json!({
            "operation":"effect_observe", "admission_token":token,
            "objective_id":record.proposal.objective_id,
            "effect_id":record.effect_id,
        }),
    )
    .filter(|response| {
        response["status"] == "ok"
            && matches!(
                response["result"]["projection"]["state"].as_str(),
                Some("COMMITTED" | "FAILED")
            )
    }) {
        let evidence_ref = existing["result"]["projection"]["evidence_ref"]
            .as_str()
            .ok_or_else(|| io::Error::other("terminal effect evidence missing"))?;
        return Ok((
            observe_provider(provider_socket, record)?,
            evidence_ref.into(),
        ));
    }
    let external_ref = provider_transport_id(record);
    persist_dispatch_chain(state_socket, token, record, &external_ref)?;
    let acknowledged = execute_provider(provider_socket, record)?;
    if acknowledged.transport_id != external_ref {
        return Err(io::Error::other("provider transport identity mismatch"));
    }
    let observed = observe_provider(provider_socket, record)?;
    if observed != acknowledged {
        return Err(io::Error::other(
            "provider independent observation mismatch",
        ));
    }
    let evidence_ref = persist_provider_transition(
        state_socket,
        token,
        record,
        Some("DISPATCHED"),
        if observed.outcome == "SUCCEEDED" {
            "OBSERVED_SUCCEEDED"
        } else {
            "OBSERVED_FAILED"
        },
        &external_ref,
        Some(&observed),
    )?;
    Ok((observed, evidence_ref))
}

fn checkpoint_effect(
    ledger: &EffectLedger,
    store: &PostgresEffectStore,
    effect_id: &str,
) -> io::Result<()> {
    let record = ledger
        .get(effect_id)
        .ok_or_else(|| io::Error::other("effect disappeared before checkpoint"))?;
    let attempts = ledger.attempts(effect_id);
    let reconciliations = ledger.reconciliations(effect_id);
    let history = ledger.history(effect_id);
    let canonical = serde_json::json!({
        "record":record, "attempts":attempts, "reconciliations":reconciliations,
        "history":history
    });
    let event_id = format!(
        "event:sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).map_err(io::Error::other)?)
    );
    let record_json = serde_json::to_string(record).map_err(io::Error::other)?;
    let canonical_json = serde_json::to_string(&canonical).map_err(io::Error::other)?;
    let state = format!("{:?}", record.state);
    let id = sql_text(effect_id);
    let objective = sql_text(&record.proposal.objective_id);
    let digest = sql_text(&record.proposal.parameters_digest);
    let state_sql = sql_text(&state);
    let record_sql = sql_text(&record_json);
    let event = sql_text(&event_id);
    let canonical_sql = sql_text(&canonical_json);
    let compensation_sql = record
        .proposal
        .compensates_effect_id
        .as_deref()
        .map(|original| {
            let original = sql_text(original);
            format!("PERFORM effects_reserve_compensation({objective},{original});")
        })
        .unwrap_or_default();
    let mut attempt_sql = String::new();
    for (kind, values) in [
        (
            "DISPATCH",
            serde_json::to_value(attempts).map_err(io::Error::other)?,
        ),
        (
            "RECONCILIATION",
            serde_json::to_value(reconciliations).map_err(io::Error::other)?,
        ),
    ] {
        for (index, value) in values
            .as_array()
            .ok_or_else(|| io::Error::other("attempt list is not an array"))?
            .iter()
            .enumerate()
        {
            let at = value["dispatched_at"]
                .as_u64()
                .or_else(|| value["requested_at"].as_u64())
                .ok_or_else(|| io::Error::other("attempt timestamp missing"))?;
            let nullable = |name: &str| {
                value[name]
                    .as_str()
                    .map(sql_text)
                    .unwrap_or_else(|| "NULL".into())
            };
            let request_digest = sql_text(value["request_digest"].as_str().unwrap_or_default());
            let provider_id = sql_text(value["provider_id"].as_str().unwrap_or_default());
            let transport_id = sql_text(value["transport_id"].as_str().unwrap_or_default());
            let kind_sql = sql_text(kind);
            let attempt_number = index + 1;
            let response = nullable("response");
            let observation_source = nullable("observation_source");
            let terminal_classification = nullable("terminal_classification");
            attempt_sql.push_str(&format!(
                "INSERT INTO effect_attempts(effect_id,attempt_number,kind,request_digest,provider_id,transport_id,dispatched_at,response,observation_source,terminal_classification) VALUES({id},{attempt_number},{kind_sql},{request_digest},{provider_id},{transport_id},{at},{response},{observation_source},{terminal_classification}) ON CONFLICT(effect_id,kind,attempt_number) DO UPDATE SET response=COALESCE(effect_attempts.response,EXCLUDED.response),observation_source=COALESCE(effect_attempts.observation_source,EXCLUDED.observation_source),terminal_classification=COALESCE(effect_attempts.terminal_classification,EXCLUDED.terminal_classification) WHERE effect_attempts.request_digest=EXCLUDED.request_digest AND effect_attempts.provider_id=EXCLUDED.provider_id AND effect_attempts.transport_id=EXCLUDED.transport_id AND effect_attempts.dispatched_at=EXCLUDED.dispatched_at AND (effect_attempts.response IS NULL OR EXCLUDED.response IS NULL OR effect_attempts.response=EXCLUDED.response) AND (effect_attempts.observation_source IS NULL OR EXCLUDED.observation_source IS NULL OR effect_attempts.observation_source=EXCLUDED.observation_source) AND (effect_attempts.terminal_classification IS NULL OR EXCLUDED.terminal_classification IS NULL OR effect_attempts.terminal_classification=EXCLUDED.terminal_classification); DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM effect_attempts WHERE effect_id={id} AND attempt_number={attempt_number} AND kind={kind_sql} AND request_digest={request_digest} AND provider_id={provider_id} AND transport_id={transport_id} AND dispatched_at={at} AND ({response} IS NULL OR response={response}) AND ({observation_source} IS NULL OR observation_source={observation_source}) AND ({terminal_classification} IS NULL OR terminal_classification={terminal_classification})) THEN RAISE EXCEPTION 'attempt identity or outcome conflict'; END IF; END $$;"
            ));
        }
    }
    store.execute(&format!(
        "BEGIN; SELECT pg_advisory_xact_lock(hashtextextended({id},0)); \
         DO $$ DECLARE prior effect_records%ROWTYPE; next_version bigint; BEGIN \
         SELECT * INTO prior FROM effect_records WHERE effect_id={id} FOR UPDATE; \
         IF FOUND AND prior.canonical_record = ({record_sql})::jsonb THEN \
           IF prior.objective_id <> {objective} OR prior.request_digest <> {digest} OR prior.state <> {state_sql} THEN RAISE EXCEPTION 'checkpoint identity conflict'; END IF; \
         ELSE \
           IF FOUND AND prior.state IN ('ObservedSucceeded','ObservedFailed','ResolvedSucceeded','ResolvedFailed','Rejected') THEN RAISE EXCEPTION 'terminal effect is immutable'; END IF; \
           next_version := COALESCE(prior.version,0)+1; {compensation_sql} \
           INSERT INTO effect_records(effect_id,objective_id,request_digest,state,canonical_record,version) VALUES({id},{objective},{digest},{state_sql},({record_sql})::jsonb,next_version) ON CONFLICT(effect_id) DO UPDATE SET objective_id=EXCLUDED.objective_id,request_digest=EXCLUDED.request_digest,state=EXCLUDED.state,canonical_record=EXCLUDED.canonical_record,version=EXCLUDED.version,updated_at=now(); \
           INSERT INTO effect_transition_history(event_id,effect_id,previous_state,new_state,canonical_event,effect_version) VALUES({event},{id},prior.state,{state_sql},({canonical_sql})::jsonb,next_version); \
         END IF; END $$; \
         {attempt_sql} COMMIT;"
    ))?;
    Ok(())
}

fn objective_precondition(socket: &Path, objective: &str, compensation: bool) -> io::Result<bool> {
    let wire = query_state(socket, &format!("INSPECT {objective}"))?;
    let projection = serde_json::from_str::<serde_json::Value>(&wire)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let admissible_state = if compensation {
        "SATISFIED"
    } else {
        "PROPOSED"
    };
    Ok(projection["objective_id"].as_str() == Some(objective)
        && projection["objective_state"].as_str() == Some(admissible_state))
}

fn terminal_replay(
    state_socket: &Path,
    token: &str,
    request: &RuntimeEffectRequest,
    record: &habitat_effects::EffectRecord,
) -> io::Result<Option<serde_json::Value>> {
    let (projection_state, state, code) = match record.state {
        EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded => {
            ("COMMITTED", "COMMITTED", "COMMITTED")
        }
        EffectState::ObservedFailed | EffectState::ResolvedFailed => {
            ("FAILED", "FAILED", "PROVIDER_FAILED")
        }
        EffectState::Rejected => ("REJECTED", "FAILED", "REJECTED"),
        _ => return Ok(None),
    };
    let response = state_request(
        state_socket,
        &serde_json::json!({
            "operation":"effect_observe", "admission_token":token,
            "objective_id":request.objective_id,
            "effect_id":record.effect_id,
        }),
    )
    .ok_or_else(|| io::Error::other("authoritative terminal effect is unavailable"))?;
    let projection = &response["result"]["projection"];
    let evidence_ref = projection["evidence_ref"]
        .as_str()
        .filter(|reference| reference.starts_with("s3://"))
        .ok_or_else(|| io::Error::other("authoritative terminal evidence is missing"))?;
    if response["status"] != "ok"
        || projection["effect_id"] != record.effect_id
        || projection["objective_id"] != request.objective_id
        || projection["request_digest"] != request.parameters_digest
        || projection["state"] != projection_state
    {
        return Err(io::Error::other(
            "local and authoritative terminal effect disagree",
        ));
    }
    Ok(Some(serde_json::json!({
        "schema_version":"2.0", "command_id":request.command_id,
        "objective_id":request.objective_id, "effect_id":record.effect_id,
        "state":state, "code":code, "evidence_ref":evidence_ref,
    })))
}

fn persist_rejection(
    state_socket: &Path,
    token: &str,
    record: &habitat_effects::EffectRecord,
    reason: &str,
) -> io::Result<String> {
    let source = format!("sha256:{:x}", Sha256::digest(reason.as_bytes()));
    persist_provider_transition(state_socket, token, record, None, "REJECTED", &source, None)
}

fn guard_objective(
    ledger: &mut EffectLedger,
    state_socket: &Path,
    token: &str,
    objective: &str,
) -> Result<(), habitat_effects::EffectError> {
    if ledger.complete_objective(objective).is_err() {
        return ledger.mark_guard_pending(objective);
    }
    let effect_ids = ledger.objective_effects(objective);
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&effect_ids).unwrap_or_default())
    );
    let guarded = state_request(
        state_socket,
        &serde_json::json!({
            "operation":"effect_guard", "admission_token":token,
            "objective_id":objective, "effect_ids":effect_ids,
            "effect_set_digest":digest
        }),
    )
    .is_some_and(|response| response["status"] == "ok" && response["result"]["ready"] == true);
    if guarded {
        ledger.clear_guard_pending(objective)
    } else {
        ledger.mark_guard_pending(objective)
    }
}

fn reconcile_pending(
    ledger: &mut EffectLedger,
    store: &PostgresEffectStore,
    state_socket: &Path,
    authority_socket: &Path,
    _provider_socket: &Path,
    token: &str,
) -> Result<(), habitat_effects::EffectError> {
    for effect_id in ledger.recover() {
        let Some(record) = ledger.get(&effect_id).cloned() else {
            continue;
        };
        if record.state == EffectState::Reserved {
            let rejected = state_request(
                state_socket,
                &serde_json::json!({
                    "operation":"effect_observe", "admission_token":token,
                    "objective_id":record.proposal.objective_id,
                    "effect_id":record.effect_id,
                }),
            )
            .is_some_and(|response| {
                let projection = &response["result"]["projection"];
                response["status"] == "ok"
                    && projection["effect_id"] == record.effect_id
                    && projection["objective_id"] == record.proposal.objective_id
                    && projection["request_digest"] == record.proposal.parameters_digest
                    && projection["state"] == "REJECTED"
                    && projection["evidence_ref"]
                        .as_str()
                        .is_some_and(|reference| reference.starts_with("s3://"))
            });
            if rejected {
                ledger.reject_reserved(&effect_id, "authoritative rejection replay")?;
                checkpoint_effect(ledger, store, &effect_id)
                    .map_err(|_| habitat_effects::EffectError::Storage)?;
                continue;
            }
            eprintln!("recovering durable RESERVED effect {effect_id}");
            let Some(authority_request) = record.runtime_authority_request.clone() else {
                eprintln!("reserved recovery blocked: missing authority request for {effect_id}");
                continue;
            };
            let Some(forwarding) = record.runtime_forwarding.as_ref() else {
                eprintln!("reserved recovery blocked: missing forwarding proof for {effect_id}");
                continue;
            };
            let mut status = authority_decision(
                authority_socket,
                &authority_request,
                forwarding,
                "STATUS",
                Some(&effect_id),
            );
            eprintln!(
                "reserved recovery STATUS for {effect_id}: {}",
                status
                    .as_ref()
                    .map(|decision| decision.code.as_str())
                    .unwrap_or("UNAVAILABLE")
            );
            if status
                .as_ref()
                .is_some_and(|decision| decision.code == "PREPARED")
                && record
                    .proposal
                    .valid_until
                    .is_some_and(|until| now() < until)
            {
                // Retry the exact, still-bounded COMMIT. The original request
                // and its runtime MAC are never changed; authority binds the
                // durable reservation to this effect and commits quota once.
                status = authority_decision(
                    authority_socket,
                    &authority_request,
                    forwarding,
                    "COMMIT",
                    Some(&effect_id),
                );
                eprintln!(
                    "reserved recovery COMMIT for {effect_id}: {}",
                    status
                        .as_ref()
                        .map(|decision| decision.code.as_str())
                        .unwrap_or("UNAVAILABLE")
                );
            }
            if status
                .as_ref()
                .is_some_and(|decision| decision.allowed && decision.code == "AUTHORIZED")
            {
                // STATUS can return AUTHORIZED here only for the exact durable
                // COMMIT binding. Its one first dispatch remains valid after
                // the request wall-clock deadline; no fresh authority is
                // minted and the effect/idempotency identity is unchanged.
                let decision = status.expect("checked committed status");
                let attempt = Attempt::new(
                    &record.proposal.parameters_digest,
                    now(),
                    &record.proposal.provider_id,
                    &provider_transport_id(&record),
                );
                ledger.dispatch_runtime(&effect_id, attempt, &decision)?;
                // EXECUTING plus the stable provider transport identity is
                // authoritative in PostgreSQL before any external call.
                checkpoint_effect(ledger, store, &effect_id)
                    .map_err(|_| habitat_effects::EffectError::Storage)?;
                let Ok((committed, evidence_ref)) =
                    execute_observe_and_persist(_provider_socket, state_socket, token, &record)
                else {
                    ledger.transport_lost(&effect_id, "provider response unavailable")?;
                    checkpoint_effect(ledger, store, &effect_id)
                        .map_err(|_| habitat_effects::EffectError::Storage)?;
                    continue;
                };
                ledger.record_provider_response(
                    &effect_id,
                    &serde_json::to_string(&committed).unwrap_or_default(),
                )?;
                checkpoint_effect(ledger, store, &effect_id)
                    .map_err(|_| habitat_effects::EffectError::Storage)?;
                let observation = Observation::independent(
                    "habitat-execution-observe+state-transition",
                    &evidence_ref,
                    committed.outcome == "SUCCEEDED",
                );
                ledger.observe(&effect_id, observation)?;
                checkpoint_effect(ledger, store, &effect_id)
                    .map_err(|_| habitat_effects::EffectError::Storage)?;
                guard_objective(ledger, state_socket, token, &record.proposal.objective_id)?;
                continue;
            }
            // Never mutate and replay the old HMAC-bound request. A PREPARE
            // orphan is durably aborted and the caller must authenticate a
            // fresh request; no external dispatch has occurred at this point.
            if status.is_none_or(|decision| decision.code != "PREPARED") {
                continue;
            }
            let aborted = authority_decision(
                authority_socket,
                &authority_request,
                forwarding,
                "ABORT",
                None,
            )
            .is_some_and(|decision| decision.code == "ABORTED");
            if !aborted {
                continue;
            }
            ledger.reject_reserved(&effect_id, "recovered PREPARE aborted")?;
            persist_rejection(
                state_socket,
                token,
                ledger
                    .get(&effect_id)
                    .ok_or(habitat_effects::EffectError::Storage)?,
                "recovered PREPARE aborted",
            )
            .map_err(|_| habitat_effects::EffectError::Storage)?;
            checkpoint_effect(ledger, store, &effect_id)
                .map_err(|_| habitat_effects::EffectError::Storage)?;
            continue;
        } else if record.state == EffectState::Executing {
            // The admitted provider contract is idempotent by the stable
            // effect/transport identity. Reissuing that exact request closes
            // both sides of the syscall crash boundary without minting a new
            // attempt or a second external effect.
            let Ok((committed, evidence_ref)) =
                execute_observe_and_persist(_provider_socket, state_socket, token, &record)
            else {
                ledger.transport_lost(&effect_id, "provider response unavailable")?;
                checkpoint_effect(ledger, store, &effect_id)
                    .map_err(|_| habitat_effects::EffectError::Storage)?;
                continue;
            };
            ledger.record_provider_response(
                &effect_id,
                &serde_json::to_string(&committed).unwrap_or_default(),
            )?;
            checkpoint_effect(ledger, store, &effect_id)
                .map_err(|_| habitat_effects::EffectError::Storage)?;
            let observation = Observation::independent(
                "habitat-execution-observe+state-transition",
                &evidence_ref,
                committed.outcome == "SUCCEEDED",
            );
            ledger.observe(&effect_id, observation)?;
            checkpoint_effect(ledger, store, &effect_id)
                .map_err(|_| habitat_effects::EffectError::Storage)?;
            guard_objective(ledger, state_socket, token, &record.proposal.objective_id)?;
            continue;
        } else if !matches!(
            record.state,
            EffectState::OutcomeUnknown | EffectState::Reconciling
        ) {
            continue;
        }
        let attempt_number = ledger.reconciliations(&effect_id).len();
        if attempt_number >= MAX_RECONCILIATION_ATTEMPTS {
            continue;
        }
        let state_observation = state_request(
            state_socket,
            &serde_json::json!({
                "operation":"effect_observe", "admission_token":token,
                "objective_id":record.proposal.objective_id,
                "effect_id":record.effect_id,
            }),
        );
        if let Some(terminal) = state_observation.as_ref().filter(|response| {
            response["status"] == "ok"
                && matches!(
                    response["result"]["projection"]["state"].as_str(),
                    Some("COMMITTED" | "FAILED")
                )
        }) {
            let evidence_ref = terminal["result"]["projection"]["evidence_ref"]
                .as_str()
                .ok_or(habitat_effects::EffectError::Storage)?;
            let provider_observation = observe_provider(_provider_socket, &record)
                .map_err(|_| habitat_effects::EffectError::Storage)?;
            let succeeded = terminal["result"]["projection"]["state"] == "COMMITTED"
                && provider_observation.outcome == "SUCCEEDED";
            ledger.begin_reconciliation(
                &effect_id,
                ReconciliationAttempt::new(
                    &record.proposal.parameters_digest,
                    now(),
                    &record.proposal.provider_id,
                    &provider_transport_id(&record),
                ),
            )?;
            ledger.resolve(
                &effect_id,
                Observation::independent(
                    "terminal-state+provider-observe",
                    evidence_ref,
                    succeeded,
                ),
            )?;
            checkpoint_effect(ledger, store, &effect_id)
                .map_err(|_| habitat_effects::EffectError::Storage)?;
            if succeeded {
                guard_objective(ledger, state_socket, token, &record.proposal.objective_id)?;
            }
            continue;
        }
        let provider_result = observe_provider(_provider_socket, &record).or_else(|_| {
            // A crash may occur after the idempotent world mutation but before
            // the provider record rename. Reissuing the exact digest-bound
            // command lets the provider finalize its write-ahead intent;
            // it cannot create a second semantic effect.
            execute_provider(_provider_socket, &record)?;
            observe_provider(_provider_socket, &record)
        });
        // Provider observation is read-only.  Do not durably publish a new
        // reconciliation attempt until it can be classified in the same
        // PostgreSQL checkpoint; a state-service stop must never strand an
        // attempt with nullable source/response/classification provenance.
        ledger.begin_reconciliation(
            &effect_id,
            ReconciliationAttempt::new(
                &record.proposal.parameters_digest,
                now(),
                &record.proposal.provider_id,
                &provider_transport_id(&record),
            ),
        )?;
        match provider_result {
            Ok(provider_observation) => {
                let external_ref = provider_observation.transport_id.clone();
                let observed_state = state_observation.as_ref().and_then(|response| {
                    response["result"]["projection"]["provider_state"].as_str()
                });
                // The state service can lose its response after committing
                // any member of the pre-dispatch transition chain. Resume
                // from the independently observed durable predecessor before
                // publishing UNCERTAIN; every transition is replay-bound.
                let dispatch_ready = resume_dispatch_chain(
                    state_socket,
                    token,
                    &record,
                    &external_ref,
                    observed_state,
                )
                .is_ok();
                // A response-loss crash can occur after state durably accepts
                // DISPATCHED -> UNCERTAIN.  Resume from that observed boundary
                // instead of replaying a stale predecessor forever.
                let uncertain_ready = observed_state == Some("UNCERTAIN")
                    || (dispatch_ready
                        && persist_provider_transition(
                            state_socket,
                            token,
                            &record,
                            Some("DISPATCHED"),
                            "UNCERTAIN",
                            &external_ref,
                            None,
                        )
                        .is_ok());
                if !uncertain_ready {
                    // The original terminal transition may have committed
                    // while its response was lost.  If our stale
                    // DISPATCHED -> UNCERTAIN write is rejected, re-read the
                    // independently verified state before classifying an
                    // outage; this closes the observation/write race.
                    let terminal = state_request(
                        state_socket,
                        &serde_json::json!({
                            "operation":"effect_observe", "admission_token":token,
                            "objective_id":record.proposal.objective_id,
                            "effect_id":record.effect_id,
                        }),
                    )
                    .filter(|response| {
                        response["status"] == "ok"
                            && matches!(
                                response["result"]["projection"]["state"].as_str(),
                                Some("COMMITTED" | "FAILED")
                            )
                    });
                    if let Some(terminal) = terminal {
                        let evidence_ref = terminal["result"]["projection"]["evidence_ref"]
                            .as_str()
                            .ok_or(habitat_effects::EffectError::Storage)?;
                        let succeeded = terminal["result"]["projection"]["state"] == "COMMITTED"
                            && provider_observation.outcome == "SUCCEEDED";
                        ledger.resolve(
                            &effect_id,
                            Observation::independent(
                                "terminal-state+provider-observe",
                                evidence_ref,
                                succeeded,
                            ),
                        )?;
                        checkpoint_effect(ledger, store, &effect_id)
                            .map_err(|_| habitat_effects::EffectError::Storage)?;
                        if succeeded {
                            guard_objective(
                                ledger,
                                state_socket,
                                token,
                                &record.proposal.objective_id,
                            )?;
                        }
                        continue;
                    }
                    // PostgreSQL still owns the attempt while the state
                    // observation boundary is unavailable. Persist a bounded,
                    // nonterminal classification and retry later; do not turn
                    // provider evidence into a terminal claim locally.
                    ledger.reconciliation_inconclusive(
                        &effect_id,
                        "state-observation-unavailable",
                        "UNAVAILABLE:state observation persistence",
                    )?;
                    checkpoint_effect(ledger, store, &effect_id)
                        .map_err(|_| habitat_effects::EffectError::Storage)?;
                    continue;
                }
                let succeeded = provider_observation.outcome == "SUCCEEDED";
                let evidence_ref = persist_provider_transition(
                    state_socket,
                    token,
                    &record,
                    Some("UNCERTAIN"),
                    if succeeded {
                        "RESOLVED_SUCCEEDED"
                    } else {
                        "RESOLVED_FAILED"
                    },
                    &external_ref,
                    Some(&provider_observation),
                )
                .map_err(|_| habitat_effects::EffectError::Storage)?;
                ledger.resolve(
                    &effect_id,
                    Observation::independent(
                        "habitat-execution-observe+state-transition",
                        &evidence_ref,
                        succeeded,
                    ),
                )?;
                if succeeded {
                    guard_objective(ledger, state_socket, token, &record.proposal.objective_id)?;
                }
            }
            Err(error) => ledger.reconciliation_inconclusive(
                &effect_id,
                "provider-observe-unavailable",
                &format!("UNAVAILABLE:{error}"),
            )?,
        }
        checkpoint_effect(ledger, store, &effect_id)
            .map_err(|_| habitat_effects::EffectError::Storage)?;
    }
    Ok(())
}

fn reject(transport: &mut WireTransport) -> io::Result<()> {
    reject_code(transport, "UNAUTHORIZED")
}

fn reject_code(transport: &mut WireTransport, code: &str) -> io::Result<()> {
    transport
        .send_response(
            &serde_json::json!({"schema_version":"2.0", "state":"REJECTED", "code":code})
                .to_string(),
        )
        .map_err(io::Error::other)
}

macro_rules! respond {
    ($transport:expr, $($argument:tt)*) => {{
        $transport
            .send_response(&format!($($argument)*))
            .map_err(io::Error::other)
    }};
}

fn injected_crash(stage: &str) {
    if env::var("HABITAT_TEST_FAULTS").as_deref() != Ok("1") {
        return;
    }
    let marker = PathBuf::from(format!("/run/habitat/effects/fault-{stage}"));
    if marker.exists() {
        let _ = fs::remove_file(marker);
        std::process::exit(75);
    }
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-effects [--describe | SOCKET STATE AUTHORITY PROVIDER LEGACY_LEDGER TOKEN DATABASE_URL PSQL PEERS]",
        )
    })?;
    if first == "--describe" {
        println!("{}", serde_json::json!({"abi":"2.0","service":"effects"}));
        return Ok(());
    }
    let socket = PathBuf::from(first);
    let state_socket = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing state socket"))?,
    );
    let authority_socket =
        PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing authority socket")
        })?);
    let provider_socket =
        PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing provider socket")
        })?);
    let _legacy_ledger_path = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing ledger"))?,
    );
    let token = fs::read_to_string(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing token"))?,
    )?;
    let database_url = fs::read_to_string(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing database URL"))?,
    )?;
    let psql = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing psql"))?,
    );
    let peers: Vec<RuntimePeer> =
        serde_json::from_slice(&fs::read(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing peers")
        })?)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if token.trim().len() < 32 || args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid effect service configuration",
        ));
    }
    let token = token.trim();
    let (database_name, socket_directory) = parse_local_database_url(database_url.trim())?;
    let store = PostgresEffectStore {
        database_name,
        socket_directory,
        psql,
    };
    // PostgreSQL is the production recovery authority.  The Rust ledger is an
    // in-memory semantic cache; the legacy path argument is accepted only for
    // CLI compatibility and is never opened.
    let mut ledger = EffectLedger::new();
    let authoritative = store.recover()?;
    ledger
        .restore_authoritative(&authoritative)
        .map_err(|_| io::Error::other("PostgreSQL effect recovery is corrupt"))?;
    ledger
        .register_provider_durable(ProviderContract::reconcilable(
            "habitat-offline-provider",
            ReconciliationMode::IdempotencyKey,
            ConsequenceClass::E2,
        ))
        .map_err(|_| io::Error::other("effect provider registry unavailable"))?;
    reconcile_pending(
        &mut ledger,
        &store,
        &state_socket,
        &authority_socket,
        &provider_socket,
        token,
    )
    .map_err(|_| io::Error::other("effect reconciliation failed"))?;
    // A crash after the terminal effect checkpoint but before the state guard
    // must not require a client to replay RESUME. Re-derive all guard work from
    // PostgreSQL-restored terminal records at every start.
    for objective in ledger.successful_objectives() {
        guard_objective(&mut ledger, &state_socket, token, &objective)
            .map_err(|_| io::Error::other("effect guard reconstruction failed"))?;
    }
    let services = peers
        .iter()
        .map(|peer| ServicePrincipal::new(&peer.service_id, peer.uid, peer.gid))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let command_policy = ServiceCommandPolicy::new(services.iter().cloned().map(|service| {
        let commands = if service.service_id == "service:runtime" {
            vec![EffectsCommand::Status, EffectsCommand::Submit]
        } else {
            vec![EffectsCommand::Status]
        };
        (service, commands)
    }));
    let listener = ServiceListener::bind(
        &socket,
        SocketPermissions::new(0o660).map_err(io::Error::other)?,
        ServiceAllowlist::new(services),
        StreamTimeouts::new(Duration::from_secs(10), Duration::from_secs(10))
            .map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    listener.set_nonblocking(true)?;
    let mut next_reconciliation = Instant::now() + RECONCILIATION_INTERVAL;
    loop {
        if Instant::now() >= next_reconciliation {
            reconcile_pending(
                &mut ledger,
                &store,
                &state_socket,
                &authority_socket,
                &provider_socket,
                token,
            )
            .map_err(|_| io::Error::other("effect reconciliation failed"))?;
            for objective in ledger.pending_guard_objectives() {
                guard_objective(&mut ledger, &state_socket, token, &objective)
                    .map_err(|_| io::Error::other("effect guard persistence failed"))?;
            }
            next_reconciliation = Instant::now() + RECONCILIATION_INTERVAL;
        }
        let authenticated = match listener.accept() {
            Ok(connection) => connection,
            Err(habitat_uds::TransportError::Io(error))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) if error.is_peer_rejection() => {
                eprintln!("effects peer authentication rejected: {error}");
                continue;
            }
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
        if line.trim() == "STATUS" {
            if command_policy
                .authorize(&service, &EffectsCommand::Status)
                .is_err()
            {
                continue;
            }
            respond!(
                transport,
                "READY migrations=1 leases_fenced=1 effects_classified=1 recovered={} effects={}",
                ledger.recover().len(),
                ledger.len()
            )?;
            continue;
        }
        let Ok(request) = serde_json::from_str::<RuntimeEffectRequest>(&line) else {
            reject(&mut transport)?;
            continue;
        };
        if command_policy
            .authorize(&service, &EffectsCommand::Submit)
            .is_err()
        {
            reject(&mut transport)?;
            continue;
        }
        if service_id != request.caller_service_id {
            reject(&mut transport)?;
            continue;
        }
        if !runtime_effect_request_valid(&request) {
            eprintln!(
                "runtime effect rejected: invalid bound request {}",
                request.command_id
            );
            reject(&mut transport)?;
            continue;
        }
        let mut proposal = EffectProposal::new(
            &request.command_id,
            &request.authority_request.activation_id,
            &request.objective_id,
            &request.authority_request.capability,
            &request.authority_request.operation,
            &request.authority_request.target,
            &request.parameters_digest,
            &request.idempotency_key,
            ConsequenceClass::E2,
            4_102_444_800,
        );
        proposal.provider_id = request.provider_id.clone();
        proposal = proposal.bounded(
            &request.execution_constraint_id,
            request.valid_from,
            request.valid_until,
            request.controller_ack_required,
        );
        if request.authority_request.operation == "compensate" {
            proposal.compensates_effect_id = Some(request.authority_request.target.clone());
        }
        match ledger.runtime_replay(&proposal) {
            Ok(Some(existing)) => {
                match terminal_replay(&state_socket, token, &request, &existing) {
                    Ok(Some(disposition)) => {
                        respond!(transport, "{}", disposition)?;
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        reject_code(&mut transport, "UNAVAILABLE")?;
                        continue;
                    }
                }
            }
            Err(_) => {
                reject(&mut transport)?;
                continue;
            }
            _ => {}
        }
        if now() < request.valid_from || now() >= request.valid_until {
            reject(&mut transport)?;
            continue;
        }
        match objective_precondition(
            &state_socket,
            &request.objective_id,
            request.authority_request.operation == "compensate",
        ) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "runtime effect rejected: objective precondition {}",
                    request.objective_id
                );
                reject(&mut transport)?;
                continue;
            }
            Err(error) => {
                eprintln!(
                    "runtime effect unavailable: objective precondition read failed for {}: {error}",
                    request.objective_id
                );
                reject_code(&mut transport, "UNAVAILABLE")?;
                continue;
            }
        }
        let Some(reservation_decision) = authority_decision(
            &authority_socket,
            &request.authority_request,
            &habitat_authority::RuntimeForwardingEvidence {
                provider_id: request.provider_id.clone(),
                parameters_digest: request.parameters_digest.clone(),
                idempotency_key: request.idempotency_key.clone(),
                proof: request.forwarding_proof.clone(),
            },
            "PREPARE",
            None,
        ) else {
            eprintln!(
                "runtime effect unavailable: authority PREPARE transport failed for {}",
                request.command_id
            );
            reject_code(&mut transport, "UNAVAILABLE")?;
            continue;
        };
        if admit_runtime_effect(&request, &reservation_decision).state != "RESERVED" {
            eprintln!(
                "runtime effect rejected: PREPARE decision code={} allowed={} broker={}",
                reservation_decision.code,
                reservation_decision.allowed,
                reservation_decision.broker_service_id
            );
            reject(&mut transport)?;
            continue;
        }
        injected_crash("after-prepare");
        match ledger.runtime_replay(&proposal) {
            Ok(Some(record))
                if matches!(
                    record.state,
                    EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded
                ) =>
            {
                guard_objective(&mut ledger, &state_socket, token, &request.objective_id)
                    .map_err(|_| io::Error::other("effect guard persistence failed"))?;
                respond!(
                    transport,
                    "{}",
                    serde_json::json!({
                        "schema_version":"2.0", "command_id":request.command_id,
                        "objective_id":request.objective_id, "effect_id":record.effect_id,
                        "state":"COMMITTED", "code":"COMMITTED"
                    })
                )?;
                continue;
            }
            Err(error) => {
                eprintln!("runtime effect rejected during durable reservation: {error:?}");
                reject(&mut transport)?;
                continue;
            }
            _ => {}
        }
        let forwarding = habitat_authority::RuntimeForwardingEvidence {
            provider_id: request.provider_id.clone(),
            parameters_digest: request.parameters_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
            proof: request.forwarding_proof.clone(),
        };
        let record = match ledger.reserve_runtime(
            proposal,
            &reservation_decision,
            forwarding.clone(),
            now(),
        ) {
            Ok(record) => record,
            Err(habitat_effects::EffectError::Storage) => {
                return Err(io::Error::other("effect ledger unavailable"));
            }
            Err(_) => {
                let _ = authority_decision(
                    &authority_socket,
                    &request.authority_request,
                    &forwarding,
                    "ABORT",
                    None,
                );
                reject(&mut transport)?;
                continue;
            }
        };
        injected_crash("before-pg-reserved");
        if let Err(error) = checkpoint_effect(&ledger, &store, &record.effect_id) {
            let _ = authority_decision(
                &authority_socket,
                &request.authority_request,
                &forwarding,
                "ABORT",
                None,
            );
            return Err(error);
        }
        injected_crash("after-pg-reserved");
        if record.state != EffectState::Reserved {
            let completed = matches!(
                record.state,
                EffectState::ObservedSucceeded | EffectState::ResolvedSucceeded
            );
            if completed {
                guard_objective(&mut ledger, &state_socket, token, &request.objective_id)
                    .map_err(|_| io::Error::other("effect guard persistence failed"))?;
            }
            respond!(
                transport,
                "{}",
                serde_json::json!({
                    "schema_version":"2.0", "command_id":request.command_id,
                    "objective_id":request.objective_id, "effect_id":record.effect_id,
                    "state":if completed { "COMMITTED" } else { "REJECTED" },
                    "code":if completed { "COMMITTED" } else { "UNAUTHORIZED" }
                })
            )?;
            continue;
        }
        if now() >= request.valid_until {
            let _ = authority_decision(
                &authority_socket,
                &request.authority_request,
                &forwarding,
                "ABORT",
                None,
            );
            ledger
                .reject_reserved(&record.effect_id, "execution authorization expired")
                .map_err(|_| io::Error::other("failed to reject expired reservation"))?;
            let evidence_ref = persist_rejection(
                &state_socket,
                token,
                ledger
                    .get(&record.effect_id)
                    .ok_or_else(|| io::Error::other("rejected effect disappeared"))?,
                "execution authorization expired",
            )?;
            checkpoint_effect(&ledger, &store, &record.effect_id)?;
            respond!(
                transport,
                "{}",
                serde_json::json!({
                    "schema_version":"2.0", "command_id":request.command_id,
                    "objective_id":request.objective_id, "effect_id":record.effect_id,
                    "state":"FAILED", "code":"REJECTED", "evidence_ref":evidence_ref,
                })
            )?;
            continue;
        }
        injected_crash("before-authority-commit");
        let Some(dispatch_decision) = authority_decision(
            &authority_socket,
            &request.authority_request,
            &forwarding,
            "COMMIT",
            Some(&record.effect_id),
        ) else {
            reject_code(&mut transport, "UNAVAILABLE")?;
            continue;
        };
        injected_crash("after-authority-commit");
        let attempt = Attempt::new(
            &request.parameters_digest,
            now(),
            &request.provider_id,
            &provider_transport_id(&record),
        );
        if ledger
            .dispatch_runtime(&record.effect_id, attempt, &dispatch_decision)
            .inspect_err(|error| {
                eprintln!("runtime effect rejected during dispatch admission: {error:?}")
            })
            .is_err()
        {
            reject(&mut transport)?;
            continue;
        }
        checkpoint_effect(&ledger, &store, &record.effect_id)?;
        injected_crash("before-dispatch");
        let committed =
            execute_observe_and_persist(&provider_socket, &state_socket, token, &record);
        let Ok((committed, evidence_ref)) = committed else {
            if let Err(error) = &committed {
                eprintln!("provider execution or durable observation failed: {error}");
            }
            ledger
                .transport_lost(&record.effect_id, "provider response unavailable")
                .map_err(|_| io::Error::other("failed to persist unknown outcome"))?;
            checkpoint_effect(&ledger, &store, &record.effect_id)?;
            respond!(
                transport,
                "{}",
                serde_json::json!({
                    "schema_version":"2.0", "command_id":request.command_id,
                    "objective_id":request.objective_id, "effect_id":record.effect_id,
                    "state":"OUTCOME_UNKNOWN", "code":"RECONCILIATION_REQUIRED"
                })
            )?;
            continue;
        };
        ledger
            .record_provider_response(
                &record.effect_id,
                &serde_json::to_string(&committed).unwrap_or_default(),
            )
            .map_err(|_| io::Error::other("failed to persist provider response"))?;
        checkpoint_effect(&ledger, &store, &record.effect_id)?;
        let observation = Observation::independent(
            "habitat-execution-observe+state-transition",
            &evidence_ref,
            committed.outcome == "SUCCEEDED",
        );
        let evidence = evidence_ref;
        ledger
            .observe(&record.effect_id, observation)
            .map_err(|_| io::Error::other("effect observation failed"))?;
        checkpoint_effect(&ledger, &store, &record.effect_id)?;
        let succeeded = committed.outcome == "SUCCEEDED";
        if succeeded {
            guard_objective(&mut ledger, &state_socket, token, &request.objective_id)
                .map_err(|_| io::Error::other("effect guard persistence failed"))?;
        }
        respond!(
            transport,
            "{}",
            serde_json::json!({
                "schema_version":"2.0", "command_id":request.command_id,
                "objective_id":request.objective_id, "effect_id":record.effect_id,
                "state":if succeeded { "COMMITTED" } else { "FAILED" },
                "code":if succeeded { "COMMITTED" } else { "PROVIDER_FAILED" },
                "evidence_ref":evidence
            })
        )?;
    }
}
