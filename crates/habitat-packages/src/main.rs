use habitat_uds::{connect_with_timeouts, FrameConfig, JsonTransport, DEFAULT_MAX_PAYLOAD};
use serde_json::{json, Value};
use std::{os::unix::net::UnixStream, time::Duration};

type Transport = JsonTransport<UnixStream, Value, Value>;

fn request(socket: &str, value: Value) -> Result<Value, String> {
    let frames = FrameConfig::new(DEFAULT_MAX_PAYLOAD).map_err(|e| e.to_string())?;
    let mut transport: Transport = connect_with_timeouts(
        socket,
        frames,
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string())?;
    transport.send_request(&value).map_err(|e| e.to_string())?;
    transport.receive_response().map_err(|e| e.to_string())
}

fn accepted(socket: &str, value: Value) -> Result<Value, String> {
    let response = request(socket, value)?;
    (response["status"] == "ok")
        .then(|| response["result"].clone())
        .ok_or_else(|| format!("state rejected governed change: {response}"))
}

fn transition(
    args: &[String],
    candidate: &str,
    sequence: u32,
    state: &str,
    actor: &str,
    evaluator_closure: Option<&str>,
    healthy: bool,
) -> Result<Value, String> {
    accepted(
        &args[2],
        json!({"operation":"change_transition","candidate_id":candidate,
        "command_id":format!("command:{candidate}:{sequence}"),"new_state":state,
        "actor":actor,"evidence_ref":args[6],"evaluator_closure":evaluator_closure,
        "health_ready":healthy}),
    )
}

fn proposal(args: &[String], candidate: &str) -> Value {
    json!({"operation":"change_propose","candidate_id":candidate,
        "command_id":format!("command:{candidate}:propose"),"source_digest":args[3],
        "evaluator":args[7],"evaluator_closure":args[8],
        "target_generation":format!("generation:{candidate}:target"),
        "rollback_generation":format!("generation:{candidate}:rollback"),
        "threshold":{"minimum_score":90},"evidence_ref":args[6]})
}

fn drive_to_activated(args: &[String], candidate: &str) -> Result<(), String> {
    accepted(&args[2], proposal(args, candidate))?;
    for (index, state) in ["BUILT", "EVALUATED", "SIGNED", "STAGED", "ACTIVATED"]
        .into_iter()
        .enumerate()
    {
        let evaluated = state == "EVALUATED";
        transition(
            args,
            candidate,
            index as u32,
            state,
            if evaluated {
                &args[7]
            } else {
                "actor:controller"
            },
            evaluated.then_some(args[8].as_str()),
            false,
        )?;
    }
    Ok(())
}

fn qualify_change(args: &[String]) -> Result<Value, String> {
    if args.len() != 9 {
        return Err("qualify-change requires state socket, source, closure, tests, evaluator, and evaluator closure".into());
    }
    let captured_candidate = "change:qualification-captured";
    accepted(&args[2], proposal(args, captured_candidate))?;
    transition(
        args,
        captured_candidate,
        0,
        "BUILT",
        "actor:controller",
        None,
        false,
    )?;
    let evaluator_capture_rejected = request(
        &args[2],
        json!({
        "operation":"change_transition","candidate_id":captured_candidate,
        "command_id":"command:attack:evaluator","new_state":"EVALUATED","actor":"candidate:self",
        "evidence_ref":args[6],"evaluator_closure":args[8]}),
    )?["status"]
        != "ok";
    let closure_candidate = "change:qualification-closure-capture";
    accepted(&args[2], proposal(args, closure_candidate))?;
    transition(
        args,
        closure_candidate,
        0,
        "BUILT",
        "actor:controller",
        None,
        false,
    )?;
    let evaluator_closure_capture_rejected = request(
        &args[2],
        json!({
        "operation":"change_transition","candidate_id":closure_candidate,
        "command_id":"command:attack:closure","new_state":"EVALUATED","actor":args[6],
        "evidence_ref":args[5],"evaluator_closure":"sha256:captured"}),
    )?["status"]
        != "ok";
    let confirmed = "change:qualification-confirmed";
    drive_to_activated(args, confirmed)?;
    transition(
        args,
        confirmed,
        6,
        "CONFIRMED",
        "health:independent",
        None,
        true,
    )?;
    let rollback = "change:qualification-rollback";
    drive_to_activated(args, rollback)?;
    let attack = request(
        &args[2],
        json!({"operation":"change_transition",
        "candidate_id":rollback,"command_id":"command:attack:self-confirm","new_state":"CONFIRMED",
        "actor":args[7],"evidence_ref":args[6],"health_ready":true}),
    )?;
    transition(
        args,
        rollback,
        7,
        "QUARANTINED",
        "health:independent",
        None,
        false,
    )?;
    let rolled_back = transition(
        args,
        rollback,
        8,
        "ROLLED_BACK",
        "actor:controller",
        None,
        false,
    )?;
    Ok(
        json!({"repository":"postgresql","confirmed_candidate":confirmed,
        "rollback_candidate":rollback,"confirmed_state":"CONFIRMED","rollback_state":"ROLLED_BACK",
        "rollback_generation":rolled_back["rollback_generation"],
        "attacks":{"evaluator_capture_rejected":evaluator_capture_rejected,
            "evaluator_closure_capture_rejected":evaluator_closure_capture_rejected,
            "self_confirmation_rejected":attack["status"] != "ok"}}),
    )
}

fn inspect_change(args: &[String]) -> Result<Value, String> {
    if args.len() != 4 {
        return Err("inspect-change requires state socket and candidate".into());
    }
    accepted(
        &args[2],
        json!({"operation":"change_get","candidate_id":args[3]}),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("qualify-change") => qualify_change(&args),
        Some("inspect-change") => inspect_change(&args),
        _ => Err("usage: habitat-packages {qualify-change|inspect-change} ...".into()),
    };
    match result {
        Ok(value) => println!("{}", serde_json::to_string(&value).expect("serializable")),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
