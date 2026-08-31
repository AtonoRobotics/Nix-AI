#!/usr/bin/env python3
"""Execute governed-change qualification through the habitat-packages state machine."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qualification import canonical_json, closure_digest, derive_metric, digest_file, source_digest

STATE_UNIT = "habitat-state.service"


def service_identity() -> dict[str, str]:
    result = subprocess.run(
        ["systemctl", "show", STATE_UNIT, "--property=MainPID,InvocationID,ActiveState"],
        capture_output=True, text=True, check=True)
    identity = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if identity.get("ActiveState") != "active" or identity.get("MainPID") in {None, "", "0"} \
            or not identity.get("InvocationID"):
        raise SystemExit("deployed state service is not ready")
    return identity


def inspect_postgresql(database_url: str, candidate: str) -> dict:
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        with connection.cursor() as cursor:
            cursor.execute("""SELECT candidate_id,state,target_generation,rollback_generation,
                               evaluator_generation,evaluator_closure,source_digest
                               FROM change_candidates WHERE candidate_id=%s""", (candidate,))
            record = cursor.fetchone()
            cursor.execute("""SELECT version,previous_state,new_state,actor,evidence_ref,observation
                               FROM change_history WHERE candidate_id=%s ORDER BY version""", (candidate,))
            history = cursor.fetchall()
    if not record or not history:
        raise SystemExit(f"durable PostgreSQL state is absent for {candidate}")
    return {"record": record, "history": history}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state-socket", required=True)
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    root, controller = args.root.resolve(), args.controller.resolve()
    if not controller.is_file():
        raise SystemExit("governed-change controller is unavailable")
    evaluator_closure = closure_digest(root)
    evaluator_identity = "evaluator:" + digest_file(controller)
    execution = subprocess.run([
        str(controller), "qualify-change", args.state_socket, source_digest(root), evaluator_closure,
        digest_file(root / "crates/habitat-packages/tests/change_cli.rs"),
        "evidence:" + digest_file(controller), evaluator_identity, evaluator_closure,
    ], cwd=root, capture_output=True, text=True)
    if execution.returncode:
        raise SystemExit(f"governed-change controller failed: {execution.stderr.strip()}")
    controller_output = json.loads(execution.stdout)
    before_restart = service_identity()
    restart = subprocess.run(["systemctl", "restart", STATE_UNIT], cwd=root,
                             capture_output=True, text=True)
    if restart.returncode:
        raise SystemExit(f"state restart failed: {restart.stderr.strip()}")
    after_restart = service_identity()
    if (before_restart["MainPID"] == after_restart["MainPID"]
            or before_restart["InvocationID"] == after_restart["InvocationID"]):
        raise SystemExit("state restart did not change process and service generation")
    candidates = {"confirmed": "change:qualification-confirmed",
                  "rollback": "change:qualification-rollback"}
    durable = {label: inspect_postgresql(args.database_url, candidate)
               for label, candidate in candidates.items()}
    observation = {"repository": "postgresql", "controller_output_sha256":
                   __import__("hashlib").sha256(execution.stdout.encode()).hexdigest(),
                   "restart": {"before": before_restart, "after": after_restart},
                   "post_restart": durable}

    with tempfile.TemporaryDirectory() as temporary:
        clone = Path(temporary) / "tree"
        shutil.copytree(root, clone, ignore=shutil.ignore_patterns(".git", "target", "result"))
        candidate = clone / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
        candidate.write_bytes(candidate.read_bytes() + b"\n")
        mutation = subprocess.run(
            [sys.executable, "tools/derive_v2_contract.py", "--root", str(clone), "--check"],
            cwd=clone, capture_output=True, text=True,
        )
    checks = {
        "governed lifecycle reached independent confirmation": durable["confirmed"]["record"]["state"] == "CONFIRMED",
        "failed candidate rolled back to confirmed generation": durable["rollback"]["record"]["state"] == "ROLLED_BACK" and bool(durable["rollback"]["record"]["rollback_generation"]),
        "candidate self-confirmation was rejected": not any(row["new_state"] == "CONFIRMED" and row["actor"] == evaluator_identity for row in durable["rollback"]["history"]),
        "protected evaluator identity rejected capture": durable["confirmed"]["record"]["evaluator_generation"] == evaluator_identity,
        "protected evaluator closure rejected capture": durable["confirmed"]["record"]["evaluator_closure"] == evaluator_closure,
        "confirmed generation survived state restart": durable["confirmed"]["record"]["state"] == "CONFIRMED" and any((row["observation"] or {}).get("health_ready") is True for row in durable["confirmed"]["history"]),
        "rollback generation survived state restart": durable["rollback"]["record"]["state"] == "ROLLED_BACK",
        "released contract mutation was rejected": mutation.returncode != 0,
    }
    if not all(checks.values()):
        raise SystemExit("one or more governed-change executable observations failed")
    check_observations = {}
    observation_by_name = {}
    for index, (name, passed) in enumerate(checks.items()):
        payload = {"schema_version":"1.0", "kind":"governed_change_check", "name":name,
                   "passed":passed, "provenance":{"database":"postgresql",
                   "restart_invocation":after_restart["InvocationID"]}}
        observation_id = "observation:" + __import__("hashlib").sha256(canonical_json(payload)).hexdigest()
        check_observations[observation_id] = {**payload, "observation_id":observation_id}
        observation_by_name[name] = observation_id
    observed_metrics = {
        "self_confirmed_candidate_count": int(not checks["candidate self-confirmation was rejected"]),
        "evaluator_capture_count": sum(not checks[name] for name in (
            "protected evaluator identity rejected capture",
            "protected evaluator closure rejected capture")),
        "in_place_contract_mutation_count": int(not checks["released contract mutation was rejected"]),
    }
    metric_observations = {}
    metric_derivations = {}
    for metric, value in observed_metrics.items():
        payload = {"schema_version":"1.0", "kind":"metric_observation", "metric":metric,
                   "value":value, "subject":"V-CHANGE", "provenance":{
                   "database":"postgresql", "restart_invocation":after_restart["InvocationID"],
                   "check_observation_ids":sorted(observation_by_name.values())}}
        observation_id = "observation:" + __import__("hashlib").sha256(canonical_json(payload)).hexdigest()
        metric_observations[observation_id] = {**payload, "observation_id":observation_id}
        metric_derivations[metric] = {"metric":metric, "operation":"value",
                                      "observation_ids":[observation_id]}
    metrics = {name:derive_metric(derivation,metric_observations)
               for name,derivation in metric_derivations.items()}
    report = {
        "schema_version": "1.0", "gate": "V-CHANGE",
        "runner": "self_change_adversarial_qualification", "result": "pass",
        "controller_sha256": digest_file(controller),
        "protected_evaluator": evaluator_identity,
        "protected_evaluator_closure": evaluator_closure,
        "deployed_dependencies": [evaluator_identity, evaluator_closure],
        "observation": observation,
        "attacks": [{"case": name, "rejected": passed} for name, passed in checks.items()],
        "metrics": metrics, "metric_derivations":metric_derivations,
        "observations":metric_observations,
        "qualification_result": {"outcome": "passed", "evidence_origin": "executed",
                                 "skip_count": 0,
                                 "assertions": [{"name": item["name"], "passed": item["passed"],
                                                 "observation_id":observation_id}
                                                for observation_id,item in check_observations.items()]},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    print(canonical_json(report).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
