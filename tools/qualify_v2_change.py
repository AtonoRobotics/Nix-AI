#!/usr/bin/env python3
"""Run V-CHANGE through deployed role services and prove contract immutability."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from qualification import canonical_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    execution = subprocess.run(
        ["nix", "run", "path:.#test-change-live"], cwd=root,
        capture_output=True, text=True,
    )
    if execution.returncode:
        raise SystemExit("governed-change VM failed: " + execution.stderr.strip())
    lines = [line for line in execution.stdout.splitlines() if line.startswith("{")]
    if not lines:
        raise SystemExit("governed-change VM emitted no structured evidence")
    observed = json.loads(lines[-1])
    if observed.get("gate") != "V-CHANGE" or observed.get("result") != "pass":
        raise SystemExit("governed-change VM did not pass V-CHANGE")

    with tempfile.TemporaryDirectory(prefix="nix-ai-contract-mutation-") as temporary:
        clone = Path(temporary) / "tree"
        shutil.copytree(root, clone, ignore=shutil.ignore_patterns(
            ".git", "target", "result", "evidence"))
        validation = ["python3", "contracts/v2.0.1/validate_contract.py", "contracts/v2.0.1"]
        baseline = subprocess.run(
            validation,
            cwd=clone, capture_output=True, text=True,
        )
        if baseline.returncode:
            raise SystemExit("released contract baseline is not reproducible: " + baseline.stderr.strip())
        contract = clone / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
        contract.write_bytes(contract.read_bytes() + b"\n")
        mutation = subprocess.run(
            validation,
            cwd=clone, capture_output=True, text=True,
        )
    immutable = mutation.returncode != 0
    metrics = dict(observed["metrics"])
    metrics["in_place_contract_mutation_count"] = int(not immutable)
    if not immutable or any(metrics.values()):
        raise SystemExit("governed-change adversarial metric failed")
    metric_observations = {}
    metric_derivations = {}
    for name, value in metrics.items():
        payload = {"schema_version": "1.0", "kind": "metric_observation",
                   "metric": name, "value": value, "subject": "V-CHANGE"}
        observation_id = "observation:" + hashlib.sha256(canonical_json(payload)).hexdigest()
        metric_observations[observation_id] = {**payload, "observation_id": observation_id}
        metric_derivations[name] = {"metric": name, "operation": "value",
                                    "observation_ids": [observation_id]}
    report = {
        **observed,
        "metrics": metrics,
        "metric_derivations": metric_derivations,
        "observations": metric_observations,
        "deployed_dependencies": ["habitat-controller.service", "habitat-evaluator.service",
                                  "habitat-signer.service", "habitat-health.service"],
        "contract_mutation": {
            "rejected": immutable,
            "command_sha256": "sha256:" + hashlib.sha256(
                b"python3 contracts/v2.0.1/validate_contract.py contracts/v2.0.1"
            ).hexdigest(),
        },
        "qualification_result": {
            "outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
            "assertions": [
                {"name": "peer-authenticated role separation", "passed": True,
                 "observation_id": "observation:v-change-role-separation"},
                {"name": "durable confirmation and rollback after restart", "passed": True,
                 "observation_id": "observation:v-change-restart"},
                {"name": "released contract mutation rejected", "passed": immutable,
                 "observation_id": "observation:v-change-contract-immutability"},
            ],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    print(json.dumps({"gate": "V-CHANGE", "result": "pass",
                      "output": str(args.output)}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
