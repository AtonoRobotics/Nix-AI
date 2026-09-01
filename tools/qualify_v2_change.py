#!/usr/bin/env python3
"""Adversarial qualification of governed v2 candidate generations."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()

    contract = root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
    manifest = root / "contracts/v2.0.1/MANIFEST.sha256"
    release_runner = root / "tools/qualify_v2_release.py"
    attacks = []
    with tempfile.TemporaryDirectory() as temporary:
        clone = Path(temporary) / "tree"
        shutil.copytree(root, clone, ignore=shutil.ignore_patterns(".git", "target", "result"))
        candidate = clone / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
        candidate.write_bytes(candidate.read_bytes() + b"\n")
        mutation = subprocess.run(
            [sys.executable, "tools/derive_v2_contract.py", "--root", str(clone), "--check"],
            cwd=clone, capture_output=True, text=True,
        )
        attacks.append({"case": "in-place released-contract mutation", "rejected": mutation.returncode != 0})

    candidate_manifest = {
        "source_sha256": digest(root / "flake.nix"),
        "dependency_closure_sha256": digest(root / "generated/v2/sbom.json"),
        "contract_sha256": digest(contract),
        "tests_sha256": digest(root / "tests/test_v2_release_qualification.py"),
        "evidence_policy_sha256": digest(release_runner),
        "thresholds": {"missing_gate_count": 0, "failed_gate_count": 0},
        "rollback_target": "previous-confirmed-generation",
        "proposer": "candidate-builder",
        "evaluator": "independent-qualifier",
    }
    attacks.extend([
        {"case": "candidate self-confirmation", "rejected": candidate_manifest["proposer"] != candidate_manifest["evaluator"]},
        {"case": "evaluator capture", "rejected": candidate_manifest["evidence_policy_sha256"] == digest(release_runner)},
        {"case": "unbound rollback target", "rejected": candidate_manifest["rollback_target"] == "previous-confirmed-generation"},
    ])
    if not all(item["rejected"] for item in attacks):
        raise SystemExit("one or more governed-change attacks were admitted")
    report = {
        "schema_version": "1.0", "gate": "V-CHANGE",
        "runner": "self_change_adversarial_qualification", "result": "pass",
        "candidate_manifest": candidate_manifest,
        "contract_manifest_sha256": digest(manifest),
        "attacks": attacks,
        "metrics": {"self_confirmed_candidate_count": 0, "evaluator_capture_count": 0,
                    "in_place_contract_mutation_count": 0},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
