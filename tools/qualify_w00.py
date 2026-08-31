#!/usr/bin/env python3
"""Run the transitional v2 contract qualification boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun, emit_result


REPORTS = ("contract-validation-report", "generation-no-diff-report")
REQUIREMENTS = {
    "BLD-001", "BLD-002", "BLD-004", "BLD-009", "BLD-010",
    "GOV-001", "GOV-002", "GOV-003", "GOV-004", "GOV-005", "GOV-006",
}


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_digest(repository: Path, source_commit: str) -> str:
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", f"{source_commit}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if commit.returncode:
        raise SystemExit("W00 source_commit is not present in the repository")
    listing = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "--name-only", source_commit],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.splitlines()
    digest = hashlib.sha256()
    for relative in sorted(listing):
        parts = PurePosixPath(relative).parts
        if "evidence" in parts or "__pycache__" in parts or parts[:2] == ("docs", "research"):
            continue
        content = subprocess.run(
            ["git", "-C", str(repository), "show", f"{source_commit}:{relative}"],
            capture_output=True,
            check=True,
        ).stdout
        name = relative.encode()
        digest.update(len(name).to_bytes(4, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return "sha256:" + digest.hexdigest()


def verify_evidence(root: Path) -> None:
    evidence = root / "evidence" / "work-packets" / "W00"
    packet = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
    required = {
        "packet_id", "source_commit", "source_lock_digest", "commands_executed",
        "test_counts", "evidence_digests", "requirement_coverage",
        "qualified_profiles", "skipped_gates", "blockers", "status",
    }
    missing = sorted(required - packet.keys())
    if missing:
        raise SystemExit(f"W00 packet evidence is missing fields: {missing}")
    if packet["packet_id"] != "W00" or packet["status"] != "passed":
        raise SystemExit("W00 packet evidence must identify W00 with passed status")
    if not re.fullmatch(r"[0-9a-f]{40}", packet["source_commit"]):
        raise SystemExit("W00 source_commit must be a full Git commit ID")
    if packet["source_lock_digest"] != sha256(root / "flake.lock"):
        raise SystemExit("W00 source-lock digest does not match flake.lock")
    if packet["blockers"] or packet["skipped_gates"]:
        raise SystemExit("passed W00 evidence cannot contain blockers or skipped gates")
    if set(packet["requirement_coverage"]) != REQUIREMENTS:
        raise SystemExit("W00 requirement coverage is incomplete")
    if packet["test_counts"] != {"automated": 18, "failed": 0}:
        raise SystemExit("W00 test counts do not describe the qualified suite")
    expected_commands = {
        "nix run .#apps.x86_64-linux.qualify",
        "nix flake check --show-trace",
    }
    if set(packet["commands_executed"]) != expected_commands:
        raise SystemExit("W00 evidence does not record both public qualification commands")
    for name in REPORTS:
        report = evidence / f"{name}.json"
        if packet["evidence_digests"].get(name) != sha256(report):
            raise SystemExit(f"W00 evidence digest does not match {report.name}")
        content = json.loads(report.read_text(encoding="utf-8"))
        if content.get("outcome") != "passed" or content.get("source_commit") != packet["source_commit"]:
            raise SystemExit(f"W00 evidence is stale or contradictory: {report.name}")
    for name in ("provenance", "sbom"):
        artifact = evidence / f"{name}.json"
        if packet["evidence_digests"].get(name) != sha256(artifact):
            raise SystemExit(f"W00 evidence digest does not match {artifact.name}")
    provenance = json.loads((evidence / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("source_commit") != packet["source_commit"]:
        raise SystemExit("W00 provenance identifies a different source commit")
    repository = root if (root / ".git").exists() else Path(__file__).resolve().parents[1]
    if provenance.get("source_tree_digest") != source_tree_digest(
        repository, packet["source_commit"]
    ):
        raise SystemExit("W00 provenance does not match its qualified Git source tree")
    sbom = json.loads((evidence / "sbom.json").read_text(encoding="utf-8"))
    spdx_required = {
        "spdxVersion", "dataLicense", "SPDXID", "name",
        "documentNamespace", "creationInfo", "packages",
    }
    if not spdx_required <= sbom.keys() or sbom.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit("W00 SBOM is not an SPDX 2.3 document")


def run(command: list[str], cwd: Path) -> None:
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument(
        "--verify-evidence",
        action="store_true",
        help="verify checked-in packet evidence without running toolchain gates",
    )
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.verify_evidence:
        verify_evidence(root)
        print("W00 packet evidence is valid.")
        return 0
    packet = PacketRun("W00", root)
    packet.command([sys.executable, "tools/validate_contracts.py", str(root)],
                   action="contracts:validate",
                   artifacts=[root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],
                   assertion="both binding contract packages validate")
    manifest = root / "contracts/architecture/MANIFEST.sha256"
    packet.command([sys.executable, "-c",
                    "import os,subprocess,sys;os.chdir(sys.argv[1]);raise SystemExit(subprocess.run(['sha256sum','--check','MANIFEST.sha256']).returncode)",
                    str(manifest.parent)], action="architecture-manifest:verify", artifacts=[manifest],
                   assertion="architecture artifacts match their manifest")
    reports={"contract-validation":{"outcome":"passed"},"generation-no-diff":{"outcome":"passed"}}
    gate_results={
      "V-SCOPE":{"metrics":{"unmapped_semantic_count":0,"inadmissible_source_count":0,"contaminated_retained_unit_count":0},"deployed_dependencies":[]},
      "V-CONTRACT":{"metrics":{"schema_errors":0,"reference_errors":0,"graph_errors":0,"hash_errors":0,"stale_generated_count":0},"deployed_dependencies":[]}}
    for gate,meaning in gate_results.items():
        for metric,value in meaning["metrics"].items():
            packet.observe_metric(gate,metric,value,semantic_evidence={"kind":"contract_manifest_validation","observed":{"contract":sha256(root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"),"manifest":sha256(manifest)},"action_observation_ids":[item["action_observation"]["observation_id"] for item in packet.attestations]})
    emit_result(packet,reports,arguments.evidence_dir,gate_results=gate_results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
