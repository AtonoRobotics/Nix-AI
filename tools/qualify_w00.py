#!/usr/bin/env python3
"""Run the transitional v2 contract qualification boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


REPORTS = ("contract-validation-report", "generation-no-diff-report")
REQUIREMENTS = {
    "BLD-001", "BLD-002", "BLD-004", "BLD-009", "BLD-010",
    "GOV-001", "GOV-002", "GOV-003", "GOV-004", "GOV-005", "GOV-006",
}


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", provenance.get("source_tree_digest", "")):
        raise SystemExit("W00 provenance has an invalid qualified source-tree digest")
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
    run([sys.executable, "tools/validate_contracts.py", str(root)], root)
    run(["sha256sum", "--check", "MANIFEST.sha256"], root / "contracts" / "architecture")
    print("W00 transitional v2 qualification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
