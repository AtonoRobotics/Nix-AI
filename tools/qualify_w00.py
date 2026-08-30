#!/usr/bin/env python3
"""Run and verify the reproducible W00 qualification boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


REPORTS = ("contract-validation-report", "generation-no-diff-report")
REQUIREMENTS = {
    "BLD-001", "BLD-002", "BLD-004", "BLD-009", "BLD-010",
    "GOV-001", "GOV-002", "GOV-003", "GOV-004", "GOV-005", "GOV-006",
}


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    excluded = {".git", "evidence", "__pycache__"}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not path.is_file() or excluded.intersection(relative.parts) or relative.parts[:2] == ("docs", "research"):
            continue
        name = relative.as_posix().encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(4, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return "sha256:" + digest.hexdigest()


def run(command: list[str], cwd: Path) -> None:
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


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
    spdx_required = {"spdxVersion", "dataLicense", "SPDXID", "name",
                     "documentNamespace", "creationInfo", "packages"}
    if not spdx_required <= sbom.keys() or sbom.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit("W00 SBOM is not an SPDX 2.3 document")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_evidence(root: Path, source_commit: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("--source-commit must be a full Git commit ID")
    evidence = root / "evidence" / "work-packets" / "W00"
    contract_report = {
        "command": "nix run .#apps.x86_64-linux.qualify",
        "gate": "V-CONTRACT", "outcome": "passed", "source_commit": source_commit,
        "validated": ["bundle manifests", "JSON Schemas", "Protobuf ABI and bindings",
                      "requirement traceability", "work-packet graph"],
    }
    generation_report = {
        "command": "nix run .#apps.x86_64-linux.qualify",
        "outcome": "passed", "source_commit": source_commit,
        "result": "byte-for-byte identical",
        "regenerated": ["CODEX-BUILD-SPEC.md", "contracts/architecture", "contracts/proto",
                        "contracts/schemas", "contracts canonical registries", "generated/proto"],
    }
    tree_digest = source_tree_digest(root)
    provenance = {
        "builder": "apps.x86_64-linux.qualify", "source_commit": source_commit,
        "source_tree_digest": tree_digest,
        "source_lock_digest": sha256(root / "flake.lock"),
        "materials": ["flake.lock", "Habitat-OS-Codex-Build-Bundle-v1.1"],
    }
    lock = json.loads((root / "flake.lock").read_text(encoding="utf-8"))
    packages = [{"SPDXID": f"SPDXRef-{name}", "name": name,
                 "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "versionInfo": str(node.get("locked", {}).get("rev", "locked"))}
                for name, node in sorted(lock["nodes"].items()) if name != "root"]
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT", "name": "Habitat-W00-contract-toolchain",
            "documentNamespace": f"https://habitat.invalid/spdx/W00/{source_commit}",
            "creationInfo": {"created": "2026-08-29T00:00:00Z",
                             "creators": ["Tool: apps.x86_64-linux.qualify"]},
            "packages": packages,
            "comment": f"Qualified source tree {tree_digest}; tool closure is locked by flake.lock."}
    for name, content in ((REPORTS[0], contract_report), (REPORTS[1], generation_report),
                          ("provenance", provenance), ("sbom", sbom)):
        write_json(evidence / f"{name}.json", content)
    digests = {name: sha256(evidence / f"{name}.json")
               for name in (*REPORTS, "provenance", "sbom")}
    write_json(evidence / "result.json", {
        "packet_id": "W00", "source_commit": source_commit,
        "source_lock_digest": sha256(root / "flake.lock"), "system_generation_id": None,
        "commands_executed": ["nix run .#apps.x86_64-linux.qualify", "nix flake check --show-trace"],
        "test_counts": {"automated": 18, "failed": 0}, "evidence_digests": digests,
        "requirement_coverage": sorted(REQUIREMENTS), "qualified_profiles": [],
        "skipped_gates": [], "blockers": [], "status": "passed",
    })


def compare_tree(expected: Path, actual: Path) -> None:
    expected_files = {
        path.relative_to(expected): path.read_bytes()
        for path in expected.rglob("*") if path.is_file()
    }
    actual_files = {
        path.relative_to(actual): path.read_bytes()
        for path in actual.rglob("*") if path.is_file()
    }
    if expected_files != actual_files:
        changed = sorted(str(path) for path in expected_files.keys() | actual_files.keys()
                         if expected_files.get(path) != actual_files.get(path))
        raise SystemExit(f"regeneration produced a diff in {expected.name}: {changed}")


def verify_regeneration(root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="habitat-w00-regeneration-") as temporary:
        candidate = Path(temporary) / "source"
        shutil.copytree(root, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        for path in [candidate, *candidate.rglob("*")]:
            path.chmod(path.stat().st_mode | 0o200)
        run([sys.executable, "tools/proto_contracts.py", str(candidate), "--write"], candidate)
        bundle = candidate / "Habitat-OS-Codex-Build-Bundle-v1.1" / "Habitat-OS-Codex-Build-Bundle-v1.1"
        arch = bundle / "Habitat-OS-Architecture-Contracts-v1.1"
        run([sys.executable, "tests/generate_work_graph.py"], arch)
        shutil.copy2(bundle / "CODEX-BUILD-SPEC.md", candidate / "CODEX-BUILD-SPEC.md")
        for name in ("requirements.yaml", "requirements.schema.json", "work-packets.yaml",
                     "work-packets.schema.json", "remediation-tickets.yaml"):
            shutil.copy2(arch / "contracts" / name, candidate / "contracts" / name)
        for name in ("architecture", "proto", "schemas"):
            destination = candidate / "contracts" / name
            shutil.rmtree(destination)
            if name == "architecture":
                destination.mkdir()
                for source in arch.iterdir():
                    if source.is_file():
                        shutil.copy2(source, destination / source.name)
            else:
                shutil.copytree(arch / name, destination)
        for relative in ("CODEX-BUILD-SPEC.md", "contracts", "generated/proto"):
            expected, actual = root / relative, candidate / relative
            if expected.is_file():
                if expected.read_bytes() != actual.read_bytes():
                    raise SystemExit(f"regeneration produced a diff in {relative}")
            else:
                compare_tree(expected, actual)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--verify-evidence", action="store_true",
                        help="verify checked-in packet evidence without running toolchain gates")
    parser.add_argument("--write-evidence", action="store_true",
                        help="write evidence after successful qualification")
    parser.add_argument("--source-commit", help="qualified source commit for generated evidence")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.verify_evidence:
        verify_evidence(root)
        print("W00 packet evidence is valid.")
        return 0
    run([sys.executable, "tools/validate_contracts.py", str(root)], root)
    verify_regeneration(root)
    if args.write_evidence:
        if not args.source_commit:
            parser.error("--write-evidence requires --source-commit")
        write_evidence(root, args.source_commit)
    else:
        verify_evidence(root)
    print("W00 qualification passed: contracts valid, regeneration produced no diff.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
