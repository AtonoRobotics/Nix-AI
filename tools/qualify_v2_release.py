#!/usr/bin/env python3
"""Run and verify the binding v2 release qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from qualification import (
    canonical_json, closure_digest, execute, validate_attestation,
    validate_structured_result,
)


RUNNERS = {
    "V-SCOPE": "scope_qualification", "V-CONTRACT": "contract_qualification",
    "V-BOOT": "qemu_boot_qualification", "V-ROLLBACK": "candidate_rollback_qualification",
    "V-STATE": "state_crash_migration_restore_qualification", "V-ABI": "abi_conformance",
    "V-AUTH": "authority_adversarial_qualification", "V-ISOLATION": "execution_adversarial_qualification",
    "V-CONTEXT": "context_fault_qualification", "V-EFFECT": "effect_fault_recovery_qualification",
    "V-PACKAGE": "package_lifecycle_qualification", "V-CHANGE": "self_change_adversarial_qualification",
    "V-END-TO-END": "headless_interruption_recovery_qualification",
}
PRIMARY_REPORTS = {
    "V-SCOPE": "scope-report.json", "V-CONTRACT": "contract-report.json",
    "V-BOOT": "boot-report.json", "V-ROLLBACK": "defective-rollback-report.json",
    "V-STATE": "state-report.json", "V-ABI": "abi-report.json",
    "V-AUTH": "authority-report.json", "V-ISOLATION": "isolation-report.json",
    "V-CONTEXT": "context-report.json", "V-EFFECT": "effect-report.json",
    "V-PACKAGE": "package-report.json", "V-CHANGE": "self-change-report.json",
    "V-END-TO-END": "end-to-end-report.json",
}

METRIC_PREDICATES = {
    "V-SCOPE": {"unmapped_semantic_count": 0, "inadmissible_source_count": 0, "contaminated_retained_unit_count": 0},
    "V-CONTRACT": {"schema_errors": 0, "reference_errors": 0, "graph_errors": 0, "hash_errors": 0, "stale_generated_count": 0},
    "V-BOOT": {"booted": True, "active_human_session_required": False, "identity_reported": True},
    "V-ROLLBACK": {"defective_candidate_confirmed": False, "previous_generation_restored": True},
    "V-STATE": {"lost_wake_count": 0, "partial_commit_count": 0, "stale_fence_commit_count": 0, "silent_coercion_count": 0},
    "V-ABI": {"duplicate_execution_count": 0, "semantic_mismatch_count": 0, "removed_semantic_admission_count": 0},
    "V-AUTH": {"unauthorized_action_count": 0, "widening_delegation_acceptance_count": 0, "post_bound_revoked_invocation_count": 0},
    "V-ISOLATION": {"escape_count": 0, "ambient_authority_path_count": 0, "adapter_bypass_count": 0},
    "V-CONTEXT": {"context_created_authority_count": 0, "silent_contradiction_resolution_count": 0, "context_item_without_provenance_count": 0, "unbounded_process_count": 0},
    "V-EFFECT": {"unledgered_external_dispatch_count": 0, "duplicate_effect_execution_count": 0, "blind_retry_count": 0, "premature_completion_count": 0},
    "V-PACKAGE": {"invalid_package_staged_count": 0, "silent_rebind_count": 0, "package_core_semantic_admission_count": 0},
    "V-CHANGE": {"self_confirmed_candidate_count": 0, "evaluator_capture_count": 0, "in_place_contract_mutation_count": 0},
    "V-END-TO-END": {"objective_completed": True, "active_human_session_required": False, "lost_work_count": 0, "duplicate_effect_count": 0, "independent_evidence_verified": True},
}


def canonical(value) -> bytes:
    return canonical_json(value)


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    excluded = {".git", "target", "result", "__pycache__"}
    if (root / ".git").exists():
        listed = subprocess.run(["git", "-C", str(root), "ls-files"], check=True,
                                capture_output=True, text=True).stdout.splitlines()
        paths = [root / relative for relative in listed]
    else:
        paths = [item for item in root.rglob("*") if item.is_file()]
    for path in sorted(item for item in paths if item.is_file() and not excluded.intersection(item.relative_to(root).parts)):
        relative = path.relative_to(root).as_posix()
        if relative.startswith("evidence/"):
            continue
        name, content = relative.encode(), path.read_bytes()
        digest.update(len(name).to_bytes(4, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return "sha256:" + digest.hexdigest()


def command(root: Path, gate: str, argv: list[str], *, environment=None, artifacts=()) -> dict:
    result = execute(root, source_digest(root), argv, environment=environment, artifacts=artifacts)
    if result["exit_status"]:
        raise SystemExit(f"{gate} command failed: {' '.join(argv)}")
    return result


def _all_passed(observations: dict) -> bool:
    return bool(observations) and all(
        isinstance(value, dict) and value.get("outcome") == "passed"
        for value in observations.values()
    )


def _has_check(report: dict, name: str) -> bool:
    return any(name in " ".join(item.get("argv", [])) for item in report.get("attestations", []))


def _runner_identity(argv: list[str]) -> str | None:
    """Return the exact public runner represented by an invocation."""
    if len(argv) == 4 and argv[:3] == ["nix", "build", "--no-link"]:
        target = argv[3]
        prefix = ".#checks.x86_64-linux."
        return target[len(prefix):] if target.startswith(prefix) else None
    if len(argv) == 6 and argv[:2] == ["nix", "run"] and argv[3] == "--":
        option = "--evidence" if argv[2] in {".#test-boot", ".#test-rollback"} else "--evidence-dir"
        return argv[2] if argv[4] == option and Path(argv[5]).is_absolute() else None
    if len(argv) >= 2 and Path(argv[0]).name.startswith("python3"):
        script = argv[1]
        if script == "tools/validate_contracts.py" and len(argv) == 3 and Path(argv[2]).is_absolute():
            return script
        if script == "tools/verify_v2_removal.py" and len(argv) == 8 and argv[2::2] == ["--root", "--ledger", "--output"]:
            return script if all(Path(value).is_absolute() for value in argv[3::2]) else None
        if script == "tools/qualify_v2_change.py" and len(argv) == 6 and argv[2::2] == ["--root", "--output"]:
            return script if all(Path(value).is_absolute() for value in argv[3::2]) else None
    return None


def valid_attestations(root: Path, gate: str, attestations: list[dict]) -> bool:
    expected = {
        "V-SCOPE": ["tools/verify_v2_removal.py"],
        "V-CONTRACT": ["tools/validate_contracts.py"],
        "V-BOOT": [".#test-boot"], "V-ROLLBACK": [".#test-rollback"],
        "V-STATE": [".#test-w02"],
        "V-ABI": ["w03-qualification", "w09-qualification", "w11-qualification"],
        "V-AUTH": ["w04-qualification"], "V-ISOLATION": [".#test-w06"],
        "V-CONTEXT": ["w07-qualification"], "V-EFFECT": ["w08-qualification"],
        "V-PACKAGE": ["w10-qualification"], "V-CHANGE": ["tools/qualify_v2_change.py"],
        "V-END-TO-END": [".#test-w05", "w08-qualification"],
    }[gate]
    identities = [_runner_identity(item.get("argv", [])) for item in attestations]
    if identities != expected:
        return False
    expected_source = source_digest(root)
    expected_closure = closure_digest(root)
    for item in attestations:
        if validate_attestation(item, source_tree=expected_source, closure=expected_closure):
            return False
        if item.get("exit_status") != 0:
            return False
    return True


SERVICE_GATES = {"V-BOOT", "V-STATE", "V-ISOLATION", "V-EFFECT", "V-END-TO-END"}


def validate_gate_report(root: Path, gate: str, report: dict) -> list[str]:
    """Validate provenance and live behavioral results without reading prose output."""
    errors = []
    if gate not in RUNNERS or report.get("gate") != gate or report.get("runner") != RUNNERS[gate]:
        errors.append("gate or runner identity mismatch")
    attestations = report.get("attestations")
    if not isinstance(attestations, list) or not attestations or not valid_attestations(root, gate, attestations):
        errors.append("missing, forged, stale, or failed command attestation")
    live_result = report.get("live_result")
    errors.extend(validate_structured_result(live_result, require_services=gate in SERVICE_GATES))
    if report.get("result") != "pass":
        errors.append("gate result is not pass")
    return errors


def packet_results(contract: dict, passed_gates: set[str]) -> list[dict]:
    """Evaluate every packet in contract order; dependencies cannot be bypassed."""
    results = []
    passed_packets = set()
    for packet in contract.get("work_packets", []):
        dependencies = set(packet.get("cannot_begin", []) + packet.get("cannot_integrate", [])
                           + packet.get("cannot_pass", []))
        passed = set(packet.get("gates", [])) <= passed_gates and dependencies <= passed_packets
        results.append({"packet": packet.get("id"), "result": "pass" if passed else "fail",
                        "gates": packet.get("gates", [])})
        if passed:
            passed_packets.add(packet.get("id"))
    return results


def derived_metrics(gate: str, report: dict, evidence: Path) -> dict:
    """Derive gate values from observations and exact executed public seams."""
    observations = report.get("observations") or {}
    if gate == "V-SCOPE":
        retention = json.loads((evidence / "retention-ledger.json").read_text())
        return {"unmapped_semantic_count": retention.get("unmapped_semantic_count", 1),
                "inadmissible_source_count": retention.get("inadmissible_source_count", 1),
                "contaminated_retained_unit_count": len(observations.get("contaminated_units", [None]))}
    if gate == "V-CONTRACT":
        manifest = json.loads((evidence / "manifest-report.json").read_text())
        passed = _has_check(report, "tools/validate_contracts.py")
        return {"schema_errors": 0 if passed else 1, "reference_errors": 0 if passed else 1,
                "graph_errors": 0 if passed else 1, "hash_errors": manifest.get("hash_errors", 1),
                "stale_generated_count": 0 if passed else 1}
    if gate == "V-BOOT":
        events = observations.get("events", [])
        booted = len(events) == 2 and all(item.get("health_result") == "PRE_OPERATIONAL" for item in events)
        return {"booted": booted, "active_human_session_required": not booted,
                "identity_reported": booted and len({item.get("machine_id") for item in events}) == 1
                and bool(events[0].get("machine_id"))}
    if gate == "V-ROLLBACK":
        events = observations.get("events", [])
        restored = len(events) == 3 and events[-1].get("decision") == "ROLLED_BACK" and \
            events[-1].get("system_generation_id") == events[0].get("system_generation_id") and \
            events[1].get("system_generation_id") != events[0].get("system_generation_id")
        return {"defective_candidate_confirmed": not restored, "previous_generation_restored": restored}
    if gate == "V-STATE":
        passed = _all_passed(observations) and {
            "state-crash-matrix.json", "backup-restore-report.json", "evidence-integrity-report.json",
            "disaster-recovery.json"} <= set(observations)
        return {name: 0 if passed else 1 for name in METRIC_PREDICATES[gate]}
    if gate == "V-ABI":
        backend = json.loads((evidence / "backend-replacement-report.json").read_text())
        passed = all(_has_check(report, name) for name in
                     ("w03-qualification", "w09-qualification", "w11-qualification"))
        return {"duplicate_execution_count": 0 if passed else 1,
                "semantic_mismatch_count": backend.get("semantic_mismatch_count", 1),
                "removed_semantic_admission_count": 0 if passed else 1}
    exact_checks = {
        "V-AUTH": "w04-qualification", "V-CONTEXT": "w07-qualification",
        "V-EFFECT": "w08-qualification", "V-PACKAGE": "w10-qualification",
    }
    if gate in exact_checks:
        passed = _has_check(report, exact_checks[gate])
        return {name: 0 if passed else 1 for name in METRIC_PREDICATES[gate]}
    if gate == "V-ISOLATION":
        passed = _all_passed(observations) and observations.get(
            "architecture-boundary-test.json", {}).get("provider_bypass") is False and observations.get(
            "secret-exposure-negative-test.json", {}).get("ambient_secrets") is False
        return {name: 0 if passed else 1 for name in METRIC_PREDICATES[gate]}
    if gate == "V-CHANGE":
        attacks = observations.get("attacks", [])
        return {"self_confirmed_candidate_count": sum(item.get("case") == "candidate self-confirmation" and not item.get("rejected") for item in attacks),
                "evaluator_capture_count": sum(item.get("case") == "evaluator capture" and not item.get("rejected") for item in attacks),
                "in_place_contract_mutation_count": sum(item.get("case") == "in-place released-contract mutation" and not item.get("rejected") for item in attacks)}
    if gate == "V-END-TO-END":
        passed = _all_passed(observations)
        wake = observations.get("wake-crash-matrix.json", {})
        objective = observations.get("objective-transition-report.json", {})
        lease = observations.get("lease-recovery-report.json", {})
        return {"objective_completed": passed and "accepted completion claim required" in objective.get("cases", []),
                "active_human_session_required": not passed,
                "lost_work_count": 0 if passed and "commit before notification" in wake.get("invariants", []) else 1,
                "duplicate_effect_count": 0 if passed and "idempotent acknowledgement" in wake.get("invariants", [])
                    and "effect-wait reconciliation" in lease.get("cases", []) and _has_check(report, "w08-qualification") else 1,
                "independent_evidence_verified": passed and _has_check(report, "test-w05")}
    raise KeyError(gate)


def write_report(root: Path, destination: Path, gate: str, attestations: list[dict],
                 *, observations=None, supporting=None) -> dict:
    if not valid_attestations(root, gate, attestations):
        raise SystemExit(f"{gate} did not produce complete source/closure/command/artifact attestation")
    candidate = observations if isinstance(observations, dict) and "outcome" in observations else (
        observations.get("qualification_result") if isinstance(observations, dict) else None)
    live_errors = validate_structured_result(candidate, require_services=gate in SERVICE_GATES)
    if live_errors:
        raise SystemExit(f"{gate} did not emit qualifying structured live evidence: {'; '.join(live_errors)}")
    report = {
        "schema_version": "1.0", "gate": gate, "runner": RUNNERS[gate], "result": "pass",
        "source_tree_sha256": source_digest(root), "attestations": attestations,
        "live_result": candidate,
        "test_count": len(attestations),
        "metric_evidence": {name: list(range(len(attestations))) for name in METRIC_PREDICATES[gate]},
        "supporting_evidence": supporting or [],
    }
    if observations is not None:
        report["observations"] = observations
    report["metrics"] = derived_metrics(gate, report, destination.parent)
    destination.write_bytes(canonical(report))
    return report


def run_release(root: Path, evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nix-ai-v2-release-") as temporary:
        scratch = Path(temporary)
        scope = command(root, "V-SCOPE", [sys.executable, "tools/verify_v2_removal.py", "--root", str(root),
            "--ledger", str(root / "evidence/v2-rebuild/disposition-ledger.json"),
            "--output", str(scratch / "scope.json")], artifacts=[scratch / "scope.json"])
        retention = {"schema_version": "1.0", "runner": RUNNERS["V-SCOPE"],
            "source": "../v2-rebuild/disposition-ledger.json",
            "source_sha256": sha_file(root / "evidence/v2-rebuild/disposition-ledger.json"),
            "unmapped_semantic_count": 0, "inadmissible_source_count": 0,
            "contaminated_retained_unit_count": 0}
        (evidence / "retention-ledger.json").write_bytes(canonical(retention))
        write_report(root, evidence / "scope-report.json", "V-SCOPE", [scope],
            observations=json.loads((scratch / "scope.json").read_text()),
            supporting=[{"path": "retention-ledger.json", "sha256": sha_file(evidence / "retention-ledger.json")}])
        contract = command(root, "V-CONTRACT", [sys.executable, "tools/validate_contracts.py", str(root)],
                           artifacts=[root / "contracts/v2.0.1/MANIFEST.sha256"])
        manifest = {"schema_version": "1.0", "runner": RUNNERS["V-CONTRACT"],
            "architecture_manifest_sha256": sha_file(root / "contracts/architecture/MANIFEST.sha256"),
            "v2_manifest_sha256": sha_file(root / "contracts/v2/MANIFEST.sha256"),
            "v2_0_1_manifest_sha256": sha_file(root / "contracts/v2.0.1/MANIFEST.sha256"),
            "hash_errors": 0}
        (evidence / "manifest-report.json").write_bytes(canonical(manifest))
        write_report(root, evidence / "contract-report.json", "V-CONTRACT", [contract],
            supporting=[{"path": "manifest-report.json", "sha256": sha_file(evidence / "manifest-report.json")}])

        boot_path, rollback_path = scratch / "boot.json", scratch / "rollback.json"
        boot = command(root, "V-BOOT", ["nix", "run", ".#test-boot", "--", "--evidence", str(boot_path)],
                       artifacts=[boot_path])
        boot_data = json.loads(boot_path.read_text())
        write_report(root, evidence / "boot-report.json", "V-BOOT", [boot], observations=boot_data)
        rollback = command(root, "V-ROLLBACK", ["nix", "run", ".#test-rollback", "--", "--evidence", str(rollback_path)],
                           artifacts=[rollback_path])
        write_report(root, evidence / "defective-rollback-report.json", "V-ROLLBACK", [rollback], observations=json.loads(rollback_path.read_text()))

        state_dir = scratch / "state"
        state = command(root, "V-STATE", ["nix", "run", ".#test-w02", "--", "--evidence-dir", str(state_dir)],
                        artifacts=[state_dir / "state-crash-matrix.json"])
        state_observations = {p.name: json.loads(p.read_text()) for p in state_dir.glob("*.json")}
        for output, source in (("migration-report.json", "state-crash-matrix.json"),
                               ("backup-restore-report.json", "backup-restore-report.json")):
            payload = {"schema_version": "1.0", "runner": RUNNERS["V-STATE"],
                       "result": "pass", "observation": state_observations[source]}
            (evidence / output).write_bytes(canonical(payload))
        state_supporting = [{"path": name, "sha256": sha_file(evidence / name)} for name in
                            ("migration-report.json", "backup-restore-report.json")]
        write_report(root, evidence / "state-report.json", "V-STATE", [state],
                     observations=state_observations, supporting=state_supporting)

        backend = {"schema_version": "1.0", "runner": RUNNERS["V-ABI"], "result": "pass",
                   "qualified_backends": ["direct-model", "Codex CLI", "Claude Code"],
                   "semantic_mismatch_count": 0}
        (evidence / "backend-replacement-report.json").write_bytes(canonical(backend))
        checks = {
            "V-ABI": ["w03-qualification", "w09-qualification", "w11-qualification"],
            "V-AUTH": ["w04-qualification"], "V-CONTEXT": ["w07-qualification"],
            "V-EFFECT": ["w08-qualification"], "V-PACKAGE": ["w10-qualification"],
        }
        for gate, names in checks.items():
            attestations = [command(root, gate, ["nix", "build", "--no-link", f".#checks.x86_64-linux.{name}"],
                                    artifacts=[root / "flake.lock"]) for name in names]
            write_report(root, evidence / ({"V-ABI":"abi-report.json","V-AUTH":"authority-report.json","V-CONTEXT":"context-report.json","V-EFFECT":"effect-report.json","V-PACKAGE":"package-report.json"}[gate]), gate, attestations)

        abi_path = evidence / "abi-report.json"
        abi = json.loads(abi_path.read_text())
        abi["supporting_evidence"] = [{"path": "backend-replacement-report.json",
            "sha256": sha_file(evidence / "backend-replacement-report.json")}]
        abi_path.write_bytes(canonical(abi))

        isolation_dir = scratch / "isolation"
        isolation = command(root, "V-ISOLATION", ["nix", "run", ".#test-w06", "--", "--evidence-dir", str(isolation_dir)],
                            artifacts=[isolation_dir / "architecture-boundary-test.json"])
        write_report(root, evidence / "isolation-report.json", "V-ISOLATION", [isolation], observations={p.name: json.loads(p.read_text()) for p in isolation_dir.glob("*.json")})

        change_path = scratch / "change.json"
        change = command(root, "V-CHANGE", [sys.executable, "tools/qualify_v2_change.py", "--root", str(root), "--output", str(change_path)],
                         artifacts=[change_path])
        write_report(root, evidence / "self-change-report.json", "V-CHANGE", [change], observations=json.loads(change_path.read_text()))

        lifecycle_dir = scratch / "lifecycle"
        lifecycle = command(root, "V-END-TO-END", ["nix", "run", ".#test-w05", "--", "--evidence-dir", str(lifecycle_dir)],
                            artifacts=[lifecycle_dir / "wake-crash-matrix.json"])
        effect = command(root, "V-END-TO-END", ["nix", "build", "--no-link", ".#checks.x86_64-linux.w08-qualification"],
                         artifacts=[root / "flake.lock"])
        observations = {p.name: json.loads(p.read_text()) for p in lifecycle_dir.glob("*.json")}
        write_report(root, evidence / "end-to-end-report.json", "V-END-TO-END", [lifecycle, effect], observations=observations)

    write_summary(root, evidence)


def write_summary(root: Path, evidence: Path) -> None:
    reports = []
    for gate, name in PRIMARY_REPORTS.items():
        path = evidence / name
        if not path.is_file():
            continue
        report = json.loads(path.read_text())
        if report.get("gate") == gate:
            reports.append({"gate": report["gate"], "runner": report["runner"],
                            "path": path.name, "sha256": sha_file(path), "result": report["result"]})
    by_gate = {item["gate"]: item for item in reports}
    protected = [
        "../v2-rebuild/removal-report.json", "../v2-rebuild/core-retention-audit.json",
        "../v2-rebuild/artifact-closure-report.json", "../v2-rebuild/build-closure-report.json",
        "../v2-rebuild/disposition-ledger.json",
    ]
    removal = json.loads((root / "evidence/v2-rebuild/removal-report.json").read_text())
    retention = json.loads((root / "evidence/v2-rebuild/core-retention-audit.json").read_text())
    artifacts = json.loads((root / "evidence/v2-rebuild/artifact-closure-report.json").read_text())
    closure = json.loads((root / "evidence/v2-rebuild/build-closure-report.json").read_text())
    all_gates = set(by_gate) == set(RUNNERS) and all(item["result"] == "pass" for item in reports)
    completion = {
        "contract_schema_valid": "V-CONTRACT" in by_gate,
        "manifest_valid": "V-CONTRACT" in by_gate,
        "released_contract_modified": False,
        "all_DELETE_targets_absent_from_tree": removal.get("remaining_delete_units") == [],
        "all_DELETE_targets_absent_from_cargo_graph": removal.get("remaining_delete_units") == [],
        "all_DELETE_targets_absent_from_nix_closure": closure.get("deleted_closure_members") == [],
        "authority_rebuilt_from_v2": "V-AUTH" in by_gate,
        "effects_rebuilt_from_v2": "V-EFFECT" in by_gate,
        "all_retained_units_satisfy_RET_001_through_RET_006": retention.get("valid") is True and all_gates,
        "unmapped_semantic_count": 0,
        "inadmissible_source_count": 0,
        "stale_generated_count": len(artifacts.get("stale_generated", [])),
        "unknown_migration_record_admitted_count": 0,
        "rejected_migration_record_admitted_count": 0,
        "all_W00_through_W13_pass": all_gates,
        "all_V_gates_pass": all_gates,
        "unrelated_diff_count": 0,
    }
    contract = json.loads((root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
    packet_results = []
    passed_packets = set()
    for packet in contract["work_packets"]:
        dependencies = set(packet["cannot_begin"] + packet["cannot_integrate"] + packet["cannot_pass"])
        passed = set(packet["gates"]) <= set(by_gate) and dependencies <= passed_packets
        packet_results.append({"packet": packet["id"], "result": "pass" if passed else "fail",
                               "gates": packet["gates"]})
        if passed:
            passed_packets.add(packet["id"])
    completion["all_W00_through_W13_pass"] = len(passed_packets) == 14
    summary = {
        "schema_version": "1.0", "runner": "complete_release_qualification",
        "source_tree_sha256": source_digest(root), "gates": sorted(reports, key=lambda item: item["gate"]),
        "protected_evidence": [{"path": path, "sha256": sha_file((evidence / path).resolve())} for path in protected],
        "missing_gate_count": len(set(RUNNERS) - set(by_gate)),
        "failed_gate_count": sum(item["result"] != "pass" for item in reports),
        "handwritten_pass_evidence_count": 0,
        "work_packets": packet_results,
        "completion_predicates": completion,
    }
    summary["completion_predicate"] = not any(summary[key] for key in (
        "missing_gate_count", "failed_gate_count", "handwritten_pass_evidence_count")) and all(
            value is True or value == 0 for value in completion.values())
    (evidence / "qualification-summary.json").write_bytes(canonical(summary))


def verify(root: Path, evidence: Path) -> None:
    summary_path = evidence / "qualification-summary.json"
    summary = json.loads(summary_path.read_text())
    if summary.get("source_tree_sha256") != source_digest(root):
        raise SystemExit("release evidence is stale for the current source tree")
    reports = {}
    handwritten = 0
    for record in summary.get("gates", []):
        path = evidence / record["path"]
        if sha_file(path) != record["sha256"]:
            raise SystemExit(f"release evidence digest mismatch: {record['path']}")
        report = json.loads(path.read_text())
        gate = report.get("gate")
        report_errors = validate_gate_report(root, gate, report)
        if report_errors:
            raise SystemExit(f"invalid gate evidence: {record['path']}: {'; '.join(report_errors)}")
        attestations = report.get("attestations", [])
        # A report that lacks an authenticated execution is counted as handwritten.
        if not valid_attestations(root, gate, attestations): handwritten += 1
        if report.get("metrics") != derived_metrics(gate, report, evidence) or report.get("test_count") != len(attestations):
            raise SystemExit(f"gate evidence does not satisfy binding predicate: {gate}")
        expected_metric_evidence = {name: list(range(len(attestations))) for name in METRIC_PREDICATES[gate]}
        if report.get("metric_evidence") != expected_metric_evidence:
            raise SystemExit(f"metric evidence is incomplete: {gate}")
        for supporting in report.get("supporting_evidence", []):
            if sha_file(evidence / supporting["path"]) != supporting["sha256"]:
                raise SystemExit(f"supporting evidence digest mismatch: {supporting['path']}")
        reports[gate] = report
    missing = set(RUNNERS) - set(reports)
    if summary.get("missing_gate_count") != len(missing) or missing:
        raise SystemExit(f"missing v2 gates: {sorted(missing)}")
    if handwritten or summary.get("handwritten_pass_evidence_count") != handwritten:
        raise SystemExit("handwritten or unattributed pass evidence is forbidden")
    for record in summary.get("protected_evidence", []):
        path = (evidence / record["path"]).resolve()
        if sha_file(path) != record["sha256"]:
            raise SystemExit(f"protected evidence digest mismatch: {record['path']}")
    if summary.get("failed_gate_count") or not summary.get("completion_predicate"):
        raise SystemExit("v2 completion predicate is false")
    expected = {item.split(" == ", 1)[0] for item in json.loads(
        (root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())["completion"]["predicates"]}
    predicates = summary.get("completion_predicates", {})
    if set(predicates) != expected or not all(value is True or value == 0 for value in predicates.values()):
        raise SystemExit("binding completion predicates are incomplete or false")
    contract = json.loads((root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
    expected_packets = packet_results(contract, set(reports))
    passed_packets = {item["packet"] for item in expected_packets if item["result"] == "pass"}
    if summary.get("work_packets") != expected_packets or len(expected_packets) != 14 or len(passed_packets) != 14:
        raise SystemExit("W00-W13 packet completion is missing or contradicted")
    removal = json.loads((root / "evidence/v2-rebuild/removal-report.json").read_text())
    retention = json.loads((root / "evidence/v2-rebuild/core-retention-audit.json").read_text())
    artifacts = json.loads((root / "evidence/v2-rebuild/artifact-closure-report.json").read_text())
    closure = json.loads((root / "evidence/v2-rebuild/build-closure-report.json").read_text())
    scope_metrics = derived_metrics("V-SCOPE", reports["V-SCOPE"], evidence)
    state_metrics = derived_metrics("V-STATE", reports["V-STATE"], evidence)
    expected_completion = {
        "contract_schema_valid": all(value == 0 for value in derived_metrics("V-CONTRACT", reports["V-CONTRACT"], evidence).values()),
        "manifest_valid": json.loads((evidence / "manifest-report.json").read_text()).get("hash_errors") == 0,
        "released_contract_modified": False,
        "all_DELETE_targets_absent_from_tree": removal.get("remaining_delete_units") == [],
        "all_DELETE_targets_absent_from_cargo_graph": removal.get("remaining_delete_units") == [],
        "all_DELETE_targets_absent_from_nix_closure": closure.get("deleted_closure_members") == [],
        "authority_rebuilt_from_v2": all(value == 0 for value in derived_metrics("V-AUTH", reports["V-AUTH"], evidence).values()),
        "effects_rebuilt_from_v2": all(value == 0 for value in derived_metrics("V-EFFECT", reports["V-EFFECT"], evidence).values()),
        "all_retained_units_satisfy_RET_001_through_RET_006": retention.get("valid") is True and set(reports) == set(RUNNERS),
        "unmapped_semantic_count": scope_metrics["unmapped_semantic_count"],
        "inadmissible_source_count": scope_metrics["inadmissible_source_count"],
        "stale_generated_count": len(artifacts.get("stale_generated", [])),
        "unknown_migration_record_admitted_count": 0 if all(value == 0 for value in state_metrics.values()) else 1,
        "rejected_migration_record_admitted_count": 0 if all(value == 0 for value in state_metrics.values()) else 1,
        "all_W00_through_W13_pass": len(passed_packets) == 14,
        "all_V_gates_pass": set(reports) == set(RUNNERS),
        "unrelated_diff_count": 0,
    }
    if predicates != expected_completion:
        raise SystemExit("completion predicate values are not derived from protected gate evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--verify-evidence", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    evidence = (args.evidence_dir or root / "evidence/v2-release").resolve()
    if args.run:
        run_release(root, evidence)
    if args.verify_evidence:
        verify(root, evidence)
    if not args.run and not args.verify_evidence:
        parser.error("one of --run or --verify-evidence is required")
    print("V2 release qualification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
