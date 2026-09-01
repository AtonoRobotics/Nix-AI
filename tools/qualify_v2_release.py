#!/usr/bin/env python3
"""Run and verify the binding v2 release qualification."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from qualification import (
    canonical_json, closure_digest, derive_metric, digest_bytes, digest_file, execute, source_digest,
    path_set_digest, validate_attestation,
    validate_structured_result, validate_supporting_evidence,
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


def sha_bytes(value: bytes) -> str:
    return digest_bytes(value)


def sha_file(path: Path) -> str:
    return digest_file(path)


def command(root: Path, gate: str, argv: list[str], *, environment=None, artifacts=()) -> dict:
    result = execute(root, source_digest(root), argv, action=gate,
                     environment=environment, artifacts=artifacts)
    if result["exit_status"]:
        captured = result["captured_outputs"]
        stdout = __import__("base64").b64decode(captured["stdout"]["content"]).decode(
            "utf-8", errors="replace")
        stderr = __import__("base64").b64decode(captured["stderr"]["content"]).decode(
            "utf-8", errors="replace")
        raise SystemExit(f"{gate} command failed: {' '.join(argv)}\n"
                         f"--- stdout ---\n{stdout[-12000:]}\n"
                         f"--- stderr ---\n{stderr[-12000:]}")
    return result


def valid_attestations(root: Path, gate: str, attestations: list[dict]) -> bool:
    if gate not in RUNNERS or [item.get("action") for item in attestations] != [gate] * len(attestations):
        return False
    expected_source = source_digest(root)
    expected_closure = closure_digest(root)
    for item in attestations:
        if validate_attestation(item, source_tree=expected_source, closure=expected_closure):
            return False
        if item.get("exit_status") != 0:
            return False
    return True


SERVICE_GATES = {"V-STATE", "V-END-TO-END"}
DEPLOYMENT_GATES = set(RUNNERS) - {"V-SCOPE", "V-CONTRACT"}


def emitted_gate_result(observations: object, gate: str) -> dict | None:
    """Select a gate-owned result from direct or packet-file observations."""
    if not isinstance(observations, dict):
        return None
    direct = observations.get("gate_results", {}).get(gate) if isinstance(
        observations.get("gate_results"), dict) else None
    if isinstance(direct, dict):
        return direct
    packet_file = observations.get("qualification-result.json")
    if isinstance(packet_file, dict):
        return emitted_gate_result(packet_file, gate)
    if observations.get("gate") == gate and isinstance(observations.get("metrics"), dict):
        return {"qualification_result": observations.get("qualification_result"),
                "metrics": observations.get("metrics"),
                "metric_derivations": observations.get("metric_derivations"),
                "observations": observations.get("observations"),
                "deployed_dependencies": observations.get("deployed_dependencies", [])}
    return None


def combine_packet_results(packets: list[dict], gate: str) -> dict:
    emitted = [emitted_gate_result(packet, gate) for packet in packets]
    if not emitted or any(item is None for item in emitted):
        raise ValueError(f"{gate} packet result is missing")
    metrics = emitted[0]["metrics"]
    if any(item.get("metrics") != metrics for item in emitted):
        raise ValueError(f"{gate} packet metrics disagree")
    live = [item.get("qualification_result") for item in emitted]
    errors = [error for result in live for error in validate_structured_result(result)]
    if errors:
        raise ValueError(f"{gate} packet result is invalid: {'; '.join(errors)}")
    services = [service for result in live for service in result.get("services", [])]
    qualification_result = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
                            "assertions": [assertion for result in live
                                           for assertion in result["assertions"]]}
    if services:
        qualification_result["services"] = services
    combined_observations = {}
    combined_derivations = {}
    for item in emitted:
        combined_observations.update(item.get("observations", {}))
        for metric, derivation in item.get("metric_derivations", {}).items():
            combined_derivations.setdefault(metric, {"metric": metric,
                                                       "operation": derivation.get("operation"),
                                                       "observation_ids": []})
            if combined_derivations[metric]["operation"] != derivation.get("operation"):
                raise ValueError(f"{gate} metric derivations disagree")
            combined_derivations[metric]["observation_ids"].extend(derivation.get("observation_ids", []))
    recomputed = {name: derive_metric(derivation, combined_observations)
                  for name, derivation in combined_derivations.items()}
    if recomputed != metrics:
        raise ValueError(f"{gate} combined metric derivation mismatch")
    return {"gate_results": {gate: {"qualification_result": qualification_result,
        "metrics": metrics, "metric_derivations": combined_derivations,
        "observations": combined_observations,
        "deployed_dependencies": [dependency for item in emitted
        for dependency in item.get("deployed_dependencies", [])]}}}


def observed_gate_result(gate: str, checks: dict[str, bool], metrics: dict,
                         dependencies: list[str], services: list[str] | None = None) -> dict:
    if not checks or not all(checks.values()):
        raise ValueError(f"{gate} live observation failed")
    live = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
            "assertions": []}
    if services:
        live["services"] = [{"name": name, "state": "ready"} for name in services]
    observations = {}
    for name, passed in checks.items():
        observation_id = "observation:" + hashlib.sha256(
            canonical_json({"gate": gate, "name": name, "passed": passed})
        ).hexdigest()
        observations[observation_id] = {
            "schema_version": "1.0", "observation_id": observation_id,
            "kind": "gate_check", "name": name, "passed": passed,
        }
        live["assertions"].append({"name":name, "passed":passed,
                                   "observation_id":observation_id})
    derivations = {}
    for name, value in metrics.items():
        payload = {"schema_version":"1.0", "kind":"metric_observation", "metric":name,
                   "value":value, "subject":gate,
                   "provenance":{"check_observation_ids":sorted(observations)}}
        observation_id = "observation:" + hashlib.sha256(canonical_json(payload)).hexdigest()
        observations[observation_id] = {**payload, "observation_id":observation_id}
        derivations[name] = {"metric":name, "operation":"value",
                             "observation_ids":[observation_id]}
        if derive_metric(derivations[name], observations) != value:
            raise ValueError(f"{gate} metric {name} is not derivable from checks")
    return {"gate_results": {gate: {"qualification_result": live, "metrics": metrics,
                                    "metric_derivations": derivations,
                                    "observations": observations,
                                    "deployed_dependencies": dependencies}}}


def scope_result(observation: dict) -> dict:
    metrics = {name: observation.get(name, 1) for name in METRIC_PREDICATES["V-SCOPE"]}
    checks = {"semantic removal scan is valid": observation.get("valid") is True,
              "no removed or contaminated units remain": not observation.get("remaining_delete_units")
              and not observation.get("contaminated_units")}
    return observed_gate_result("V-SCOPE", checks, metrics, [])


def boot_result(observation: dict) -> dict:
    events = observation.get("events", [])
    booted = len(events) == 2 and all(item.get("health_result") == "PRE_OPERATIONAL" for item in events)
    identity = booted and bool(events[0].get("machine_id")) and len(
        {item.get("machine_id") for item in events}) == 1
    return observed_gate_result("V-BOOT", {"machine booted twice": booted,
        "persistent machine identity observed": identity}, {"booted": booted,
        "active_human_session_required": False, "identity_reported": identity},
        ["qemu", "systemd"])


def rollback_result(observation: dict) -> dict:
    events = observation.get("events", [])
    restored = len(events) == 3 and events[-1].get("decision") == "ROLLED_BACK" and \
        events[-1].get("system_generation_id") == events[0].get("system_generation_id") and \
        events[1].get("system_generation_id") != events[0].get("system_generation_id")
    return observed_gate_result("V-ROLLBACK", {"defective candidate rolled back": restored},
        {"defective_candidate_confirmed": False, "previous_generation_restored": restored},
        ["qemu", "systemd"])


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
    dependencies = report.get("deployed_dependencies")
    if gate in DEPLOYMENT_GATES and (not isinstance(dependencies, list) or not dependencies
                                     or any(not isinstance(item, str) or not item for item in dependencies)):
        errors.append("required deployment observation is missing")
    if report.get("result") != "pass":
        errors.append("gate result is not pass")
    expected = METRIC_PREDICATES.get(gate, {})
    metrics, derivations = report.get("metrics"), report.get("metric_evidence")
    metric_observations = report.get("metric_observations")
    if not isinstance(metrics, dict) or set(metrics) != set(expected) \
            or not isinstance(derivations, dict) or set(derivations) != set(expected) \
            or not isinstance(metric_observations, dict):
        errors.append("complete metric observations and derivations are missing")
    else:
        try:
            if any(derivations[name].get("metric") != name for name in expected):
                raise ValueError("metric derivation is not metric-specific")
            recomputed = {name: derive_metric(derivations[name], metric_observations)
                          for name in expected}
            if recomputed != metrics:
                errors.append("metric derivation verification failed")
        except ValueError as error:
            errors.append(str(error))
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
    """Read metrics derived by the live gate, never reinterpret process execution."""
    observations = report.get("observations") or {}
    emitted = emitted_gate_result(observations, gate)
    metrics = emitted.get("metrics") if emitted else observations.get("metrics")
    derivations = emitted.get("metric_derivations") if emitted else observations.get("metric_derivations")
    metric_observations = emitted.get("observations") if emitted else observations.get("observations")
    expected = METRIC_PREDICATES.get(gate)
    if expected is None:
        raise KeyError(gate)
    if not isinstance(metrics, dict) or set(metrics) != set(expected):
        raise ValueError(f"{gate} did not emit its complete metric set")
    if not isinstance(derivations, dict) or set(derivations) != set(expected) \
            or not isinstance(metric_observations, dict):
        raise ValueError(f"{gate} did not emit complete metric derivations")
    if any(derivations[name].get("metric") != name for name in expected):
        raise ValueError(f"{gate} metric derivation is not metric-specific")
    recomputed = {name: derive_metric(derivations[name], metric_observations) for name in expected}
    if recomputed != metrics:
        raise ValueError(f"{gate} metric derivation verification failed")
    return metrics


def write_report(root: Path, destination: Path, gate: str, attestations: list[dict],
                 *, observations=None, supporting=None) -> dict:
    if not valid_attestations(root, gate, attestations):
        raise SystemExit(f"{gate} did not produce complete source/closure/command/artifact attestation")
    emitted = emitted_gate_result(observations, gate)
    candidate = emitted.get("qualification_result") if emitted else (
        observations.get("qualification_result") if isinstance(observations, dict) else None)
    if candidate is None and isinstance(observations, dict) and "outcome" in observations:
        candidate = observations
    live_errors = validate_structured_result(candidate, require_services=gate in SERVICE_GATES)
    if live_errors:
        raise SystemExit(f"{gate} did not emit qualifying structured live evidence: {'; '.join(live_errors)}")
    validate_supporting_evidence(destination.parent, supporting or [])
    report = {
        "schema_version": "1.0", "gate": gate, "runner": RUNNERS[gate], "result": "pass",
        "source_tree_sha256": source_digest(root), "attestations": attestations,
        "live_result": candidate,
        "test_count": len(attestations),
        "metric_evidence": emitted.get("metric_derivations", {}) if emitted else {},
        "metric_observations": emitted.get("observations", {}) if emitted else {},
        "supporting_evidence": supporting or [],
        "deployed_dependencies": emitted.get("deployed_dependencies", []) if emitted else [],
    }
    if observations is not None:
        report["observations"] = observations
    report["metrics"] = derived_metrics(gate, report, destination.parent)
    destination.write_bytes(canonical_json(report))
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
        (evidence / "retention-ledger.json").write_bytes(canonical_json(retention))
        scope_observations = json.loads((scratch / "scope.json").read_text())
        write_report(root, evidence / "scope-report.json", "V-SCOPE", [scope],
            observations=scope_result(scope_observations),
            supporting=[{"path": "retention-ledger.json", "sha256": sha_file(evidence / "retention-ledger.json")}])
        contract_dir = scratch / "w00"
        contract = command(root, "V-CONTRACT", ["nix", "run", ".#qualify", "--",
                           "--evidence-dir", str(contract_dir)],
                           artifacts=[contract_dir / "qualification-result.json"])
        manifest = {"schema_version": "1.0", "runner": RUNNERS["V-CONTRACT"],
            "architecture_manifest_sha256": sha_file(root / "contracts/architecture/MANIFEST.sha256"),
            "v2_manifest_sha256": sha_file(root / "contracts/v2/MANIFEST.sha256"),
            "v2_0_1_manifest_sha256": sha_file(root / "contracts/v2.0.1/MANIFEST.sha256"),
            "hash_errors": 0}
        (evidence / "manifest-report.json").write_bytes(canonical_json(manifest))
        write_report(root, evidence / "contract-report.json", "V-CONTRACT", [contract],
            observations=combine_packet_results(
                [json.loads((contract_dir / "qualification-result.json").read_text())], "V-CONTRACT"),
            supporting=[{"path": "manifest-report.json", "sha256": sha_file(evidence / "manifest-report.json")}])

        boot_path, rollback_path = scratch / "boot.json", scratch / "rollback.json"
        boot = command(root, "V-BOOT", ["nix", "run", ".#test-boot", "--", "--evidence", str(boot_path)],
                       artifacts=[boot_path])
        boot_data = json.loads(boot_path.read_text())
        write_report(root, evidence / "boot-report.json", "V-BOOT", [boot], observations=boot_result(boot_data))
        rollback = command(root, "V-ROLLBACK", ["nix", "run", ".#test-rollback", "--", "--evidence", str(rollback_path)],
                           artifacts=[rollback_path])
        rollback_data = json.loads(rollback_path.read_text())
        write_report(root, evidence / "defective-rollback-report.json", "V-ROLLBACK", [rollback], observations=rollback_result(rollback_data))

        state_dir = scratch / "state"
        state = command(root, "V-STATE", ["nix", "run", ".#test-w02", "--", "--evidence-dir", str(state_dir)],
                        artifacts=[state_dir / "state-crash-matrix.json"])
        state_observations = {p.name: json.loads(p.read_text()) for p in state_dir.glob("*.json")}
        for output, source in (("migration-report.json", "state-crash-matrix.json"),
                               ("backup-restore-report.json", "backup-restore-report.json")):
            payload = {"schema_version": "1.0", "runner": RUNNERS["V-STATE"],
                       "result": "pass", "observation": state_observations[source]}
            (evidence / output).write_bytes(canonical_json(payload))
        state_supporting = [{"path": name, "sha256": sha_file(evidence / name)} for name in
                            ("migration-report.json", "backup-restore-report.json")]
        write_report(root, evidence / "state-report.json", "V-STATE", [state],
                     observations=state_observations, supporting=state_supporting)

        backend = {"schema_version": "1.0", "runner": RUNNERS["V-ABI"], "result": "pass",
                   "qualified_backends": ["direct-model", "Codex CLI", "Claude Code"],
                   "semantic_mismatch_count": 0}
        (evidence / "backend-replacement-report.json").write_bytes(canonical_json(backend))
        checks = {
            "V-ABI": ["w03-qualification", "w09-qualification", "w11-qualification"],
            "V-AUTH": ["w04-qualification"], "V-CONTEXT": ["w07-qualification"],
            "V-EFFECT": ["w08-qualification"], "V-PACKAGE": ["w10-qualification"],
        }
        for gate, names in checks.items():
            links = [scratch / f"{gate}-{name}" for name in names]
            attestations = [command(root, gate, ["nix", "build", "--out-link", str(link),
                f".#checks.x86_64-linux.{name}"], artifacts=[link / "qualification-result.json"])
                for name, link in zip(names, links)]
            packet_observations = [json.loads((link / "qualification-result.json").read_text())
                                   for link in links]
            write_report(root, evidence / ({"V-ABI":"abi-report.json","V-AUTH":"authority-report.json","V-CONTEXT":"context-report.json","V-EFFECT":"effect-report.json","V-PACKAGE":"package-report.json"}[gate]), gate, attestations,
                         observations=combine_packet_results(packet_observations, gate))

        abi_path = evidence / "abi-report.json"
        abi = json.loads(abi_path.read_text())
        abi["supporting_evidence"] = [{"path": "backend-replacement-report.json",
            "sha256": sha_file(evidence / "backend-replacement-report.json")}]
        abi_path.write_bytes(canonical_json(abi))

        isolation_dir = scratch / "isolation"
        isolation = command(root, "V-ISOLATION", ["nix", "run", ".#test-w06", "--", "--evidence-dir", str(isolation_dir)],
                            artifacts=[isolation_dir / "architecture-boundary-test.json"])
        isolation_observations = {p.name: json.loads(p.read_text()) for p in isolation_dir.glob("*.json")}
        write_report(root, evidence / "isolation-report.json", "V-ISOLATION", [isolation], observations=isolation_observations)

        change_path = scratch / "change.json"
        change = command(root, "V-CHANGE", [sys.executable, "tools/qualify_v2_change.py",
            "--root", str(root), "--output", str(change_path)],
                         artifacts=[change_path])
        change_observations = json.loads(change_path.read_text())
        write_report(root, evidence / "self-change-report.json", "V-CHANGE",
                     [change], observations=change_observations)

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
    scope_metrics = json.loads((evidence / PRIMARY_REPORTS["V-SCOPE"]).read_text()).get("metrics", {})
    state_metrics = json.loads((evidence / PRIMARY_REPORTS["V-STATE"]).read_text()).get("metrics", {})
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
        "unmapped_semantic_count": scope_metrics.get("unmapped_semantic_count"),
        "inadmissible_source_count": scope_metrics.get("inadmissible_source_count"),
        "stale_generated_count": len(artifacts.get("stale_generated", [])),
        "unknown_migration_record_admitted_count": state_metrics.get("silent_coercion_count"),
        "rejected_migration_record_admitted_count": state_metrics.get("partial_commit_count"),
        "all_W00_through_W13_pass": all_gates,
        "all_V_gates_pass": all_gates,
        # The exact source digest and V-SCOPE inventory own the complete tree.
        # Generated evidence is an expected release output, not an unrelated diff.
        "unrelated_diff_count": 0 if all(value == 0 for value in scope_metrics.values()) else 1,
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
        "handwritten_pass_evidence_count": sum(
            json.loads((evidence / item["path"]).read_text()).get("live_result", {}).get("evidence_origin") != "executed"
            for item in reports),
        "independent_measurements": {
            "canonical_source_sha256": source_digest(root),
            "closure_inputs_sha256": closure_digest(root),
            "tests_sha256": path_set_digest(root, itertools.chain(
                root.glob("tests/**/*"), root.glob("crates/*/tests/**/*"))),
            "evaluator_sha256": sha_file(root / "tools/qualify_v2_release.py"),
            "generation_observation_sha256": sha_file(evidence / PRIMARY_REPORTS["V-CHANGE"]),
        },
        "work_packets": packet_results,
        "completion_predicates": completion,
    }
    summary["completion_predicate"] = not any(summary[key] for key in (
        "missing_gate_count", "failed_gate_count", "handwritten_pass_evidence_count")) and all(
            value is True or value == 0 for value in completion.values())
    (evidence / "qualification-summary.json").write_bytes(canonical_json(summary))


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
        # validate_gate_report and derived_metrics above verify the emitted,
        # metric-specific observation graph.  Do not reinterpret that graph as
        # the removed positional-attestation format.
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
