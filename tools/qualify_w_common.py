"""Shared fail-closed primitives for W00-W11 packet runners."""

from __future__ import annotations

import json
import base64
import re
import subprocess
import os
import socket
from pathlib import Path
from typing import Iterable, Sequence
import sys

from qualification import (canonical_json, derive_metric, execute, make_metric_observation,
                           source_digest)


class PacketRun:
    def __init__(self, packet: str, root: Path) -> None:
        self.packet = packet
        self.root = root.resolve()
        self.source_tree = source_digest(self.root)
        self.attestations: list[dict[str, object]] = []
        self.assertions: list[dict[str, object]] = []
        self.services: list[dict[str, str]] = []
        self.observations: dict[str, dict[str, object]] = {}

    def command(
        self,
        argv: Sequence[str | Path],
        *,
        action: str,
        artifacts: Iterable[Path],
        assertion: str,
        environment: dict[str, str] | None = None,
    ) -> dict[str, object]:
        rendered = [str(value) for value in argv]
        record = execute(
            self.root, self.source_tree, rendered, action=action,
            artifacts=artifacts, environment=environment
        )
        self.attestations.append(record)
        action = record["action_observation"]
        passed = action["result"] == "succeeded" and bool(action["artifact_ids"])
        observation_id = "assertion:" + action["observation_id"].split(":", 1)[1]
        observation = {
            "schema_version": "1.0", "observation_id": observation_id,
            "kind": "behavioral_assertion", "name": assertion, "passed": passed,
            "action_observation_id": action["observation_id"],
            "artifact_ids": action["artifact_ids"],
        }
        self.observations[observation_id] = observation
        self.assertions.append({"name": assertion, "passed": passed,
                                "observation_id": observation_id})
        if not passed:
            captured = record["captured_outputs"]
            stdout = base64.b64decode(captured["stdout"]["content"]).decode(
                "utf-8", errors="replace")
            stderr = base64.b64decode(captured["stderr"]["content"]).decode(
                "utf-8", errors="replace")
            raise SystemExit(
                f"{self.packet} command failed: {' '.join(rendered)}\n"
                f"--- stdout ---\n{stdout[-12000:]}\n"
                f"--- stderr ---\n{stderr[-12000:]}"
            )
        return record

    def ready_service(self, name: str, *, unit: str | None = None,
                      endpoint: str | None = None, process_id: int | None = None,
                      health: str | None = None) -> None:
        if not name or not unit or not endpoint or type(process_id) is not int \
                or process_id <= 0 or health != "ready":
            raise ValueError("readiness requires service, unit, endpoint, process, and ready health")
        if not Path(f"/proc/{process_id}").exists():
            raise ValueError("readiness process is not live")
        if endpoint.startswith("unix:"):
            address = endpoint.removeprefix("unix:")
            with socket.socket(socket.AF_UNIX) as probe_socket:
                probe_socket.settimeout(2); probe_socket.connect(address)
        elif endpoint.startswith("tcp://"):
            host, port = endpoint.removeprefix("tcp://").rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=2):
                pass
        else:
            raise ValueError("readiness endpoint must be a probed unix or tcp endpoint")
        if not self.attestations:
            raise ValueError("readiness requires an executed probe")
        probe = self.attestations[-1]["action_observation"]
        if probe["result"] != "succeeded":
            raise ValueError("readiness probe did not succeed")
        payload = {
            "schema_version": "1.0", "kind": "service_readiness", "name": name,
            "unit": unit, "endpoint": endpoint, "process_id": process_id, "health": health,
            "action_observation_id": probe["observation_id"],
        }
        readiness_id = "observation:" + __import__("hashlib").sha256(
            canonical_json(payload)).hexdigest()
        self.services.append({
            **payload, "state": "ready", "result": "ready",
            "observed_at": probe["finished_at"],
            "probe_observation_id": readiness_id,
            "identity": self.attestations[-1]["runner_identity"],
        })

    def observe_metric(self, gate: str, metric: str, value: object, *,
                       semantic_evidence: dict[str, object]) -> dict[str, object]:
        """Record a semantic metric emitted after its measuring action executed."""
        if not self.attestations:
            raise ValueError("metric observation requires an executed measuring action")
        if not semantic_evidence or not isinstance(semantic_evidence.get("kind"), str) \
                or "observed" not in semantic_evidence:
            raise ValueError("metric observation requires typed semantic evidence")
        action = self.attestations[-1]["action_observation"]
        observation = make_metric_observation(
            metric, value, subject=gate, action_observation_id=action["observation_id"],
            artifact_ids=action["artifact_ids"])
        payload = {key: item for key, item in observation.items() if key != "observation_id"}
        payload["semantic_evidence"] = semantic_evidence
        observation = {**payload, "observation_id": "observation:" +
                       __import__("hashlib").sha256(canonical_json(payload)).hexdigest()}
        self.observations[observation["observation_id"]] = observation
        return observation

    def observe_assertion(self, name: str, passed: bool, *,
                          semantic_evidence: dict[str, object]) -> dict[str, object]:
        """Record a behavioral assertion derived from an executed live probe."""
        if not self.attestations:
            raise ValueError("behavioral assertion requires an executed measuring action")
        if not name or type(passed) is not bool:
            raise ValueError("behavioral assertion requires a name and boolean result")
        if not semantic_evidence or not isinstance(semantic_evidence.get("kind"), str) \
                or "observed" not in semantic_evidence:
            raise ValueError("behavioral assertion requires typed semantic evidence")
        action = self.attestations[-1]["action_observation"]
        payload = {
            "schema_version": "1.0", "kind": "behavioral_assertion", "name": name,
            "passed": passed, "action_observation_id": action["observation_id"],
            "artifact_ids": action["artifact_ids"], "semantic_evidence": semantic_evidence,
        }
        observation_id = "assertion:" + __import__("hashlib").sha256(
            canonical_json(payload)).hexdigest()
        observation = {**payload, "observation_id": observation_id}
        self.observations[observation_id] = observation
        self.assertions.append({"name": name, "passed": passed,
                                "observation_id": observation_id})
        if not passed:
            raise SystemExit(f"{self.packet} behavioral assertion failed: {name}")
        return observation

    def result(self, reports: dict[str, object], *,
               gate_results: dict[str, dict[str, object]] | None = None) -> dict[str, object]:
        if not self.attestations or not self.assertions:
            raise SystemExit(f"{self.packet} has no executed behavioral evidence")
        if any(item["passed"] is not True for item in self.assertions):
            raise SystemExit(f"{self.packet} contains a failed behavioral assertion")
        qualification_result: dict[str, object] = {
            "outcome": "passed",
            "evidence_origin": "executed",
            "skip_count": 0,
            "assertions": self.assertions,
        }
        if self.services:
            qualification_result["services"] = self.services
        artifacts = []
        for record in self.attestations:
            artifacts.extend(record["artifact_digests"])
        rendered_gates = {}
        for gate, meaning in (gate_results or {}).items():
            metrics = meaning.get("metrics")
            dependencies = meaning.get("deployed_dependencies")
            if not isinstance(metrics, dict) or not metrics or not isinstance(dependencies, list):
                raise SystemExit(f"{self.packet} {gate} has incomplete gate meaning")
            derivations = {}
            derived = {}
            for name, expected in metrics.items():
                matches = [item for item in self.observations.values()
                           if item.get("kind") == "metric_observation"
                           and item.get("subject") == gate and item.get("metric") == name]
                if len(matches) != 1:
                    raise SystemExit(f"{self.packet} {gate} metric {name} lacks one typed observation")
                observation = matches[0]
                operation = ("all_values" if expected is True else
                             "any_values" if expected is False else "sum_values")
                derivation = {"metric": name, "operation": operation,
                              "observation_ids": [observation["observation_id"]]}
                value = derive_metric(derivation, self.observations)
                if value != expected:
                    raise SystemExit(f"{self.packet} {gate} metric {name} is not derived: "
                                     f"observed {value!r}, claimed {expected!r}")
                derivations[name] = derivation
                derived[name] = value
            rendered_gates[gate] = {
                "qualification_result": qualification_result,
                "metrics": derived,
                "metric_derivations": derivations,
                "observations": self.observations,
                "deployed_dependencies": dependencies,
            }
        return {
            "packet": self.packet,
            "outcome": "passed",
            "qualification_result": qualification_result,
            "live_services": self.services,
            "behavioral_assertions": self.assertions,
            "execution": self.attestations,
            "observations": self.observations,
            "artifact_digests": artifacts,
            "reports": reports,
            "gate_results": rendered_gates,
        }


def write_reports(directory: Path | None, reports: dict[str, object]) -> None:
    if directory is None:
        return
    directory.mkdir(parents=True, exist_ok=True)
    for name, report in reports.items():
        (directory / f"{name}.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def emit_result(run: PacketRun, reports: dict[str, object], directory: Path | None, *,
                gate_results: dict[str, dict[str, object]]) -> dict[str, object]:
    """Serialize the packet's canonical executable result for release consumption."""
    result = run.result(reports, gate_results=gate_results)
    write_reports(directory, reports)
    if directory is not None:
        (directory / "qualification-result.json").write_bytes(canonical_json(result))
    print(canonical_json(result).decode(), end="")
    return result


def observe_gate_metrics(run: PacketRun, gate: str, metrics: dict[str, object]) -> None:
    raise RuntimeError("compatibility metric synthesis is forbidden; emit each semantic observation")


def run_test_directory(run: PacketRun, directory: Path, artifact: Path, subsystem: str) -> int:
    binaries = sorted(
        path for path in directory.iterdir()
        if path.is_file() and path.stat().st_mode & 0o111
    )
    if not binaries:
        raise SystemExit(f"{subsystem} behavioral test binaries are absent")
    for binary in binaries:
        run.command(
            [binary], artifacts=[binary, artifact],
            action=f"{subsystem}:{binary.name}",
            assertion=f"{subsystem} behavioral binary {binary.name} passes",
        )
    return len(binaries)


def rust_test_proof(
    run: PacketRun, directory: Path, artifact: Path, subsystem: str
) -> dict[str, object]:
    binaries = sorted(
        path for path in directory.iterdir()
        if path.is_file() and path.stat().st_mode & 0o111
    )
    if not binaries:
        raise SystemExit(f"{subsystem} behavioral test binaries are absent")
    test_names: set[str] = set()
    for binary in binaries:
        record = run.command(
            [binary], artifacts=[binary, artifact],
            action=f"{subsystem}:{binary.name}",
            assertion=f"{subsystem} behavioral binary {binary.name} passes",
        )
        captured = record["captured_outputs"]
        output = "\n".join(
            base64.b64decode(captured[stream]["content"]).decode(
                "utf-8", errors="replace"
            )
            for stream in ("stdout", "stderr")
        )
        test_names.update(
            match.group(1) for match in re.finditer(
                r"(?m)^test ([A-Za-z0-9_:]+) \.\.\. ok$", output
            )
        )
    if not test_names:
        raise SystemExit(f"{subsystem} binaries passed without named test evidence")
    return {
        "runner": "rust-test-binaries", "outcome": "passed",
        "binary_count": len(binaries), "binaries": [path.name for path in binaries],
        "test_count": len(test_names), "test_names": sorted(test_names),
    }


def strict_unittest_argv(*modules: str) -> list[str]:
    """Run unittest while converting any skip into a failing command status."""
    if not modules or any(not value for value in modules):
        raise ValueError("at least one unittest module is required")
    wrapper = r"""import re,subprocess,sys
r=subprocess.run([sys.executable,'-m','unittest',*sys.argv[1:],'-v'],capture_output=True,text=True)
sys.stdout.write(r.stdout);sys.stderr.write(r.stderr)
skipped=bool(re.search(r'(?im)^.*\.\.\. skipped |^OK \(skipped=',r.stdout+r.stderr))
raise SystemExit(r.returncode or (1 if skipped else 0))
"""
    return [sys.executable, "-c", wrapper, *modules]
