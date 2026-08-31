"""Canonical, independently verifiable qualification evidence primitives."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import platform
import re
import socket
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def source_digest(root: Path) -> str:
    """Digest tracked source while excluding generated evidence and build outputs."""
    root = root.resolve()
    excluded = {".git", "target", "result", "__pycache__"}
    if (root / ".git").exists() and shutil.which("git"):
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"], check=True,
            capture_output=True, text=True,
        ).stdout.splitlines()
        paths = [root / relative for relative in listed]
    else:
        paths = [item for item in root.rglob("*") if item.is_file()]
    digest = hashlib.sha256()
    for path in sorted(
        item for item in paths
        if item.is_file() and not excluded.intersection(item.relative_to(root).parts)
    ):
        relative = path.relative_to(root).as_posix()
        if relative.startswith("evidence/"):
            continue
        name, content = relative.encode(), path.read_bytes()
        digest.update(len(name).to_bytes(4, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return "sha256:" + digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def runner_identity() -> dict[str, object]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "uid": os.getuid(),
        "gid": os.getgid(),
    }


def closure_digest(root: Path) -> str:
    """Bind the declared Rust/Nix closure inputs without trusting a caller claim."""
    members = []
    for relative in ("Cargo.lock", "flake.lock"):
        path = root / relative
        if not path.is_file():
            raise ValueError(f"missing closure input: {relative}")
        members.append({"path": relative, "sha256": digest_file(path)})
    return digest_bytes(canonical_json(members))


def realized_closure(argv: Sequence[str], environment: Mapping[str, str] | None = None) -> list[dict[str, str]]:
    """Resolve the executed program and, for Nix outputs, its recursive store closure."""
    executable = Path(argv[0]) if Path(argv[0]).is_absolute() else Path(
        shutil.which(argv[0], path=(environment or os.environ).get("PATH")) or argv[0])
    executable = executable.resolve(strict=True)
    paths = [executable]
    members = []
    for path in sorted(set(paths), key=str):
        if path.is_file():
            identity = digest_file(path)
        else:
            query = subprocess.run(["nix-store", "--query", "--hash", str(path)],
                                   capture_output=True, text=True)
            if query.returncode or not query.stdout.strip():
                raise ValueError(f"realized output identity unavailable: {path}")
            identity = query.stdout.strip()
        members.append({"path": str(path), "identity": identity})
    if str(executable).startswith("/nix/store/"):
        output = Path("/nix/store") / executable.relative_to("/nix/store").parts[0]
        members.append({"path": str(output), "identity": output.name.split("-", 1)[0]})
    if not members:
        raise ValueError("realized executable closure is empty")
    return members


def path_set_digest(root: Path, paths: Iterable[Path]) -> str:
    members = []
    for path in sorted({item.resolve() for item in paths}, key=str):
        if path.is_file():
            members.append({"path": path.relative_to(root.resolve()).as_posix(),
                            "sha256": digest_file(path)})
    if not members:
        raise ValueError("measured path set is empty")
    return digest_bytes(canonical_json(members))


def artifact_digests(paths: Iterable[Path], root: Path) -> list[dict[str, str]]:
    records = []
    for path in sorted((item.resolve() for item in paths), key=str):
        if not path.is_file():
            raise ValueError(f"missing command artifact: {path}")
        try:
            name = path.relative_to(root.resolve()).as_posix()
        except ValueError:
            name = str(path)
        records.append({"path": name, "sha256": digest_file(path)})
    return records


def captured_bytes(value: bytes) -> dict[str, object]:
    """Store exact bytes inline under their independently recomputable address."""
    digest = digest_bytes(value)
    return {
        "sha256": digest,
        "content_address": "sha256/" + digest.removeprefix("sha256:"),
        "bytes": len(value),
        "encoding": "base64",
        "content": base64.b64encode(value).decode("ascii"),
    }


def verify_captured_bytes(record: object) -> bool:
    if not isinstance(record, dict) or record.get("encoding") != "base64":
        return False
    try:
        value = base64.b64decode(record.get("content", ""), validate=True)
    except (ValueError, TypeError):
        return False
    digest = digest_bytes(value)
    return (record.get("bytes") == len(value) and record.get("sha256") == digest
            and record.get("content_address") == "sha256/" + digest.removeprefix("sha256:"))


class EvidenceByteStore:
    """Atomic, write-once, digest-addressed storage for qualification bytes."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, value: bytes) -> dict[str, object]:
        digest = digest_bytes(value)
        directory = self.root / "sha256"
        directory.mkdir(mode=0o755, exist_ok=True)
        path = directory / digest.removeprefix("sha256:")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        except FileExistsError:
            if path.read_bytes() != value:
                raise ValueError("digest-addressed evidence collision")
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(path, 0o444)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return {"sha256": digest, "bytes": len(value), "path": str(path)}

    def read(self, digest: str) -> bytes:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid evidence address")
        path = self.root / "sha256" / digest.removeprefix("sha256:")
        value = path.read_bytes()
        if digest_bytes(value) != digest:
            raise ValueError("digest-addressed evidence bytes do not recompute")
        return value


def validate_supporting_evidence(evidence_root: Path,
                                 records: Sequence[Mapping[str, object]]) -> None:
    root = evidence_root.resolve()
    for record in records:
        relative = record.get("path")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ValueError("supporting evidence path must be relative")
        resolved = (root / relative).resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError("supporting evidence escapes evidence root") from error
        if not resolved.is_file() or record.get("sha256") != digest_file(resolved):
            raise ValueError("supporting evidence digest mismatch")


def execute(
    root: Path,
    source_tree: str,
    argv: Sequence[str],
    *,
    action: str,
    artifacts: Iterable[Path] = (),
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Execute argv and attest the complete observation; never infer pass from text."""
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty string sequence")
    started = utc_now()
    result = subprocess.run(list(argv), cwd=root, env=environment, capture_output=True)
    finished = utc_now()
    artifact_records = artifact_digests(artifacts, root)
    realized = realized_closure(argv, environment)
    declared_closure = closure_digest(root)
    built_closure = digest_bytes(canonical_json({
        "declared_input_closure_sha256": declared_closure,
        "realized_closure": realized,
    }))
    artifact_bytes = []
    for item in artifact_records:
        path = Path(item["path"])
        resolved = path if path.is_absolute() else root / path
        capture = captured_bytes(resolved.read_bytes())
        capture["path"] = item["path"]
        artifact_bytes.append(capture)
    output_ids = [digest_bytes(result.stdout), digest_bytes(result.stderr)]
    action_payload = {
        "schema_version": "1.0", "kind": "command_action", "action": action,
        "result": "succeeded" if result.returncode == 0 else "failed",
        "exit_status": result.returncode, "started_at": started, "finished_at": finished,
        "output_ids": output_ids,
        "artifact_ids": [item["sha256"] for item in artifact_records],
        "source_tree_sha256": source_tree,
    }
    observation_id = "observation:" + hashlib.sha256(canonical_json(action_payload)).hexdigest()
    return {
        "schema_version": "2.0",
        "kind": "executed_command",
        "action": action,
        "source_tree_sha256": source_tree,
        "built_closure_sha256": built_closure,
        "declared_input_closure_sha256": declared_closure,
        "realized_closure": realized,
        "argv": list(argv),
        "exit_status": result.returncode,
        "started_at": started,
        "finished_at": finished,
        "stdout_sha256": digest_bytes(result.stdout),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": digest_bytes(result.stderr),
        "stderr_bytes": len(result.stderr),
        "artifact_digests": artifact_digests(artifacts, root),
        "captured_outputs": {
            "stdout": captured_bytes(result.stdout),
            "stderr": captured_bytes(result.stderr),
            "artifacts": artifact_bytes,
        },
        "action_observation": {**action_payload, "observation_id": observation_id},
        "runner_identity": runner_identity(),
    }


def validate_attestation(record: object, *, source_tree: str, closure: str) -> list[str]:
    if not isinstance(record, dict):
        return ["attestation is not an object"]
    errors = []
    required = {
        "schema_version", "kind", "action", "source_tree_sha256", "built_closure_sha256",
        "argv", "exit_status", "started_at", "finished_at", "stdout_sha256",
        "stdout_bytes", "stderr_sha256", "stderr_bytes", "artifact_digests",
        "runner_identity",
        "captured_outputs", "action_observation",
        "declared_input_closure_sha256", "realized_closure",
    }
    missing = sorted(required - record.keys())
    if missing:
        errors.append(f"missing attestation fields: {missing}")
    if record.get("schema_version") != "2.0" or record.get("kind") != "executed_command":
        errors.append("unsupported attestation schema or kind")
    if not isinstance(record.get("action"), str) or not record.get("action"):
        errors.append("invalid attestation action")
    if record.get("source_tree_sha256") != source_tree:
        errors.append("attestation source tree mismatch")
    if closure not in {record.get("declared_input_closure_sha256"),
                       record.get("built_closure_sha256")}:
        errors.append("attestation declared closure mismatch")
    realized = record.get("realized_closure")
    if not isinstance(realized, list) or not realized or any(
        not isinstance(item, dict) or set(item) != {"path", "identity"}
        or not item["path"] or not item["identity"] for item in realized
    ):
        errors.append("attestation realized closure is missing")
    else:
        expected_built = digest_bytes(canonical_json({
            "declared_input_closure_sha256": record.get("declared_input_closure_sha256"),
            "realized_closure": realized,
        }))
        if record.get("built_closure_sha256") != expected_built:
            errors.append("attestation realized closure mismatch")
    argv = record.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
        errors.append("invalid attestation argv")
    if type(record.get("exit_status")) is not int:
        errors.append("invalid exit status")
    parsed_times = {}
    for field in ("started_at", "finished_at"):
        try:
            parsed_times[field] = datetime.fromisoformat(str(record.get(field)).replace("Z", "+00:00"))
            if parsed_times[field].utcoffset() is None:
                errors.append(f"invalid {field}")
        except (TypeError, ValueError):
            errors.append(f"invalid {field}")
    if len(parsed_times) == 2 and parsed_times["finished_at"] < parsed_times["started_at"]:
        errors.append("attestation timestamps are reversed")
    for stream in ("stdout", "stderr"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(record.get(f"{stream}_sha256"))):
            errors.append(f"invalid {stream} digest")
        if type(record.get(f"{stream}_bytes")) is not int or record.get(f"{stream}_bytes", -1) < 0:
            errors.append(f"invalid {stream} length")
    artifacts = record.get("artifact_digests")
    captures = record.get("captured_outputs")
    if not isinstance(captures, dict):
        errors.append("captured output bytes are missing")
    else:
        for stream in ("stdout", "stderr"):
            capture = captures.get(stream)
            if not verify_captured_bytes(capture):
                errors.append(f"invalid captured {stream} bytes")
            elif (capture.get("sha256") != record.get(f"{stream}_sha256")
                  or capture.get("bytes") != record.get(f"{stream}_bytes")):
                errors.append(f"captured {stream} metadata mismatch")
        captured_artifacts = captures.get("artifacts")
        if not isinstance(captured_artifacts, list) or any(
            not verify_captured_bytes(item) or not item.get("path") for item in captured_artifacts
        ):
            errors.append("invalid captured artifact bytes")
        elif [{"path": item["path"], "sha256": item["sha256"]}
              for item in captured_artifacts] != artifacts:
            errors.append("captured artifact metadata mismatch")
    if not isinstance(artifacts, list) or not artifacts or any(
        not isinstance(item, dict) or set(item) != {"path", "sha256"}
        or not isinstance(item["path"], str) or not item["path"]
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(item["sha256"]))
        for item in artifacts
    ):
        errors.append("invalid artifact digest set")
    elif len({item["path"] for item in artifacts}) != len(artifacts):
        errors.append("duplicate artifact path")
    identity = record.get("runner_identity")
    if not isinstance(identity, dict) or set(identity) != {"hostname", "platform", "uid", "gid"}:
        errors.append("invalid runner identity")
    action_observation = record.get("action_observation")
    if not isinstance(action_observation, dict) or not re.fullmatch(
        r"observation:[0-9a-f]{64}", str(action_observation.get("observation_id"))
    ) or action_observation.get("result") not in {"succeeded", "failed"}:
        errors.append("invalid structured action observation")
    else:
        expected_action = {
            "schema_version": "1.0", "kind": "command_action",
            "action": record.get("action"),
            "result": "succeeded" if record.get("exit_status") == 0 else "failed",
            "exit_status": record.get("exit_status"), "started_at": record.get("started_at"),
            "finished_at": record.get("finished_at"),
            "output_ids": [record.get("stdout_sha256"), record.get("stderr_sha256")],
            "artifact_ids": [item.get("sha256") for item in artifacts]
                if isinstance(artifacts, list) else [],
            "source_tree_sha256": record.get("source_tree_sha256"),
        }
        expected_id = "observation:" + hashlib.sha256(canonical_json(expected_action)).hexdigest()
        if action_observation != {**expected_action, "observation_id": expected_id}:
            errors.append("action observation is not canonically bound to attestation")
    return errors


def make_metric_observation(metric: str, value: object, *, subject: str,
                            action_observation_id: str,
                            artifact_ids: Sequence[str]) -> dict[str, object]:
    """Create a content-addressed semantic measurement with execution provenance."""
    if not metric or not subject or not re.fullmatch(r"observation:[0-9a-f]{64}", action_observation_id):
        raise ValueError("metric observation provenance is malformed")
    if not artifact_ids or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item)
                               for item in artifact_ids):
        raise ValueError("metric observation requires digest-addressed artifacts")
    payload = {"schema_version": "1.0", "kind": "metric_observation",
               "metric": metric, "value": value, "subject": subject,
               "provenance": {"action_observation_id": action_observation_id,
                              "artifact_ids": list(artifact_ids)}}
    return {**payload, "observation_id": "observation:" +
            hashlib.sha256(canonical_json(payload)).hexdigest()}


def derive_metric(derivation: object, observations: Mapping[str, object]) -> object:
    if not isinstance(derivation, dict) or not isinstance(derivation.get("observation_ids"), list):
        raise ValueError("metric derivation is malformed")
    selected = []
    for observation_id in derivation["observation_ids"]:
        observation = observations.get(observation_id)
        if not isinstance(observation, dict):
            raise ValueError(f"metric observation is missing: {observation_id}")
        if derivation.get("metric"):
            payload = {key: value for key, value in observation.items()
                       if key != "observation_id"}
            expected_id = "observation:" + hashlib.sha256(canonical_json(payload)).hexdigest()
            if (observation.get("kind") != "metric_observation"
                    or observation.get("metric") != derivation["metric"]
                    or observation_id != expected_id):
                raise ValueError(f"metric observation is not typed or provenance-bound: {observation_id}")
        selected.append(observation)
    passed = [item.get("passed") is True for item in selected]
    operation = derivation.get("operation")
    if operation == "value":
        if len(selected) != 1:
            raise ValueError("value metric requires exactly one observation")
        return selected[0].get("value")
    if operation == "sum_values":
        values = [item.get("value") for item in selected]
        if not values or any(type(value) is not int for value in values):
            raise ValueError("sum metric requires integer observations")
        return sum(values)
    if operation == "all_values":
        values = [item.get("value") for item in selected]
        if not values or any(type(value) is not bool for value in values):
            raise ValueError("all metric requires boolean observations")
        return all(values)
    if operation == "any_values":
        values = [item.get("value") for item in selected]
        if not values or any(type(value) is not bool for value in values):
            raise ValueError("any metric requires boolean observations")
        return any(values)
    if operation == "count_failed":
        return sum(not value for value in passed)
    if operation == "all_passed":
        return bool(passed) and all(passed)
    if operation == "any_failed":
        return any(not value for value in passed)
    raise ValueError(f"unsupported metric derivation: {operation}")


def verify_service_readiness(service: object) -> bool:
    if not isinstance(service, dict):
        return False
    payload = {key: service.get(key) for key in (
        "schema_version", "kind", "name", "unit", "endpoint", "process_id", "health",
        "action_observation_id")}
    expected = "observation:" + hashlib.sha256(canonical_json(payload)).hexdigest()
    return (service.get("schema_version") == "1.0"
            and service.get("kind") == "service_readiness"
            and service.get("probe_observation_id") == expected)


def validate_structured_result(result: object, *, require_services: bool = False) -> list[str]:
    """Reject skipped, synthetic, or process-only claims at the report boundary."""
    if not isinstance(result, dict):
        return ["structured result is missing"]
    errors = []
    if result.get("outcome") not in {"passed", "failed"}:
        errors.append("structured outcome is missing")
    if result.get("outcome") != "passed":
        errors.append("structured result did not pass")
    if result.get("skipped") or result.get("skipped_tests") or result.get("skip_count", 0):
        errors.append("skipped live qualification is forbidden")
    assertions = result.get("assertions")
    if not isinstance(assertions, list) or not assertions or any(
        not isinstance(item, dict) or item.get("passed") is not True or not item.get("name")
        or not re.fullmatch(r"(?:assertion|observation):[0-9a-z:-]+",
                            str(item.get("observation_id")))
        for item in assertions
    ):
        errors.append("behavioral assertions are missing or failed")
    if result.get("evidence_origin") != "executed":
        errors.append("handwritten evidence is forbidden")
    if require_services:
        services = result.get("services")
        if not isinstance(services, list) or not services or any(
            not verify_service_readiness(service) or service.get("state") != "ready"
            or service.get("result") != "ready" or not service.get("name")
            or not service.get("unit") or type(service.get("process_id")) is not int
            or service.get("process_id", 0) <= 0 or service.get("health") != "ready"
            or not service.get("endpoint") or not service.get("observed_at")
            or not re.fullmatch(r"observation:[0-9a-f]{64}",
                                str(service.get("probe_observation_id")))
            or not re.fullmatch(r"observation:[0-9a-f]{64}",
                                str(service.get("action_observation_id")))
            or not isinstance(service.get("identity"), dict)
            for service in services
        ):
            errors.append("required live services are absent or not ready")
    return errors
