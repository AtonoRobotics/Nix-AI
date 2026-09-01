"""Canonical, independently verifiable qualification evidence primitives."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


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


def execute(
    root: Path,
    source_tree: str,
    argv: Sequence[str],
    *,
    artifacts: Iterable[Path] = (),
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Execute argv and attest the complete observation; never infer pass from text."""
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty string sequence")
    started = utc_now()
    result = subprocess.run(list(argv), cwd=root, env=environment, capture_output=True)
    finished = utc_now()
    return {
        "schema_version": "2.0",
        "kind": "executed_command",
        "source_tree_sha256": source_tree,
        "built_closure_sha256": closure_digest(root),
        "argv": list(argv),
        "exit_status": result.returncode,
        "started_at": started,
        "finished_at": finished,
        "stdout_sha256": digest_bytes(result.stdout),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": digest_bytes(result.stderr),
        "stderr_bytes": len(result.stderr),
        "artifact_digests": artifact_digests(artifacts, root),
        "runner_identity": runner_identity(),
    }


def validate_attestation(record: object, *, source_tree: str, closure: str) -> list[str]:
    if not isinstance(record, dict):
        return ["attestation is not an object"]
    errors = []
    required = {
        "schema_version", "kind", "source_tree_sha256", "built_closure_sha256",
        "argv", "exit_status", "started_at", "finished_at", "stdout_sha256",
        "stdout_bytes", "stderr_sha256", "stderr_bytes", "artifact_digests",
        "runner_identity",
    }
    missing = sorted(required - record.keys())
    if missing:
        errors.append(f"missing attestation fields: {missing}")
    if record.get("schema_version") != "2.0" or record.get("kind") != "executed_command":
        errors.append("unsupported attestation schema or kind")
    if record.get("source_tree_sha256") != source_tree:
        errors.append("attestation source tree mismatch")
    if record.get("built_closure_sha256") != closure:
        errors.append("attestation closure mismatch")
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
    return errors


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
        for item in assertions
    ):
        errors.append("behavioral assertions are missing or failed")
    if result.get("evidence_origin") != "executed":
        errors.append("handwritten evidence is forbidden")
    if require_services:
        services = result.get("services")
        if not isinstance(services, list) or not services or any(
            not isinstance(service, dict) or service.get("state") != "ready" or not service.get("name")
            for service in services
        ):
            errors.append("required live services are absent or not ready")
    return errors
