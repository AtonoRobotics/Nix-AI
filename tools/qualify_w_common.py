"""Shared fail-closed primitives for W00-W11 packet runners."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Iterable, Sequence
import sys

from qualification import execute


def source_digest(root: Path) -> str:
    """Digest the current tracked source using the release verifier's algorithm."""
    import hashlib

    root = root.resolve()
    excluded = {".git", "target", "result", "__pycache__"}
    if (root / ".git").exists():
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files"], check=True, capture_output=True, text=True
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


class PacketRun:
    def __init__(self, packet: str, root: Path) -> None:
        self.packet = packet
        self.root = root.resolve()
        self.source_tree = source_digest(self.root)
        self.attestations: list[dict[str, object]] = []
        self.assertions: list[dict[str, object]] = []
        self.services: list[dict[str, str]] = []

    def command(
        self,
        argv: Sequence[str | Path],
        *,
        artifacts: Iterable[Path],
        assertion: str,
        environment: dict[str, str] | None = None,
    ) -> dict[str, object]:
        rendered = [str(value) for value in argv]
        record = execute(
            self.root, self.source_tree, rendered, artifacts=artifacts, environment=environment
        )
        self.attestations.append(record)
        passed = record["exit_status"] == 0
        self.assertions.append({"name": assertion, "passed": passed})
        if not passed:
            raise SystemExit(f"{self.packet} command failed: {' '.join(rendered)}")
        return record

    def ready_service(self, name: str) -> None:
        if not name:
            raise ValueError("service name is required")
        self.services.append({"name": name, "state": "ready"})

    def result(self, reports: dict[str, object]) -> dict[str, object]:
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
        return {
            "packet": self.packet,
            "outcome": "passed",
            "qualification_result": qualification_result,
            "live_services": self.services,
            "behavioral_assertions": self.assertions,
            "execution": self.attestations,
            "artifact_digests": artifacts,
            "reports": reports,
        }


def write_reports(directory: Path | None, reports: dict[str, object]) -> None:
    if directory is None:
        return
    directory.mkdir(parents=True, exist_ok=True)
    for name, report in reports.items():
        (directory / f"{name}.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


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
            assertion=f"{subsystem} behavioral binary {binary.name} passes",
        )
    return len(binaries)


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
