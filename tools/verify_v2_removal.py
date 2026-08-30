#!/usr/bin/env python3
"""Verify the v2 deletion boundary established by issue #25."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


RUNNER = {"name": "verify-v2-removal", "version": 1}
FORBIDDEN = re.compile(
    r"(?i)(?:\bcordis\b|\bphysical(?:[-_ ]ai)?\b|\brobot(?:ics)?\b|\bros\b|"
    r"\bisaac\b|\bomniverse\b|\bsimulation\b|\bembodiment\b|\bjetson\b)"
)
SCAN_ROOTS = (
    "CODEX-BUILD-SPEC.md",
    "Cargo.toml",
    "Cargo.lock",
    "flake.nix",
    "contracts/architecture",
    "contracts/proto",
    "contracts/requirements.yaml",
    "contracts/schemas",
    "contracts/work-packets.yaml",
    "crates",
    "docs/implementation",
    "src",
    "tools",
)
SCAN_SUFFIXES = {".json", ".md", ".nix", ".proto", ".py", ".rs", ".toml", ".yaml", ".yml"}
POLICY_TOOLS = {"classify_v2_scope.py", "inventory_v2.py", "verify_v2_removal.py"}


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True
    )
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return result.stdout.strip()


def scan_paths(root: Path):
    for item in SCAN_ROOTS:
        path = root / item
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from (candidate for candidate in path.rglob("*") if candidate.is_file())


def verify(root: Path, ledger_path: Path) -> dict:
    ledger = json.loads(ledger_path.read_text())
    delete_targets = sorted(
        record["identity"]
        for record in ledger["dispositions"]["tracked_paths"]
        if record["action"] == "DELETE"
    )
    remaining_delete_targets = [path for path in delete_targets if (root / path).exists()]
    contaminated = []
    for path in sorted(set(scan_paths(root))):
        if path.suffix not in SCAN_SUFFIXES or path.name in POLICY_TOOLS:
            continue
        text = path.read_text(errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN.search(line):
                contaminated.append(
                    {"path": path.relative_to(root).as_posix(), "line": line_number}
                )
    tracked = set(git(root, "ls-files").splitlines())
    rejected_build_members = sorted(
        path
        for path in tracked
        if path.startswith("crates/habitat-simulation/")
        or path == "tools/qualify_w12.py"
        or path.startswith("evidence/work-packets/W12/")
    )
    valid = not remaining_delete_targets and not contaminated and not rejected_build_members
    return {
        "schema_version": 1,
        "runner": RUNNER,
        "verified_commit": git(root, "rev-parse", "HEAD^{commit}"),
        "valid": valid,
        "delete_target_count": len(delete_targets),
        "remaining_delete_targets": remaining_delete_targets,
        "contaminated_units": contaminated,
        "rejected_build_members": rejected_build_members,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = verify(arguments.root.resolve(), arguments.ledger.resolve())
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
