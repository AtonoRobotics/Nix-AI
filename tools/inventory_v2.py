#!/usr/bin/env python3
"""Emit the baseline inventory that starts the Nix-AI v2 rebuild."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib


RUNNER = {"name": "inventory-v2", "version": 1}
INVENTORY_CLASSES = (
    "tracked_paths",
    "public_semantics",
    "dependencies",
    "generated_artifacts",
    "build_closure_members",
)


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or "git command failed")
    return result.stdout


def tracked_paths(root: Path) -> list[str]:
    return sorted(path for path in git(root, "ls-files").splitlines() if path)


def indexed_text(root: Path, relative: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f":{relative}"],
        cwd=root,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def public_semantics(root: Path, paths: list[str]) -> list[dict[str, str | int]]:
    patterns = {
        ".rs": re.compile(
            r"^\s*pub(?:\([^)]*\))?\s+(?:async\s+)?"
            r"(?P<kind>struct|enum|trait|fn|type|const|static|mod)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        ),
        ".py": re.compile(r"^(?P<kind>class|def)\s+(?P<name>[A-Za-z][A-Za-z0-9_]*)"),
        ".proto": re.compile(
            r"^\s*(?P<kind>message|enum|service|rpc)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        ),
    }
    found: list[dict[str, str | int]] = []
    for relative in paths:
        pattern = patterns.get(Path(relative).suffix)
        if pattern is None:
            continue
        content = indexed_text(root, relative)
        if content is None:
            continue
        lines = content.splitlines()
        for line_number, line in enumerate(lines, 1):
            match = pattern.match(line)
            if match:
                found.append(
                    {
                        "path": relative,
                        "line": line_number,
                        "kind": match.group("kind"),
                        "name": match.group("name"),
                    }
                )
    return found


def dependencies(root: Path, paths: list[str]) -> list[dict[str, str]]:
    found: set[tuple[str, str, str]] = set()
    dependency_sections = {
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
    }
    for relative in paths:
        if not relative.endswith("Cargo.toml"):
            continue
        content = indexed_text(root, relative)
        if content is None:
            continue
        document = tomllib.loads(content)
        for section, values in document.items():
            if section in dependency_sections and isinstance(values, dict):
                for name in values:
                    found.add((relative, section, name))
        for target in document.get("target", {}).values():
            if not isinstance(target, dict):
                continue
            for section in dependency_sections:
                for name in target.get(section, {}):
                    found.add((relative, f"target.{section}", name))

    if "flake.lock" in paths:
        lock = json.loads(indexed_text(root, "flake.lock") or "{}")
        for name in lock.get("nodes", {}):
            if name != "root":
                found.add(("flake.lock", "flake-input", name))

    return [
        {"path": path, "class": dependency_class, "name": name}
        for path, dependency_class, name in sorted(found)
    ]


def generated_artifacts(paths: list[str]) -> list[dict[str, str]]:
    generated_names = {"Cargo.lock", "flake.lock"}
    result = []
    for path in paths:
        if path.startswith("generated/"):
            result.append({"path": path, "class": "generated-output"})
        elif Path(path).name in generated_names:
            result.append({"path": path, "class": "dependency-lock"})
        elif Path(path).name.endswith("MANIFEST.sha256"):
            result.append({"path": path, "class": "integrity-manifest"})
    return result


def build_closure_members(root: Path, paths: list[str]) -> list[dict[str, str]]:
    members: set[tuple[str, str]] = set()
    if "Cargo.toml" in paths:
        cargo = tomllib.loads(indexed_text(root, "Cargo.toml") or "")
        for member in cargo.get("workspace", {}).get("members", []):
            members.add(("cargo-workspace", member))

    if "flake.nix" in paths:
        text = indexed_text(root, "flake.nix") or ""
        for match in re.finditer(
            r"^\s{8}(?P<name>[A-Za-z][A-Za-z0-9_-]*)\s*=\s*",
            text,
            re.MULTILINE,
        ):
            members.add(("nix-declared-closure-root", match.group("name")))

    return [
        {"class": member_class, "name": name}
        for member_class, name in sorted(members)
    ]


def inventory(root: Path, baseline: str) -> dict:
    resolved = git(root, "rev-parse", f"{baseline}^{{commit}}").strip()
    inventory_tree = git(root, "write-tree").strip()
    paths = tracked_paths(root)
    report = {
        "schema_version": 1,
        "runner": RUNNER,
        "rebuild_baseline_commit": resolved,
        "inventory_tree": inventory_tree,
        "inventory_source": {
            "tracked_paths": "git-index",
            "file_contents": "git-index",
            "build_closure_members": "declared-source-graph",
            "snapshot_boundary": "before-report-publication",
        },
        "tracked_paths": paths,
        "public_semantics": public_semantics(root, paths),
        "dependencies": dependencies(root, paths),
        "generated_artifacts": generated_artifacts(paths),
        "build_closure_members": build_closure_members(root, paths),
    }
    report["counts"] = {name: len(report[name]) for name in INVENTORY_CLASSES}
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        report = inventory(arguments.root.resolve(), arguments.baseline)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        parser.error(str(error))

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"valid": True, "output": str(arguments.output), "counts": report["counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
