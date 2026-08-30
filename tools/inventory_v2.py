#!/usr/bin/env python3
"""Emit the baseline inventory that starts the Nix-AI v2 rebuild."""

from __future__ import annotations

import argparse
import ast
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


def tracked_paths(root: Path, tree: str) -> list[str]:
    return sorted(
        path
        for path in git(root, "ls-tree", "-r", "--name-only", tree).splitlines()
        if path
    )


def tree_text(root: Path, tree: str, relative: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{tree}:{relative}"],
        cwd=root,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def public_semantics_from_contents(paths, read_text) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    for relative in paths:
        content = read_text(relative)
        if content is None:
            continue
        suffix = Path(relative).suffix
        if suffix == ".rs":
            declaration = re.compile(
                r"(?:#\[[^\]]+\]\s*)*\bpub(?:\([^)]*\))?\s+(?:async\s+)?"
                r"(?P<kind>struct|enum|trait|fn|type|const|static|mod)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            )
            for match in declaration.finditer(content):
                found.append(semantic_record(relative, content, match))
            tests = re.compile(
                r"#\[(?:[^\]]*::)?test\]\s*(?:async\s+)?fn\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
                re.MULTILINE,
            )
            for match in tests.finditer(content):
                found.append(semantic_record(relative, content, match, "test_fixture"))
            found.extend(rust_enum_values(relative, content))
            found.extend(rust_macro_generated_types(relative, content))
        elif suffix == ".py":
            for node in ast.walk(ast.parse(content, filename=relative)):
                if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name.startswith("_"):
                    continue
                kind = "class" if isinstance(node, ast.ClassDef) else "def"
                if node.name.startswith("test_"):
                    kind = "test_fixture"
                found.append(
                    {"path": relative, "line": node.lineno, "kind": kind, "name": node.name}
                )
        elif suffix == ".proto":
            pattern = re.compile(
                r"^\s*(?P<kind>message|enum|service|rpc)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
                re.MULTILINE,
            )
            for match in pattern.finditer(content):
                found.append(semantic_record(relative, content, match))
        elif suffix == ".json":
            found.extend(contract_json_semantics(relative, content))
    return found


def semantic_record(relative, content, match, kind=None) -> dict[str, str | int]:
    return {
        "path": relative,
        "line": content.count("\n", 0, match.start()) + 1,
        "kind": kind or match.group("kind"),
        "name": match.group("name"),
    }


def rust_macro_generated_types(relative: str, content: str) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    for definition in re.finditer(
        r"macro_rules!\s+(?P<macro>[A-Za-z_][A-Za-z0-9_]*)", content
    ):
        body_end = content.find("\n}\n", definition.end())
        body = content[definition.end() : body_end if body_end >= 0 else len(content)]
        if not re.search(r"\bpub\s+(?:struct|enum|type|trait)\s+\$", body):
            continue
        invocation = re.compile(
            rf"\b{re.escape(definition.group('macro'))}!\(\s*"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        )
        for match in invocation.finditer(content, definition.end()):
            found.append(semantic_record(relative, content, match, "macro_generated_type"))
    return found


def contract_json_semantics(relative: str, content: str) -> list[dict[str, str | int]]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        return []
    canonical = document.get("canonical_model")
    if not isinstance(canonical, dict):
        return []
    kinds = {
        "principals": "canonical_principal",
        "records": "canonical_record",
        "services": "canonical_service",
        "effect_classes": "effect_class",
        "effect_states": "effect_state",
        "execution_profiles": "execution_profile",
        "hardware_profiles": "hardware_profile",
        "change_states": "change_state",
        "error_codes": "error_code",
    }
    found: list[dict[str, str | int]] = []
    for collection, kind in kinds.items():
        for item in canonical.get(collection, []):
            name = item.get("id") if isinstance(item, dict) else item
            if not isinstance(name, str):
                continue
            offset = content.find(json.dumps(name))
            found.append(
                {
                    "path": relative,
                    "line": content.count("\n", 0, max(offset, 0)) + 1,
                    "kind": kind,
                    "name": name,
                }
            )
    return found


def rust_enum_values(relative: str, content: str) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    declaration = re.compile(
        r"(?:#\[[^\]]+\]\s*)*pub(?:\([^)]*\))?\s+enum\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{",
        re.MULTILINE,
    )
    for match in declaration.finditer(content):
        enum_name = match.group("name")
        body_start = match.end()
        depth = 1
        cursor = body_start
        while cursor < len(content) and depth:
            if content[cursor] == "{":
                depth += 1
            elif content[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            continue
        body = content[body_start : cursor - 1]
        segment_start = 0
        nested = 0
        for offset, character in enumerate(body + ","):
            if character in "({[":
                nested += 1
            elif character in ")}]":
                nested -= 1
            elif character == "," and nested == 0:
                segment = body[segment_start:offset].strip()
                variant = re.match(r"(?:#\[[^\]]+\]\s*)*(?P<name>[A-Za-z_][A-Za-z0-9_]*)", segment)
                if variant:
                    absolute = body_start + segment_start
                    found.append(
                        {
                            "path": relative,
                            "line": content.count("\n", 0, absolute) + 1,
                            "kind": "enum_value",
                            "name": f"{enum_name}::{variant.group('name')}",
                        }
                    )
                segment_start = offset + 1
    return found


def public_semantics(root: Path, paths: list[str]) -> list[dict[str, str | int]]:
    tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    return public_semantics_from_contents(paths, lambda path: tree_text(root, tree, path))


def dependencies_from_contents(paths, read_text) -> list[dict[str, str]]:
    found: set[tuple[str, str, str]] = set()
    dependency_sections = {
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
    }
    for relative in paths:
        if not relative.endswith("Cargo.toml"):
            continue
        content = read_text(relative)
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

    if "pyproject.toml" in paths:
        document = tomllib.loads(read_text("pyproject.toml") or "")
        declared = list(document.get("project", {}).get("dependencies", []))
        declared.extend(document.get("build-system", {}).get("requires", []))
        for requirement in declared:
            match = re.match(r"[A-Za-z0-9_.-]+", requirement)
            if match:
                found.add(("pyproject.toml", "python-declared", match.group(0)))

    for relative in paths:
        if not relative.endswith(".py"):
            continue
        content = read_text(relative)
        if content is None:
            continue
        for node in ast.walk(ast.parse(content, filename=relative)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add((relative, "python-import", alias.name.split(".")[0]))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level:
                    found.add(
                        (
                            relative,
                            "python-relative-import",
                            "." * node.level + node.module,
                        )
                    )
                else:
                    found.add((relative, "python-import", node.module.split(".")[0]))

    if "flake.lock" in paths:
        lock = json.loads(read_text("flake.lock") or "{}")
        for name in lock.get("nodes", {}):
            if name != "root":
                found.add(("flake.lock", "flake-input", name))

    return [
        {"path": path, "class": dependency_class, "name": name}
        for path, dependency_class, name in sorted(found)
    ]


def dependencies(root: Path, paths: list[str]) -> list[dict[str, str]]:
    tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    return dependencies_from_contents(paths, lambda path: tree_text(root, tree, path))


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


def build_closure_members_from_contents(paths, read_text) -> list[dict[str, str]]:
    members: set[tuple[str, str]] = set()
    if "Cargo.toml" in paths:
        cargo = tomllib.loads(read_text("Cargo.toml") or "")
        for member in cargo.get("workspace", {}).get("members", []):
            members.add(("cargo-workspace", member))

    if "flake.nix" in paths:
        text = read_text("flake.nix") or ""
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


def build_closure_members(root: Path, paths: list[str]) -> list[dict[str, str]]:
    tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    return build_closure_members_from_contents(
        paths, lambda path: tree_text(root, tree, path)
    )


def inventory(root: Path, baseline: str) -> dict:
    resolved = git(root, "rev-parse", f"{baseline}^{{commit}}").strip()
    inventory_commit = git(root, "rev-parse", "HEAD^{commit}").strip()
    inventory_tree = git(root, "rev-parse", f"{inventory_commit}^{{tree}}").strip()
    paths = tracked_paths(root, inventory_tree)
    read_tree = lambda path: tree_text(root, inventory_tree, path)
    report = {
        "schema_version": 1,
        "runner": RUNNER,
        "rebuild_baseline_commit": resolved,
        "inventory_commit": inventory_commit,
        "inventory_tree": inventory_tree,
        "inventory_source": {
            "tracked_paths": "git-tree",
            "file_contents": "git-tree",
            "build_closure_members": "declared-source-graph",
            "snapshot_boundary": "before-report-publication",
        },
        "tracked_paths": paths,
        "public_semantics": public_semantics_from_contents(paths, read_tree),
        "dependencies": dependencies_from_contents(paths, read_tree),
        "generated_artifacts": generated_artifacts(paths),
        "build_closure_members": build_closure_members_from_contents(paths, read_tree),
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
