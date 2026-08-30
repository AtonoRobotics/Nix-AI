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
                r"#\[(?:[^\]]*::)?test(?:\([^\]]*\))?\]\s*(?:async\s+)?fn\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
                re.MULTILINE,
            )
            for match in tests.finditer(content):
                found.append(semantic_record(relative, content, match, "test_fixture"))
            found.extend(rust_enum_values(relative, content))
            found.extend(rust_macro_generated_types(relative, content))
            found.extend(rust_state_transitions(relative, content))
        elif suffix == ".py":
            python_tree = ast.parse(content, filename=relative)
            for node in ast.walk(python_tree):
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
            found.extend(python_enum_values(relative, python_tree))
            found.extend(python_state_transitions(relative, python_tree))
        elif suffix == ".proto":
            pattern = re.compile(
                r"\b(?P<kind>message|enum|service|rpc)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            )
            for match in pattern.finditer(content):
                found.append(semantic_record(relative, content, match))
            found.extend(proto_enum_values(relative, content))
        elif suffix == ".json":
            found.extend(contract_json_semantics(relative, content))
        elif suffix == ".nix":
            found.extend(nix_service_semantics(relative, content))
    return found


def semantic_record(relative, content, match, kind=None) -> dict[str, str | int]:
    position = match.start("name")
    return {
        "path": relative,
        "line": content.count("\n", 0, position) + 1,
        "kind": kind or match.group("kind"),
        "name": match.group("name"),
    }


def python_enum_values(relative: str, tree: ast.AST) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {ast.unparse(base).rsplit(".", 1)[-1] for base in node.bases}
        if not bases.intersection({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}):
            continue
        for statement in node.body:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name) and not target.id.startswith("_"):
                    found.append(
                        {
                            "path": relative,
                            "line": statement.lineno,
                            "kind": "enum_value",
                            "name": f"{node.name}::{target.id}",
                        }
                    )
    return found


def python_state_transitions(relative: str, tree: ast.AST) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        for key, value in zip(node.value.keys, node.value.values):
            if not isinstance(key, ast.Tuple) or len(key.elts) != 2:
                continue
            if not isinstance(value, (ast.Set, ast.List, ast.Tuple)):
                continue
            source = f"{ast.unparse(key.elts[0])}:{ast.unparse(key.elts[1])}"
            for target in value.elts:
                found.append(
                    {
                        "path": relative,
                        "line": getattr(target, "lineno", node.lineno),
                        "kind": "transition",
                        "name": f"{source}->{ast.unparse(target)}",
                    }
                )
    return found


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
            rf"\b{re.escape(definition.group('macro'))}!\s*[({{\[]\s*"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        )
        for match in invocation.finditer(content, definition.end()):
            found.append(semantic_record(relative, content, match, "macro_generated_type"))
    return found


def rust_state_transitions(relative: str, content: str) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    seen = set()
    direct = re.compile(
        r"(?P<type>[A-Za-z_][A-Za-z0-9_]*State)::(?P<source>[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*=>\s*(?P=type)::(?P<target>[A-Za-z_][A-Za-z0-9_]*)"
    )
    for match in direct.finditer(content):
        name = (
            f"{match.group('type')}::{match.group('source')}->"
            f"{match.group('type')}::{match.group('target')}"
        )
        seen.add(name)
        found.append(
            {
                "path": relative,
                "line": content.count("\n", 0, match.start("source")) + 1,
                "kind": "transition",
                "name": name,
            }
        )
    assignment = re.compile(r"\.state\s*=\s*(?P<expression>[^;\n]+)")
    target = re.compile(
        r"(?P<type>[A-Za-z_][A-Za-z0-9_]*State)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    )
    for match in assignment.finditer(content):
        for state in target.finditer(match.group("expression")):
            name = f"state_assignment->{state.group('type')}::{state.group('name')}"
            if name in seen:
                continue
            seen.add(name)
            position = match.start("expression") + state.start("name")
            found.append(
                {
                    "path": relative,
                    "line": content.count("\n", 0, position) + 1,
                    "kind": "transition",
                    "name": name,
                }
            )
    return found


def nix_service_semantics(relative: str, content: str) -> list[dict[str, str | int]]:
    found = []
    pattern = re.compile(
        r"\bsystemd\.(?:user\.)?services\."
        r"(?:\"(?P<quoted>[^\"]+)\"|(?P<plain>[A-Za-z0-9_@.-]+))"
    )
    for match in pattern.finditer(content):
        name = match.group("quoted") or match.group("plain")
        position = match.start("quoted") if match.group("quoted") else match.start("plain")
        found.append(
            {
                "path": relative,
                "line": content.count("\n", 0, position) + 1,
                "kind": "service",
                "name": name,
            }
        )
    return found


def proto_enum_values(relative: str, content: str) -> list[dict[str, str | int]]:
    found: list[dict[str, str | int]] = []
    for declaration in re.finditer(
        r"\benum\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{", content
    ):
        cursor = declaration.end()
        depth = 1
        while cursor < len(content) and depth:
            if content[cursor] == "{":
                depth += 1
            elif content[cursor] == "}":
                depth -= 1
            cursor += 1
        body = content[declaration.end() : cursor - 1]
        for value in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=", body
        ):
            absolute = declaration.end() + value.start()
            found.append(
                {
                    "path": relative,
                    "line": content.count("\n", 0, absolute) + 1,
                    "kind": "enum_value",
                    "name": f"{declaration.group('name')}::{value.group('name')}",
                }
            )
    return found


def contract_json_semantics(relative: str, content: str) -> list[dict[str, str | int]]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        return []
    canonical = document.get("canonical_model")
    if not isinstance(canonical, dict):
        return json_schema_semantics(relative, content, document)
    value_offsets, _ = json_token_offsets(content)
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
        for index, item in enumerate(canonical.get(collection, [])):
            name = item.get("id") if isinstance(item, dict) else item
            if not isinstance(name, str):
                continue
            path = ("canonical_model", collection, index)
            if isinstance(item, dict):
                path += ("id",)
            offset = value_offsets[path]
            found.append(
                {
                    "path": relative,
                    "line": content.count("\n", 0, max(offset, 0)) + 1,
                    "kind": kind,
                    "name": name,
                }
            )
    return found


def json_schema_semantics(
    relative: str, content: str, document: dict
) -> list[dict[str, str | int]]:
    definitions_key = "$defs" if isinstance(document.get("$defs"), dict) else "definitions"
    definitions = document.get(definitions_key)
    if not isinstance(definitions, dict) and "enum" not in json.dumps(document):
        return []
    value_offsets, key_offsets = json_token_offsets(content)
    found: list[dict[str, str | int]] = []
    for name in (definitions or {}):
        offset = key_offsets[(definitions_key, name)]
        found.append(
            {
                "path": relative,
                "line": content.count("\n", 0, max(offset, 0)) + 1,
                "kind": "schema_definition",
                "name": f"{definitions_key}/{name}",
            }
        )
    for path, value in schema_enum_values(document):
        value_offset = value_offsets[path]
        pointer = "#/" + "/".join(str(part) for part in path[:-1])
        found.append(
            {
                "path": relative,
                "line": content.count("\n", 0, max(value_offset, 0)) + 1,
                "kind": "schema_enum_value",
                "name": f"{pointer}::{value}",
            }
        )
    return found


def schema_enum_values(value, path=()):
    if isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list):
            for index, item in enumerate(enum):
                yield path + ("enum", index), item
        for key, child in value.items():
            if key != "enum":
                yield from schema_enum_values(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from schema_enum_values(child, path + (index,))


def json_token_offsets(content: str):
    decoder = json.JSONDecoder()
    value_offsets = {}
    key_offsets = {}

    def whitespace(index):
        while index < len(content) and content[index].isspace():
            index += 1
        return index

    def parse(index, path):
        index = whitespace(index)
        value_offsets[path] = index
        if content[index] == "{":
            index = whitespace(index + 1)
            while content[index] != "}":
                key_start = index
                key, index = decoder.raw_decode(content, index)
                child_path = path + (key,)
                key_offsets[child_path] = key_start
                index = whitespace(index)
                if content[index] != ":":
                    raise ValueError("invalid JSON object separator")
                index = parse(index + 1, child_path)
                index = whitespace(index)
                if content[index] == ",":
                    index = whitespace(index + 1)
                elif content[index] != "}":
                    raise ValueError("invalid JSON object terminator")
            return index + 1
        if content[index] == "[":
            index = whitespace(index + 1)
            item = 0
            while content[index] != "]":
                index = parse(index, path + (item,))
                item += 1
                index = whitespace(index)
                if content[index] == ",":
                    index = whitespace(index + 1)
                elif content[index] != "]":
                    raise ValueError("invalid JSON array terminator")
            return index + 1
        _, end = decoder.raw_decode(content, index)
        return end

    parse(0, ())
    return value_offsets, key_offsets


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
                raw_segment = body[segment_start:offset]
                leading = len(raw_segment) - len(raw_segment.lstrip())
                segment = raw_segment.strip()
                variant = re.match(r"(?:#\[[^\]]+\]\s*)*(?P<name>[A-Za-z_][A-Za-z0-9_]*)", segment)
                if variant:
                    absolute = (
                        body_start
                        + segment_start
                        + leading
                        + variant.start("name")
                    )
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
        for optional in document.get("project", {}).get("optional-dependencies", {}).values():
            declared.extend(optional)
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
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = "." * node.level + (node.module or "")
                    if node.module:
                        found.add((relative, "python-relative-import", base))
                    else:
                        for alias in node.names:
                            found.add(
                                (
                                    relative,
                                    "python-relative-import",
                                    base + alias.name,
                                )
                            )
                elif node.module:
                    found.add((relative, "python-import", node.module.split(".")[0]))

    for relative in paths:
        if relative.endswith(".proto"):
            content = read_text(relative) or ""
            for match in re.finditer(
                r"\bimport\s+(?:public\s+|weak\s+)?\"(?P<name>[^\"]+)\"",
                content,
            ):
                found.add((relative, "proto-import", match.group("name")))
        elif relative.endswith(".nix"):
            found.update(nix_dependencies(relative, read_text(relative) or ""))

    if "buf.gen.yaml" in paths:
        content = read_text("buf.gen.yaml") or ""
        for match in re.finditer(
            r"^\s*-\s+(?:local|remote):\s*(?P<name>\S+)", content, re.MULTILINE
        ):
            found.add(("buf.gen.yaml", "buf-plugin", match.group("name")))

    if "flake.lock" in paths:
        lock = json.loads(read_text("flake.lock") or "{}")
        for name in lock.get("nodes", {}):
            if name != "root":
                found.add(("flake.lock", "flake-input", name))

    return [
        {"path": path, "class": dependency_class, "name": name}
        for path, dependency_class, name in sorted(found)
    ]


def nix_dependencies(relative: str, content: str) -> set[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for match in re.finditer(
        r"\bpkgs\.(?:python3Packages\.)?(?P<name>[A-Za-z0-9_-]+)", content
    ):
        found.add((relative, "nix-package", match.group("name")))
    for match in re.finditer(
        r"\b(?:ps|pkgs\.python3Packages)\.(?P<name>[A-Za-z0-9_-]+)", content
    ):
        found.add((relative, "nix-package", match.group("name")))
    for block in re.finditer(
        r"with\s+pkgs(?:\.python3Packages)?\s*;\s*\[(?P<body>.*?)\]",
        content,
        re.DOTALL,
    ):
        for name in re.findall(r"\b[A-Za-z][A-Za-z0-9_-]*\b", block.group("body")):
            found.add((relative, "nix-package", name))
    for match in re.finditer(r"(?P<path>(?:\.\.?/)+[A-Za-z0-9_./-]+\.nix)\b", content):
        found.add((relative, "nix-module", match.group("path")))
    for match in re.finditer(
        r"modulesPath\s*\+\s*\"(?P<path>[^\"]+\.nix)\"", content
    ):
        found.add((relative, "nix-module", "modulesPath:" + match.group("path")))
    return found


def dependencies(root: Path, paths: list[str]) -> list[dict[str, str]]:
    tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    return dependencies_from_contents(paths, lambda path: tree_text(root, tree, path))


def generated_artifacts(paths: list[str]) -> list[dict[str, str]]:
    return generated_artifacts_from_contents(paths, lambda _path: None)


def generated_artifacts_from_contents(paths, read_text) -> list[dict[str, str]]:
    generated_names = {"Cargo.lock", "flake.lock"}
    result = []
    for path in paths:
        if path.startswith("generated/"):
            result.append({"path": path, "class": "generated-output"})
        elif Path(path).name in generated_names:
            result.append({"path": path, "class": "dependency-lock"})
        elif Path(path).name.endswith("MANIFEST.sha256"):
            result.append({"path": path, "class": "integrity-manifest"})
        required_class = generated_required_class(path)
        if required_class:
            result.append(
                {
                    "path": path,
                    "class": "generated-output",
                    "required_class": required_class,
                }
            )
    binding_path = "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
    if binding_path in paths:
        contract = json.loads(read_text(binding_path) or "{}")
        required = contract.get("repository_rebuild", {}).get(
            "generated_artifacts", {}
        ).get("required_classes", [])
        for name in required:
            result.append(
                {
                    "path": binding_path,
                    "class": "required-generated-class",
                    "name": name,
                }
            )
    return result


def generated_required_class(path: str) -> str | None:
    name = Path(path).name
    if name == "requirements.yaml":
        return "requirements_registry"
    if name == "work-packets.yaml" or name == "13-IMPLEMENTATION-WORK-GRAPH.md":
        return "work_graph"
    if path.startswith("contracts/architecture/") and path.endswith(".md"):
        return "architecture_projections"
    if path.endswith(".schema.json"):
        return "json_schemas"
    if name == "descriptor.bin":
        return "protobuf_descriptors"
    if path.startswith("generated/proto/") and path.endswith((".rs", ".py")):
        return "language_bindings"
    if name in {"Cargo.lock", "flake.lock"}:
        return "lockfiles"
    if name == "sbom.json":
        return "sbom"
    if name == "provenance.json":
        return "provenance"
    if path.startswith("evidence/") and path.endswith(".json"):
        return "evidence_indexes"
    if "evidence" in path.lower() and "index" in name.lower():
        return "evidence_indexes"
    if name.endswith("MANIFEST.sha256"):
        return "sha256_manifests"
    return None


def build_closure_members_from_contents(paths, read_text) -> list[dict[str, str]]:
    members: set[tuple[str, str]] = set()
    if "Cargo.toml" in paths:
        cargo = tomllib.loads(read_text("Cargo.toml") or "")
        for member in cargo.get("workspace", {}).get("members", []):
            members.add(("cargo-workspace", member))

    if "flake.nix" in paths:
        text = read_text("flake.nix") or ""
        bindings = list(
            re.finditer(
                r"^ {6}(?P<name>[A-Za-z][A-Za-z0-9_-]*)\s*=\s*",
                text,
                re.MULTILINE,
            )
        )
        binding_names = {match.group("name") for match in bindings}
        for index, match in enumerate(bindings):
            name = match.group("name")
            members.add(("nix-internal-derivation", name))
            end = bindings[index + 1].start() if index + 1 < len(bindings) else len(text)
            expression = text[match.end() : end]
            for dependency in sorted(
                set(re.findall(r"\b[A-Za-z][A-Za-z0-9_-]*\b", expression))
                & binding_names
                - {name}
            ):
                members.add(("nix-dependency-edge", f"{name}->{dependency}"))

        lines = text.splitlines()
        output_class = None
        for line in lines:
            container = re.match(
                r"^ {6}(?P<class>apps|packages|checks)\.\$\{system\}\s*=\s*\{",
                line,
            )
            if container:
                output_class = container.group("class")
                continue
            if output_class and line == "      };":
                output_class = None
                continue
            if output_class:
                member = re.match(r"^ {8}(?P<name>[A-Za-z0-9_-]+)\s*=", line)
                if member:
                    members.add((f"nix-{output_class}-output", member.group("name")))

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
        "generated_artifacts": generated_artifacts_from_contents(paths, read_tree),
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
