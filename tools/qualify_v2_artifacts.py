#!/usr/bin/env python3
"""Regenerate and qualify the complete v2 artifact set and declared build graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

from derive_v2_contract import INTERFACE_SOURCE_SHA256, outputs as contract_outputs
from proto_contracts import source_digest

REQUIRED_CLASSES = (
    "requirements_registry", "work_graph", "architecture_projections", "json_schemas",
    "protobuf_descriptors", "language_bindings", "lockfiles", "sbom", "provenance",
    "evidence_indexes", "sha256_manifests",
)
FORBIDDEN_CLOSURE_TERMS = ("habitat-physical", "ros2", "rcl", "rmw", "robotics", "isaac", "gazebo")
FORBIDDEN_GENERATED = re.compile(
    r"(?:^|[^a-z0-9])(?:physical[_ -]?ai|robot(?:ics|_arm)?|ros2?|gazebo|isaac|nvidia|cuda)(?:$|[^a-z0-9])",
    re.I)


def canonical(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cargo_sections(data, prefix=""):
    for key, value in data.items():
        section = f"{prefix}.{key}" if prefix else key
        if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(value, dict):
            yield section, value
        elif isinstance(value, dict):
            yield from cargo_sections(value, section)


def cargo_inventory(root: Path):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    members = sorted(workspace["workspace"]["members"])
    owners = []
    for member in members:
        manifest = tomllib.loads((root / member / "Cargo.toml").read_text())
        package = manifest["package"]["name"]
        owners.append({"dependency": package, "owner": "workspace", "section": "members"})
        for section, dependencies in cargo_sections(manifest):
            for name, declaration in dependencies.items():
                actual = declaration.get("package", name) if isinstance(declaration, dict) else name
                owners.append({"dependency": actual, "owner": package, "section": section})
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    packages = sorted(lock["package"], key=lambda item: (item["name"], item["version"], item.get("source", "")))
    locked_names = {item["name"] for item in packages}
    missing = set(item["dependency"] for item in owners) - locked_names
    for package in packages:
        owner = f"{package['name']}@{package['version']}"
        for dependency in package.get("dependencies", []):
            owners.append({"dependency": dependency.split()[0], "owner": owner, "section": "Cargo.lock"})
    owned_names = {item["dependency"] for item in owners}
    missing.update(locked_names - owned_names)
    sbom = {
        "format": "nix-ai-v2-cargo-sbom-1",
        "workspace_members": members,
        "packages": [{key: item[key] for key in ("name", "version", "source", "checksum") if key in item}
                     for item in packages],
        "dependency_ownership": sorted(owners, key=lambda item: (item["dependency"], item["owner"], item["section"])),
    }
    return sbom, sorted(missing)


def evidence_index(root: Path):
    entries = []
    for path in sorted((root / "evidence").rglob("*.json")):
        relative = path.relative_to(root).as_posix()
        if relative in {"evidence/v2-rebuild/artifact-closure-report.json",
                        "evidence/v2-rebuild/build-closure-report.json"}:
            continue
        entries.append({"path": relative, "sha256": sha(path.read_bytes())})
    return {"format": "nix-ai-v2-evidence-index-1", "entries": entries}


def provenance(root: Path):
    sources = [
        "contracts/v2.0.1/nix-ai-v2.0.1.contract.json", "Cargo.toml", "Cargo.lock",
        "flake.nix", "flake.lock", "tools/derive_v2_contract.py", "tools/proto_contracts.py",
        "tools/qualify_v2_artifacts.py", "tools/verify_v2_build_closure.py", "buf.yaml", "buf.gen.yaml",
    ]
    sources.extend(path.relative_to(root).as_posix() for path in sorted((root / "crates").glob("*/Cargo.toml")))
    sources.extend(path.relative_to(root).as_posix() for path in sorted((root / "contracts/proto").glob("*.proto")))
    return {"format": "nix-ai-v2-artifact-provenance-1",
            "sources": [{"path": path, "sha256": sha((root / path).read_bytes())} for path in sorted(sources)]}


def metadata_outputs(root: Path):
    sbom, _ = cargo_inventory(root)
    return {
        "generated/v2/sbom.json": canonical(sbom),
        "generated/v2/provenance.json": canonical(provenance(root)),
        "generated/v2/evidence-index.json": canonical(evidence_index(root)),
        "generated/v2/lock-regeneration.json": canonical({
            "format": "nix-ai-v2-lock-regeneration-1",
            "command": "cargo generate-lockfile --offline",
            "cargo_lock_sha256": sha((root / "Cargo.lock").read_bytes()),
        }),
    }


def manifest_members(root: Path, generated: dict[str, bytes]):
    paths = set(contract_outputs(root))
    paths.update(generated)
    paths.update(path.relative_to(root).as_posix() for path in (root / "contracts/schemas").glob("*.schema.json"))
    paths.update(path.relative_to(root).as_posix() for path in (root / "generated/proto").rglob("*.*") if path.is_file())
    paths.update(("Cargo.lock", "flake.lock", "contracts/v2/MANIFEST.sha256", "contracts/v2.0.1/MANIFEST.sha256"))
    return sorted(paths)


def expected_outputs(root: Path):
    generated = metadata_outputs(root)
    lines = []
    for relative in manifest_members(root, generated):
        content = generated[relative] if relative in generated else (root / relative).read_bytes()
        lines.append(f"{sha(content)}  {relative}\n")
    generated["generated/v2/MANIFEST.sha256"] = "".join(lines).encode()
    return generated


def artifact_classes(root: Path):
    return {
        "requirements_registry": ["contracts/requirements.yaml"],
        "work_graph": ["contracts/work-packets.yaml", "contracts/architecture/13-IMPLEMENTATION-WORK-GRAPH.md"],
        "architecture_projections": sorted(path.relative_to(root).as_posix() for path in (root / "contracts/architecture").glob("*.md")),
        "json_schemas": sorted(path.relative_to(root).as_posix() for path in (root / "contracts").rglob("*.schema.json")),
        "protobuf_descriptors": ["generated/proto/descriptor.bin"],
        "language_bindings": sorted(path.relative_to(root).as_posix() for path in (root / "generated/proto/rust").rglob("*.rs")),
        "lockfiles": ["Cargo.lock", "flake.lock"],
        "sbom": ["generated/v2/sbom.json"],
        "provenance": ["generated/v2/provenance.json"],
        "evidence_indexes": ["generated/v2/evidence-index.json"],
        "sha256_manifests": sorted(path.relative_to(root).as_posix() for path in root.rglob("MANIFEST.sha256")),
    }


def qualify(root: Path):
    expected = expected_outputs(root)
    stale = sorted(path for path, content in {**contract_outputs(root), **expected}.items()
                   if not (root / path).is_file() or (root / path).read_bytes() != content)
    classes = artifact_classes(root)
    interface_stale = [relative for relative, expected_hash in INTERFACE_SOURCE_SHA256.items()
                       if sha((root / relative).read_bytes()) != expected_hash]
    expected_source_digest = source_digest(root / "contracts/proto")
    if (root / "generated/proto/SOURCE.sha256").read_text().split()[0] != expected_source_digest:
        interface_stale.append("generated/proto/SOURCE.sha256")
    stale = sorted(set(stale + interface_stale))
    contaminated = []
    for path in classes["language_bindings"]:
        if FORBIDDEN_GENERATED.search((root / path).read_text(errors="replace")):
            contaminated.append(path)
    sbom, unowned = cargo_inventory(root)
    closure_identities = [item["dependency"] for item in sbom["dependency_ownership"]]
    deleted = sorted(item for item in closure_identities if any(term in item.lower() for term in FORBIDDEN_CLOSURE_TERMS))
    records = []
    for name in REQUIRED_CLASSES:
        for path in classes[name]:
            records.append({"class": name, "path": path, "sha256": sha((root / path).read_bytes())})
    return {
        "schema_version": "1.0", "scope": "issue-29-generated-artifacts-and-declared-build-graph",
        "artifact_classes": list(REQUIRED_CLASSES), "records": records,
        "dependency_owner_count": len(sbom["dependency_ownership"]),
        "unowned_dependencies": unowned, "deleted_closure_members": deleted,
        "stale_generated": stale, "contaminated_generated": contaminated,
        "valid": not stale and not contaminated and not unowned and not deleted and set(classes) == set(REQUIRED_CLASSES),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--verify-cargo", type=Path)
    parser.add_argument("--verify-nix", type=Path)
    args = parser.parse_args(); root = args.root.resolve()
    if args.write:
        for relative, content in expected_outputs(root).items():
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
    if args.verify_cargo:
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "workspace"
            clone.mkdir()
            shutil.copy2(root / "Cargo.toml", clone / "Cargo.toml")
            shutil.copytree(root / "crates", clone / "crates")
            subprocess.run([str(args.verify_cargo), "generate-lockfile", "--offline"], cwd=clone, check=True,
                           capture_output=True, text=True)
            if (clone / "Cargo.lock").read_bytes() != (root / "Cargo.lock").read_bytes():
                raise SystemExit("clean cargo generate-lockfile did not reproduce Cargo.lock")
    if args.verify_nix:
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary)
            shutil.copy2(root / "flake.nix", clone / "flake.nix")
            shutil.copy2(root / "flake.lock", clone / "flake.lock")
            subprocess.run([str(args.verify_nix), "flake", "lock", "--offline", f"path:{clone}"], cwd=clone, check=True,
                           capture_output=True, text=True)
            if (clone / "flake.lock").read_bytes() != (root / "flake.lock").read_bytes():
                raise SystemExit("clean nix flake lock did not reproduce flake.lock")
    report = qualify(root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_bytes(canonical(report))
    print(json.dumps({key: report[key] for key in ("valid", "artifact_classes", "stale_generated", "unowned_dependencies", "deleted_closure_members")}, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
