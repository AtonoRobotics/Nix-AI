#!/usr/bin/env python3
"""Bounded retention audit for the remaining v2 core-service candidates.

Whole-repository disposition belongs to the exact-tree ledger produced for issue #24.
This audit covers only the retained service roots named below. Each exact source file is
the review unit: its digest and v2 authority are recorded, and any byte change requires a
new checked ledger. Language syntax is deliberately not reimplemented here.
"""
import argparse
import ast
import hashlib
import json
import tomllib
from pathlib import Path

COMPONENTS = {
    "crates/habitat-abi/": ("ABI-001", "ABI-002", "ABI-004"),
    "crates/habitat-authority/": ("AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"),
    "crates/habitat-context/": ("CTX-001", "CTX-002", "CTX-003", "CTX-004"),
    "crates/habitat-execution/": ("AUTH-004", "EXEC-001", "EXEC-002", "SYS-004"),
    "crates/habitat-effects/": ("EFFECT-001", "EFFECT-002", "EFFECT-003", "EFFECT-004", "EFFECT-005"),
    "crates/habitat-models/": ("ABI-003",),
    "crates/habitat-packages/": ("PKG-001", "PKG-002", "PKG-003"),
    "crates/habitat-harnesses/": ("ABI-003", "EXEC-003"),
    "src/habitat_state/": ("STATE-001", "STATE-002", "STATE-003", "STATE-004"),
}
EXTRA_FILES = {
    "tests/test_w01_profile.py": ("SYS-004",),
    "tests/test_w02_state.py": ("STATE-001", "STATE-003", "STATE-004"),
    "tests/test_w05_lifecycle.py": ("CORE-002", "STATE-002"),
    "tests/fixtures/proto-contracts/": ("ABI-001", "ABI-004"),
    "tests/fixtures/schema-contracts/": ("PKG-001",),
    "nix/profiles/qemu-x86_64-conformance.json": ("SYS-004",),
    "contracts/schemas/hardware-profile.schema.json": ("SYS-004",),
}
ALLOWED_CARGO = {
    "crates/habitat-abi/": {"hyper-util", "prost", "prost-types", "serde", "serde_json", "sha2", "tokio", "tokio-stream", "tonic", "tonic-prost", "tower", "tempfile", "tonic-prost-build"},
    "crates/habitat-authority/": {"serde", "serde_json", "sha2", "libc", "tempfile"},
    "crates/habitat-context/": {"serde", "serde_json", "sha2"},
    "crates/habitat-execution/": {"serde", "serde_json"},
    "crates/habitat-effects/": {"habitat-authority", "serde", "serde_json", "sha2", "tempfile"},
    "crates/habitat-models/": {"serde", "serde_json"},
    "crates/habitat-packages/": {"ed25519-dalek", "serde", "serde_json", "sha2"},
    "crates/habitat-harnesses/": {"habitat-models", "serde", "serde_json"},
}
DEPENDENCY_PURPOSES = {
    "serde": "canonical record encoding", "serde_json": "typed JSON boundary encoding",
    "sha2": "content identity digests", "libc": "Linux peer identity enforcement",
    "tempfile": "isolated persistence tests", "prost": "protobuf ABI",
    "prost-types": "protobuf well-known types", "tonic": "gRPC boundary",
    "tonic-prost": "gRPC protobuf codec", "tonic-prost-build": "protobuf generation",
    "hyper-util": "gRPC connector runtime", "tokio": "asynchronous transport runtime",
    "tokio-stream": "Unix listener adaptation", "tower": "transport service adaptation",
    "ed25519-dalek": "package signature verification",
    "habitat-authority": "current authority evaluation at effect admission",
    "habitat-models": "normalized cognition ABI consumed by harnesses",
}
PYTHON_ALLOWED = {"__future__", "boto3", "botocore", "concurrent", "dataclasses", "datetime",
    "base64", "domain", "enum", "habitat_state", "hashlib", "json", "lifecycle", "os", "pathlib", "re",
    "psycopg", "secrets", "store", "time", "typing", "unittest", "uuid"}
ADAPTER_ROOTS = ("crates/habitat-models/", "crates/habitat-harnesses/")
FORBIDDEN_ADAPTER_DEPENDENCIES = {"habitat-authority", "habitat-effects",
    "reqwest", "hyper", "libc", "tokio"}

def authority(path):
    value = path.as_posix()
    for prefix, requirements in COMPONENTS.items():
        if value.startswith(prefix): return prefix, requirements
    for selector, requirements in EXTRA_FILES.items():
        if value == selector or value.startswith(selector): return selector, requirements
    return None, None

def dependency_sections(data, prefix=""):
    for key, value in data.items():
        section = f"{prefix}.{key}" if prefix else key
        if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(value, dict):
            yield section, value
        elif isinstance(value, dict):
            yield from dependency_sections(value, section)

def record(kind, identity, requirements, source, digest, **details):
    return {"kind": kind, "identity": identity, "source": source, "sha256": digest,
        "requirement_ids": list(requirements),
        "authority": [f"contracts/v2.0.1/nix-ai-v2.0.1.contract.json#/requirements/{item}" for item in requirements],
        "review_unit": "exact-file-bytes", **details}

def audit(root):
    contract = json.loads((root / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
    known_requirements = {item["id"] for item in contract["requirements"]}
    records, unresolved, candidates = [], [], []
    for path in sorted(root.rglob("*")):
        if any(part in {"__pycache__", "target", ".pytest_cache"} for part in path.relative_to(root).parts): continue
        if not path.is_file() or path.is_symlink(): continue
        relative = path.relative_to(root)
        selector, requirements = authority(relative)
        if not requirements: continue
        candidates.append(relative.as_posix())
        raw = path.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
        try: content = raw.decode()
        except UnicodeDecodeError:
            unresolved.append(f"undecodable-retention-candidate:{relative}"); continue
        is_test = "/tests/" in relative.as_posix() or relative.name.startswith("test_")
        is_fixture = relative.as_posix().startswith("tests/fixtures/")
        kind = "fixture" if is_fixture else "test" if is_test else "source_unit"
        predicates = ["RET-004"] if is_test or is_fixture else ["RET-001", "RET-002"]
        records.append(record(kind, relative.as_posix(), requirements, relative.as_posix(), digest,
            selector=selector, predicates=predicates,
            coverage="all APIs and control flow in these exact reviewed bytes" if kind == "source_unit" else "canonical or opaque test material"))
        if path.name == "Cargo.toml":
            component = next(prefix for prefix in COMPONENTS if relative.as_posix().startswith(prefix))
            for section, dependencies in dependency_sections(tomllib.loads(content)):
                for dependency in sorted(dependencies):
                    purpose = DEPENDENCY_PURPOSES.get(dependency)
                    records.append(record("dependency", f"{relative}:{section}:{dependency}", requirements,
                        relative.as_posix(), digest, predicates=["RET-003"], necessity=purpose))
                    if dependency not in ALLOWED_CARGO[component] or not purpose:
                        unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
                    if component in ADAPTER_ROOTS and dependency in FORBIDDEN_ADAPTER_DEPENDENCIES:
                        unresolved.append(f"adapter-direct-path:{relative}:{dependency}")
        if relative.suffix == ".py" and relative.as_posix().startswith("src/habitat_state/"):
            tree = ast.parse(content)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import): names = [item.name.split(".")[0] for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module: names = [node.module.split(".")[0]]
                for dependency in names:
                    records.append(record("dependency", f"{relative}:python:{dependency}", requirements,
                        relative.as_posix(), digest, predicates=["RET-003"], necessity="declared Python import"))
                    if dependency not in PYTHON_ALLOWED:
                        unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
        if relative.as_posix().startswith(ADAPTER_ROOTS) and "transcript" in content.lower():
            unresolved.append(f"authoritative-transcript-surface:{relative}")

    profile = json.loads((root / "nix/profiles/qemu-x86_64-conformance.json").read_text())
    profile_ok = (profile.get("profile_id") in set(contract["canonical_model"]["hardware_profiles"])
        and profile.get("gpu", {}).get("status") == "absent" and profile.get("devices") == []
        and bool(profile.get("capacity")) and profile.get("isolation", {}).get("default") == "DENY"
        and bool(profile.get("kernel", {}).get("digest")) and bool(profile.get("firmware", {}).get("digest"))
        and bool(profile.get("drivers", {}).get("digest")))
    if not profile_ok: unresolved.append("hardware-profile-missing-capacity-or-explicit-absence")
    unknown = sorted({req for item in records for req in item["requirement_ids"] if req not in known_requirements})
    unresolved.extend(f"unknown-requirement:{item}" for item in unknown)
    digest = hashlib.sha256()
    for relative in candidates: digest.update(relative.encode() + b"\0" + (root / relative).read_bytes() + b"\0")
    counts = {kind: sum(item["kind"] == kind for item in records)
        for kind in ("source_unit", "dependency", "test", "fixture")}
    return {"schema_version": 2, "runner": {"name": "audit-v2-core", "version": 2},
        "scope": "issue-28-retained-core-candidates", "scope_boundary": sorted(COMPONENTS) + sorted(EXTRA_FILES),
        "mapping_granularity": "exact-file authority scope; no source-language parser",
        "scope_digest": digest.hexdigest(), "candidate_file_count": len(candidates), "counts": counts,
        "adapter_boundary": {"direct_dependency_count": sum(item.startswith("adapter-direct-path:") for item in unresolved),
            "provider_transcripts": "diagnostic-only"},
        "hardware_profile": {"profile_id": profile.get("profile_id"), "capacity_declared": bool(profile.get("capacity")),
            "gpu": profile.get("gpu", {}).get("status"), "devices": profile.get("devices")},
        "records": records, "unresolved_candidates": sorted(set(unresolved)),
        "untrusted_candidates": sorted(set(unresolved)), "valid": not unresolved}

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    report = audit(args.root.resolve()); args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("valid", "counts", "candidate_file_count", "unresolved_candidates")}, sort_keys=True))
    raise SystemExit(0 if report["valid"] else 1)

if __name__ == "__main__": main()
