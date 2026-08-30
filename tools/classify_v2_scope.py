#!/usr/bin/env python3
"""Classify a complete repository inventory against the binding v2 scope."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from inventory_v2 import (
    build_closure_members_from_contents,
    dependencies_from_contents,
    generated_artifacts_from_contents,
    public_semantics_from_contents,
)


RUNNER = {"name": "classify-v2-scope", "version": 1}
BINDING_CONTRACT_SHA256 = "f3548fa489fbc9a09aacaaeb62381bbea65a175ca0fcf300b9d911b48c555f1a"
BINDING_MANIFEST_SHA256 = "5ccdd43bd2489b3f202ffa1620a11ff8593e8ffc26161c2c3f2a8e2d55aacb8c"
ARCHIVED_V2_CONTRACT_SHA256 = "49b1638fb71cbe8e6664d7463132d33b3fd121e88468608699e613685af83dd6"
ARCHIVED_V2_MANIFEST_SHA256 = "63621cccd011aca6704bba1e2d5ef78bdd5967e6576da012f28430657d422ce5"
INVENTORY_CLASSES = (
    "tracked_paths",
    "public_semantics",
    "dependencies",
    "generated_artifacts",
    "build_closure_members",
)
INVENTORY_KEYS = set(INVENTORY_CLASSES) | {
    "counts",
    "inventory_commit",
    "inventory_source",
    "inventory_tree",
    "rebuild_baseline_commit",
    "runner",
    "schema_version",
}
FINAL_ACTIONS = {"RETAIN", "DELETE", "DELETE_AND_REBUILD", "REGENERATE"}
DOMAIN_TERMS = (
    "cordis",
    "physical",
    "robot",
    "ros",
    "isaac",
    "omniverse",
    "simulation",
    "jetson",
    "embodiment",
    "sensor",
    "actuator",
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(term) for term in DOMAIN_TERMS) + r")\b",
    re.IGNORECASE,
)


PATH_REQUIREMENTS = (
    ("crates/habitat-abi/", ("CORE-001", "ABI-001", "ABI-002", "ABI-004")),
    ("crates/habitat-authority/", ("AUTH-001", "AUTH-002", "AUTH-003")),
    ("crates/habitat-context/", ("CTX-001", "CTX-002", "CTX-003", "CTX-004")),
    ("crates/habitat-effects/", ("EFFECT-001", "EFFECT-002", "EFFECT-003", "EFFECT-004", "EFFECT-005")),
    ("crates/habitat-execution/", ("AUTH-004", "EXEC-001", "EXEC-002")),
    ("crates/habitat-harnesses/", ("EXEC-003",)),
    ("crates/habitat-models/", ("ABI-003",)),
    ("crates/habitat-packages/", ("PKG-001", "PKG-002", "PKG-003")),
    ("src/habitat_state/", ("STATE-001", "STATE-002", "STATE-003", "STATE-004")),
    ("docs/agents/", ("SCOPE-001",)),
    ("contracts/v2.0.1/", ("SCOPE-001", "SCOPE-003")),
    ("contracts/v2/", ("CHANGE-003",)),
)


def requirement_ids_for(path: str) -> list[str]:
    for prefix, requirements in PATH_REQUIREMENTS:
        if path.startswith(prefix):
            return list(requirements)
    if path in {"AGENTS.md", ".gitignore"}:
        return ["SCOPE-001"]
    if path.startswith("tools/inventory_v2.py") or path.startswith("tools/classify_v2_scope.py"):
        return ["SCOPE-001", "VERIFY-001"]
    if path.startswith("tests/test_v2_"):
        return ["SCOPE-001", "VERIFY-001"]
    if path.startswith("evidence/v2-rebuild/"):
        return ["SCOPE-001", "VERIFY-001"]
    return []


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=root, text=True, capture_output=True
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or "git command failed")
    return result.stdout


def inventory_tree_contents(root: Path, tree: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{tree}:{path}"], cwd=root, capture_output=True
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result.stdout.decode("utf-8", errors="replace")


def inventory_tree_bytes(root: Path, tree: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{tree}:{path}"], cwd=root, capture_output=True
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def explicit_path_disposition(path: str, dispositions: list[dict]) -> tuple[str, str, str] | None:
    for disposition in dispositions:
        selector = disposition["selector"]
        selected_path = selector.get("path")
        selected_glob = selector.get("glob")
        if selected_path and (path == selected_path or path.startswith(selected_path + "/")):
            return disposition["action"], disposition["id"], disposition["reason"]
        if selected_glob and fnmatch.fnmatch(path, selected_glob):
            return disposition["action"], disposition["id"], disposition["reason"]
    return None


def classify_path(
    path: str,
    content: str,
    dispositions: list[dict],
    predicates: list[str],
) -> dict:
    explicit = explicit_path_disposition(path, dispositions)
    if explicit:
        action, rule_id, reason = explicit
        return record(path, action, rule_id, reason, [], [])

    lowered = path.lower()
    if DOMAIN_PATTERN.search(lowered):
        return record(
            path,
            "DELETE",
            "D-006",
            "Domain or vendor work cannot remain in the v2 core or gate its release.",
            [],
            [],
        )
    if (
        not path.startswith(("contracts/v2/", "contracts/v2.0.1/"))
        and DOMAIN_PATTERN.search(content)
    ):
        return record(
            path,
            "DELETE_AND_REBUILD",
            "D-028",
            "Unit content contains prior-project, domain, or vendor semantics and must be rebuilt from v2 requirements.",
            [],
            [],
        )

    if path.startswith(("contracts/v2/", "contracts/v2.0.1/")):
        requirements = requirement_ids_for(path)
        return record(
            path,
            "RETAIN",
            "RET-BINDING-CONTRACT",
            "Content-addressed released contract package or binding successor.",
            requirements,
            predicates,
        )

    if path.startswith("contracts/architecture/") or path.startswith("contracts/"):
        return record(
            path,
            "DELETE_AND_REBUILD",
            "D-029",
            "Legacy contract material requires derivation from the binding v2 contract.",
            [],
            [],
        )
    if path.startswith("evidence/"):
        return record(path, "REGENERATE", "D-024", "Evidence must be produced by v2 qualification.", [], [])
    if path.startswith("generated/"):
        return record(path, "REGENERATE", "D-023", "Generated output must derive only from v2.", [], [])
    if path in {"README.md", "CODEX-BUILD-SPEC.md", "buf.yaml", "buf.gen.yaml", "pyproject.toml"}:
        return record(
            path,
            "DELETE_AND_REBUILD",
            "D-029",
            "Repository-level public semantics must be re-derived or proven under v2.",
            [],
            [],
        )
    if path.startswith("docs/implementation/") or path.startswith("tools/qualify_w") or path.startswith("tests/"):
        return record(
            path,
            "DELETE_AND_REBUILD",
            "D-028",
            "Legacy packet evidence or fixtures must be rebuilt from canonical v2 semantics.",
            [],
            [],
        )

    if path.startswith(("crates/", "src/", "nix/")):
        return record(
            path,
            "DELETE_AND_REBUILD",
            "D-030",
            "Executable retention predicates require a per-unit audit; this legacy implementation is not trusted by module name.",
            [],
            [],
        )

    return record(
        path,
        "DELETE_AND_REBUILD",
        "D-029",
        "No authoritative v2 retention mapping exists.",
        [],
        [],
    )


def record(
    identity: str,
    action: str,
    rule_id: str,
    reason: str,
    requirement_ids: list[str],
    retention_predicates: list[str],
) -> dict:
    return {
        "identity": identity,
        "action": action,
        "rule_id": rule_id,
        "reason": reason,
        "requirement_ids": sorted(requirement_ids),
        "retention_predicates": sorted(retention_predicates),
        "predicate_evidence": {},
        "authority_evidence": [],
    }


def inherited_record(identity: str, parent: dict) -> dict:
    return record(
        identity,
        parent["action"],
        parent["rule_id"],
        f"Inherited from containing unit: {parent['identity']}",
        parent["requirement_ids"],
        parent["retention_predicates"],
    )


def semantic_identity(item: dict) -> str:
    return f"{item['path']}:{item['line']}:{item['kind']}:{item['name']}"


def dependency_identity(item: dict) -> str:
    return f"{item['path']}:{item['class']}:{item['name']}"


def generic_identity(item: dict) -> str:
    if item.get("required_class"):
        return f"{item['path']}:{item['class']}:{item['required_class']}"
    if item.get("path") and item.get("name"):
        return f"{item['path']}:{item['class']}:{item['name']}"
    return item.get("path") or f"{item['class']}:{item['name']}"


def classify(root: Path, inventory: dict, contract: dict) -> dict:
    unknown_inventory_keys = set(inventory) - INVENTORY_KEYS
    if unknown_inventory_keys:
        raise ValueError(
            "unknown inventory classes or fields: "
            + ", ".join(sorted(unknown_inventory_keys))
        )
    if set(inventory.get("counts", {})) != set(INVENTORY_CLASSES):
        raise ValueError("inventory counts must name exactly the five inventory classes")
    expected_source = {
        "tracked_paths": "git-tree",
        "file_contents": "git-tree",
        "build_closure_members": "declared-source-graph",
        "snapshot_boundary": "before-report-publication",
    }
    expected_counts = {
        inventory_class: len(inventory.get(inventory_class, []))
        for inventory_class in INVENTORY_CLASSES
    }
    if (
        inventory.get("schema_version") != 1
        or inventory.get("runner") != {"name": "inventory-v2", "version": 1}
        or inventory.get("inventory_source") != expected_source
        or inventory.get("counts") != expected_counts
    ):
        raise ValueError("inventory metadata does not match trusted format")
    repository_rebuild = contract["repository_rebuild"]
    dispositions = repository_rebuild["dispositions"]
    predicate_ids = [item["id"] for item in repository_rebuild["retention_predicate"]]
    tree = inventory["inventory_tree"]
    resolved_tree = git(root, "rev-parse", f"{tree}^{{tree}}").strip()
    if resolved_tree != tree:
        raise ValueError("inventory tree did not resolve exactly")
    inventory_commit = git(
        root, "rev-parse", f"{inventory['inventory_commit']}^{{commit}}"
    ).strip()
    commit_tree = git(root, "rev-parse", f"{inventory_commit}^{{tree}}").strip()
    if commit_tree != tree:
        raise ValueError("inventory tree is not the tree of inventory commit")
    binding_contract = json.loads(
        inventory_tree_contents(
            root, tree, "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
        )
    )
    binding_contract_bytes = inventory_tree_bytes(
        root, tree, "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
    )
    if hashlib.sha256(binding_contract_bytes).hexdigest() != BINDING_CONTRACT_SHA256:
        raise ValueError("binding contract digest does not match trusted v2.0.1 authority")
    binding_manifest_bytes = inventory_tree_bytes(
        root, tree, "contracts/v2.0.1/MANIFEST.sha256"
    )
    if hashlib.sha256(binding_manifest_bytes).hexdigest() != BINDING_MANIFEST_SHA256:
        raise ValueError("binding manifest digest does not match trusted v2.0.1 authority")
    archived_contract_bytes = inventory_tree_bytes(
        root, tree, "contracts/v2/nix-ai-v2.0.0.contract.json"
    )
    if hashlib.sha256(archived_contract_bytes).hexdigest() != ARCHIVED_V2_CONTRACT_SHA256:
        raise ValueError("archived v2.0.0 contract digest does not match trusted authority")
    archived_manifest_bytes = inventory_tree_bytes(
        root, tree, "contracts/v2/MANIFEST.sha256"
    )
    if hashlib.sha256(archived_manifest_bytes).hexdigest() != ARCHIVED_V2_MANIFEST_SHA256:
        raise ValueError("archived v2.0.0 manifest digest does not match trusted authority")
    if contract != binding_contract:
        raise ValueError("contract input does not match inventory tree binding contract")
    if (
        inventory.get("rebuild_baseline_commit")
        != binding_contract["contract"]["target"]["baseline_commit"]
    ):
        raise ValueError("inventory metadata does not match trusted format")
    tree_paths = sorted(
        path
        for path in git(root, "ls-tree", "-r", "--name-only", tree).splitlines()
        if path
    )
    if tree_paths != inventory["tracked_paths"]:
        raise ValueError("inventory tracked paths do not match inventory tree")
    read_tree = lambda path: inventory_tree_contents(root, tree, path)
    reconstructed = {
        "public_semantics": public_semantics_from_contents(tree_paths, read_tree),
        "dependencies": dependencies_from_contents(tree_paths, read_tree),
        "generated_artifacts": generated_artifacts_from_contents(tree_paths, read_tree),
        "build_closure_members": build_closure_members_from_contents(
            tree_paths, read_tree
        ),
    }
    for inventory_class, expected in reconstructed.items():
        if inventory[inventory_class] != expected:
            raise ValueError(
                f"inventory {inventory_class} does not match inventory tree"
            )
    contract_gates = validate_contract_packages(root, tree, tree_paths)
    path_records = [
        classify_path(
            path,
            inventory_tree_contents(root, tree, path),
            dispositions,
            predicate_ids,
        )
        for path in inventory["tracked_paths"]
    ]
    by_path = {item["identity"]: item for item in path_records}

    classified = {"tracked_paths": path_records}
    for inventory_class, identity_function in (
        ("public_semantics", semantic_identity),
        ("dependencies", dependency_identity),
        ("generated_artifacts", generic_identity),
    ):
        records = []
        for item in inventory[inventory_class]:
            parent = by_path[item["path"]]
            identity = identity_function(item)
            if (
                inventory_class == "generated_artifacts"
                and parent["action"] != "RETAIN"
                and (
                    item["class"] == "required-generated-class"
                    or item.get("required_class")
                )
            ):
                records.append(
                    record(
                        identity,
                        "REGENERATE",
                        "D-023",
                        "Binding v2.0.1 contract requires this generated artifact class.",
                        [],
                        [],
                    )
                )
                continue
            if (
                parent["action"] == "RETAIN"
                and inventory_class in {"public_semantics", "dependencies"}
            ):
                records.append(
                    record(
                        identity,
                        "DELETE_AND_REBUILD",
                        "D-030",
                        "Immutable package bytes remain archived, but executable semantics and dependencies require independent per-unit v2 proof.",
                        [],
                        [],
                    )
                )
            else:
                records.append(inherited_record(identity, parent))
        classified[inventory_class] = records

    closure_records = []
    for item in inventory["build_closure_members"]:
        identity = generic_identity(item)
        lowered = identity.lower()
        if any(term in lowered for term in DOMAIN_TERMS) or relegacy_packet(lowered):
            closure_records.append(
                record(identity, "DELETE", "D-006", "Rejected domain or legacy work-packet closure member.", [], [])
            )
        else:
            closure_records.append(
                record(identity, "DELETE_AND_REBUILD", "D-025", "Build graph must be rebuilt from v2-only declarations.", [], [])
            )
    classified["build_closure_members"] = closure_records

    for inventory_class, records in classified.items():
        for item in records:
            if item["action"] != "RETAIN":
                continue
            item["predicate_evidence"] = retention_evidence(
                item["identity"],
                item["retention_predicates"],
                contract_gates,
            )
            package = contract_package(item["identity"])
            item["authority_evidence"] = [
                {
                    "requirement_ids": item["requirement_ids"],
                    "invariant": "released contract package bytes cannot be mutated in place",
                    "evidence": contract_gates[package]["manifest"],
                }
            ]

    all_records = [item for records in classified.values() for item in records]
    unclassified = [item for item in all_records if item["action"] not in FINAL_ACTIONS]
    unmapped_retained = [item for item in all_records if item["action"] == "RETAIN" and not item["requirement_ids"]]
    return {
        "schema_version": 1,
        "runner": RUNNER,
        "contract": f"{contract['contract']['id']}@{contract['contract']['version']}",
        "inventory_tree": inventory["inventory_tree"],
        "dispositions": classified,
        "summary": {
            "counts_by_action": {
                action: sum(item["action"] == action for item in all_records)
                for action in sorted(FINAL_ACTIONS)
            },
            "total_disposition_count": len(all_records),
            "unclassified_count": len(unclassified),
            "unmapped_retained_count": len(unmapped_retained),
        },
    }


def relegacy_packet(identity: str) -> bool:
    return any(token in identity for token in ("w12", "w13", "w14", "w15"))


def contract_package(identity: str) -> str | None:
    for package in ("contracts/v2", "contracts/v2.0.1"):
        if identity == package or identity.startswith(package + "/"):
            return package
    return None


def validate_contract_packages(
    root: Path, tree: str, tree_paths: list[str]
) -> dict[str, dict[str, str]]:
    evidence: dict[str, dict[str, str]] = {}
    for package in ("contracts/v2", "contracts/v2.0.1"):
        package_paths = [
            path for path in tree_paths if path.startswith(package + "/")
        ]
        if not package_paths:
            continue
        manifest_path = f"{package}/MANIFEST.sha256"
        canonical_manifest = "".join(
            f"{hashlib.sha256(inventory_tree_bytes(root, tree, path)).hexdigest()}  "
            f"{path.removeprefix(package + '/')}\n"
            for path in sorted(package_paths)
            if path != manifest_path
        ).encode()
        if inventory_tree_bytes(root, tree, manifest_path) != canonical_manifest:
            raise ValueError(
                f"{manifest_path} does not reproduce canonical SHA-256 manifest bytes"
            )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            for path in package_paths:
                destination = temporary_root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(inventory_tree_bytes(root, tree, path))
            validator = temporary_root / package / "validate_contract.py"
            result = subprocess.run(
                [sys.executable, str(validator)],
                cwd=temporary_root,
                text=True,
                capture_output=True,
            )
        if result.returncode:
            raise ValueError(
                f"exact-tree contract gate failed for {package}: "
                f"{result.stdout}{result.stderr}".strip()
            )
        evidence[package] = {
            "manifest": (
                f"{manifest_path} exactly equals canonical SHA-256 manifest bytes "
                f"regenerated from exact inventory tree {tree}"
            ),
            "gate": (
                f"clean temporary extraction of exact inventory tree {tree} executed "
                f"{package}/validate_contract.py successfully"
            ),
            "live_gate_applicable": package == "contracts/v2.0.1",
        }
    return evidence


def retention_evidence(
    identity: str,
    predicate_ids: list[str],
    contract_gates: dict[str, dict[str, str]],
) -> dict[str, dict[str, str | list[str]]]:
    package = contract_package(identity)
    if package is None or package not in contract_gates:
        raise ValueError(f"retained unit lacks an exact-tree live gate: {identity}")

    is_manifest = identity.endswith("MANIFEST.sha256")

    results: dict[str, dict[str, str | list[str]]] = {}
    for predicate in predicate_ids:
        if predicate == "RET-005" and is_manifest:
            results[predicate] = {
                "result": "satisfied",
                "evidence": [contract_gates[package]["manifest"]],
            }
        elif predicate == "RET-006" and contract_gates[package][
            "live_gate_applicable"
        ]:
            results[predicate] = {
                "result": "satisfied",
                "evidence": [contract_gates[package]["gate"]],
            }
        else:
            applicability = {
                "RET-001": "unit is not a public semantic",
                "RET-002": "immutable package bytes are archived for provenance; executable semantics are separately classified DELETE_AND_REBUILD",
                "RET-003": "unit is not a declared dependency",
                "RET-004": "unit is not a test or fixture",
                "RET-005": "unit is not a generated output",
                "RET-006": "superseded v2.0.0 package is preserved as immutable provenance but is not an applicable live v2.0.1 gate",
            }[predicate]
            results[predicate] = {
                "result": "not_applicable",
                "evidence": [f"{identity}: {applicability}"],
            }
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        contract = json.loads(arguments.contract.read_text(encoding="utf-8"))
        ledger = classify(arguments.root.resolve(), inventory, contract)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))

    if ledger["summary"]["unclassified_count"] or ledger["summary"]["unmapped_retained_count"]:
        parser.error("classification is incomplete")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"valid": True, "output": str(arguments.output), "summary": ledger["summary"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
