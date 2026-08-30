#!/usr/bin/env python3
"""Verify the exhaustive v2 deletion boundary established by issue #25."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


RUNNER = {"name": "verify-v2-removal", "version": 2}
INVENTORY_CLASSES = (
    "tracked_paths",
    "public_semantics",
    "dependencies",
    "generated_artifacts",
    "build_closure_members",
)
FORBIDDEN = re.compile(
    r"(?i)(?:(?:cordis|physical(?:[-_ ]?ai)?|robot(?:ics)?|isaac(?:[-_ ]sim)?|"
    r"omniverse|simulation|embodiment|jetson|nvidia|rtx|cuda)(?![a-z0-9])|"
    r"(?<![a-z0-9])ros(?![a-z0-9]))"
)
POLICY_PATHS = {
    "AGENTS.md",
    "docs/agents/domain.md",
    "docs/agents/issue-tracker.md",
    "docs/agents/triage-labels.md",
    "tools/classify_v2_scope.py",
    "tools/inventory_v2.py",
    "tools/verify_v2_removal.py",
    "tests/test_v2_rebuild_frontier.py",
    "tests/test_v2_scope_classification.py",
    "tests/test_v2_scope_removal.py",
}
POLICY_PREFIXES = ("contracts/v2/", "contracts/v2.0.1/", "evidence/v2-rebuild/")


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True
    )
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return result.stdout.strip()


def item_path(inventory_class: str, item) -> str | None:
    if inventory_class == "tracked_paths":
        return item
    if isinstance(item, dict):
        return item.get("path")
    return None


def closure_identity(item: dict) -> str:
    return f"{item['class']}:{item['name']}"


def verify(root: Path, ledger_path: Path) -> dict:
    ledger = json.loads(ledger_path.read_text())
    inventory = json.loads((ledger_path.parent / "inventory.json").read_text())
    tracked = sorted(filter(None, git(root, "ls-files").splitlines()))
    tracked_set = set(tracked)
    inventoried_policy_paths = {
        path
        for path in inventory["tracked_paths"]
        if path.startswith(POLICY_PREFIXES)
    }

    delete_counts = {}
    remaining_delete_units = []
    for inventory_class in INVENTORY_CLASSES:
        source_items = inventory[inventory_class]
        dispositions = ledger["dispositions"][inventory_class]
        if len(source_items) != len(dispositions):
            raise ValueError(f"inventory/ledger length mismatch for {inventory_class}")
        deleted = [
            (item, record)
            for item, record in zip(source_items, dispositions)
            if record["action"] == "DELETE"
        ]
        delete_counts[inventory_class] = len(deleted)
        for item, record in deleted:
            path = item_path(inventory_class, item)
            if path is not None and path in tracked_set:
                remaining_delete_units.append(
                    {"inventory_class": inventory_class, "identity": record["identity"]}
                )

    sys.path.insert(0, str(root / "tools"))
    from inventory_v2 import build_closure_members_from_contents

    current_closure = {
        closure_identity(item)
        for item in build_closure_members_from_contents(
            tracked,
            lambda path: (root / path).read_text(errors="replace")
            if (root / path).is_file()
            else None,
        )
    }
    for record in ledger["dispositions"]["build_closure_members"]:
        if record["action"] == "DELETE" and record["identity"] in current_closure:
            remaining_delete_units.append(
                {"inventory_class": "build_closure_members", "identity": record["identity"]}
            )

    contaminated = []
    for relative in tracked:
        if relative in POLICY_PATHS or relative in inventoried_policy_paths:
            continue
        path = root / relative
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if FORBIDDEN.search(line):
                contaminated.append({"path": relative, "line": line_number})

    valid = not remaining_delete_units and not contaminated
    return {
        "schema_version": 1,
        "runner": RUNNER,
        "verified_commit": git(root, "rev-parse", "HEAD^{commit}"),
        "valid": valid,
        "delete_counts_by_inventory_class": delete_counts,
        "remaining_delete_units": remaining_delete_units,
        "contaminated_units": contaminated,
        "scanned_tracked_path_count": len(tracked),
        "policy_exclusions": sorted(POLICY_PATHS),
        "policy_prefix_exclusions": list(POLICY_PREFIXES),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = verify(arguments.root.resolve(), arguments.ledger.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
