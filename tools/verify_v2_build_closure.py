#!/usr/bin/env python3
"""Normalize an evaluated Nix closure and reject deleted v1/domain components."""

import argparse
import hashlib
import json
import re
from pathlib import Path

FORBIDDEN = re.compile(r"(?:^|[-_.])(habitat-physical|ros2?|robotics|gazebo|isaac|cuda|nvidia)(?:[-_.]|$)", re.I)


def name(path: str) -> str:
    value = Path(path).name
    return value.split("-", 1)[1] if re.match(r"^[0-9a-z]{32}-", value) else value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--closure-paths", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw_paths = sorted({line.strip() for line in args.closure_paths.read_text().splitlines() if line.strip()})
    members = sorted({name(line) for line in raw_paths})
    non_store_inputs = [path for path in raw_paths
                        if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-.+", path)]
    deleted = [item for item in members if FORBIDDEN.search(item)]
    encoded = "".join(f"{item}\n" for item in members).encode()
    report = {
        "schema_version": "1.0", "scope": "issue-29-evaluated-nix-closure",
        "member_count": len(members), "member_names": members,
        "normalized_closure_sha256": hashlib.sha256(encoded).hexdigest(),
        "deleted_closure_members": deleted, "non_store_inputs": non_store_inputs,
        "input_proof": "evaluated recursive pkgs.closureInfo store-paths",
        "valid": not deleted and not non_store_inputs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"valid": report["valid"], "member_count": len(members), "deleted_closure_members": deleted}, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
