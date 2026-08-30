#!/usr/bin/env python3
"""Validate immutable v2 authority and its active derived projections."""

from __future__ import annotations

import subprocess
import sys
import json
import tempfile
from pathlib import Path


ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
PACKAGES = (ROOT / "contracts" / "v2", ROOT / "contracts" / "v2.0.1")


def run(command: list[str], cwd: Path) -> None:
    print(f"+ (cd {cwd.relative_to(ROOT)} && {' '.join(command)})", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    for package in PACKAGES:
        if not package.is_dir():
            raise SystemExit(f"missing immutable contract package: {package.relative_to(ROOT)}")
        run([sys.executable, "validate_contract.py", "."], package)
    run(
        [sys.executable, "tools/derive_v2_contract.py", "--root", str(ROOT), "--check"],
        ROOT,
    )
    run([sys.executable, "tools/schema_contracts.py", "contracts"], ROOT)
    with tempfile.TemporaryDirectory() as temporary:
        generated = Path(temporary) / "core-retention-audit.json"
        run([sys.executable, "tools/audit_v2_core.py", "--root", str(ROOT), "--output", str(generated)], ROOT)
        checked = ROOT / "evidence" / "v2-rebuild" / "core-retention-audit.json"
        if generated.read_bytes() != checked.read_bytes():
            raise SystemExit("checked v2 core retention audit is stale")
    scope = json.loads(
        (ROOT / "evidence" / "v2-rebuild" / "removal-report.json").read_text()
    )
    if (
        not scope.get("valid")
        or scope.get("remaining_delete_units")
        or scope.get("contaminated_units")
    ):
        raise SystemExit("checked V-SCOPE removal evidence is not clean")
    print("Immutable v2 contract packages, active projections, and retained core are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
