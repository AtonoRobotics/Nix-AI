#!/usr/bin/env python3
"""Verify bundle integrity before running the architecture contract validator."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / "Habitat-OS-Architecture-Contracts-v1.1"
MANIFEST = ROOT / "BUNDLE-MANIFEST.sha256"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tracked_files() -> set[str]:
    return {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.name != MANIFEST.name
        and "__pycache__" not in path.parts
    }


def main() -> int:
    errors: list[str] = []
    if not MANIFEST.is_file():
        errors.append("missing BUNDLE-MANIFEST.sha256")
    else:
        entries: dict[str, str] = {}
        for number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if not match:
                errors.append(f"invalid bundle manifest line {number}")
                continue
            expected, relative = match.groups()
            if relative in entries:
                errors.append(f"duplicate bundle manifest entry: {relative}")
            entries[relative] = expected
        actual = tracked_files()
        for relative in sorted(actual - set(entries)):
            errors.append(f"file omitted from bundle manifest: {relative}")
        for relative in sorted(set(entries) - actual):
            errors.append(f"stale bundle manifest entry: {relative}")
        for relative, expected in entries.items():
            path = ROOT / relative
            if path.is_file() and digest(path) != expected:
                errors.append(f"bundle manifest digest mismatch: {relative}")
    if not errors:
        result = subprocess.run(
            [sys.executable, str(ARCH / "tests/validate_contracts.py")],
            cwd=ARCH,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            errors.append(result.stdout.strip() or result.stderr.strip())
        else:
            print(result.stdout.strip())
    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("- bundle manifest complete")
    print("- nested manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
