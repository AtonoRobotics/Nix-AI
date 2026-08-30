#!/usr/bin/env python3
"""Run the transitional v2 contract qualification boundary."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(command: list[str], cwd: Path) -> None:
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    run([sys.executable, "tools/validate_contracts.py", str(root)], root)
    run(["sha256sum", "--check", "MANIFEST.sha256"], root / "contracts" / "architecture")
    print("W00 transitional v2 qualification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
