#!/usr/bin/env python3
"""Validate the immutable source bundle and its repository projections."""

from __future__ import annotations

import filecmp
from pathlib import Path
import subprocess
import sys


ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
BUNDLE = (
    ROOT
    / "Habitat-OS-Codex-Build-Bundle-v1.1"
    / "Habitat-OS-Codex-Build-Bundle-v1.1"
)
ARCH = BUNDLE / "Habitat-OS-Architecture-Contracts-v1.1"


def run(command: list[str], cwd: Path) -> None:
    print(f"+ (cd {cwd.relative_to(ROOT)} && {' '.join(command)})", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def compare_file(source: Path, destination: Path) -> None:
    if not destination.is_file():
        raise SystemExit(f"missing contract projection: {destination.relative_to(ROOT)}")
    if not filecmp.cmp(source, destination, shallow=False):
        raise SystemExit(
            "contract projection differs from governing source: "
            f"{destination.relative_to(ROOT)}"
        )


def compare_tree(source: Path, destination: Path, *, allow_extra: bool = False) -> None:
    source_files = {path.relative_to(source) for path in source.rglob("*") if path.is_file()}
    destination_files = {
        path.relative_to(destination) for path in destination.rglob("*") if path.is_file()
    }
    if source_files - destination_files or (not allow_extra and destination_files - source_files):
        missing = sorted(source_files - destination_files)
        extra = sorted(destination_files - source_files)
        raise SystemExit(f"contract projection inventory mismatch: missing={missing}, extra={extra}")
    for relative in sorted(source_files):
        compare_file(source / relative, destination / relative)


def main() -> int:
    run(["sha256sum", "--check", "BUNDLE-MANIFEST.sha256"], BUNDLE)
    run(["sha256sum", "--check", "MANIFEST.sha256"], ARCH)
    run([sys.executable, "tests/validate_bundle.py"], BUNDLE)
    run([sys.executable, "tests/validate_contracts.py"], ARCH)
    run([sys.executable, "tests/generate_work_graph.py", "--check"], ARCH)

    run(
        [
            sys.executable,
            "tools/schema_contracts.py",
            "contracts",
            "--generated-from",
            str(ARCH),
        ],
        ROOT,
    )
    run([sys.executable, "tools/proto_contracts.py", str(ROOT)], ROOT)
    run([sys.executable, "tools/registry_contracts.py", str(ROOT)], ROOT)
    run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        ROOT,
    )

    compare_file(BUNDLE / "CODEX-BUILD-SPEC.md", ROOT / "CODEX-BUILD-SPEC.md")
    compare_tree(ARCH / "contracts", ROOT / "contracts", allow_extra=True)
    compare_tree(ARCH / "proto", ROOT / "contracts/proto")
    compare_tree(ARCH / "schemas", ROOT / "contracts/schemas")

    architecture = ROOT / "contracts/architecture"
    governing_files = [path for path in ARCH.iterdir() if path.is_file()]
    projected_files = [path for path in architecture.iterdir() if path.is_file()]
    if {path.name for path in governing_files} != {path.name for path in projected_files}:
        raise SystemExit("architecture projection inventory differs from governing source")
    for source in governing_files:
        compare_file(source, architecture / source.name)

    print("Contract bundle and repository projections are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
