#!/usr/bin/env python3
"""Generate and verify the versioned Protobuf ABI artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


class ProtoContractError(RuntimeError):
    """Raised when the Protobuf contracts or generated artifacts are invalid."""


def _run(command: list[str], *, cwd: Path, expect_success: bool = True) -> None:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if (result.returncode == 0) != expect_success:
        detail = (result.stdout + result.stderr).strip()
        expectation = "succeed" if expect_success else "reject the incompatible fixture"
        raise ProtoContractError(
            f"expected {' '.join(command)} to {expectation}; exit={result.returncode}"
            + (f"\n{detail}" if detail else "")
        )


def source_digest(proto_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(proto_root.glob("*.proto")):
        relative = path.relative_to(proto_root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def generate(root: Path, output: Path) -> None:
    proto_root = root / "contracts" / "proto"
    digest = source_digest(proto_root)
    output.mkdir(parents=True, exist_ok=True)
    _run(["buf", "build", str(proto_root), "-o", str(output / "descriptor.bin")], cwd=root)
    _run(
        [
            "buf",
            "generate",
            str(proto_root),
            "--template",
            str(root / "buf.gen.yaml"),
            "--output",
            str(output),
        ],
        cwd=root,
    )
    rust_root = output / "rust"
    generated = sorted(rust_root.rglob("*.rs"))
    if not generated:
        raise ProtoContractError("protoc-gen-prost produced no Rust bindings")
    header = f"// @generated from Protobuf sources sha256:{digest}; do not edit.\n"
    for path in generated:
        path.write_text(header + path.read_text(encoding="utf-8"), encoding="utf-8")
        _run(["rustfmt", "--edition", "2021", str(path)], cwd=root)
    (output / "SOURCE.sha256").write_text(f"{digest}  contracts/proto\n", encoding="ascii")


def _files(root: Path) -> dict[Path, bytes]:
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def verify_generated(expected: Path, actual: Path) -> None:
    expected_files = _files(expected) if expected.is_dir() else {}
    actual_files = _files(actual)
    if expected_files.keys() != actual_files.keys():
        missing = sorted(str(path) for path in actual_files.keys() - expected_files.keys())
        extra = sorted(str(path) for path in expected_files.keys() - actual_files.keys())
        raise ProtoContractError(f"generated Protobuf inventory is stale: missing={missing}, extra={extra}")
    changed = sorted(str(path) for path in actual_files if actual_files[path] != expected_files[path])
    if changed:
        raise ProtoContractError(f"generated Protobuf artifacts are stale: {changed}")


def verify_formatted_sources(source: Path, formatted: Path) -> None:
    """Permit only the governing bundle's known extra EOF newline."""
    source_files = _files(source)
    formatted_files = _files(formatted)
    if source_files.keys() != formatted_files.keys():
        raise ProtoContractError("formatted Protobuf inventory differs from source")
    unexpected = []
    for path, source_content in source_files.items():
        formatted_content = formatted_files[path]
        if source_content == formatted_content:
            continue
        if source_content.endswith(b"\n\n") and source_content[:-1] == formatted_content:
            continue
        unexpected.append(str(path))
    if unexpected:
        raise ProtoContractError(f"Protobuf sources are not canonically formatted: {unexpected}")


def create_breaking_fixture(proto_root: Path, fixture: Path, destination: Path) -> None:
    """Create a complete contract set with exactly one incompatible field removal."""
    shutil.copytree(proto_root, destination)
    marker = fixture.read_text(encoding="utf-8").strip()
    target = destination / "nix_ai_agent_v2.proto"
    if not target.exists():
        target = destination / "habitat_agent_v1.proto"
    target.chmod(target.stat().st_mode | 0o200)
    content = target.read_text(encoding="utf-8")
    field = f"  {marker}\n"
    if content.count(field) != 1:
        raise ProtoContractError(f"breaking fixture field must occur exactly once: {marker}")
    target.write_text(content.replace(field, ""), encoding="utf-8")


def validate(root: Path, *, write: bool = False) -> None:
    proto_root = root / "contracts" / "proto"
    generated_root = root / "generated" / "proto"
    fixture = (
        root
        / "tests"
        / "fixtures"
        / "proto-contracts"
        / "breaking"
        / "remove-activation-id.field"
    )
    with tempfile.TemporaryDirectory(prefix="habitat-buf-cache-") as cache:
        previous_cache = os.environ.get("BUF_CACHE_DIR")
        os.environ["BUF_CACHE_DIR"] = cache
        try:
            # The governing v1.1 bundle is immutable and contains a harmless
            # extra EOF newline. Format a copy so validation never rewrites it.
            with tempfile.TemporaryDirectory(prefix="habitat-proto-format-") as temporary:
                formatted = Path(temporary) / "proto"
                shutil.copytree(proto_root, formatted)
                for path in formatted.rglob("*.proto"):
                    path.chmod(path.stat().st_mode | 0o200)
                _run(["buf", "format", "--write", str(formatted)], cwd=root)
                _run(["buf", "format", "--diff", "--exit-code", str(formatted)], cwd=root)
                verify_formatted_sources(proto_root, formatted)
            _run(["buf", "lint", str(proto_root)], cwd=root)
            with tempfile.TemporaryDirectory(prefix="habitat-proto-") as temporary:
                candidate = Path(temporary) / "proto"
                generate(root, candidate)
                if write:
                    if generated_root.exists():
                        shutil.rmtree(generated_root)
                    shutil.copytree(candidate, generated_root)
                else:
                    verify_generated(generated_root, candidate)
            baseline = generated_root / "descriptor.bin"
            if not baseline.is_file():
                raise ProtoContractError("missing generated Protobuf descriptor baseline")
            _run(["buf", "breaking", str(proto_root), "--against", str(baseline)], cwd=root)
            with tempfile.TemporaryDirectory(prefix="habitat-proto-breaking-") as temporary:
                breaking = Path(temporary) / "proto"
                create_breaking_fixture(proto_root, fixture, breaking)
                _run(
                    ["buf", "breaking", str(breaking), "--against", str(baseline)],
                    cwd=root,
                    expect_success=False,
                )
        finally:
            if previous_cache is None:
                os.environ.pop("BUF_CACHE_DIR", None)
            else:
                os.environ["BUF_CACHE_DIR"] = previous_cache


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--write", action="store_true", help="replace checked-in generated artifacts")
    args = parser.parse_args()
    try:
        validate(args.root.resolve(), write=args.write)
    except ProtoContractError as error:
        parser.error(str(error))
    print("Protobuf contracts and generated Rust bindings are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
