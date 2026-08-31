#!/usr/bin/env python3
"""Reject architectural drift in release qualification evidence."""
import argparse
import re
from pathlib import Path


def find_drift(root: Path) -> list[str]:
    tools = root / "tools"
    release_path = tools / "qualify_v2_release.py"
    release = release_path.read_text() if release_path.is_file() else ""
    errors = []
    rules = [
        (r"_runner_identity|argv\s*\[[^]]+\]", "runner argv inference"),
        (r"\bif\s+gate\s*==|\bmatch\s+gate\b", "gate-name switch"),
        (r"\bdef\s+canonical(?:_json)?\s*\(", "duplicate canonical JSON"),
        (r"\bstructured_result\s*\(", "synthetic pass result"),
        (r"(?i)\b(?:stub|placeholder|fake)(?:\b|_)", "stub, placeholder, or fake"),
    ]
    for pattern, name in rules:
        if re.search(pattern, release): errors.append(f"{release_path.relative_to(root)}: {name}")
    for path in sorted(tools.glob("qualify_w*.py")):
        text = path.read_text()
        if re.search(r"(?i)\bminio\b", text): errors.append(f"{path.relative_to(root)}: stale MinIO dependency")
        if re.search(r"(?i)\b(?:stub|placeholder|fake)(?:\b|_)", text):
            errors.append(f"{path.relative_to(root)}: stub, placeholder, or fake")
        if path.name != "qualify_w_common.py" and re.search(r"\bdef\s+canonical(?:_json)?\s*\(", text):
            errors.append(f"{path.relative_to(root)}: duplicate canonical JSON")
    w00 = tools / "qualify_w00.py"
    w00_text = w00.read_text() if w00.is_file() else ""
    if not all(token in w00_text for token in ("def source_tree_digest", "ls-tree", "show")):
        errors.append("tools/qualify_w00.py: stale exact-tree evidence is not verified")
    package_cli = root / "crates/habitat-packages/src/main.rs"
    if package_cli.is_file() and "qualify-change" not in package_cli.read_text():
        errors.append("crates/habitat-packages/src/main.rs: governed-change execution is absent")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True)
    errors = find_drift(parser.parse_args().root.resolve())
    if errors:
        for error in errors: print(error)
        return 1
    print("drift-free")
    return 0


if __name__ == "__main__": raise SystemExit(main())
