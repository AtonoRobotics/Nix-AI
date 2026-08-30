#!/usr/bin/env python3
"""Generate every Markdown work-graph projection from the canonical YAML."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import yaml


ARCH_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ARCH_ROOT.parent
SOURCE = ARCH_ROOT / "contracts" / "work-packets.yaml"
TARGETS = [
    ARCH_ROOT / "13-IMPLEMENTATION-WORK-GRAPH.md",
    BUNDLE_ROOT / "CODEX-BUILD-SPEC.md",
]
BEGIN = "<!-- BEGIN GENERATED WORK GRAPH -->"
END = "<!-- END GENERATED WORK GRAPH -->"


def load_graph() -> dict:
    data = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("packets"), list):
        raise ValueError("work-packets.yaml must contain a packets list")
    return data


def render(data: dict) -> str:
    packets = data["packets"]
    labels = {packet["id"]: packet["title"] for packet in packets}
    lines = ["```mermaid", "flowchart TD"]
    for packet in packets:
        packet_id = packet["id"]
        safe_title = labels[packet_id].replace('"', "'")
        lines.append(f'    {packet_id}["{packet_id} {safe_title}"]')
    for packet in packets:
        for dependency in packet["cannot_begin"]:
            lines.append(f"    {dependency} --> {packet['id']}")
    lines.append("```")
    lines.extend(
        [
            "",
            "The diagram shows `cannot_begin` edges. Integration and pass dependencies are explicit below.",
            "",
            "| Packet | Cannot begin until | Cannot integrate until | Cannot pass until |",
            "|---|---|---|---|",
        ]
    )
    for packet in packets:
        def cell(key: str) -> str:
            values = packet[key]
            return ", ".join(f"`{value}`" for value in values) if values else "—"

        lines.append(
            f"| `{packet['id']}` | {cell('cannot_begin')} | "
            f"{cell('cannot_integrate')} | {cell('cannot_pass')} |"
        )
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    lines.extend(["", f"Source SHA-256: `{digest}`"])
    return "\n".join(lines)


def project(path: Path, generated: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8")
    if current.count(BEGIN) != 1 or current.count(END) != 1:
        raise ValueError(f"{path} must contain exactly one generated graph marker pair")
    before, remainder = current.split(BEGIN, 1)
    _, after = remainder.split(END, 1)
    expected = f"{before}{BEGIN}\n{generated}\n{END}{after}"
    if current == expected:
        return True
    if check:
        print(f"stale generated graph: {path.relative_to(BUNDLE_ROOT)}", file=sys.stderr)
        return False
    path.write_text(expected, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = render(load_graph())
    results = [project(path, generated, args.check) for path in TARGETS]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
