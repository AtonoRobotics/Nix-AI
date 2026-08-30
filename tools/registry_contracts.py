#!/usr/bin/env python3
"""Validate canonical requirement and work-packet registry semantics."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys

import yaml

from schema_contracts import SchemaContractError, validate_schema_contracts


REQUIREMENT_DEFINITION = re.compile(r"\*\*([A-Z]{3}-\d{3})\s+—\s+(.+?)\.\*\*")
GATE_DEFINITION = re.compile(r"^\| (V-[A-Z0-9-]+) \|", flags=re.MULTILINE)
GRAPH_BEGIN = "<!-- BEGIN GENERATED WORK GRAPH -->"
GRAPH_END = "<!-- END GENERATED WORK GRAPH -->"


class RegistryContractError(ValueError):
    """A canonical registry or generated projection is invalid."""


def _load_yaml(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryContractError(f"invalid YAML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RegistryContractError(f"YAML root must be an object: {path}")
    return value


def _requirement_definitions(root: Path) -> dict[str, str]:
    sources = sorted((root / "contracts" / "architecture").glob("*.md"))
    sources.append(root / "CODEX-BUILD-SPEC.md")
    definitions: dict[str, str] = {}
    duplicates: list[str] = []
    for source in sources:
        for requirement_id, title in REQUIREMENT_DEFINITION.findall(
            source.read_text(encoding="utf-8")
        ):
            if requirement_id in definitions:
                duplicates.append(requirement_id)
            definitions[requirement_id] = title
    if duplicates:
        raise RegistryContractError(
            f"duplicate normative requirement definitions: {sorted(set(duplicates))}"
        )
    return definitions


def _gate_ids(root: Path) -> set[str]:
    matrix = root / "contracts" / "architecture" / "12-VERIFICATION-MATRIX.md"
    gates = set(GATE_DEFINITION.findall(matrix.read_text(encoding="utf-8")))
    if not gates:
        raise RegistryContractError("verification matrix defines no gates")
    return gates


def _cycle(packet_map: dict[str, dict], relation: str) -> list[str]:
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(packet_id: str) -> list[str]:
        if packet_id in visiting:
            start = visiting.index(packet_id)
            return visiting[start:] + [packet_id]
        if packet_id in visited:
            return []
        visiting.append(packet_id)
        for dependency in packet_map[packet_id][relation]:
            found = visit(dependency)
            if found:
                return found
        visiting.pop()
        visited.add(packet_id)
        return []

    for packet_id in packet_map:
        found = visit(packet_id)
        if found:
            return found
    return []


def _validate_work_graph(root: Path) -> set[str]:
    graph = _load_yaml(root / "contracts" / "work-packets.yaml")
    packets = graph.get("packets")
    if not isinstance(packets, list):
        raise RegistryContractError("work graph packets must be a list")
    packet_map = {
        packet.get("id"): packet
        for packet in packets
        if isinstance(packet, dict) and isinstance(packet.get("id"), str)
    }
    expected = {f"W{number:02d}" for number in range(16)}
    if set(packet_map) != expected or len(packets) != len(expected):
        raise RegistryContractError("work graph must define exactly W00-W15")
    relations = ("cannot_begin", "cannot_integrate", "cannot_pass")
    for packet_id, packet in packet_map.items():
        for field in ("title", "owner", "deliverable"):
            if not isinstance(packet.get(field), str) or not packet[field]:
                raise RegistryContractError(f"{packet_id} has empty {field}")
        evidence = packet.get("exit_evidence")
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            raise RegistryContractError(
                f"{packet_id} exit_evidence must be a nonempty unique list"
            )
        for relation in relations:
            dependencies = packet.get(relation)
            if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
                raise RegistryContractError(f"{packet_id} {relation} must be a unique list")
            for dependency in dependencies:
                if dependency not in packet_map:
                    raise RegistryContractError(
                        f"{packet_id} {relation} references unknown {dependency}"
                    )
                if dependency == packet_id:
                    raise RegistryContractError(f"{packet_id} cannot depend on itself")
        if not set(packet["cannot_begin"]) <= set(packet["cannot_pass"]):
            raise RegistryContractError(
                f"{packet_id} begin dependencies must also be pass dependencies"
            )
        if not set(packet["cannot_integrate"]) <= set(packet["cannot_pass"]):
            raise RegistryContractError(
                f"{packet_id} integrate dependencies must also be pass dependencies"
            )
    for relation in relations:
        found = _cycle(packet_map, relation)
        if found:
            raise RegistryContractError(f"cycle in {relation}: {' -> '.join(found)}")
    if set(packet_map["W15"]["cannot_pass"]) != expected - {"W15"}:
        raise RegistryContractError("W15 cannot_pass must contain every W00-W14 packet")
    return set(packet_map)


def _render_work_graph(root: Path, graph: dict) -> str:
    packets = graph["packets"]
    lines = ["```mermaid", "flowchart TD"]
    for packet in packets:
        title = packet["title"].replace('"', "'")
        lines.append(f'    {packet["id"]}["{packet["id"]} {title}"]')
    for packet in packets:
        for dependency in packet["cannot_begin"]:
            lines.append(f"    {dependency} --> {packet['id']}")
    lines.extend(
        [
            "```",
            "",
            "The diagram shows `cannot_begin` edges. Integration and pass dependencies are explicit below.",
            "",
            "| Packet | Cannot begin until | Cannot integrate until | Cannot pass until |",
            "|---|---|---|---|",
        ]
    )
    for packet in packets:
        def cell(relation: str) -> str:
            values = packet[relation]
            return ", ".join(f"`{value}`" for value in values) if values else "—"

        lines.append(
            f"| `{packet['id']}` | {cell('cannot_begin')} | "
            f"{cell('cannot_integrate')} | {cell('cannot_pass')} |"
        )
    source = root / "contracts" / "work-packets.yaml"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    lines.extend(["", f"Source SHA-256: `{digest}`"])
    return "\n".join(lines)


def _validate_generated_projections(root: Path) -> None:
    graph = _load_yaml(root / "contracts" / "work-packets.yaml")
    generated = _render_work_graph(root, graph)
    targets = (
        root / "contracts" / "architecture" / "13-IMPLEMENTATION-WORK-GRAPH.md",
        root / "CODEX-BUILD-SPEC.md",
    )
    for target in targets:
        current = target.read_text(encoding="utf-8")
        if current.count(GRAPH_BEGIN) != 1 or current.count(GRAPH_END) != 1:
            raise RegistryContractError(
                f"generated projection marker mismatch: {target.relative_to(root)}"
            )
        before, remainder = current.split(GRAPH_BEGIN, 1)
        _, after = remainder.split(GRAPH_END, 1)
        expected = f"{before}{GRAPH_BEGIN}\n{generated}\n{GRAPH_END}{after}"
        if current != expected:
            raise RegistryContractError(
                f"stale generated projection: {target.relative_to(root)}"
            )


def _source_path(root: Path, relative: str) -> Path:
    prefix = "Habitat-OS-Architecture-Contracts-v1.1/"
    if relative.startswith(prefix):
        return root / "contracts" / "architecture" / relative.removeprefix(prefix)
    return root / relative


def _validate_requirement_semantics(
    root: Path,
    requirements: list[dict],
    definitions: dict[str, str],
    packets: set[str],
    gates: set[str],
) -> None:
    for item in requirements:
        requirement_id = item.get("id", "<missing>")
        owner = item.get("owner_packet")
        if owner not in packets:
            raise RegistryContractError(
                f"{requirement_id} unknown owner packet: {owner}"
            )
        criticality = item.get("criticality")
        if criticality not in {"critical", "release", "profile"}:
            raise RegistryContractError(
                f"{requirement_id} invalid criticality: {criticality}"
            )
        for field in ("implementation", "enforcement", "acceptance"):
            if not isinstance(item.get(field), str) or not item[field]:
                raise RegistryContractError(f"{requirement_id} empty {field}")
        requirement_gates = item.get("gates")
        if not isinstance(requirement_gates, list) or not requirement_gates:
            raise RegistryContractError(f"{requirement_id} has no gates")
        for gate in requirement_gates:
            if gate not in gates:
                raise RegistryContractError(
                    f"{requirement_id} references unknown gate: {gate}"
                )
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise RegistryContractError(
                f"{requirement_id} has no objective evidence mapping"
            )
        locator = item.get("source")
        match = re.fullmatch(r"(.+):(\d+)", locator or "")
        if not match:
            raise RegistryContractError(
                f"{requirement_id} invalid source locator: {locator}"
            )
        relative, line_text = match.groups()
        source = _source_path(root, relative)
        if not source.is_file():
            raise RegistryContractError(
                f"{requirement_id} source file missing: {relative}"
            )
        lines = source.read_text(encoding="utf-8").splitlines()
        line_number = int(line_text)
        if line_number < 1 or line_number > len(lines) or requirement_id not in lines[line_number - 1]:
            raise RegistryContractError(
                f"{requirement_id} stale source locator: {locator}"
            )
        if item.get("title") != definitions.get(requirement_id):
            raise RegistryContractError(
                f"{requirement_id} title differs from governing definition"
            )


def validate(root: Path) -> tuple[int, int]:
    root = root.resolve()
    definitions = _requirement_definitions(root)
    if len(definitions) != 135:
        raise RegistryContractError(
            f"normative requirement definitions must total 135; found {len(definitions)}"
        )
    gates = _gate_ids(root)
    packets = _validate_work_graph(root)
    registry = _load_yaml(root / "contracts" / "requirements.yaml")
    requirements = registry.get("requirements")
    if not isinstance(requirements, list):
        raise RegistryContractError("requirement registry requirements must be a list")
    if registry.get("expected_requirement_count") != 135:
        raise RegistryContractError("expected requirement count must be 135")
    ids = [item.get("id") for item in requirements if isinstance(item, dict)]
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise RegistryContractError(f"duplicate requirement registry ids: {duplicates}")
    missing = sorted(set(definitions) - set(ids))
    if missing:
        raise RegistryContractError(f"requirement missing from registry: {missing[0]}")
    extra = sorted(set(ids) - set(definitions))
    if extra:
        raise RegistryContractError(f"registry contains undefined requirement: {extra[0]}")
    if len(requirements) != 135:
        raise RegistryContractError(
            f"requirement registry mappings must total 135; found {len(requirements)}"
        )
    _validate_requirement_semantics(root, requirements, definitions, packets, gates)
    try:
        validate_schema_contracts(root / "contracts")
    except SchemaContractError as exc:
        raise RegistryContractError(f"registry schema validation failed: {exc}") from exc
    _validate_generated_projections(root)
    return len(requirements), len(packets)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        requirements, packets = validate(args.root)
    except RegistryContractError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {requirements} requirement mappings and {packets} work packets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
