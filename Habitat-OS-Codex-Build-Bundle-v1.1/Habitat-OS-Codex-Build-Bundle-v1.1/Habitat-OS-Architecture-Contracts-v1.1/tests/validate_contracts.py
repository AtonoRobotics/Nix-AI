#!/usr/bin/env python3
"""Validate the complete Habitat OS v1.1 architecture contract baseline."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ROOT.parent
BUILD_SPEC = BUNDLE_ROOT / "CODEX-BUILD-SPEC.md"
KNOWN_PREFIXES = {
    "GOV", "ARC", "ABI", "STA", "AUT", "EFF", "CTX", "PKG",
    "GEN", "SEC", "SAF", "HWP", "OBS", "VER", "BLD",
}
REQ_DEFINITION = re.compile(r"\*\*([A-Z]{3}-\d{3})\s+—\s+(.+?)\.\*\*")
REQ_REFERENCE = re.compile(
    r"\b(" + "|".join(sorted(KNOWN_PREFIXES)) + r")-(\d{3})(?:–(\d{3}))?\b"
)
GATE_PATTERN = re.compile(r"^V-[A-Z0-9-]+$")

REQUIRED_FILES = [
    "README.md", "00-GOVERNANCE.md", "01-ARCHITECTURE.md", "02-AGENT-ABI.md",
    "03-STATE-AND-LIFECYCLE.md", "04-AUTHORITY-CAPABILITIES.md", "05-EFFECTS.md",
    "06-CONTEXT.md", "07-CAPABILITY-PACKAGES.md", "08-SYSTEM-GENERATIONS.md",
    "09-THREAT-SAFETY.md", "10-HARDWARE-PROFILES.md", "11-OBSERVABILITY-SLOS.md",
    "12-VERIFICATION-MATRIX.md", "13-IMPLEMENTATION-WORK-GRAPH.md",
    "14-DECISION-REGISTER.md", "15-TRACEABILITY.md", "17-REMEDIATION-RECORD.md",
    "contracts/requirements.yaml", "contracts/requirements.schema.json",
    "contracts/work-packets.yaml", "contracts/work-packets.schema.json",
    "contracts/remediation-tickets.yaml", "proto/habitat_agent_v1.proto",
    "proto/habitat_authority_effect_v1.proto", "tests/generate_work_graph.py",
    "tests/validate_contracts.py",
]


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tracked_files() -> set[str]:
    return {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.name != "MANIFEST.sha256"
        and "__pycache__" not in path.parts
    }


def validate_manifest(errors: list[str]) -> None:
    manifest = ROOT / "MANIFEST.sha256"
    if not manifest.is_file():
        fail(errors, "missing internal MANIFEST.sha256")
        return
    entries: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(errors, f"invalid manifest line {line_number}")
            continue
        digest, relative = match.groups()
        if relative in entries:
            fail(errors, f"duplicate manifest entry: {relative}")
        entries[relative] = digest
    expected = tracked_files()
    if set(entries) != expected:
        for item in sorted(expected - set(entries)):
            fail(errors, f"file omitted from internal manifest: {item}")
        for item in sorted(set(entries) - expected):
            fail(errors, f"stale internal manifest entry: {item}")
    for relative, expected_digest in entries.items():
        path = ROOT / relative
        if path.is_file() and sha256(path) != expected_digest:
            fail(errors, f"internal manifest digest mismatch: {relative}")


def validate_json_schemas(errors: list[str]) -> int:
    schema_paths = sorted((ROOT / "schemas").glob("*.schema.json"))
    schema_paths += sorted((ROOT / "contracts").glob("*.schema.json"))
    schema_ids: list[str] = []
    schema_refs: list[str] = []
    for path in schema_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(errors, f"invalid JSON {path.relative_to(ROOT)}: {exc}")
            continue
        for field in ("$schema", "$id", "title", "type"):
            if field not in data:
                fail(errors, f"schema {path.relative_to(ROOT)} missing {field}")
        if "$id" in data:
            schema_ids.append(data["$id"])
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                ref = item.get("$ref")
                if isinstance(ref, str) and not ref.startswith("#"):
                    schema_refs.append(ref)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    duplicates = [item for item, count in Counter(schema_ids).items() if count > 1]
    if duplicates:
        fail(errors, f"duplicate schema ids: {duplicates}")
    unresolved = sorted(set(schema_refs) - set(schema_ids))
    if unresolved:
        fail(errors, f"unresolved external schema refs: {unresolved}")
    return len(schema_paths)


def requirement_sources(errors: list[str]) -> tuple[dict[str, dict], dict[Path, str]]:
    markdown_paths = sorted(ROOT.glob("*.md")) + [BUILD_SPEC]
    definitions: dict[str, dict] = {}
    texts: dict[Path, str] = {}
    for path in markdown_paths:
        if not path.is_file():
            fail(errors, f"missing build specification: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        texts[path] = text
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in REQ_DEFINITION.finditer(line):
                requirement_id, title = match.groups()
                if requirement_id in definitions:
                    fail(errors, f"duplicate requirement id: {requirement_id}")
                definitions[requirement_id] = {
                    "title": title, "path": path, "line": line_number,
                }
    referenced: set[str] = set()
    for text in texts.values():
        for match in REQ_REFERENCE.finditer(text):
            prefix, start_text, end_text = match.groups()
            start = int(start_text)
            end = int(end_text) if end_text else start
            referenced.update(f"{prefix}-{number:03d}" for number in range(start, end + 1))
    for requirement_id in sorted(referenced - set(definitions)):
        fail(errors, f"undefined requirement reference: {requirement_id}")
    present_prefixes = {item.split("-")[0] for item in definitions}
    for prefix in sorted(KNOWN_PREFIXES - present_prefixes):
        fail(errors, f"missing normative requirement family: {prefix}")
    return definitions, texts


def gate_ids(errors: list[str]) -> set[str]:
    text = (ROOT / "12-VERIFICATION-MATRIX.md").read_text(encoding="utf-8")
    gates = set(re.findall(r"^\| (V-[A-Z0-9-]+) \|", text, flags=re.MULTILINE))
    if "V-CONTRACT" not in gates:
        fail(errors, "verification matrix missing V-CONTRACT")
    return gates


def validate_markdown_links(errors: list[str], texts: dict[Path, str]) -> int:
    checked = 0
    for source, text in texts.items():
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "sandbox:", "#", "mailto:")):
                continue
            relative = target.split("#", 1)[0]
            if not relative:
                continue
            checked += 1
            if not (source.parent / relative).resolve().exists():
                errors.append(
                    f"broken Markdown link in {source.relative_to(BUNDLE_ROOT)}: {target}"
                )
    return checked


def load_yaml(path: Path, errors: list[str]) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(errors, f"invalid YAML {path.relative_to(ROOT)}: {exc}")
        return {}
    if not isinstance(data, dict):
        fail(errors, f"YAML root must be an object: {path.relative_to(ROOT)}")
        return {}
    return data


def cycle_nodes(packet_map: dict[str, dict], relation: str) -> list[str]:
    visiting: set[str] = set()
    visited: set[str] = set()
    cycle: list[str] = []

    def visit(packet_id: str) -> bool:
        if packet_id in visiting:
            cycle.append(packet_id)
            return True
        if packet_id in visited:
            return False
        visiting.add(packet_id)
        for dependency in packet_map[packet_id][relation]:
            if visit(dependency):
                cycle.append(packet_id)
                return True
        visiting.remove(packet_id)
        visited.add(packet_id)
        return False

    for packet_id in packet_map:
        if visit(packet_id):
            return list(reversed(cycle))
    return []


def validate_work_graph(errors: list[str]) -> set[str]:
    data = load_yaml(ROOT / "contracts/work-packets.yaml", errors)
    packets = data.get("packets", [])
    if data.get("source_of_truth") is not True:
        fail(errors, "work graph must declare source_of_truth: true")
    if not isinstance(packets, list):
        fail(errors, "work graph packets must be a list")
        return set()
    packet_ids = [packet.get("id") for packet in packets if isinstance(packet, dict)]
    expected = {f"W{number:02d}" for number in range(16)}
    if set(packet_ids) != expected or len(packet_ids) != len(expected):
        fail(errors, f"work graph must define exactly W00-W15; found {packet_ids}")
    packet_map = {
        packet["id"]: packet for packet in packets
        if isinstance(packet, dict) and packet.get("id")
    }
    required = {
        "id", "title", "owner", "deliverable", "cannot_begin",
        "cannot_integrate", "cannot_pass", "exit_evidence",
    }
    for packet_id, packet in packet_map.items():
        missing = required - set(packet)
        if missing:
            fail(errors, f"{packet_id} missing fields: {sorted(missing)}")
        for relation in ("cannot_begin", "cannot_integrate", "cannot_pass"):
            dependencies = packet.get(relation, [])
            if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
                fail(errors, f"{packet_id} {relation} must be a unique list")
                continue
            for dependency in dependencies:
                if dependency not in packet_map:
                    fail(errors, f"{packet_id} {relation} references unknown {dependency}")
                if dependency == packet_id:
                    fail(errors, f"{packet_id} cannot depend on itself")
        begin = set(packet.get("cannot_begin", []))
        integrate = set(packet.get("cannot_integrate", []))
        passed = set(packet.get("cannot_pass", []))
        if not begin <= passed:
            fail(errors, f"{packet_id} begin dependencies must also be pass dependencies")
        if not integrate <= passed:
            fail(errors, f"{packet_id} integrate dependencies must also be pass dependencies")
        evidence = packet.get("exit_evidence", [])
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            fail(errors, f"{packet_id} exit_evidence must be a nonempty unique list")
    for relation in ("cannot_begin", "cannot_integrate", "cannot_pass"):
        cycle = cycle_nodes(packet_map, relation) if packet_map else []
        if cycle:
            fail(errors, f"cycle in {relation}: {' -> '.join(cycle)}")
    if set(packet_map.get("W15", {}).get("cannot_pass", [])) != expected - {"W15"}:
        fail(errors, "W15 cannot_pass must contain every W00-W14 packet")
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests/generate_work_graph.py"), "--check"],
        cwd=BUNDLE_ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        fail(errors, result.stderr.strip() or "generated work graphs are stale")
    return set(packet_map)


def validate_requirement_registry(
    errors: list[str],
    definitions: dict[str, dict],
    packets: set[str],
    gates: set[str],
) -> int:
    data = load_yaml(ROOT / "contracts/requirements.yaml", errors)
    requirements = data.get("requirements", [])
    if not isinstance(requirements, list):
        fail(errors, "requirement registry requirements must be a list")
        return 0
    if data.get("expected_requirement_count") != 135:
        fail(errors, "requirement registry expected count must be 135")
    ids = [item.get("id") for item in requirements if isinstance(item, dict)]
    duplicates = [item for item, count in Counter(ids).items() if count > 1]
    if duplicates:
        fail(errors, f"duplicate requirement registry ids: {duplicates}")
    if set(ids) != set(definitions):
        for item in sorted(set(definitions) - set(ids)):
            fail(errors, f"requirement missing from registry: {item}")
        for item in sorted(set(ids) - set(definitions)):
            fail(errors, f"registry contains undefined requirement: {item}")
    required_fields = {
        "id", "title", "source", "criticality", "owner_packet",
        "implementation", "enforcement", "gates", "evidence", "acceptance",
    }
    for item in requirements:
        if not isinstance(item, dict):
            fail(errors, "requirement registry item must be an object")
            continue
        requirement_id = item.get("id", "<missing>")
        missing = required_fields - set(item)
        if missing:
            fail(errors, f"{requirement_id} registry entry missing: {sorted(missing)}")
            continue
        if item["criticality"] not in {"critical", "release", "profile"}:
            fail(errors, f"{requirement_id} invalid criticality")
        if item["owner_packet"] not in packets:
            fail(errors, f"{requirement_id} unknown owner packet: {item['owner_packet']}")
        if not item["implementation"] or not item["enforcement"] or not item["acceptance"]:
            fail(errors, f"{requirement_id} has empty implementation, enforcement or acceptance")
        if not isinstance(item["gates"], list) or not item["gates"]:
            fail(errors, f"{requirement_id} has no gates")
        else:
            for gate in item["gates"]:
                if gate not in gates:
                    fail(errors, f"{requirement_id} references unknown gate: {gate}")
        if not isinstance(item["evidence"], list) or not item["evidence"]:
            fail(errors, f"{requirement_id} has no objective evidence mapping")
        source_match = re.fullmatch(r"(.+):(\d+)", item["source"])
        if not source_match:
            fail(errors, f"{requirement_id} invalid source locator: {item['source']}")
        else:
            relative, line_text = source_match.groups()
            source_path = BUNDLE_ROOT / relative
            if not source_path.is_file():
                fail(errors, f"{requirement_id} source file missing: {relative}")
            else:
                lines = source_path.read_text(encoding="utf-8").splitlines()
                line_number = int(line_text)
                if line_number < 1 or line_number > len(lines) or requirement_id not in lines[line_number - 1]:
                    fail(errors, f"{requirement_id} stale source locator: {item['source']}")
        definition = definitions.get(requirement_id)
        if definition and item["title"] != definition["title"]:
            fail(errors, f"{requirement_id} title differs from governing definition")
    return len(requirements)


def validate_decisions(errors: list[str]) -> None:
    text = (ROOT / "14-DECISION-REGISTER.md").read_text(encoding="utf-8")
    for decision in range(16, 22):
        if f"DEC-{decision:03d}" not in text:
            fail(errors, f"missing approved reference decision DEC-{decision:03d}")
    for decision in range(1, 6):
        pattern = rf"\| OPEN-{decision:03d} \| Closed"
        if not re.search(pattern, text):
            fail(errors, f"OPEN-{decision:03d} is not explicitly closed or closed for scope")
    if "## Open bounded decisions" in text:
        fail(errors, "obsolete open-decision section remains")


def validate_remediation(errors: list[str]) -> None:
    data = load_yaml(ROOT / "contracts/remediation-tickets.yaml", errors)
    tickets = data.get("tickets", [])
    if not isinstance(tickets, list):
        fail(errors, "remediation tickets must be a list")
        return
    expected = {f"RMD-{number:03d}" for number in range(1, 5)}
    ticket_map = {
        ticket.get("id"): ticket for ticket in tickets if isinstance(ticket, dict)
    }
    if set(ticket_map) != expected:
        fail(errors, f"remediation registry must contain exactly {sorted(expected)}")
    for ticket_id, ticket in ticket_map.items():
        if ticket.get("status") != "closed":
            fail(errors, f"remediation ticket not closed: {ticket_id}")
        if not ticket.get("closure_evidence"):
            fail(errors, f"remediation ticket lacks closure evidence: {ticket_id}")
        for relation in ("blocks", "depends_on"):
            for reference in ticket.get(relation, []):
                if reference not in ticket_map:
                    fail(errors, f"{ticket_id} {relation} references unknown {reference}")


def validate_proto(errors: list[str]) -> int:
    paths = sorted((ROOT / "proto").glob("*.proto"))
    proto_text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for token in (
        "service AgentRuntime", "service CapabilityAuthority",
        "service EffectRuntime", "OUTCOME_UNKNOWN",
    ):
        if token not in proto_text:
            fail(errors, f"protobuf contract missing token: {token}")
    return len(paths)


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            fail(errors, f"missing required file: {relative}")
    validate_manifest(errors)
    schema_count = validate_json_schemas(errors)
    definitions, texts = requirement_sources(errors)
    link_count = validate_markdown_links(errors, texts)
    gates = gate_ids(errors)
    packets = validate_work_graph(errors)
    registry_count = validate_requirement_registry(
        errors, definitions, packets, gates
    )
    validate_decisions(errors)
    validate_remediation(errors)
    proto_count = validate_proto(errors)
    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS")
    print(f"- {len(texts)} Markdown requirement sources")
    print(f"- {schema_count} JSON Schemas")
    print(f"- {len(definitions)} unique normative requirements")
    print(f"- {link_count} local Markdown links verified")
    print(f"- {registry_count} executable requirement mappings")
    print(f"- {len(packets)} typed work packets")
    print(f"- {len(gates)} verification gates")
    print(f"- {proto_count} Protobuf contracts")
    print("- reference decisions closed")
    print("- generated graph projections current")
    print("- internal manifest complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
