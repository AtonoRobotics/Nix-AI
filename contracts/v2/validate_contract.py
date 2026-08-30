#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
CONTRACT_PATH = ROOT / "nix-ai-v2.0.0.contract.json"
SCHEMA_PATH = ROOT / "contract.schema.json"
MANIFEST_PATH = ROOT / "MANIFEST.sha256"


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def unique(values: list[str], label: str, errors: list[str]) -> None:
    require(len(values) == len(set(values)), f"duplicate {label}", errors)


def acyclic(nodes: set[str], edges: list[tuple[str, str]], label: str, errors: list[str]) -> None:
    incoming = {node: 0 for node in nodes}
    outgoing = {node: [] for node in nodes}
    for source, target in edges:
        if source not in nodes or target not in nodes:
            errors.append(f"{label} unknown edge {source}->{target}")
            continue
        incoming[target] += 1
        outgoing[source].append(target)
    ready = sorted(node for node, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        node = ready.pop(0)
        visited += 1
        for target in outgoing[node]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
                ready.sort()
    require(visited == len(nodes), f"{label} cycle", errors)


def validate_manifest(errors: list[str]) -> None:
    require(MANIFEST_PATH.exists(), "missing MANIFEST.sha256", errors)
    if not MANIFEST_PATH.exists():
        return
    expected_files = {
        "contract.schema.json",
        "nix-ai-v2.0.0.contract.json",
        "validate_contract.py",
    }
    observed_files = set()
    for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        parts = line.split("  ", 1)
        require(len(parts) == 2, f"invalid manifest line {line!r}", errors)
        if len(parts) != 2:
            continue
        digest, relative = parts
        observed_files.add(relative)
        path = ROOT / relative
        require(path.is_file(), f"manifest path missing {relative}", errors)
        if path.is_file():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            require(actual == digest, f"manifest digest mismatch {relative}", errors)
    require(observed_files == expected_files, "manifest file set mismatch", errors)


def validate_structure(contract: dict, errors: list[str]) -> None:
    required_top = {
        "contract",
        "authority",
        "mission",
        "scope",
        "canonical_model",
        "requirements",
        "repository_rebuild",
        "work_packets",
        "verification_gates",
        "completion",
    }
    require(set(contract) == required_top | {"$schema"}, "top-level field set mismatch", errors)
    metadata = contract.get("contract", {})
    require(metadata.get("id") == "nix-ai-core", "contract id mismatch", errors)
    require(metadata.get("version") == "2.0.0", "contract version mismatch", errors)
    require(metadata.get("status") == "BINDING", "contract status mismatch", errors)
    immutable = metadata.get("immutability", {})
    require(immutable.get("content_addressed") is True, "contract is not content addressed", errors)
    require(immutable.get("mutation") == "PROHIBITED", "contract mutation is not prohibited", errors)
    require(immutable.get("successor") == "NEW_SEMVER_AND_NEW_DIGEST", "successor rule mismatch", errors)
    target = metadata.get("target", {})
    require(target.get("repository") == "AtonoRobotics/Nix-AI", "target repository mismatch", errors)
    baseline = target.get("baseline_commit", "")
    require(len(baseline) == 40 and all(c in "0123456789abcdef" for c in baseline), "invalid baseline commit", errors)
    mission = contract.get("mission", {})
    require(mission == {
        "product": "BOOTABLE_AUTONOMOUS_AGENT_OPERATING_SYSTEM",
        "kernel": "LINUX",
        "construction": "NIX",
        "native_principal": "DURABLE_AGENT",
        "autonomy": "NO_ACTIVE_HUMAN_SESSION_REQUIRED",
    }, "mission mismatch", errors)
    require(contract.get("authority", {}).get("default") == "DENY", "authority default is not DENY", errors)
    require(contract.get("completion", {}).get("operator") == "ALL", "completion operator is not ALL", errors)
    require(contract.get("completion", {}).get("on_false") == "NOT_COMPLETE", "completion failure state mismatch", errors)


def main() -> int:
    errors: list[str] = []
    json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    validate_structure(contract, errors)

    requirements = contract["requirements"]
    requirement_ids = [item["id"] for item in requirements]
    unique(requirement_ids, "requirement id", errors)
    requirement_set = set(requirement_ids)

    packets = contract["work_packets"]
    packet_ids = [item["id"] for item in packets]
    unique(packet_ids, "work packet id", errors)
    require(packet_ids == [f"W{i:02d}" for i in range(14)], "work packet set must be W00..W13 in order", errors)
    packet_set = set(packet_ids)

    gates = contract["verification_gates"]
    gate_ids = [item["id"] for item in gates]
    unique(gate_ids, "gate id", errors)
    gate_set = set(gate_ids)

    dispositions = contract["repository_rebuild"]["dispositions"]
    unique([item["id"] for item in dispositions], "disposition id", errors)
    steps = contract["repository_rebuild"]["execution_order"]
    ordinals = [item["ordinal"] for item in steps]
    require(ordinals == list(range(1, len(steps) + 1)), "execution ordinals must be contiguous", errors)
    for step in steps:
        require(all(value < step["ordinal"] for value in step["blocked_by"]), f"step {step['ordinal']} has non-prior blocker", errors)

    mapped: dict[str, list[str]] = {item: [] for item in requirement_ids}
    for packet in packets:
        for relation in ("cannot_begin", "cannot_integrate", "cannot_pass"):
            for dependency in packet[relation]:
                require(dependency in packet_set, f"{packet['id']} unknown {relation} {dependency}", errors)
                require(dependency != packet["id"], f"{packet['id']} self dependency in {relation}", errors)
        for requirement in packet["requirements"]:
            require(requirement in requirement_set, f"{packet['id']} unknown requirement {requirement}", errors)
            if requirement in mapped:
                mapped[requirement].append(packet["id"])
        for gate in packet["gates"]:
            require(gate in gate_set, f"{packet['id']} unknown gate {gate}", errors)

    for requirement in requirements:
        owner = requirement["owner_packet"]
        require(owner in packet_set, f"{requirement['id']} unknown owner {owner}", errors)
        require(mapped[requirement["id"]] == [owner], f"{requirement['id']} mapping must be exactly [{owner}]", errors)

    for relation in ("cannot_begin", "cannot_integrate", "cannot_pass"):
        edges = []
        for packet in packets:
            edges.extend((dependency, packet["id"]) for dependency in packet[relation])
        acyclic(packet_set, edges, relation, errors)

    canonical = contract["canonical_model"]
    prohibited = set(contract["scope"]["prohibited_core_semantics"])
    serialized_canonical = json.dumps(canonical, sort_keys=True).lower()
    for semantic in prohibited:
        require(semantic.lower() not in serialized_canonical, f"prohibited semantic in canonical model: {semantic}", errors)

    validate_manifest(errors)
    result = {
        "contract_id": contract["contract"]["id"],
        "version": contract["contract"]["version"],
        "valid": not errors,
        "requirement_count": len(requirements),
        "work_packet_count": len(packets),
        "gate_count": len(gates),
        "disposition_count": len(dispositions),
        "errors": errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
