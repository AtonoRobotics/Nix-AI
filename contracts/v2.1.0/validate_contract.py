#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import jsonschema

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
CONTRACT = ROOT / "nix-ai-architecture-v2.1.0.contract.json"
SCHEMA = ROOT / "contract.schema.json"
MANIFEST = ROOT / "MANIFEST.sha256"
PREDECESSOR = REPO / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
EXPECTED = {"IMPLEMENTATION-PLAN.md", "contract.schema.json", "nix-ai-architecture-v2.1.0.contract.json", "validate_contract.py"}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def need(value, message, errors):
    if not value: errors.append(message)
def unique(values, label, errors): need(len(values) == len(set(values)), f"duplicate {label}", errors)

def acyclic(nodes, edges, errors):
    incoming = {node: 0 for node in nodes}; outgoing = {node: [] for node in nodes}
    for source, target in edges:
        if source not in nodes or target not in nodes: errors.append(f"unknown packet dependency {source}->{target}"); continue
        incoming[target] += 1; outgoing[source].append(target)
    ready = sorted(node for node, count in incoming.items() if count == 0); visited = 0
    while ready:
        node = ready.pop(0); visited += 1
        for target in outgoing[node]:
            incoming[target] -= 1
            if incoming[target] == 0: ready.append(target); ready.sort()
    need(visited == len(nodes), "packet dependency cycle", errors)

def main():
    errors = []; schema = json.loads(SCHEMA.read_text()); contract = json.loads(CONTRACT.read_text())
    try:
        jsonschema.Draft202012Validator.check_schema(schema); jsonschema.Draft202012Validator(schema).validate(contract)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as error: errors.append(f"schema validation failed: {error.message}")
    need(sha(PREDECESSOR) == contract["contract"]["predecessor"]["sha256"], "predecessor digest mismatch", errors)
    modules = {item["id"] for item in contract["modules"]}; requirements = contract["requirements"]
    requirement_ids = [item["id"] for item in requirements]; unique(requirement_ids, "requirement id", errors); requirement_set = set(requirement_ids)
    packets = contract["work_packets"]; packet_ids = [item["id"] for item in packets]; unique(packet_ids, "packet id", errors); packet_set = set(packet_ids)
    gates = contract["verification_gates"]; gate_ids = [item["id"] for item in gates]; unique(gate_ids, "gate id", errors); gate_set = set(gate_ids)
    for item in requirements:
        need(item["owner_module"] in modules, f"{item['id']} unknown owner module", errors); need(item["owner_packet"] in packet_set, f"{item['id']} unknown owner packet", errors)
    mapped = set(); edges = []
    for packet in packets:
        mapped.update(packet["requirements"]); need(set(packet["requirements"]) <= requirement_set, f"{packet['id']} unknown requirement", errors); need(set(packet["gates"]) <= gate_set, f"{packet['id']} unknown gate", errors)
        for field in ("cannot_begin", "cannot_integrate", "cannot_pass"):
            need(packet["id"] not in packet[field], f"{packet['id']} self dependency", errors); need(set(packet[field]) <= packet_set, f"{packet['id']} unknown dependency", errors)
        edges.extend((dependency, packet["id"]) for dependency in packet["cannot_begin"])
    need(mapped == requirement_set, "requirement coverage mismatch", errors); acyclic(packet_set, edges, errors)
    need(set(contract["completion"]["required_gates"]) == gate_set, "completion gate mismatch", errors)
    observed = set()
    for line in MANIFEST.read_text().splitlines():
        digest, relative = line.split("  ", 1); observed.add(relative); path = ROOT / relative; need(path.is_file() and sha(path) == digest, f"manifest mismatch {relative}", errors)
    need(observed == EXPECTED, "manifest file set mismatch", errors)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Validated immutable Nix AI architecture v2.1.0: sha256:{sha(CONTRACT)}"); return 0

if __name__ == "__main__": raise SystemExit(main())
