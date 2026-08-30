#!/usr/bin/env python3
"""Derive active architecture artifacts from the immutable v2.0.1 contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


CONTRACT_PATH = Path("contracts/v2.0.1/nix-ai-v2.0.1.contract.json")
ARCHITECTURE_FILES = (
    "00-GOVERNANCE.md", "01-ARCHITECTURE.md", "02-AGENT-ABI.md",
    "03-STATE-AND-LIFECYCLE.md", "04-AUTHORITY-CAPABILITIES.md",
    "05-EFFECTS.md", "06-CONTEXT.md", "07-CAPABILITY-PACKAGES.md",
    "08-SYSTEM-GENERATIONS.md", "09-THREAT-SAFETY.md",
    "10-HARDWARE-PROFILES.md", "11-OBSERVABILITY-SLOS.md",
    "12-VERIFICATION-MATRIX.md", "13-IMPLEMENTATION-WORK-GRAPH.md",
    "14-DECISION-REGISTER.md", "15-TRACEABILITY.md",
    "17-REMEDIATION-RECORD.md", "README.md",
)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def table(headers: list[str], rows: list[list[object]]) -> str:
    def cell(value: object) -> str:
        if isinstance(value, list):
            value = ", ".join(map(str, value)) or "—"
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def document(title: str, body: str, digest: str) -> bytes:
    return (
        f"# {title}\n\n"
        f"> Generated from `{CONTRACT_PATH}` (`sha256:{digest}`). Do not edit by hand.\n\n"
        f"{body.rstrip()}\n"
    ).encode()


def requirement_registry(contract: dict, digest: str) -> dict:
    return {
        "schema_version": 2,
        "registry_id": "nix-ai-core-requirements-v2.0.1",
        "source_authority": str(CONTRACT_PATH),
        "source_sha256": digest,
        "expected_requirement_count": len(contract["requirements"]),
        "requirements": contract["requirements"],
    }


def work_registry(contract: dict, digest: str) -> dict:
    return {
        "schema_version": 2,
        "graph_id": "nix-ai-core-work-graph-v2.0.1",
        "source_authority": str(CONTRACT_PATH),
        "source_sha256": digest,
        "dependency_semantics": {
            "cannot_begin": "predecessor must pass before work begins",
            "cannot_integrate": "predecessor must pass before integration",
            "cannot_pass": "predecessor must pass before this packet passes",
        },
        "packets": contract["work_packets"],
    }


def requirements_schema() -> dict:
    text = {"type": "string", "minLength": 1}
    text_list = {"type": "array", "items": text, "minItems": 1, "uniqueItems": True}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://nix-ai.invalid/contracts/requirements-v2.schema.json",
        "title": "Nix AI v2 requirement registry",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "registry_id", "source_authority", "source_sha256", "expected_requirement_count", "requirements"],
        "properties": {
            "schema_version": {"const": 2},
            "registry_id": {"const": "nix-ai-core-requirements-v2.0.1"},
            "source_authority": {"const": str(CONTRACT_PATH)},
            "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "expected_requirement_count": {"const": 40},
            "requirements": {
                "type": "array", "minItems": 40, "maxItems": 40,
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "shall", "trigger", "boundary", "failure", "enforcement", "evidence", "acceptance", "owner_packet", "source_authority", "source_reference"],
                    "properties": {
                        "id": {"type": "string", "pattern": "^[A-Z]+-[0-9]{3}$"},
                        "shall": text, "trigger": text, "boundary": text,
                        "failure": text, "enforcement": text_list,
                        "evidence": text_list, "acceptance": text,
                        "owner_packet": {"type": "string", "pattern": "^W(?:0[0-9]|1[0-3])$"},
                        "source_authority": text, "source_reference": text,
                    },
                },
            },
        },
    }


def work_schema() -> dict:
    identifier_list = {"type": "array", "items": {"type": "string"}, "uniqueItems": True}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://nix-ai.invalid/contracts/work-packets-v2.schema.json",
        "title": "Nix AI v2 work graph",
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "graph_id", "source_authority", "source_sha256", "dependency_semantics", "packets"],
        "properties": {
            "schema_version": {"const": 2},
            "graph_id": {"const": "nix-ai-core-work-graph-v2.0.1"},
            "source_authority": {"const": str(CONTRACT_PATH)},
            "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "dependency_semantics": {
                "type": "object", "additionalProperties": False,
                "required": ["cannot_begin", "cannot_integrate", "cannot_pass"],
                "properties": {name: {"type": "string"} for name in ("cannot_begin", "cannot_integrate", "cannot_pass")},
            },
            "packets": {
                "type": "array", "minItems": 14, "maxItems": 14,
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "deliverable", "requirements", "cannot_begin", "cannot_integrate", "cannot_pass", "gates"],
                    "properties": {
                        "id": {"type": "string", "pattern": "^W(?:0[0-9]|1[0-3])$"},
                        "deliverable": {"type": "string", "minLength": 1},
                        "requirements": identifier_list,
                        "cannot_begin": identifier_list,
                        "cannot_integrate": identifier_list,
                        "cannot_pass": identifier_list,
                        "gates": identifier_list,
                    },
                },
            },
        },
    }


def canonical_schema(model: dict) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://nix-ai.invalid/contracts/schemas/v2-canonical.schema.json",
        "title": "Nix AI v2 canonical vocabulary",
        "type": "object", "additionalProperties": False,
        "required": ["principal", "effect_class", "execution_profile", "hardware_profile"],
        "properties": {
            "principal": {"enum": model["principals"]},
            "effect_class": {"enum": model["effect_classes"]},
            "execution_profile": {"enum": model["execution_profiles"]},
            "hardware_profile": {"enum": model["hardware_profiles"]},
        },
    }


def architecture(contract: dict, digest: str) -> dict[str, bytes]:
    model = contract["canonical_model"]
    requirements = contract["requirements"]
    packets = contract["work_packets"]
    gates = contract["verification_gates"]
    services = model["services"]
    common = {
        "00-GOVERNANCE.md": ("Governance", "## Mission\n\n" + table(["Property", "Value"], [[key, value] for key, value in contract["mission"].items()]) + "\n\n## Authority\n\n" + table(["Rank", "Source"], [[i + 1, value] for i, value in enumerate(contract["authority"]["precedence"])])),
        "01-ARCHITECTURE.md": ("Architecture", "## Records\n\n" + ", ".join(f"`{x}`" for x in model["records"]) + "\n\n## Services and ownership\n\n" + table(["Service", "Owns", "Must not own"], [[s["id"], s["owns"], s["must_not_own"]] for s in services])),
        "02-AGENT-ABI.md": ("Agent ABI", "## Principals\n\n" + ", ".join(f"`{x}`" for x in model["principals"]) + "\n\n## Stable records\n\n" + table(["Record"], [[x] for x in model["records"]]) + "\n\n## Error codes\n\n" + ", ".join(f"`{x}`" for x in model["error_codes"])),
        "03-STATE-AND-LIFECYCLE.md": ("State and lifecycle", "## Effect states\n\n" + " → ".join(f"`{x}`" for x in model["effect_states"]) + "\n\n## Change states\n\n" + " → ".join(f"`{x}`" for x in model["change_states"])),
        "04-AUTHORITY-CAPABILITIES.md": ("Authority and capabilities", table(["Service", "Owns", "Excluded ownership"], [[s["id"], s["owns"], s["must_not_own"]] for s in services if s["id"] in {"identity", "authority", "activation"}])),
        "05-EFFECTS.md": ("Effects", "## Classes\n\n" + table(["Class"], [[x] for x in model["effect_classes"]]) + "\n\n## Lifecycle\n\n" + table(["State"], [[x] for x in model["effect_states"]])),
        "06-CONTEXT.md": ("Context", "Context transport uses canonical records and remains separate from authority and effect execution.\n\n" + table(["Context record"], [[x] for x in model["records"] if "Context" in x or "Memory" in x])),
        "07-CAPABILITY-PACKAGES.md": ("Capability packages", "Package selection is content-addressed, policy constrained, and generation pinned. Canonical ownership remains with the package and activation services.\n\n" + table(["Related record"], [[x] for x in model["records"] if "Package" in x or "Activation" in x])),
        "08-SYSTEM-GENERATIONS.md": ("System generations", "Generation changes follow the canonical change-state sequence and require governed recovery.\n\n" + table(["Change state"], [[x] for x in model["change_states"]])),
        "09-THREAT-SAFETY.md": ("Threat and safety", table(["Requirement", "Boundary", "Failure", "Enforcement"], [[r["id"], r["boundary"], r["failure"], r["enforcement"]] for r in requirements if r["id"].startswith(("AUTH-", "EFF-"))])),
        "10-HARDWARE-PROFILES.md": ("Hardware profiles", table(["Canonical profile"], [[x] for x in model["hardware_profiles"]]) + "\n\nOnly these generic conformance identities are canonical."),
        "11-OBSERVABILITY-SLOS.md": ("Observability and SLOs", table(["Requirement", "Statement", "Evidence"], [[r["id"], r["shall"], r["evidence"]] for r in requirements if r["id"].startswith("OBS-")])),
        "12-VERIFICATION-MATRIX.md": ("Verification matrix", table(["Gate", "Runner", "Pass condition", "Evidence"], [[g["id"], g["runner"], g["pass"], g["evidence"]] for g in gates])),
        "13-IMPLEMENTATION-WORK-GRAPH.md": ("Implementation work graph", table(["Packet", "Deliverable", "Requirements", "Begin after", "Integrate after", "Pass after", "Gates"], [[p["id"], p["deliverable"], p["requirements"], p["cannot_begin"], p["cannot_integrate"], p["cannot_pass"], p["gates"]] for p in packets])),
        "14-DECISION-REGISTER.md": ("Binding decisions", table(["Disposition", "Selector", "Action", "Reason", "Proof"], [[x["id"], json.dumps(x["selector"], sort_keys=True), x["action"], x["reason"], x["proof"]] for x in contract["repository_rebuild"]["dispositions"] if x["action"] != "DELETE"])),
        "15-TRACEABILITY.md": ("Traceability", table(["Requirement", "Owner", "Source", "Evidence", "Acceptance"], [[r["id"], r["owner_packet"], r["source_reference"], r["evidence"], r["acceptance"]] for r in requirements])),
        "17-REMEDIATION-RECORD.md": ("Remediation record", "The active tree is rebuilt under the binding v2 dispositions. Any failed predicate or verification gate blocks completion and is recorded against its owning work packet."),
    }
    common["README.md"] = ("Nix AI v2 architecture projections", "These files are deterministic projections of the immutable v2.0.1 contract.\n\n" + table(["Projection"], [[name] for name in ARCHITECTURE_FILES if name != "README.md"]))
    return {f"contracts/architecture/{name}": document(title, body, digest) for name, (title, body) in common.items()}


def build_spec(contract: dict, digest: str) -> bytes:
    packets = contract["work_packets"]
    body = "## Execution order\n\n" + table(["Order", "Action", "Blocked by"], [[step["ordinal"], step["action"], step["blocked_by"]] for step in contract["repository_rebuild"]["execution_order"]])
    body += "\n\n## Work packets\n\n" + table(["Packet", "Deliverable", "Gates"], [[p["id"], p["deliverable"], p["gates"]] for p in packets])
    return document("Nix AI v2 build specification", body, digest)


def outputs(root: Path) -> dict[str, bytes]:
    source = (root / CONTRACT_PATH).read_bytes()
    contract = json.loads(source)
    digest = hashlib.sha256(source).hexdigest()
    values = {
        "contracts/requirements.yaml": json_bytes(requirement_registry(contract, digest)),
        "contracts/work-packets.yaml": json_bytes(work_registry(contract, digest)),
        "contracts/requirements.schema.json": json_bytes(requirements_schema()),
        "contracts/work-packets.schema.json": json_bytes(work_schema()),
        "contracts/schemas/v2-canonical.schema.json": json_bytes(canonical_schema(contract["canonical_model"])),
        "CODEX-BUILD-SPEC.md": build_spec(contract, digest),
    }
    values.update(architecture(contract, digest))
    manifest_paths = sorted(path for path in values if path.startswith("contracts/architecture/"))
    values["contracts/architecture/MANIFEST.sha256"] = "".join(
        f"{hashlib.sha256(values[path]).hexdigest()}  {Path(path).name}\n" for path in manifest_paths
    ).encode()
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    generated = outputs(root)
    stale = []
    for relative, content in generated.items():
        path = root / relative
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        elif not path.is_file() or path.read_bytes() != content:
            stale.append(relative)
    if stale:
        print("stale generated v2 artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    if args.check:
        from proto_contracts import validate as validate_proto_contracts

        validate_proto_contracts(root)
    interface_count = 6
    print(
        f"{'wrote' if args.write else 'verified'} {len(generated)} v2 contract projections"
        + (f" and {interface_count} interface artifacts" if args.check else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
