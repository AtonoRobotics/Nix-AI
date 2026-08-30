import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "v2.0.1" / "nix-ai-v2.0.1.contract.json"


class V2ContractDerivationTests(unittest.TestCase):
    def test_generated_registries_are_exact_contract_projections(self):
        contract = json.loads(CONTRACT.read_text())
        requirements = json.loads((ROOT / "contracts" / "requirements.yaml").read_text())
        work_graph = json.loads((ROOT / "contracts" / "work-packets.yaml").read_text())
        self.assertEqual(requirements["requirements"], contract["requirements"])
        self.assertEqual(work_graph["packets"], contract["work_packets"])
        self.assertEqual(requirements["expected_requirement_count"], 40)
        requirement_ids = [item["id"] for item in requirements["requirements"]]
        self.assertEqual(len(requirement_ids), len(set(requirement_ids)))
        owners = [item["owner_packet"] for item in requirements["requirements"]]
        packet_ids = {item["id"] for item in work_graph["packets"]}
        self.assertTrue(set(owners) <= packet_ids)
        declared = {
            requirement
            for packet in work_graph["packets"]
            for requirement in packet["requirements"]
        }
        self.assertEqual(declared, set(requirement_ids))
        for requirement in requirements["requirements"]:
            packet = next(item for item in work_graph["packets"] if item["id"] == requirement["owner_packet"])
            self.assertIn(requirement["id"], packet["requirements"])

    def test_work_graph_is_acyclic(self):
        graph = json.loads((ROOT / "contracts" / "work-packets.yaml").read_text())
        dependencies = {
            packet["id"]: set(packet["cannot_begin"] + packet["cannot_integrate"] + packet["cannot_pass"])
            for packet in graph["packets"]
        }
        resolved = set()
        while dependencies:
            ready = {node for node, edges in dependencies.items() if edges <= resolved}
            self.assertTrue(ready, f"dependency cycle: {dependencies}")
            resolved |= ready
            dependencies = {node: edges for node, edges in dependencies.items() if node not in ready}

    def test_canonical_schema_rejects_removed_domain_values(self):
        schema = json.loads(
            (ROOT / "contracts" / "schemas" / "v2-canonical.schema.json").read_text()
        )
        validator = Draft202012Validator(schema)
        canonical = {
            "principal": "AGENT",
            "effect_class": "E2",
            "execution_profile": "WASI_COMPONENT",
            "hardware_profile": "generic-aarch64",
        }
        self.assertEqual(list(validator.iter_errors(canonical)), [])
        for field, value in (
            ("principal", "ROBOT"),
            ("effect_class", "PHYSICAL_ACTUATION"),
            ("execution_profile", "ROS_NODE"),
            ("hardware_profile", "gpu:rtx"),
        ):
            with self.subTest(field=field, value=value):
                invalid = canonical | {field: value}
                self.assertTrue(list(validator.iter_errors(invalid)))

    def test_interface_namespace_is_v2_only(self):
        sources = {
            path.name: path.read_text()
            for path in (ROOT / "contracts" / "proto").glob("*.proto")
        }
        self.assertEqual(
            set(sources), {"nix_ai_agent_v2.proto", "nix_ai_authority_effect_v2.proto"}
        )
        self.assertIn("package nix_ai.agent.v2;", sources["nix_ai_agent_v2.proto"])
        self.assertIn(
            "package nix_ai.authority.v2;",
            sources["nix_ai_authority_effect_v2.proto"],
        )
        self.assertNotIn(".v1", "\n".join(sources.values()))
        authority = sources["nix_ai_authority_effect_v2.proto"]
        self.assertNotIn("E4 =", authority)
        self.assertIn("AUTHORITY_REQUIRED = 11;", authority)
        self.assertNotIn("MANUAL_AUTHORITY_REQUIRED", authority)

    def test_regeneration_produces_no_diff(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "derive_v2_contract.py"), "--root", str(ROOT), "--check"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_interface_artifact_mutations_break_derivation_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "repository"
            shutil.copytree(
                ROOT,
                clone,
                ignore=shutil.ignore_patterns(".git", "target", "__pycache__"),
            )
            artifacts = [
                clone / "contracts" / "proto" / "nix_ai_agent_v2.proto",
                clone / "contracts" / "proto" / "nix_ai_authority_effect_v2.proto",
                clone / "generated" / "proto" / "descriptor.bin",
                clone / "generated" / "proto" / "SOURCE.sha256",
                *sorted((clone / "generated" / "proto" / "rust").rglob("*.rs")),
            ]
            self.assertEqual(len(artifacts), 6)
            for artifact in artifacts:
                with self.subTest(artifact=str(artifact.relative_to(clone))):
                    original = artifact.read_bytes()
                    try:
                        artifact.write_bytes(original + b"\n")
                        result = subprocess.run(
                            [
                                sys.executable,
                                str(clone / "tools" / "derive_v2_contract.py"),
                                "--root", str(clone), "--check",
                            ],
                            capture_output=True,
                            text=True,
                        )
                        self.assertNotEqual(result.returncode, 0)
                    finally:
                        artifact.write_bytes(original)

    def test_v_scope_and_v_contract_pass(self):
        contract = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "validate_contracts.py"), str(ROOT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(contract.returncode, 0, contract.stdout + contract.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            scope = subprocess.run(
                [
                    sys.executable, str(ROOT / "tools" / "verify_v2_removal.py"),
                    "--root", str(ROOT),
                    "--ledger", str(ROOT / "evidence" / "v2-rebuild" / "disposition-ledger.json"),
                    "--output", str(Path(temporary) / "scope-report.json"),
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(scope.returncode, 0, scope.stdout + scope.stderr)


if __name__ == "__main__":
    unittest.main()
