import json
import jsonschema
from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class V2RebuildFrontierTests(unittest.TestCase):
    def test_binding_contract_validates_at_its_public_cli(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "contracts" / "v2.0.1" / "validate_contract.py"),
            ],
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["contract_id"], "nix-ai-core")
        self.assertEqual(report["version"], "2.0.1")
        self.assertTrue(report["valid"])
        self.assertEqual(report["errors"], [])

        package = ROOT / "contracts" / "v2.0.1"
        schema = json.loads((package / "contract.schema.json").read_text())
        contract = json.loads((package / "nix-ai-v2.0.1.contract.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(contract)

    def test_recorded_rebuild_baseline_matches_the_binding_contract(self):
        contract = json.loads(
            (ROOT / "contracts" / "v2.0.1" / "nix-ai-v2.0.1.contract.json").read_text()
        )
        baseline = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "baseline.json").read_text()
        )

        self.assertEqual(
            baseline["baseline_commit"], contract["contract"]["target"]["baseline_commit"]
        )
        self.assertEqual(
            baseline["contract_commit"],
            "b342161f5abd5feedd8373c0a989a05949eb43e8",
        )
        self.assertEqual(baseline["runner"], {"name": "inventory-v2", "version": 1})

    def test_checked_in_inventory_evidence_is_machine_readable_and_attributed(self):
        report = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "inventory.json").read_text()
        )

        self.assertEqual(report["runner"], {"name": "inventory-v2", "version": 1})
        inventory_commit = report["inventory_commit"]
        resolved_tree = subprocess.run(
            ["git", "rev-parse", f"{inventory_commit}^{{tree}}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(report["inventory_tree"], resolved_tree)
        self.assertEqual(
            report["rebuild_baseline_commit"],
            "c61d6be13cd9593284c32249c5b9a11691df0f67",
        )
        self.assertIn("evidence/v2-rebuild/inventory.json", report["tracked_paths"])
        semantics = {
            (item["path"], item["kind"], item["name"])
            for item in report["public_semantics"]
        }
        self.assertIn(
            ("crates/habitat-effects/src/lib.rs", "enum", "EffectError"),
            semantics,
        )
        self.assertIn(
            (
                "crates/habitat-effects/src/lib.rs",
                "enum_value",
                "EffectError::AdmissionDenied",
            ),
            semantics,
        )
        self.assertIn(
            (
                "tests/test_v2_rebuild_frontier.py",
                "test_fixture",
                "test_binding_contract_validates_at_its_public_cli",
            ),
            semantics,
        )
        for expected in (
            ("crates/habitat-harnesses/src/lib.rs", "fn", "compare"),
            (
                "crates/habitat-harnesses/tests/runtime_boundary.rs",
                "test_fixture",
                "process_success_prose_and_session_completion_do_not_complete_objective",
            ),
            (
                "crates/habitat-authority/src/lib.rs",
                "macro_generated_type",
                "MachineId",
            ),
            (
                "contracts/v2.0.1/nix-ai-v2.0.1.contract.json",
                "canonical_record",
                "Effect",
            ),
            (
                "contracts/v2.0.1/nix-ai-v2.0.1.contract.json",
                "canonical_service",
                "effect",
            ),
            (
                "contracts/v2.0.1/nix-ai-v2.0.1.contract.json",
                "effect_state",
                "OUTCOME_UNKNOWN",
            ),
            (
                "contracts/proto/habitat_authority_effect_v1.proto",
                "enum_value",
                "EffectState::OUTCOME_UNKNOWN",
            ),
            (
                "src/habitat_state/domain.py",
                "enum_value",
                "State::RUNNING",
            ),
            (
                "src/habitat_state/domain.py",
                "transition",
                "EntityKind.ACTIVATION:State.RUNNING->State.COMPLETED",
            ),
            (
                "contracts/v2.0.1/contract.schema.json",
                "schema_definition",
                "$defs/requirement",
            ),
        ):
            self.assertIn(expected, semantics)
        self.assertEqual(
            sum(item["kind"] == "schema_definition" for item in report["public_semantics"]),
            38,
        )
        self.assertEqual(
            sum(item["kind"] == "schema_enum_value" for item in report["public_semantics"]),
            122,
        )
        semantic_lines = {
            (item["path"], item["kind"], item["name"]): item["line"]
            for item in report["public_semantics"]
        }
        self.assertEqual(
            semantic_lines[
                (
                    "contracts/v2.0.1/nix-ai-v2.0.1.contract.json",
                    "canonical_service",
                    "authority",
                )
            ],
            128,
        )
        self.assertEqual(
            semantic_lines[
                (
                    "crates/habitat-authority/src/lib.rs",
                    "enum_value",
                    "AuthorityError::IdentityInvalid",
                )
            ],
            26,
        )
        self.assertEqual(
            semantic_lines[
                (
                    "contracts/requirements.schema.json",
                    "schema_enum_value",
                    "#/properties/requirements/items/properties/criticality/enum::critical",
                )
            ],
            33,
        )
        self.assertIn(
            (
                "nix/modules/habitat-image.nix",
                "service",
                "habitat-bootstrap",
            ),
            semantics,
        )
        self.assertIn(
            (
                "crates/habitat-effects/src/lib.rs",
                "transition",
                "state_assignment->EffectState::Executing",
            ),
            semantics,
        )
        dependencies = {
            (item["path"], item["class"], item["name"])
            for item in report["dependencies"]
        }
        for dependency in ("setuptools", "boto3", "psycopg"):
            self.assertIn(("pyproject.toml", "python-declared", dependency), dependencies)
        self.assertIn(
            (
                "contracts/v2.0.1/validate_contract.py",
                "python-import",
                "jsonschema",
            ),
            dependencies,
        )
        generated_classes = {
            item["name"]
            for item in report["generated_artifacts"]
            if item["class"] == "required-generated-class"
        }
        self.assertEqual(
            generated_classes,
            {
                "requirements_registry",
                "work_graph",
                "architecture_projections",
                "json_schemas",
                "protobuf_descriptors",
                "language_bindings",
                "lockfiles",
                "sbom",
                "provenance",
                "evidence_indexes",
                "sha256_manifests",
            },
        )
        concrete_generated_classes = {
            item["required_class"]
            for item in report["generated_artifacts"]
            if item.get("required_class")
        }
        self.assertEqual(
            concrete_generated_classes,
            generated_classes,
        )
        self.assertIn(
            {
                "path": "evidence/v2-rebuild/inventory.json",
                "class": "generated-output",
                "required_class": "evidence_indexes",
            },
            report["generated_artifacts"],
        )
        closure = {
            (item["class"], item["name"])
            for item in report["build_closure_members"]
        }
        self.assertIn(("nix-internal-derivation", "habitatSimulation"), closure)
        self.assertIn(("nix-dependency-edge", "habitatQemu->habitatRaw"), closure)
        self.assertNotIn(("nix-declared-closure-root", "version"), closure)
        self.assertIn(
            ("src/habitat_state/store.py", "python-relative-import", ".domain"),
            dependencies,
        )
        self.assertIn(
            ("buf.gen.yaml", "buf-plugin", "protoc-gen-prost"), dependencies
        )
        for dependency in ("docker-client", "qemu", "protobuf", "coreutils", "mtools"):
            self.assertIn(("flake.nix", "nix-package", dependency), dependencies)
        self.assertIn(
            (
                "contracts/proto/habitat_agent_v1.proto",
                "proto-import",
                "google/protobuf/struct.proto",
            ),
            dependencies,
        )
        self.assertIn(
            ("nix/modules/habitat-image.nix", "nix-package", "findutils"),
            dependencies,
        )
        self.assertIn(
            (
                "nix/profiles/qemu-x86_64-conformance.nix",
                "nix-module",
                "../modules/habitat-image.nix",
            ),
            dependencies,
        )
        self.assertEqual(
            report["counts"],
            {
                key: len(report[key])
                for key in (
                    "tracked_paths",
                    "public_semantics",
                    "dependencies",
                    "generated_artifacts",
                    "build_closure_members",
                )
            },
        )

    def test_cross_relation_dependency_cycle_is_rejected(self):
        source = ROOT / "contracts" / "v2.0.1"
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "v2.0.1"
            shutil.copytree(source, package)
            contract_path = package / "nix-ai-v2.0.1.contract.json"
            contract = json.loads(contract_path.read_text())
            contract["work_packets"][0]["cannot_integrate"] = ["W01"]
            contract_path.write_text(json.dumps(contract, indent=2) + "\n")
            digest = hashlib.sha256(contract_path.read_bytes()).hexdigest()
            manifest_path = package / "MANIFEST.sha256"
            manifest = manifest_path.read_text()
            manifest = re.sub(
                r"^[0-9a-f]{64}(  nix-ai-v2\.0\.1\.contract\.json)$",
                digest + r"\1",
                manifest,
                flags=re.MULTILINE,
            )
            manifest_path.write_text(manifest)

            result = subprocess.run(
                [sys.executable, str(package / "validate_contract.py")],
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("combined dependency graph cycle", result.stdout)

    def test_requirement_derivation_references_are_resolved_and_acyclic(self):
        source = ROOT / "contracts" / "v2.0.1"
        mutations = {
            "unknown source reference": "MISSING-001",
            "requirement derivation graph cycle": "CHANGE-003",
        }
        for expected_error, source_reference in mutations.items():
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary) / "v2.0.1"
                shutil.copytree(source, package)
                contract_path = package / "nix-ai-v2.0.1.contract.json"
                contract = json.loads(contract_path.read_text())
                contract["requirements"][2]["source_reference"] = source_reference
                contract_path.write_text(json.dumps(contract, indent=2) + "\n")
                digest = hashlib.sha256(contract_path.read_bytes()).hexdigest()
                manifest_path = package / "MANIFEST.sha256"
                manifest_path.write_text(
                    re.sub(
                        r"^[0-9a-f]{64}(  nix-ai-v2\.0\.1\.contract\.json)$",
                        digest + r"\1",
                        manifest_path.read_text(),
                        flags=re.MULTILINE,
                    )
                )

                result = subprocess.run(
                    [sys.executable, str(package / "validate_contract.py")],
                    text=True,
                    capture_output=True,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stdout)

    def test_inventory_cli_records_the_baseline_and_every_inventory_class(self):
        baseline = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "inventory.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "inventory_v2.py"),
                    "--root",
                    str(ROOT),
                    "--baseline",
                    baseline,
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report["rebuild_baseline_commit"], baseline)
            self.assertEqual(report["inventory_commit"], baseline)
            self.assertRegex(report["inventory_tree"], r"^[0-9a-f]{40}$")
            self.assertEqual(report["inventory_source"]["file_contents"], "git-tree")
            self.assertEqual(
                report["inventory_source"]["snapshot_boundary"],
                "before-report-publication",
            )
            self.assertEqual(report["runner"], {"name": "inventory-v2", "version": 1})
            self.assertIn("Cargo.toml", report["tracked_paths"])
            self.assertIn(
                "contracts/v2.0.1/nix-ai-v2.0.1.contract.json",
                report["tracked_paths"],
            )
            for inventory_class in (
                "public_semantics",
                "dependencies",
                "generated_artifacts",
                "build_closure_members",
            ):
                self.assertIsInstance(report[inventory_class], list)
                self.assertGreater(len(report[inventory_class]), 0, inventory_class)
            self.assertEqual(
                report["counts"],
                {
                    key: len(report[key])
                    for key in (
                        "tracked_paths",
                        "public_semantics",
                        "dependencies",
                        "generated_artifacts",
                        "build_closure_members",
                    )
                },
            )


if __name__ == "__main__":
    unittest.main()
