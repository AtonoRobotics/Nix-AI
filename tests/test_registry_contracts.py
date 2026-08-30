from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable
import unittest

import yaml


REPOSITORY = Path(__file__).resolve().parents[1]
VALIDATOR = REPOSITORY / "tools" / "registry_contracts.py"


class RegistryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(REPOSITORY / "contracts", self.root / "contracts")
        shutil.copy2(REPOSITORY / "CODEX-BUILD-SPEC.md", self.root)
        for path in self.root.rglob("*"):
            path.chmod(path.stat().st_mode | 0o200)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def mutate_yaml(
        self, relative: str | Path, mutate: Callable[[dict[str, Any]], object]
    ) -> None:
        path = self.root / relative
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    def mutate_yaml_and_validate(
        self, relative: str | Path, mutate: Callable[[dict[str, Any]], object]
    ) -> subprocess.CompletedProcess[str]:
        self.mutate_yaml(relative, mutate)
        return self.run_validator()

    def assert_rejected(
        self, result: subprocess.CompletedProcess[str], message: str
    ) -> None:
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(message, result.stderr)

    def test_missing_requirement_mapping_is_rejected(self) -> None:
        missing: list[str] = []
        result = self.mutate_yaml_and_validate(
            "contracts/requirements.yaml",
            lambda registry: missing.append(registry["requirements"].pop(0)["id"]),
        )
        self.assert_rejected(result, f"requirement missing from registry: {missing[0]}")

    def test_definition_and_mapping_counts_are_independently_fixed_at_135(self) -> None:
        self.mutate_yaml(
            "contracts/requirements.yaml",
            lambda registry: registry.update(
                requirements=[
                    item
                    for item in registry["requirements"]
                    if item["id"] != "ABI-001"
                ]
            ),
        )
        source = self.root / "contracts" / "architecture" / "02-AGENT-ABI.md"
        source.write_text(
            source.read_text(encoding="utf-8").replace(
                "**ABI-001 — Backend neutrality.**", "Backend neutrality."
            ),
            encoding="utf-8",
        )

        self.assert_rejected(
            self.run_validator(), "normative requirement definitions must total 135"
        )

    def test_unknown_verification_gate_is_rejected(self) -> None:
        result = self.mutate_yaml_and_validate(
            "contracts/requirements.yaml",
            lambda registry: registry["requirements"][0].update(
                gates=["V-NOT-REAL"]
            ),
        )
        self.assert_rejected(result, "ABI-001 references unknown gate: V-NOT-REAL")

    def test_cycle_in_each_dependency_relation_is_rejected(self) -> None:
        path = self.root / "contracts" / "work-packets.yaml"
        source = REPOSITORY / "contracts" / "work-packets.yaml"
        for relation in ("cannot_begin", "cannot_integrate", "cannot_pass"):
            with self.subTest(relation=relation):
                shutil.copyfile(source, path)
                def add_cycle(graph: dict[str, Any]) -> None:
                    packets = {packet["id"]: packet for packet in graph["packets"]}
                    packets["W00"][relation] = ["W01"]
                    if relation != "cannot_pass":
                        packets["W00"]["cannot_pass"] = ["W01"]
                        packets["W01"][relation] = ["W00"]

                result = self.mutate_yaml_and_validate(path.relative_to(self.root), add_cycle)
                self.assert_rejected(result, f"cycle in {relation}")

    def test_stale_generated_projection_is_rejected(self) -> None:
        targets = (
            Path("CODEX-BUILD-SPEC.md"),
            Path("contracts/architecture/13-IMPLEMENTATION-WORK-GRAPH.md"),
        )
        for relative in targets:
            with self.subTest(target=str(relative)):
                shutil.copyfile(REPOSITORY / relative, self.root / relative)
                path = self.root / relative
                current = path.read_text(encoding="utf-8")
                path.write_text(
                    current.replace("Source SHA-256: `", "Source SHA-256: `stale-", 1),
                    encoding="utf-8",
                )

                result = self.run_validator()

                self.assert_rejected(result, f"stale generated projection: {relative}")

    def test_non_executable_requirement_mapping_is_rejected(self) -> None:
        path = self.root / "contracts" / "requirements.yaml"
        source = REPOSITORY / "contracts" / "requirements.yaml"
        cases = (
            ("owner_packet", "W99", "unknown owner packet: W99"),
            ("criticality", "optional", "invalid criticality: optional"),
            ("implementation", "", "empty implementation"),
            ("evidence", [], "has no objective evidence mapping"),
            ("source", "missing.md:1", "source file missing: missing.md"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                shutil.copyfile(source, path)
                result = self.mutate_yaml_and_validate(
                    path.relative_to(self.root),
                    lambda registry: registry["requirements"][0].update(
                        {field: value}
                    ),
                )
                self.assert_rejected(result, f"ABI-001 {message}")

    def test_registry_metadata_must_satisfy_canonical_schemas(self) -> None:
        cases = (
            (
                Path("contracts/work-packets.yaml"),
                lambda value: value.update(source_of_truth=False),
                "registry schema validation failed",
            ),
            (
                Path("contracts/work-packets.yaml"),
                lambda value: value["dependency_semantics"].pop("cannot_begin"),
                "registry schema validation failed",
            ),
            (
                Path("contracts/requirements.yaml"),
                lambda value: value.update(expected_requirement_count=134),
                "expected requirement count must be 135",
            ),
        )
        for relative, mutate, message in cases:
            with self.subTest(target=str(relative), message=message):
                shutil.copyfile(
                    REPOSITORY / "contracts" / "requirements.yaml",
                    self.root / "contracts" / "requirements.yaml",
                )
                shutil.copyfile(
                    REPOSITORY / "contracts" / "work-packets.yaml",
                    self.root / "contracts" / "work-packets.yaml",
                )
                result = self.mutate_yaml_and_validate(relative, mutate)
                self.assert_rejected(result, message)


if __name__ == "__main__":
    unittest.main()
