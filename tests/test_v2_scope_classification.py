import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class V2ScopeClassificationTests(unittest.TestCase):
    def run_classifier(
        self,
        output: Path,
        inventory: Path | None = None,
        root: Path = ROOT,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "classify_v2_scope.py"),
                "--root",
                str(root),
                "--inventory",
                str(inventory or ROOT / "evidence" / "v2-rebuild" / "inventory.json"),
                "--contract",
                str(ROOT / "contracts" / "v2.0.1" / "nix-ai-v2.0.1.contract.json"),
                "--output",
                str(output),
            ],
            text=True,
            capture_output=True,
        )

    def test_every_inventory_entry_has_a_final_disposition(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ledger.json"
            result = self.run_classifier(output)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            ledger = json.loads(output.read_text())
            inventory = json.loads(
                (ROOT / "evidence" / "v2-rebuild" / "inventory.json").read_text()
            )
            self.assertEqual(ledger["runner"], {"name": "classify-v2-scope", "version": 1})
            self.assertEqual(ledger["inventory_tree"], inventory["inventory_tree"])
            for inventory_class in (
                "tracked_paths",
                "public_semantics",
                "dependencies",
                "generated_artifacts",
                "build_closure_members",
            ):
                self.assertEqual(
                    len(ledger["dispositions"][inventory_class]),
                    len(inventory[inventory_class]),
                    inventory_class,
                )
            actions = {
                record["action"]
                for records in ledger["dispositions"].values()
                for record in records
            }
            self.assertNotIn("UNCLASSIFIED", actions)
            self.assertNotIn("AUDIT_FOR_RETENTION", actions)

    def test_domain_and_contaminated_components_are_not_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ledger.json"
            result = self.run_classifier(output)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            paths = {
                record["identity"]: record
                for record in json.loads(output.read_text())["dispositions"]["tracked_paths"]
            }

            for prefix in (
                "crates/habitat-simulation/",
                "Habitat-OS-Codex-Build-Bundle-v1.1/",
            ):
                matched = [record for path, record in paths.items() if path.startswith(prefix)]
                self.assertTrue(matched, prefix)
                self.assertTrue(all(record["action"] == "DELETE" for record in matched))

            physical = [
                record
                for path, record in paths.items()
                if path.startswith("crates/habitat-physical/")
            ]
            self.assertTrue(
                all(record["action"] == "DELETE" for record in physical)
            )

            for prefix in ("crates/habitat-authority/", "crates/habitat-effects/"):
                matched = [record for path, record in paths.items() if path.startswith(prefix)]
                self.assertTrue(matched, prefix)
                self.assertTrue(
                    all(record["action"] == "DELETE_AND_REBUILD" for record in matched)
                )

    def test_retained_units_have_requirement_authority_and_predicate_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ledger.json"
            result = self.run_classifier(output)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            ledger = json.loads(output.read_text())

            retained = [
                record
                for records in ledger["dispositions"].values()
                for record in records
                if record["action"] == "RETAIN"
            ]
            self.assertTrue(retained)
            for record in retained:
                self.assertTrue(record["requirement_ids"], record["identity"])
                self.assertTrue(record["authority_evidence"], record["identity"])
                self.assertTrue(record["retention_predicates"], record["identity"])
                self.assertEqual(
                    set(record["predicate_evidence"]),
                    set(record["retention_predicates"]),
                    record["identity"],
                )
                self.assertTrue(
                    all(
                        evidence["result"] in {"satisfied", "not_applicable"}
                        for evidence in record["predicate_evidence"].values()
                    )
                )
                self.assertTrue(
                    all(
                        evidence.get("evidence")
                        for evidence in record["predicate_evidence"].values()
                    ),
                    record["identity"],
                )
            distinct_evidence = {
                json.dumps(record["predicate_evidence"], sort_keys=True)
                for record in retained
            }
            self.assertGreater(len(distinct_evidence), 3)

            retained_by_identity = {record["identity"]: record for record in retained}
            self.assertFalse(
                any(
                    record["action"] == "RETAIN"
                    for record in ledger["dispositions"]["public_semantics"]
                )
            )
            self.assertFalse(
                any(
                    record["action"] == "RETAIN"
                    for record in ledger["dispositions"]["dependencies"]
                )
            )

            manifest = retained_by_identity["contracts/v2.0.1/MANIFEST.sha256"]
            self.assertEqual(
                manifest["predicate_evidence"]["RET-005"]["result"], "satisfied"
            )
            self.assertEqual(
                manifest["predicate_evidence"]["RET-006"]["result"], "satisfied"
            )
            self.assertIn(
                "canonical SHA-256 manifest bytes",
                manifest["predicate_evidence"]["RET-005"]["evidence"][0],
            )
            archived_v2 = retained_by_identity[
                "contracts/v2/nix-ai-v2.0.0.contract.json"
            ]
            self.assertEqual(archived_v2["requirement_ids"], ["CHANGE-003"])
            self.assertEqual(
                archived_v2["predicate_evidence"]["RET-006"]["result"],
                "not_applicable",
            )

            for identity in (".gitignore", "AGENTS.md", "tools/inventory_v2.py"):
                self.assertNotIn(identity, retained_by_identity)
            self.assertEqual(ledger["summary"]["unclassified_count"], 0)
            self.assertEqual(ledger["summary"]["unmapped_retained_count"], 0)

    def test_checked_in_disposition_ledger_is_complete_and_attributed(self):
        ledger = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "disposition-ledger.json").read_text()
        )
        inventory = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "inventory.json").read_text()
        )

        self.assertEqual(ledger["runner"], {"name": "classify-v2-scope", "version": 1})
        self.assertEqual(ledger["inventory_tree"], inventory["inventory_tree"])
        self.assertEqual(ledger["summary"]["unclassified_count"], 0)
        self.assertEqual(ledger["summary"]["unmapped_retained_count"], 0)
        self.assertEqual(
            ledger["summary"]["total_disposition_count"],
            sum(len(records) for records in ledger["dispositions"].values()),
        )

        with tempfile.TemporaryDirectory() as temporary:
            regenerated = Path(temporary) / "ledger.json"
            result = self.run_classifier(regenerated)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(regenerated.read_text()), ledger)

    def test_prior_project_and_domain_fixtures_fail_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ledger.json"
            result = self.run_classifier(output)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            ledger = json.loads(output.read_text())
            paths = {
                record["identity"]: record
                for record in ledger["dispositions"]["tracked_paths"]
            }

            for path in (
                "crates/habitat-packages/src/lib.rs",
                "crates/habitat-context/tests/compiler.rs",
                "crates/habitat-context/tests/faults.rs",
            ):
                self.assertEqual(paths[path]["action"], "DELETE_AND_REBUILD", path)

            retained_identities = {
                record["identity"].lower()
                for records in ledger["dispositions"].values()
                for record in records
                if record["action"] == "RETAIN"
            }
            self.assertFalse(any("cordis" in identity for identity in retained_identities))

            self.assertEqual(
                paths["contracts/v2.0.1/nix-ai-v2.0.1.contract.json"]["action"],
                "RETAIN",
            )
            self.assertEqual(paths["nix/images/habitat-raw.nix"]["action"], "DELETE_AND_REBUILD")

    def test_every_inventory_class_is_reconstructed_from_the_exact_tree(self):
        source = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "inventory.json").read_text()
        )
        for inventory_class in (
            "public_semantics",
            "dependencies",
            "generated_artifacts",
            "build_closure_members",
        ):
            with self.subTest(inventory_class=inventory_class):
                forged = dict(source)
                forged[inventory_class] = []
                forged["counts"] = dict(source["counts"])
                forged["counts"][inventory_class] = 0
                with tempfile.TemporaryDirectory() as temporary:
                    temporary_path = Path(temporary)
                    inventory = temporary_path / "inventory.json"
                    inventory.write_text(json.dumps(forged))
                    result = self.run_classifier(
                        temporary_path / "ledger.json", inventory
                    )

                self.assertNotEqual(result.returncode, 0, inventory_class)
                self.assertIn(
                    f"inventory {inventory_class} does not match inventory tree",
                    result.stderr,
                )

    def test_inventory_commit_is_reachable_from_a_fresh_clone(self):
        inventory = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "inventory.json").read_text()
        )
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "clone"
            subprocess.run(
                ["git", "clone", "--no-local", "--quiet", str(ROOT), str(clone)],
                check=True,
                text=True,
                capture_output=True,
            )
            resolved = subprocess.run(
                ["git", "rev-parse", f"{inventory['inventory_commit']}^{{tree}}"],
                cwd=clone,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()

        self.assertEqual(resolved, inventory["inventory_tree"])

    def test_noncanonical_manifest_bytes_fail_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            clone = temporary_path / "clone"
            subprocess.run(
                ["git", "clone", "--quiet", str(ROOT), str(clone)],
                check=True,
                text=True,
                capture_output=True,
            )
            manifest = clone / "contracts" / "v2.0.1" / "MANIFEST.sha256"
            manifest.write_text("\n".join(reversed(manifest.read_text().splitlines())) + "\n")
            subprocess.run(["git", "add", str(manifest)], cwd=clone, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=V2 Test",
                    "-c",
                    "user.email=v2-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "noncanonical manifest fixture",
                ],
                cwd=clone,
                check=True,
            )
            inventory_path = temporary_path / "inventory.json"
            inventory_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "inventory_v2.py"),
                    "--root",
                    str(clone),
                    "--baseline",
                    "HEAD",
                    "--output",
                    str(inventory_path),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                inventory_result.returncode,
                0,
                inventory_result.stdout + inventory_result.stderr,
            )
            result = self.run_classifier(
                temporary_path / "ledger.json", inventory_path, clone
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "binding manifest digest does not match trusted v2.0.1 authority",
            result.stderr,
        )

    def test_external_contract_cannot_weaken_binding_predicates(self):
        binding = json.loads(
            (ROOT / "contracts" / "v2.0.1" / "nix-ai-v2.0.1.contract.json").read_text()
        )
        binding["repository_rebuild"]["retention_predicate"] = binding[
            "repository_rebuild"
        ]["retention_predicate"][-1:]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            substituted = temporary_path / "contract.json"
            substituted.write_text(json.dumps(binding))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "classify_v2_scope.py"),
                    "--root",
                    str(ROOT),
                    "--inventory",
                    str(ROOT / "evidence" / "v2-rebuild" / "inventory.json"),
                    "--contract",
                    str(substituted),
                    "--output",
                    str(temporary_path / "ledger.json"),
                ],
                text=True,
                capture_output=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contract input does not match inventory tree", result.stderr)

    def test_same_tree_contract_mutation_cannot_replace_binding_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            clone = temporary_path / "clone"
            subprocess.run(
                ["git", "clone", "--quiet", str(ROOT), str(clone)],
                check=True,
                text=True,
                capture_output=True,
            )
            contract_path = (
                clone / "contracts" / "v2.0.1" / "nix-ai-v2.0.1.contract.json"
            )
            contract = json.loads(contract_path.read_text())
            contract["repository_rebuild"]["retention_predicate"][0][
                "assertion"
            ] = "weakened in-place mutation"
            contract_path.write_text(json.dumps(contract, indent=2) + "\n")
            import hashlib

            digest = hashlib.sha256(contract_path.read_bytes()).hexdigest()
            manifest_path = clone / "contracts" / "v2.0.1" / "MANIFEST.sha256"
            lines = []
            for line in manifest_path.read_text().splitlines():
                if line.endswith("  nix-ai-v2.0.1.contract.json"):
                    line = f"{digest}  nix-ai-v2.0.1.contract.json"
                lines.append(line)
            manifest_path.write_text("\n".join(lines) + "\n")
            subprocess.run(
                ["git", "add", str(contract_path), str(manifest_path)],
                cwd=clone,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=V2 Test",
                    "-c",
                    "user.email=v2-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "mutated binding fixture",
                ],
                cwd=clone,
                check=True,
            )
            inventory_path = temporary_path / "inventory.json"
            inventory_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "inventory_v2.py"),
                    "--root",
                    str(clone),
                    "--baseline",
                    "HEAD",
                    "--output",
                    str(inventory_path),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(inventory_result.returncode, 0, inventory_result.stderr)
            result = self.run_classifier(
                temporary_path / "ledger.json", inventory_path, clone
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binding contract digest does not match", result.stderr)

    def test_archived_v2_package_cannot_be_self_resigned_after_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            clone = temporary_path / "clone"
            subprocess.run(
                ["git", "clone", "--quiet", str(ROOT), str(clone)],
                check=True,
                text=True,
                capture_output=True,
            )
            contract_path = clone / "contracts" / "v2" / "nix-ai-v2.0.0.contract.json"
            contract_path.write_bytes(contract_path.read_bytes() + b" \n")
            import hashlib

            digest = hashlib.sha256(contract_path.read_bytes()).hexdigest()
            manifest_path = clone / "contracts" / "v2" / "MANIFEST.sha256"
            lines = [
                f"{digest}  nix-ai-v2.0.0.contract.json"
                if line.endswith("  nix-ai-v2.0.0.contract.json")
                else line
                for line in manifest_path.read_text().splitlines()
            ]
            manifest_path.write_text("\n".join(lines) + "\n")
            subprocess.run(
                ["git", "add", str(contract_path), str(manifest_path)],
                cwd=clone,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=V2 Test",
                    "-c",
                    "user.email=v2-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "mutated archived contract fixture",
                ],
                cwd=clone,
                check=True,
            )
            inventory_path = temporary_path / "inventory.json"
            inventory_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "inventory_v2.py"),
                    "--root",
                    str(clone),
                    "--baseline",
                    "HEAD",
                    "--output",
                    str(inventory_path),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(inventory_result.returncode, 0, inventory_result.stderr)
            result = self.run_classifier(
                temporary_path / "ledger.json", inventory_path, clone
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archived v2.0.0 contract digest does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
