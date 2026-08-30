import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "evidence" / "v2-rebuild" / "disposition-ledger.json"


class V2ScopeRemovalTests(unittest.TestCase):
    def test_checked_removal_report_is_runner_attributed_and_clean(self):
        report = json.loads(
            (ROOT / "evidence" / "v2-rebuild" / "removal-report.json").read_text()
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["runner"], {"name": "verify-v2-removal", "version": 2})
        self.assertTrue(report["valid"])
        self.assertEqual(
            report["delete_counts_by_inventory_class"],
            {
                "build_closure_members": 14,
                "dependencies": 36,
                "generated_artifacts": 2,
                "public_semantics": 193,
                "tracked_paths": 51,
            },
        )
        self.assertEqual(report["remaining_delete_units"], [])
        self.assertEqual(report["contaminated_units"], [])
        self.assertEqual(
            report["verified_commit"],
            subprocess.run(
                ["git", "-C", str(ROOT), "rev-parse", "HEAD^"],
                capture_output=True,
                check=True,
                text=True,
            ).stdout.strip(),
        )
        subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f'{report["verified_commit"]}^{{commit}}'],
            check=True,
        )

    def test_exact_delete_set_and_semantic_scope_are_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "tools" / "verify_v2_removal.py"),
                    "--root",
                    str(ROOT),
                    "--ledger",
                    str(LEDGER),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(output.read_text())
        self.assertTrue(report["valid"])
        self.assertEqual(report["delete_counts_by_inventory_class"]["tracked_paths"], 51)
        self.assertEqual(report["remaining_delete_units"], [])
        self.assertEqual(report["contaminated_units"], [])

    def test_semantic_scope_scan_rejects_opaque_and_vendor_contamination(self):
        for value in ("physical_safety", "robot_arm", "isaac_sim", "gpu:rtx", "nvidia", "cuda"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                clone = Path(temporary) / "repository"
                subprocess.run(
                    ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(clone)],
                    check=True,
                )
                contaminated = clone / "opaque.txt"
                contaminated.write_text(value)
                subprocess.run(["git", "-C", str(clone), "add", "opaque.txt"], check=True)
                result = subprocess.run(
                    [
                        "python3",
                        str(clone / "tools" / "verify_v2_removal.py"),
                        "--root",
                        str(clone),
                        "--ledger",
                        str(clone / "evidence" / "v2-rebuild" / "disposition-ledger.json"),
                        "--output",
                        str(clone / "report.json"),
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, value)
                self.assertIn("opaque.txt", result.stdout)

    def test_rejected_domain_components_are_untracked(self):
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.splitlines()
        self.assertFalse(any("Habitat-OS-Codex-Build-Bundle-v1.1" in path for path in tracked))
        self.assertFalse(any(path.startswith("crates/habitat-simulation/") for path in tracked))
        self.assertNotIn("tools/qualify_w12.py", tracked)

    def test_contract_validation_no_longer_depends_on_deleted_v1_bundle(self):
        validator = (ROOT / "tools" / "validate_contracts.py").read_text()
        self.assertNotIn("Habitat-OS-Codex-Build-Bundle-v1.1", validator)
        result = subprocess.run(
            ["python3", str(ROOT / "tools" / "validate_contracts.py"), str(ROOT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_active_architecture_manifest_is_coherent(self):
        result = subprocess.run(
            ["sha256sum", "--check", "MANIFEST.sha256"],
            cwd=ROOT / "contracts" / "architecture",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
