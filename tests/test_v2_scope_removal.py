import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "evidence" / "v2-rebuild" / "disposition-ledger.json"


class V2ScopeRemovalTests(unittest.TestCase):
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
        self.assertEqual(report["delete_target_count"], 51)
        self.assertEqual(report["remaining_delete_targets"], [])
        self.assertEqual(report["contaminated_units"], [])
        self.assertEqual(report["rejected_build_members"], [])

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


if __name__ == "__main__":
    unittest.main()
