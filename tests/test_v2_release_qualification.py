import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATES = {
    "V-SCOPE", "V-CONTRACT", "V-BOOT", "V-ROLLBACK", "V-STATE", "V-ABI",
    "V-AUTH", "V-ISOLATION", "V-CONTEXT", "V-EFFECT", "V-PACKAGE",
    "V-CHANGE", "V-END-TO-END",
}


class V2ReleaseQualificationTests(unittest.TestCase):
    def test_checked_release_evidence_satisfies_the_binding_completion_predicate(self):
        result = subprocess.run(
            [sys.executable, "tools/qualify_v2_release.py", "--root", str(ROOT),
             "--verify-evidence"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(
            (ROOT / "evidence/v2-release/qualification-summary.json").read_text()
        )
        self.assertEqual({gate["gate"] for gate in summary["gates"]}, GATES)
        self.assertEqual(summary["missing_gate_count"], 0)
        self.assertEqual(summary["handwritten_pass_evidence_count"], 0)
        self.assertEqual(summary["failed_gate_count"], 0)
        self.assertTrue(summary["completion_predicate"])
        contract = json.loads(
            (ROOT / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text()
        )
        expected_predicates = {
            predicate.split(" == ", 1)[0]
            for predicate in contract["completion"]["predicates"]
        }
        self.assertEqual(set(summary["completion_predicates"]), expected_predicates)
        self.assertFalse(summary["completion_predicates"]["released_contract_modified"])
        self.assertTrue(all(
            value is True or value == 0
            for value in summary["completion_predicates"].values()
        ))
        for name in (
            "retention-ledger.json", "manifest-report.json", "migration-report.json",
            "backup-restore-report.json", "backend-replacement-report.json",
        ):
            self.assertTrue((ROOT / "evidence/v2-release" / name).is_file(), name)

    def test_missing_gate_and_forged_command_attribution_are_rejected(self):
        source = ROOT / "evidence/v2-release"
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "release"
            subprocess.run(["cp", "-a", str(source), str(evidence)], check=True)
            summary_path = evidence / "qualification-summary.json"
            summary = json.loads(summary_path.read_text())
            summary["gates"] = [item for item in summary["gates"] if item["gate"] != "V-AUTH"]
            summary["missing_gate_count"] = 1
            summary["completion_predicate"] = False
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
            result = subprocess.run(
                [sys.executable, "tools/qualify_v2_release.py", "--root", str(ROOT),
                 "--evidence-dir", str(evidence), "--verify-evidence"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            subprocess.run(["cp", "-a", str(source) + "/.", str(evidence)], check=True)
            report_path = evidence / "authority-report.json"
            report = json.loads(report_path.read_text())
            report["attestations"][0] = {
                "kind": "executed_command",
                "argv": ["handwritten-pass", "w04-qualification"], "exit_code": 0,
                "output": "fabricated runner output",
                "output_sha256": "sha256:" + "0" * 64, "output_bytes": 999999,
            }
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            summary = json.loads(summary_path.read_text())
            for record in summary["gates"]:
                if record["gate"] == "V-AUTH":
                    import hashlib
                    record["sha256"] = "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
            result = subprocess.run(
                [sys.executable, "tools/qualify_v2_release.py", "--root", str(ROOT),
                 "--evidence-dir", str(evidence), "--verify-evidence"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_contradictory_headless_observation_and_packet_status_are_rejected(self):
        source = ROOT / "evidence/v2-release"
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "release"
            subprocess.run(["cp", "-a", str(source), str(evidence)], check=True)
            report_path = evidence / "end-to-end-report.json"
            report = json.loads(report_path.read_text())
            report["observations"]["wake-crash-matrix.json"] = {
                "outcome": "failed", "reason": "lost work and duplicate effect; active human required"
            }
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            summary_path = evidence / "qualification-summary.json"
            summary = json.loads(summary_path.read_text())
            import hashlib
            for record in summary["gates"]:
                if record["gate"] == "V-END-TO-END":
                    record["sha256"] = "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
            result = subprocess.run(
                [sys.executable, "tools/qualify_v2_release.py", "--root", str(ROOT),
                 "--evidence-dir", str(evidence), "--verify-evidence"], cwd=ROOT,
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            subprocess.run(["cp", "-a", str(source) + "/.", str(evidence)], check=True)
            summary = json.loads(summary_path.read_text())
            summary["work_packets"] = [{"packet": "W00", "result": "fail", "gates": []}]
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
            result = subprocess.run(
                [sys.executable, "tools/qualify_v2_release.py", "--root", str(ROOT),
                 "--evidence-dir", str(evidence), "--verify-evidence"], cwd=ROOT,
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
