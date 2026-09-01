import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class V2AuthorityEffectEvidenceTests(unittest.TestCase):
    def test_v_auth_evidence_satisfies_binding_gate(self):
        report = json.loads(
            (ROOT / "evidence/work-packets/W04/authority-report.json").read_text()
        )
        self.assertEqual(report["gate"], "V-AUTH")
        self.assertEqual(report["runner"], "authority_adversarial_qualification")
        self.assertEqual(report["outcome"], "passed")
        self.assertEqual(report["abi"], "2.0")
        self.assertEqual(
            report["metrics"],
            {
                "unauthorized_action_count": 0,
                "widening_delegation_acceptance_count": 0,
                "post_bound_revoked_invocation_count": 0,
            },
        )
        self.assertEqual(report["requirements"], ["AUTH-001", "AUTH-002", "AUTH-003"])
        proof = report["behavioral_test_proof"]
        self.assertEqual(proof["runner"], "rust-test-binaries")
        self.assertEqual(proof["outcome"], "passed")
        self.assertGreaterEqual(proof["test_count"], 7)
        self.assertEqual(len(proof["test_names"]), proof["test_count"])
        self.assert_report_is_contract_bound(report, "crates/habitat-authority")

    def test_v_effect_evidence_satisfies_binding_gate(self):
        report = json.loads(
            (ROOT / "evidence/work-packets/W08/effect-report.json").read_text()
        )
        self.assertEqual(report["gate"], "V-EFFECT")
        self.assertEqual(report["runner"], "effect_fault_recovery_qualification")
        self.assertEqual(report["outcome"], "passed")
        self.assertEqual(report["abi"]["abi"], "2.0")
        self.assertEqual(
            {key for key, value in report["metrics"].items() if value != 0}, set()
        )
        self.assertEqual(
            report["requirements"],
            ["EFFECT-001", "EFFECT-002", "EFFECT-003", "EFFECT-004", "EFFECT-005"],
        )
        proof = report["behavioral_test_proof"]
        self.assertEqual(proof["runner"], "rust-test-binaries")
        self.assertEqual(proof["outcome"], "passed")
        self.assertGreaterEqual(proof["test_count"], 8)
        self.assertEqual(len(proof["test_names"]), proof["test_count"])
        self.assert_report_is_contract_bound(report, "crates/habitat-effects")

    def assert_report_is_contract_bound(self, report, relative):
        contract = ROOT / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
        self.assertEqual(report["contract_sha256"], hashlib.sha256(contract.read_bytes()).hexdigest())
        self.assertRegex(report["artifact_sha256"], re.compile(r"^[0-9a-f]{64}$"))
        digest = hashlib.sha256()
        for path in sorted((ROOT / relative).rglob("*.rs")):
            name = path.relative_to(ROOT).as_posix().encode()
            content = path.read_bytes()
            digest.update(
                len(name).to_bytes(4, "big")
                + name
                + len(content).to_bytes(8, "big")
                + content
            )
        self.assertEqual(report["implementation_sha256"], digest.hexdigest())


if __name__ == "__main__":
    unittest.main()
