import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import qualification  # noqa: E402
import qualify_v2_release as release  # noqa: E402


class QualificationPrimitiveTests(unittest.TestCase):
    def test_canonical_json_is_sorted_and_stable(self):
        self.assertEqual(qualification.canonical_json({"z": 1, "a": 2}), b'{\n  "a": 2,\n  "z": 1\n}\n')

    def test_execution_attestation_binds_every_required_dimension(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("cargo")
            (root / "flake.lock").write_text("flake")
            artifact = root / "result.json"
            artifact.write_text('{"outcome":"passed"}\n')
            source = "sha256:" + "1" * 64
            record = qualification.execute(
                root, source, [sys.executable, "-c", "print('live')"], artifacts=[artifact]
            )
            self.assertEqual(qualification.validate_attestation(
                record, source_tree=source, closure=qualification.closure_digest(root)), [])
            self.assertEqual(record["exit_status"], 0)
            self.assertEqual(record["stdout_sha256"], qualification.digest_bytes(b"live\n"))
            self.assertEqual(record["artifact_digests"][0]["sha256"], qualification.digest_file(artifact))
            for field in (
                "source_tree_sha256", "built_closure_sha256", "argv", "exit_status",
                "started_at", "finished_at", "stdout_sha256", "stderr_sha256",
                "artifact_digests", "runner_identity",
            ):
                self.assertIn(field, record)

    def test_tampered_or_incomplete_attestations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("cargo")
            (root / "flake.lock").write_text("flake")
            source = "sha256:" + "2" * 64
            original = qualification.execute(root, source, [sys.executable, "-c", "pass"])
            for field, value in (
                ("source_tree_sha256", "sha256:" + "0" * 64),
                ("built_closure_sha256", "sha256:" + "0" * 64),
                ("exit_status", "0"), ("runner_identity", {}),
                ("artifact_digests", [{"path": "x"}]),
            ):
                with self.subTest(field=field):
                    changed = dict(original); changed[field] = value
                    self.assertTrue(qualification.validate_attestation(
                        changed, source_tree=source, closure=qualification.closure_digest(root)))


class ReleaseVerifierTests(unittest.TestCase):
    def test_live_release_wrapper_uses_git_workspace_root(self):
        flake = (ROOT / "flake.nix").read_text()

        self.assertIn('qualify_v2_release.py} --root "$PWD" --run', flake)

    def live_result(self, *, services=False):
        value = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
                 "assertions": [{"name": "behavior observed", "passed": True}]}
        if services: value["services"] = [{"name": "runtime", "state": "ready"}]
        return value

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        (root / "Cargo.lock").write_text("cargo"); (root / "flake.lock").write_text("flake")
        fake_nix = root / "nix"
        fake_nix.write_text("#!/bin/sh\nexit 0\n"); fake_nix.chmod(0o755)
        return temporary, root

    def report(self, root, gate):
        argv = ({"V-AUTH": ["nix", "build", "--no-link", ".#checks.x86_64-linux.w04-qualification"],
                 "V-BOOT": ["nix", "run", ".#test-boot", "--", "--evidence", "/tmp/live.json"]})[gate]
        artifact = root / f"{gate}.json"
        artifact.write_text('{"outcome":"passed","evidence_origin":"executed"}\n')
        return {"gate": gate, "runner": release.RUNNERS[gate], "result": "pass",
                "attestations": [qualification.execute(
                    root, release.source_digest(root), argv, artifacts=[artifact],
                    environment={**os.environ, "PATH": f"{root}:{os.environ.get('PATH', '')}"})],
                "live_result": self.live_result(services=gate in release.SERVICE_GATES)}

    def test_structured_live_report_is_accepted(self):
        temporary, root = self.fixture()
        with temporary:
            self.assertEqual(release.validate_gate_report(root, "V-AUTH", self.report(root, "V-AUTH")), [])
            self.assertEqual(release.validate_gate_report(root, "V-BOOT", self.report(root, "V-BOOT")), [])

    def test_skips_missing_services_handwritten_and_stale_evidence_are_rejected(self):
        temporary, root = self.fixture()
        with temporary:
            skipped = self.report(root, "V-AUTH"); skipped["live_result"]["skip_count"] = 1
            absent = self.report(root, "V-BOOT"); absent["live_result"]["services"] = []
            handwritten = self.report(root, "V-AUTH"); handwritten["live_result"]["evidence_origin"] = "handwritten"
            stale = self.report(root, "V-AUTH"); stale["attestations"][0]["source_tree_sha256"] = "sha256:" + "0" * 64
            failed = self.report(root, "V-AUTH"); failed["attestations"][0]["exit_status"] = 1
            for index, report in enumerate((skipped, absent, handwritten, stale, failed)):
                with self.subTest(index=index):
                    self.assertTrue(release.validate_gate_report(root, report["gate"], report))

    def test_compile_or_process_health_alone_is_rejected(self):
        temporary, root = self.fixture()
        with temporary:
            report = self.report(root, "V-AUTH")
            report["live_result"] = {"outcome": "passed", "evidence_origin": "executed",
                                     "assertions": [], "skip_count": 0}
            self.assertTrue(any("behavioral assertions" in error
                                for error in release.validate_gate_report(root, "V-AUTH", report)))

    def test_all_thirteen_gates_are_required_for_all_fourteen_packets(self):
        contract = __import__("json").loads(
            (ROOT / "contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
        complete = release.packet_results(contract, set(release.RUNNERS))
        self.assertEqual(len(release.RUNNERS), 13)
        self.assertEqual(len(complete), 14)
        self.assertTrue(all(item["result"] == "pass" for item in complete))
        for gate in release.RUNNERS:
            with self.subTest(gate=gate):
                incomplete = release.packet_results(contract, set(release.RUNNERS) - {gate})
                self.assertTrue(any(item["result"] == "fail" for item in incomplete))


if __name__ == "__main__":
    unittest.main()
