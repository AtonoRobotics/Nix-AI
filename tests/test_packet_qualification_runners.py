import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from qualify_w_common import PacketRun, run_test_directory, strict_unittest_argv  # noqa: E402
from qualification import validate_attestation, validate_structured_result  # noqa: E402


class PacketRunnerTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "Cargo.lock").write_text("cargo", encoding="utf-8")
        (root / "flake.lock").write_text("flake", encoding="utf-8")
        artifact = root / "artifact"
        artifact.write_text("artifact", encoding="utf-8")
        return temporary, root, artifact

    def test_executed_packet_result_is_structured_and_attested(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            run.command(
                [sys.executable, "-c", "print('behavior observed')"],
                artifacts=[artifact], assertion="behavior is observed",
            )
            run.ready_service("runtime")
            result = run.result({"live": {"outcome": "passed"}})
            self.assertEqual(validate_structured_result(
                result["qualification_result"], require_services=True), [])
            self.assertEqual(validate_attestation(
                result["execution"][0], source_tree=run.source_tree,
                closure=result["execution"][0]["built_closure_sha256"]), [])
            self.assertEqual(result["artifact_digests"], result["execution"][0]["artifact_digests"])

    def test_test_directory_executes_binaries_without_listing_names(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            test_dir = root / "tests"; test_dir.mkdir()
            binary = test_dir / "behavior"
            binary.write_text("#!/bin/sh\ntest \"$#\" -eq 0\n", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            run = PacketRun("W99", root)
            self.assertEqual(run_test_directory(run, test_dir, artifact, "sample"), 1)
            self.assertEqual(run.attestations[0]["argv"], [str(binary)])


class PacketRunnerAdversarialTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        (root / "Cargo.lock").write_text("cargo"); (root / "flake.lock").write_text("flake")
        artifact = root / "artifact"; artifact.write_text("artifact")
        return temporary, root, artifact

    def test_failed_command_is_never_reported_as_passed(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            with self.assertRaises(SystemExit):
                run.command([sys.executable, "-c", "raise SystemExit(7)"],
                            artifacts=[artifact], assertion="must fail")
            self.assertEqual(run.attestations[0]["exit_status"], 7)
            self.assertFalse(run.assertions[0]["passed"])

    def test_missing_artifact_and_absent_binaries_fail_closed(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            with self.assertRaises(ValueError):
                run.command([sys.executable, "-c", "pass"], artifacts=[root / "missing"], assertion="x")
            empty = root / "empty"; empty.mkdir()
            with self.assertRaises(SystemExit):
                run_test_directory(run, empty, artifact, "sample")

    def test_no_execution_cannot_create_pass_result(self):
        temporary, root, _ = self.fixture()
        with temporary:
            with self.assertRaises(SystemExit):
                PacketRun("W99", root).result({})

    def test_validator_rejects_skips_absent_services_and_failed_assertions(self):
        base = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
                "assertions": [{"name": "live", "passed": True}],
                "services": [{"name": "runtime", "state": "ready"}]}
        mutations = [
            {**base, "skip_count": 1},
            {**base, "services": []},
            {**base, "assertions": [{"name": "live", "passed": False}]},
            {**base, "evidence_origin": "handwritten"},
        ]
        for value in mutations:
            with self.subTest(value=value):
                self.assertTrue(validate_structured_result(value, require_services=True))

    def test_strict_unittest_wrapper_turns_a_skip_into_failure(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            module = root / "test_skip.py"
            module.write_text("import unittest\nclass T(unittest.TestCase):\n @unittest.skip('absent service')\n def test_live(self): pass\n")
            run = PacketRun("W99", root)
            environment = {**os.environ, "PYTHONPATH": str(root)}
            with self.assertRaises(SystemExit):
                run.command(strict_unittest_argv("test_skip"), artifacts=[artifact],
                            environment=environment, assertion="no skips")


if __name__ == "__main__":
    unittest.main()
