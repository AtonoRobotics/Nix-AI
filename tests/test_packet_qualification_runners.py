import json
import os
import stat
from unittest import mock
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from qualify_w_common import PacketRun, run_test_directory, strict_unittest_argv  # noqa: E402
from qualification import (derive_metric, make_metric_observation, validate_attestation,
                           validate_structured_result)  # noqa: E402


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
                action="behavioral-test", artifacts=[artifact], assertion="behavior is observed",
            )
            endpoint = str(root / "runtime.sock")
            with mock.patch("qualify_w_common.socket.socket"):
                run.ready_service("runtime", unit="runtime.service", endpoint="unix:" + endpoint,
                                  process_id=os.getpid(), health="ready")
            run.observe_metric("V-SAMPLE", "failure_count", 0,
                               semantic_evidence={"kind":"failure_scan", "observed":[]})
            result = run.result({"live": {"outcome": "passed"}}, gate_results={
                "V-SAMPLE": {"metrics": {"failure_count": 0},
                             "deployed_dependencies": ["runtime"]}
            })
            self.assertEqual(validate_structured_result(
                result["qualification_result"], require_services=True), [])
            self.assertEqual(validate_attestation(
                result["execution"][0], source_tree=run.source_tree,
                closure=result["execution"][0]["built_closure_sha256"]), [])
            self.assertEqual(result["artifact_digests"], result["execution"][0]["artifact_digests"])
            self.assertEqual(result["gate_results"]["V-SAMPLE"]["metrics"], {"failure_count": 0})

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
            self.assertEqual(run.attestations[0]["action"], "sample:behavior")


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
                            action="failure-probe", artifacts=[artifact], assertion="must fail")
            self.assertEqual(run.attestations[0]["exit_status"], 7)
            self.assertFalse(run.assertions[0]["passed"])

    def test_missing_artifact_and_absent_binaries_fail_closed(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            with self.assertRaises(ValueError):
                run.command([sys.executable, "-c", "pass"], action="artifact-probe",
                            artifacts=[root / "missing"], assertion="x")
            empty = root / "empty"; empty.mkdir()
            with self.assertRaises(SystemExit):
                run_test_directory(run, empty, artifact, "sample")

    def test_no_execution_cannot_create_pass_result(self):
        temporary, root, _ = self.fixture()
        with temporary:
            with self.assertRaises(SystemExit):
                PacketRun("W99", root).result({})

    def test_process_only_readiness_is_rejected(self):
        temporary, root, _ = self.fixture()
        with temporary:
            with self.assertRaises(ValueError):
                PacketRun("W99", root).ready_service("runtime")

    def test_readiness_requires_service_unit_endpoint_process_and_health(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            run.command([sys.executable, "-c", "print('probe')"], action="service:probe",
                        artifacts=[artifact], assertion="probe executed")
            for kwargs in ({"unit": "runtime.service", "endpoint": "/run/runtime.sock",
                            "process_id": 0, "health": "ready"},
                           {"unit": "", "endpoint": "/run/runtime.sock",
                            "process_id": 1, "health": "ready"}):
                with self.assertRaises(ValueError):
                    run.ready_service("runtime", **kwargs)

    def test_metric_claim_must_equal_independent_observation_derivation(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            run.command([sys.executable, "-c", "print('observed')"], action="probe",
                        artifacts=[artifact], assertion="probe passed")
            with self.assertRaises(SystemExit):
                run.result({}, gate_results={"V-SAMPLE": {
                    "metrics": {"failure_count": 7}, "deployed_dependencies": ["runtime"]}})

    def test_generic_success_cannot_back_a_named_metric(self):
        generic = {"observation:" + "1" * 64: {
            "kind": "behavioral_assertion", "passed": True}}
        with self.assertRaises(ValueError):
            derive_metric({"metric": "failure_count", "operation": "value",
                           "observation_ids": list(generic)}, generic)

    def test_metric_observation_id_binds_value_and_provenance(self):
        observation = make_metric_observation(
            "failure_count", 0, subject="V-SAMPLE",
            action_observation_id="observation:" + "1" * 64,
            artifact_ids=["sha256:" + "2" * 64])
        changed = dict(observation); changed["value"] = 1
        observations = {observation["observation_id"]: changed}
        with self.assertRaises(ValueError):
            derive_metric({"metric": "failure_count", "operation": "value",
                           "observation_ids": list(observations)}, observations)

    def test_metric_requires_typed_semantic_evidence(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            run.command([sys.executable, "-c", "print('probe')"], action="metric:probe",
                        artifacts=[artifact], assertion="metric probe")
            with self.assertRaises(ValueError):
                run.observe_metric("V-SAMPLE", "failure_count", 0,
                                   semantic_evidence={"kind":"failure_scan"})

    def test_validator_rejects_skips_absent_services_and_failed_assertions(self):
        base = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
                "assertions": [{"name": "live", "passed": True,
                                "observation_id":"observation:" + "1" * 64}],
                "services": [{"name": "runtime", "state": "ready"}]}
        mutations = [
            {**base, "skip_count": 1},
            {**base, "services": []},
            {**base, "assertions": [{"name": "live", "passed": False,
                                     "observation_id":"observation:" + "1" * 64}]},
            {**base, "evidence_origin": "handwritten"},
        ]
        for value in mutations:
            with self.subTest(value=value):
                self.assertTrue(validate_structured_result(value, require_services=True))

    def test_validator_rejects_forged_readiness_binding(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            run = PacketRun("W99", root)
            run.command([sys.executable, "-c", "print('probe')"], action="service:probe",
                        artifacts=[artifact], assertion="service probe")
            with mock.patch("qualify_w_common.socket.socket"):
                run.ready_service("runtime", unit="runtime.service", endpoint="unix:/run/runtime.sock",
                                  process_id=os.getpid(), health="ready")
            result = run.result({}, gate_results=None)["qualification_result"]
            result["services"][0]["endpoint"] = "unix:/run/forged.sock"
            self.assertTrue(validate_structured_result(result, require_services=True))

    def test_strict_unittest_wrapper_turns_a_skip_into_failure(self):
        temporary, root, artifact = self.fixture()
        with temporary:
            module = root / "test_skip.py"
            module.write_text("import unittest\nclass T(unittest.TestCase):\n @unittest.skip('absent service')\n def test_live(self): pass\n")
            run = PacketRun("W99", root)
            environment = {**os.environ, "PYTHONPATH": str(root)}
            with self.assertRaises(SystemExit):
                run.command(strict_unittest_argv("test_skip"), artifacts=[artifact],
                            action="strict-unittest", environment=environment, assertion="no skips")


if __name__ == "__main__":
    unittest.main()
