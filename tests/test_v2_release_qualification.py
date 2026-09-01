import os
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import qualification  # noqa: E402
import qualify_v2_release as release  # noqa: E402


class QualificationPrimitiveTests(unittest.TestCase):
    def test_release_uses_the_canonical_source_identity_implementation(self):
        self.assertIs(release.source_digest, qualification.source_digest)

    def test_canonical_json_is_sorted_and_stable(self):
        self.assertEqual(qualification.canonical_json({"z": 1, "a": 2}), b'{\n  "a": 2,\n  "z": 1\n}\n')

    def test_source_identity_ignores_local_tool_environments_without_git_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.py").write_text("value = 1\n")
            expected = qualification.source_digest(root)
            for directory in (".venv", ".pytest_cache", "graphify-out"):
                path = root / directory / "local-state"
                path.parent.mkdir(parents=True)
                path.write_text("host-local\n")
            self.assertEqual(qualification.source_digest(root), expected)

    def test_execution_attestation_binds_every_required_dimension(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("cargo")
            (root / "flake.lock").write_text("flake")
            artifact = root / "result.json"
            artifact.write_text('{"outcome":"passed"}\n')
            source = "sha256:" + "1" * 64
            record = qualification.execute(
                root, source, [sys.executable, "-c", "print('live')"],
                action="behavioral-test", artifacts=[artifact]
            )
            self.assertEqual(qualification.validate_attestation(
                record, source_tree=source, closure=qualification.closure_digest(root)), [])
            self.assertEqual(record["exit_status"], 0)
            self.assertEqual(record["stdout_sha256"], qualification.digest_bytes(b"live\n"))
            self.assertEqual(record["artifact_digests"][0]["sha256"], qualification.digest_file(artifact))
            self.assertTrue(record["realized_closure"])
            self.assertEqual(record["declared_input_closure_sha256"],
                             qualification.closure_digest(root))
            self.assertNotEqual(record["built_closure_sha256"],
                                record["declared_input_closure_sha256"])
            for field in (
                "source_tree_sha256", "built_closure_sha256", "argv", "exit_status",
                "action",
                "started_at", "finished_at", "stdout_sha256", "stderr_sha256",
                "artifact_digests", "runner_identity",
            ):
                self.assertIn(field, record)

    def test_failed_command_attests_failure_without_requiring_uncreated_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("cargo")
            (root / "flake.lock").write_text("flake")
            record = qualification.execute(
                root, "sha256:" + "1" * 64,
                [sys.executable, "-c", "raise SystemExit(7)"],
                action="expected-failure", artifacts=[root / "never-created.json"])
            self.assertEqual(record["exit_status"], 7)
            self.assertEqual(record["artifact_digests"], [])

    def test_tampered_or_incomplete_attestations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("cargo")
            (root / "flake.lock").write_text("flake")
            source = "sha256:" + "2" * 64
            original = qualification.execute(
                root, source, [sys.executable, "-c", "pass"], action="behavioral-test"
            )
            for field, value in (
                ("source_tree_sha256", "sha256:" + "0" * 64),
                ("built_closure_sha256", "sha256:" + "0" * 64),
                ("exit_status", "0"), ("runner_identity", {}),
                ("artifact_digests", [{"path": "x"}]),
                ("action", ""),
            ):
                with self.subTest(field=field):
                    changed = dict(original); changed[field] = value
                    self.assertTrue(qualification.validate_attestation(
                        changed, source_tree=source, closure=qualification.closure_digest(root)))

    def test_evidence_store_is_immutable_and_recomputes_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = qualification.EvidenceByteStore(Path(temporary))
            record = store.put(b"canonical evidence")
            self.assertEqual(store.read(record["sha256"]), b"canonical evidence")
            Path(record["path"]).chmod(0o644)
            Path(record["path"]).write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                store.read(record["sha256"])

    def test_supporting_evidence_must_stay_beneath_evidence_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            outside = evidence.parent / "outside-evidence.json"
            outside.write_text("{}")
            with self.assertRaises(ValueError):
                qualification.validate_supporting_evidence(
                    evidence, [{"path": "../outside-evidence.json",
                                "sha256": qualification.digest_file(outside)}])


class ReleaseVerifierTests(unittest.TestCase):
    def test_live_release_wrapper_uses_git_workspace_root(self):
        flake = (ROOT / "flake.nix").read_text()

        self.assertIn('qualify_v2_release.py} --root "$PWD" --run', flake)

    def test_gate_identity_comes_from_attested_action_not_argv(self):
        temporary, root = self.fixture()
        with temporary:
            report = self.report(root, "V-AUTH")
            report["attestations"][0]["argv"] = ["completely", "different", "launcher"]
            self.assertEqual(release.validate_gate_report(root, "V-AUTH", report), [])
            report["attestations"][0]["action"] = "V-BOOT"
            self.assertTrue(release.validate_gate_report(root, "V-AUTH", report))

    def test_packet_normalization_prefers_canonical_qualification_result(self):
        from tools.qualification import validate_structured_result

        packet = {
            "outcome": "passed",
            "qualification_result": self.live_result(services=True),
        }
        self.assertEqual(
            validate_structured_result(packet["qualification_result"], require_services=True),
            [],
        )

    def test_named_packet_gate_result_is_normalized_without_gate_switch(self):
        emitted = {"gate_results": {"V-AUTH": {
            "qualification_result": self.live_result(),
            "metrics": dict(release.METRIC_PREDICATES["V-AUTH"]),
            "deployed_dependencies": ["authority-library"],
        }}}
        self.assertEqual(release.emitted_gate_result(emitted, "V-AUTH")["metrics"],
                         release.METRIC_PREDICATES["V-AUTH"])

    def live_result(self, *, services=False):
        value = {"outcome": "passed", "evidence_origin": "executed", "skip_count": 0,
                 "assertions": [{"name": "behavior observed", "passed": True,
                                 "observation_id":"observation:" + "1" * 64}]}
        if services:
            service = {"schema_version":"1.0", "kind":"service_readiness",
                "name": "runtime", "state": "ready", "result": "ready",
                "endpoint": "/run/runtime.sock", "observed_at": "2026-01-01T00:00:00Z",
                "action_observation_id": "observation:" + "2" * 64,
                "unit": "runtime.service", "process_id": 123, "health": "ready",
                "identity": {"uid": 1, "gid": 1}}
            payload={key:service[key] for key in ("schema_version","kind","name","unit",
                "endpoint","process_id","health","action_observation_id")}
            service["probe_observation_id"]="observation:"+hashlib.sha256(
                qualification.canonical_json(payload)).hexdigest()
            value["services"] = [service]
        return value

    def test_captured_stdout_and_artifact_bytes_are_recomputed(self):
        temporary, root = self.fixture()
        with temporary:
            artifact = root / "artifact.json"; artifact.write_text('{"observed":true}\n')
            record = qualification.execute(root, qualification.source_digest(root),
                [sys.executable, "-c", "print('captured')"], action="capture",
                artifacts=[artifact])
            record["captured_outputs"]["stdout"]["content"] = "Zm9yZ2Vk"
            self.assertTrue(any("captured stdout" in error for error in
                qualification.validate_attestation(record, source_tree=qualification.source_digest(root),
                                                   closure=qualification.closure_digest(root))))

    def test_large_artifacts_are_digest_attested_without_unbounded_inline_bytes(self):
        temporary, root = self.fixture()
        with temporary:
            artifact = root / "disk.img"
            artifact.write_bytes(b"x" * (qualification.MAX_INLINE_ARTIFACT_BYTES + 1))
            record = qualification.execute(
                root, qualification.source_digest(root),
                [sys.executable, "-c", "pass"], action="large-artifact",
                artifacts=[artifact])
            capture = record["captured_outputs"]["artifacts"][0]
            self.assertEqual(capture["encoding"], "digest-only")
            self.assertNotIn("content", capture)
            self.assertEqual(capture["sha256"], qualification.digest_file(artifact))
            self.assertEqual(qualification.validate_attestation(
                record, source_tree=qualification.source_digest(root),
                closure=qualification.closure_digest(root)), [])

    def test_action_observation_is_canonically_bound_to_captured_outputs(self):
        temporary, root = self.fixture()
        with temporary:
            artifact = root / "artifact.json"; artifact.write_text('{"observed":true}\n')
            record = qualification.execute(root, qualification.source_digest(root),
                [sys.executable, "-c", "print('captured')"], action="capture",
                artifacts=[artifact])
            record["action_observation"]["output_ids"] = ["sha256:" + "0" * 64]
            errors = qualification.validate_attestation(
                record, source_tree=qualification.source_digest(root),
                closure=qualification.closure_digest(root))
            self.assertTrue(any("action observation" in error for error in errors))

    def test_source_digest_includes_admissible_untracked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            __import__("subprocess").run(["git", "init", "-q"], cwd=root, check=True)
            tracked = root / "tracked"; tracked.write_text("a")
            __import__("subprocess").run(["git", "add", "tracked"], cwd=root, check=True)
            before = qualification.source_digest(root)
            (root / "untracked").write_text("b")
            self.assertNotEqual(before, qualification.source_digest(root))

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
        observations = {}; derivations = {}
        for name, expected in release.METRIC_PREDICATES[gate].items():
            payload = {"schema_version":"1.0", "kind":"metric_observation",
                       "metric":name, "value":expected, "subject":gate,
                       "provenance":{"fixture":"executed"}}
            observation_id = "observation:" + hashlib.sha256(
                qualification.canonical_json(payload)).hexdigest()
            observations[observation_id] = {**payload, "observation_id":observation_id}
            derivations[name] = {"metric":name, "operation":"value",
                                 "observation_ids":[observation_id]}
        return {"gate": gate, "runner": release.RUNNERS[gate], "result": "pass",
                "deployed_dependencies": ["runtime"],
                "metrics": dict(release.METRIC_PREDICATES[gate]),
                "metric_evidence": derivations, "metric_observations": observations,
                "attestations": [qualification.execute(
                    root, release.source_digest(root), argv, action=gate, artifacts=[artifact],
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
            absent = self.live_result(services=True); absent["services"] = []
            handwritten = self.report(root, "V-AUTH"); handwritten["live_result"]["evidence_origin"] = "handwritten"
            stale = self.report(root, "V-AUTH"); stale["attestations"][0]["source_tree_sha256"] = "sha256:" + "0" * 64
            failed = self.report(root, "V-AUTH"); failed["attestations"][0]["exit_status"] = 1
            self.assertTrue(qualification.validate_structured_result(absent, require_services=True))
            for index, report in enumerate((skipped, handwritten, stale, failed)):
                with self.subTest(index=index):
                    self.assertTrue(release.validate_gate_report(root, report["gate"], report))

    def test_missing_deployed_dependency_observation_fails_closed(self):
        temporary, root = self.fixture()
        with temporary:
            report = self.report(root, "V-AUTH")
            report["deployed_dependencies"] = []
            self.assertTrue(any("deployment" in error for error in
                                release.validate_gate_report(root, "V-AUTH", report)))

    def test_compile_or_process_health_alone_is_rejected(self):
        temporary, root = self.fixture()
        with temporary:
            report = self.report(root, "V-AUTH")
            report["live_result"] = {"outcome": "passed", "evidence_origin": "executed",
                                     "assertions": [], "skip_count": 0}
            self.assertTrue(any("behavioral assertions" in error
                                for error in release.validate_gate_report(root, "V-AUTH", report)))

    def test_metrics_must_be_emitted_by_the_gate_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                release.derived_metrics("V-AUTH", {"observations": {}}, Path(temporary))

    def test_combined_packet_derivations_remain_metric_specific(self):
        observations = {}
        derivations = {}
        for name in release.METRIC_PREDICATES["V-CONTRACT"]:
            observation = qualification.make_metric_observation(
                name, 0, subject="V-CONTRACT",
                action_observation_id="observation:" + "1" * 64,
                artifact_ids=["sha256:" + "2" * 64])
            observations[observation["observation_id"]] = observation
            derivations[name] = {"metric": name, "operation": "sum_values",
                                 "observation_ids": [observation["observation_id"]]}
        packet = {"gate_results": {"V-CONTRACT": {
            "qualification_result": {"outcome": "passed", "evidence_origin": "executed",
              "skip_count": 0, "assertions": [{"name": "contract", "passed": True,
              "observation_id": "assertion:" + "2" * 64}]},
            "metrics": {name: 0 for name in release.METRIC_PREDICATES["V-CONTRACT"]},
            "metric_derivations": derivations,
            "observations": observations,
            "deployed_dependencies": []}}}
        combined = release.emitted_gate_result(
            release.combine_packet_results([packet], "V-CONTRACT"), "V-CONTRACT")
        self.assertTrue(all(derivation["metric"] == name for name, derivation in
                            combined["metric_derivations"].items()))

    def test_metric_derivation_tampering_is_rejected(self):
        temporary, root = self.fixture()
        with temporary:
            report = self.report(root, "V-AUTH")
            report["metrics"]["unauthorized_action_count"] = 1
            self.assertTrue(any("metric derivation" in error for error in
                                release.validate_gate_report(root, "V-AUTH", report)))

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

    def test_v_change_runs_deployed_roles_and_contract_mutation_attack(self):
        source = (ROOT / "tools/qualify_v2_change.py").read_text()
        self.assertIn("path:.#test-change-live", source)
        self.assertIn("contracts/v2.0.1/validate_contract.py", source)
        self.assertNotIn("HABITAT_STATE_SOCKET", source)
        role = (ROOT / "src/habitat_state/change_role.py").read_text()
        for authority in ("controller", "evaluator", "signer", "health"):
            self.assertIn(f'"{authority}"', role)


if __name__ == "__main__":
    unittest.main()
