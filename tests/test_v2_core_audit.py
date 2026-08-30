import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class V2CoreAuditTests(unittest.TestCase):
    def run_audit(self, root, output):
        return subprocess.run([sys.executable, str(root / "tools/audit_v2_core.py"), "--root", str(root),
            "--output", str(output)], capture_output=True, text=True)

    def test_checked_ledger_is_bounded_exact_and_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "audit.json"; result = self.run_audit(ROOT, output)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            generated = json.loads(output.read_text())
        checked = json.loads((ROOT / "evidence/v2-rebuild/core-retention-audit.json").read_text())
        self.assertEqual(generated, checked); self.assertTrue(generated["valid"])
        self.assertEqual(generated["scope"], "current-v2-retained-implementation")
        self.assertEqual(generated["unresolved_candidates"], [])
        self.assertIn("no source-language parser", generated["mapping_granularity"])
        self.assertEqual(len({item["source"] for item in generated["records"]}), generated["candidate_file_count"])
        owned_records = [item for item in generated["records"] if item["kind"] != "dependency"]
        source_records = [item for item in owned_records if item["kind"] == "source_unit"]
        self.assertTrue(all(item["action"] == "RETAIN_CURRENT" for item in owned_records))
        self.assertEqual(len({item["identity"] for item in owned_records}), len(owned_records))
        self.assertTrue(any(item["source"].startswith("crates/habitat-runtime/") for item in source_records))
        self.assertTrue(any(item["source"].startswith("contracts/proto/") for item in source_records))
        self.assertTrue(any(item["source"].startswith("nix/modules/") for item in source_records))
        self.assertTrue(all(item.get("verification_tests") for item in source_records))

    def test_every_record_has_exact_bytes_and_explicit_authority(self):
        report = json.loads((ROOT / "evidence/v2-rebuild/core-retention-audit.json").read_text())
        for item in report["records"]:
            self.assertTrue(item["requirement_ids"] and item["authority"] and item["sha256"])
            self.assertEqual(item["review_unit"], "exact-file-bytes")
        self.assertGreater(report["counts"]["source_unit"], 0)
        self.assertGreater(report["counts"]["dependency"], 0)
        self.assertGreater(report["counts"]["test"], 0)
        self.assertGreater(report["counts"]["fixture"], 0)

    def test_new_core_file_is_included_and_invalidates_checked_ledger(self):
        source = ROOT / "crates/habitat-models/src/new_unit.rs"
        try:
            source.write_text("pub struct NewUnit;\n")
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "audit.json"; result = self.run_audit(ROOT, output)
                generated = json.loads(output.read_text())
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue(any(item["source"] == "crates/habitat-models/src/new_unit.rs" for item in generated["records"]))
            self.assertNotEqual(generated, json.loads((ROOT / "evidence/v2-rebuild/core-retention-audit.json").read_text()))
        finally:
            if source.exists(): source.unlink()

    def test_new_unowned_component_fails_closed(self):
        source = ROOT / "crates/habitat-unowned/src/lib.rs"
        try:
            source.parent.mkdir(parents=True)
            source.write_text("pub struct Unowned;\n")
            with tempfile.TemporaryDirectory() as temporary:
                result = self.run_audit(ROOT, Path(temporary) / "audit.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unclassified-current-source:crates/habitat-unowned/src/lib.rs", result.stdout)
        finally:
            if source.exists(): source.unlink()
            if source.parent.exists(): source.parent.rmdir()
            if source.parent.parent.exists(): source.parent.parent.rmdir()

    def test_prohibited_concept_in_current_source_fails_closed(self):
        source = ROOT / "crates/habitat-models/src/forbidden_unit.rs"
        try:
            source.write_text("pub struct OmniverseAdapter;\n")
            with tempfile.TemporaryDirectory() as temporary:
                result = self.run_audit(ROOT, Path(temporary) / "audit.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prohibited-current-concept", result.stdout)
        finally:
            if source.exists(): source.unlink()

    def test_undeclared_and_adapter_dependencies_fail_closed(self):
        manifest = ROOT / "crates/habitat-harnesses/Cargo.toml"; original = manifest.read_text()
        try:
            manifest.write_text(original.replace("[dependencies]\n", "[dependencies]\nhabitat-effects = { path = \"../habitat-effects\" }\n"))
            with tempfile.TemporaryDirectory() as temporary: result = self.run_audit(ROOT, Path(temporary) / "audit.json")
            self.assertNotEqual(result.returncode, 0); self.assertIn("adapter-direct-path", result.stdout)
        finally: manifest.write_text(original)

    def test_target_specific_dependency_is_not_hidden(self):
        manifest = ROOT / "crates/habitat-models/Cargo.toml"; original = manifest.read_text()
        try:
            manifest.write_text(original + "\n[target.'cfg(target_os = \"none\")'.dependencies]\nhidden-edge = \"1\"\n")
            with tempfile.TemporaryDirectory() as temporary: result = self.run_audit(ROOT, Path(temporary) / "audit.json")
            self.assertNotEqual(result.returncode, 0); self.assertIn("untrusted-dependency", result.stdout)
        finally: manifest.write_text(original)

    def test_transcript_state_in_adapter_fails_closed(self):
        source = ROOT / "crates/habitat-models/src/transcript_state.rs"
        try:
            source.write_text("pub struct AuthoritativeTranscript;\n")
            with tempfile.TemporaryDirectory() as temporary: result = self.run_audit(ROOT, Path(temporary) / "audit.json")
            self.assertNotEqual(result.returncode, 0); self.assertIn("authoritative-transcript-surface", result.stdout)
        finally:
            if source.exists(): source.unlink()

    def test_hardware_profile_is_generic_and_explicit(self):
        report = json.loads((ROOT / "evidence/v2-rebuild/core-retention-audit.json").read_text())
        self.assertEqual(report["hardware_profile"]["profile_id"], "qemu-x86_64-conformance")
        self.assertTrue(report["hardware_profile"]["capacity_declared"])
        profile = json.loads((ROOT / "nix/profiles/qemu-x86_64-conformance.json").read_text())
        self.assertEqual(profile["capacity"]["process_limit"], 64)
        self.assertEqual(profile["capacity"]["timeout_seconds"], 300)
        self.assertEqual(report["hardware_profile"]["gpu"], "absent")
        self.assertEqual(report["hardware_profile"]["devices"], [])

    def test_retained_core_evidence_is_live_test_backed(self):
        expected = {"W07/context-conformance-suite.json": 6, "W09/structured-disposition-test.json": 5,
            "W10/package-lifecycle-suite.json": 4, "W11/cross-backend-conformance-report.json": 5}
        for relative, count in expected.items():
            proof = json.loads((ROOT / "evidence/work-packets" / relative).read_text())["behavioral_test_proof"]
            self.assertEqual(proof["runner"], "rust-test-binaries"); self.assertEqual(proof["test_count"], count)

if __name__ == "__main__": unittest.main()
