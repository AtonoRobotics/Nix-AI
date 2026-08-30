import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class V2CoreAuditTests(unittest.TestCase):
    def run_audit(self,root,output):
        return subprocess.run([sys.executable,str(root/"tools/audit_v2_core.py"),"--root",str(root),"--output",str(output)],capture_output=True,text=True)

    def test_checked_audit_is_exhaustive_mapped_and_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            generated=json.loads(output.read_text());checked=json.loads((ROOT/"evidence/v2-rebuild/core-retention-audit.json").read_text())
            self.assertEqual(generated,checked);self.assertTrue(generated["valid"])
            self.assertEqual(generated["unresolved_candidates"],[]);self.assertEqual(generated["untrusted_candidates"],[])
            self.assertEqual(generated["adapter_direct_path_count"],0)
            self.assertTrue(all(item["requirement_ids"] and item["authority"] for item in generated["records"]))
            for kind in ("public_interface","branch","dependency","test","fixture"): self.assertGreater(generated["counts"][kind],0)

    def test_new_adapter_credential_path_fails_closed(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        try:
            source.write_text(original+"\npub struct CredentialBroker;\n")
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("forbidden-adapter-path",result.stdout)
        finally: source.write_text(original)

    def test_unmapped_fixture_fails_closed(self):
        fixture=ROOT/"tests/fixtures/unmapped/new.fixture";fixture.parent.mkdir(parents=True,exist_ok=True);fixture.write_text("opaque")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
        finally:
            fixture.unlink();fixture.parent.rmdir()

    def test_undeclared_dependency_fails_closed(self):
        manifest=ROOT/"crates/habitat-models/Cargo.toml";original=manifest.read_text()
        try:
            manifest.write_text(original.replace("[dependencies]\n","[dependencies]\nambient-network-client = \"1\"\n"))
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("untrusted-dependency",result.stdout)
        finally:manifest.write_text(original)

    def test_retained_core_evidence_is_backed_by_executed_suites(self):
        expected={"W07/context-conformance-suite.json":6,"W09/structured-disposition-test.json":6,
            "W10/package-lifecycle-suite.json":4,"W11/cross-backend-conformance-report.json":5}
        for relative,count in expected.items():
            report=json.loads((ROOT/"evidence/work-packets"/relative).read_text())
            proof=report["behavioral_test_proof"]
            self.assertEqual(proof["runner"],"rust-test-binaries")
            self.assertEqual(proof["outcome"],"passed")
            self.assertEqual(proof["test_count"],count)
            self.assertEqual(len(proof["test_names"]),count)

if __name__=="__main__":unittest.main()
