import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "requirements_registry", "work_graph", "architecture_projections", "json_schemas",
    "protobuf_descriptors", "language_bindings", "lockfiles", "sbom", "provenance",
    "evidence_indexes", "sha256_manifests",
}


class V2ArtifactClosureTests(unittest.TestCase):
    def test_checked_report_reproduces_every_required_artifact_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact-closure-report.json"
            subprocess.run([
                sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(ROOT),
                "--output", str(output),
            ], cwd=ROOT, check=True)
            generated = json.loads(output.read_text())
        checked = json.loads((ROOT / "evidence/v2-rebuild/artifact-closure-report.json").read_text())
        self.assertEqual(generated, checked)
        self.assertTrue(generated["valid"])
        self.assertEqual(set(generated["artifact_classes"]), REQUIRED)
        self.assertEqual(generated["stale_generated"], [])
        self.assertEqual(generated["unowned_dependencies"], [])
        self.assertEqual(generated["deleted_closure_members"], [])
        sbom = json.loads((ROOT / "generated/v2/sbom.json").read_text())
        locked = {item["name"] for item in sbom["packages"]}
        owned = {item["dependency"] for item in sbom["dependency_ownership"]}
        self.assertEqual(locked, owned)

    def test_mutating_any_generated_class_is_rejected(self):
        representatives = [
            "contracts/requirements.yaml", "contracts/work-packets.yaml",
            "contracts/architecture/00-GOVERNANCE.md", "contracts/schemas/v2-canonical.schema.json",
            "generated/proto/descriptor.bin", "generated/proto/rust/nix_ai/agent/v2/nix_ai.agent.v2.rs", "Cargo.lock",
            "generated/v2/sbom.json", "generated/v2/provenance.json",
            "generated/v2/evidence-index.json", "generated/v2/MANIFEST.sha256",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "tree"
            shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns(".git", "target", "result"))
            for relative in representatives:
                with self.subTest(relative=relative):
                    path = clone / relative; original = path.read_bytes(); path.write_bytes(original + b"\n")
                    result = subprocess.run([
                        sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(clone),
                    ], cwd=clone, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, relative)
                    path.write_bytes(original)

    def test_nix_closure_report_rejects_deleted_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            closure = Path(temporary) / "store-paths"
            closure.write_text("/nix/store/abc-habitat-models-0.1.0\n/nix/store/def-serde-1.0.0\n")
            output = Path(temporary) / "report.json"
            subprocess.run([sys.executable, "tools/verify_v2_build_closure.py", "--closure-paths", str(closure),
                            "--output", str(output)], cwd=ROOT, check=True)
            self.assertTrue(json.loads(output.read_text())["valid"])
            closure.write_text(closure.read_text() + "/nix/store/ghi-habitat-physical-0.1.0\n")
            result = subprocess.run([sys.executable, "tools/verify_v2_build_closure.py", "--closure-paths", str(closure),
                                     "--output", str(output)], cwd=ROOT)
            self.assertNotEqual(result.returncode, 0)

    def test_removed_semantics_cannot_be_resigned_into_generated_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "tree"
            shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns(".git", "target", "result"))
            binding = clone / "generated/proto/rust/nix_ai/agent/v2/nix_ai.agent.v2.rs"
            binding.write_text(binding.read_text() + "\npub const ROBOT_ARM: bool = true;\n")
            subprocess.run([sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(clone), "--write"],
                           cwd=clone, capture_output=True, text=True)
            result = subprocess.run([sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(clone)],
                                    cwd=clone, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_clean_cargo_lock_regeneration_is_byte_identical(self):
        cargo = shutil.which("cargo")
        if not cargo:
            self.skipTest("cargo is not available")
        version = subprocess.run([cargo, "--version"], capture_output=True, text=True, check=True).stdout
        minor = int(version.split()[1].split(".")[1])
        if minor < 78:
            self.skipTest("host Cargo cannot produce lockfile v4; pinned Nix suite exercises this seam")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            subprocess.run([sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(ROOT),
                            "--verify-cargo", cargo, "--output", str(output)], cwd=ROOT, check=True)

    def test_clean_flake_lock_regeneration_is_byte_identical(self):
        nix = shutil.which("nix")
        if not nix:
            self.skipTest("nix is not available")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            subprocess.run([sys.executable, "tools/qualify_v2_artifacts.py", "--root", str(ROOT),
                            "--verify-nix", nix, "--output", str(output)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
