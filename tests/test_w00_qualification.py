import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class W00QualificationTests(unittest.TestCase):
    def test_packet_evidence_is_bound_to_a_real_source_tree(self):
        for forged_commit, forged_tree in (
            ("0" * 40, None),
            (None, "sha256:" + "0" * 64),
        ):
            with self.subTest(forged_commit=forged_commit, forged_tree=forged_tree), tempfile.TemporaryDirectory() as temporary:
                fixture = Path(temporary)
                evidence = fixture / "evidence" / "work-packets" / "W00"
                evidence.mkdir(parents=True)
                for source in (ROOT / "evidence" / "work-packets" / "W00").iterdir():
                    (evidence / source.name).write_bytes(source.read_bytes())
                (fixture / "flake.lock").write_bytes((ROOT / "flake.lock").read_bytes())
                packet = json.loads((evidence / "result.json").read_text())
                provenance = json.loads((evidence / "provenance.json").read_text())
                if forged_commit is not None:
                    packet["source_commit"] = forged_commit
                    provenance["source_commit"] = forged_commit
                    for name in ("contract-validation-report", "generation-no-diff-report"):
                        path = evidence / f"{name}.json"
                        report = json.loads(path.read_text())
                        report["source_commit"] = forged_commit
                        path.write_text(json.dumps(report))
                if forged_tree is not None:
                    provenance["source_tree_digest"] = forged_tree
                (evidence / "provenance.json").write_text(json.dumps(provenance))
                for name in ("contract-validation-report", "generation-no-diff-report", "provenance", "sbom"):
                    packet["evidence_digests"][name] = "sha256:" + hashlib.sha256(
                        (evidence / f"{name}.json").read_bytes()
                    ).hexdigest()
                (evidence / "result.json").write_text(json.dumps(packet))

                result = subprocess.run(
                    [sys.executable, str(ROOT / "tools" / "qualify_w00.py"),
                     str(fixture), "--verify-evidence"],
                    text=True, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_checked_in_packet_evidence_is_complete_and_self_consistent(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "qualify_w00.py"),
                str(ROOT),
                "--verify-evidence",
            ],
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        packet = json.loads(
            (ROOT / "evidence" / "work-packets" / "W00" / "result.json").read_text()
        )
        self.assertEqual(packet["packet_id"], "W00")
        self.assertEqual(packet["status"], "passed")
        self.assertTrue(
            {"contract-validation-report", "generation-no-diff-report"}
            <= set(packet["evidence_digests"])
        )

    def test_contradictory_packet_evidence_is_rejected(self):
        mutations = {
            "source_lock_digest": "sha256:" + "0" * 64,
            "blockers": ["unresolved"],
            "skipped_gates": [{"gate": "V-CONTRACT", "reason": "skipped"}],
            "requirement_coverage": [],
        }
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = Path(temporary)
                (fixture / "evidence" / "work-packets").mkdir(parents=True)
                (fixture / "evidence" / "work-packets" / "W00").symlink_to(
                    ROOT / "evidence" / "work-packets" / "W00", target_is_directory=True
                )
                (fixture / "flake.lock").write_bytes((ROOT / "flake.lock").read_bytes())
                packet = json.loads(
                    (ROOT / "evidence" / "work-packets" / "W00" / "result.json").read_text()
                )
                packet[field] = value
                copied = fixture / "evidence-copy"
                copied.mkdir()
                for source in (ROOT / "evidence" / "work-packets" / "W00").iterdir():
                    (copied / source.name).write_bytes(source.read_bytes())
                (copied / "result.json").write_text(json.dumps(packet))
                (fixture / "evidence" / "work-packets" / "W00").unlink()
                copied.rename(fixture / "evidence" / "work-packets" / "W00")

                result = subprocess.run(
                    [sys.executable, str(ROOT / "tools" / "qualify_w00.py"),
                     str(fixture), "--verify-evidence"],
                    text=True, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
