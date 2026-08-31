import tempfile
import unittest
from pathlib import Path

from tools.verify_v2_drift import find_drift


class DriftVerifierTests(unittest.TestCase):
    def fixture(self, release="", qualification="", w00="def source_tree_digest():\n git ls-tree show", packet=""):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        (root / "tools").mkdir(); (root / "crates/habitat-packages/src").mkdir(parents=True)
        (root / "tools/qualify_v2_release.py").write_text(release)
        (root / "tools/qualification.py").write_text(qualification)
        (root / "tools/qualify_w00.py").write_text(w00)
        (root / "tools/qualify_w02.py").write_text(packet)
        (root / "crates/habitat-packages/src/main.rs").write_text("qualify-change")
        return temporary, root

    def test_clean_declarative_shape_is_accepted(self):
        temporary, root = self.fixture("GATES = definitions\n")
        with temporary: self.assertEqual(find_drift(root), [])

    def test_architectural_regressions_are_rejected(self):
        cases = [
            {"release": "def _runner_identity(argv): return argv[1]"},
            {"release": "if gate == 'V-AUTH': pass"},
            {"release": "def canonical_json(x): return json.dumps(x)"},
            {"release": "structured_result('tests passed')"},
            {"packet": "MINIO_IMAGE = 'minio:latest'"},
            {"packet": "fake_result = {'outcome': 'passed'}"},
            {"w00": "source_commit = 'whatever'"},
            {"release": "placeholder = True"},
        ]
        for values in cases:
            with self.subTest(values=values):
                temporary, root = self.fixture(**values)
                with temporary: self.assertTrue(find_drift(root))


if __name__ == "__main__": unittest.main()
