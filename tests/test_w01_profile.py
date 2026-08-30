import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


class W01ProfileTests(unittest.TestCase):
    def test_qemu_profile_is_schema_valid_and_truthfully_declares_absent_features(self):
        profile = json.loads((ROOT / "nix/profiles/qemu-x86_64-conformance.json").read_text())
        schema = json.loads((ROOT / "contracts/schemas/hardware-profile.schema.json").read_text())

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["profile_id"], "qemu-x86-64-conformance")
        self.assertEqual(profile["trust_root"], "SOFTWARE_DEGRADED")
        self.assertEqual(profile["gpu"]["status"], "absent")
        self.assertEqual(profile["devices"], [])


if __name__ == "__main__":
    unittest.main()
