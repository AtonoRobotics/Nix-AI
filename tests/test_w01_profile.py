import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from tools.test_w01 import decode_event_line


ROOT = Path(__file__).resolve().parents[1]


class W01ProfileTests(unittest.TestCase):
    def test_qemu_event_parser_accepts_systemd_console_prefix(self):
        event = decode_event_line(
            '[   36.1] python[862]: {"event":"habitat.runtime","outcome":"passed"}'
        )

        self.assertEqual(event["event"], "habitat.runtime")
        self.assertIsNone(decode_event_line("Started Habitat runtime service."))

    def test_shared_state_root_is_traversable_but_not_listable(self):
        image_module = (ROOT / "nix/modules/habitat-image.nix").read_text()
        runtime_module = (ROOT / "nix/modules/habitat-runtime.nix").read_text()

        self.assertIn('"d /var/lib/habitat 0711 root root -"', image_module)
        self.assertIn('StateDirectoryMode = "0700"', runtime_module)

    def test_state_service_admits_every_runtime_state_client(self):
        runtime_module = (ROOT / "nix/modules/habitat-runtime.nix").read_text()

        for principal in ("abi", "scheduler", "authority", "effects", "runtime"):
            self.assertIn(
                f'id -u habitat-{principal})"',
                runtime_module,
                f"state allowlist omits habitat-{principal}",
            )

    def test_qemu_conformance_uses_systemd_credential_directory(self):
        flake = (ROOT / "flake.nix").read_text()

        self.assertIn('os.environ["CREDENTIALS_DIRECTORY"]', flake)
        self.assertNotIn("/run/credentials/habitat-runtime-conformance/", flake)

    def test_runtime_credentials_are_machine_persistent_across_generations(self):
        flake = (ROOT / "flake.nix").read_text()

        self.assertIn("/var/lib/habitat/credentials", flake)
        self.assertIn('if [ ! -s "$token_file" ]', flake)
        self.assertIn('token="$(cat "$token_file")"', flake)

    def test_bootstrap_evidence_uses_systemd_console_routing(self):
        image_module = (ROOT / "nix/modules/habitat-image.nix").read_text()
        bootstrap = image_module.split(
            "systemd.services.habitat-stage-candidate", maxsplit=1
        )[0]

        self.assertNotIn('> /dev/ttyS0', bootstrap)
        self.assertIn('StandardOutput = "journal+console"', bootstrap)

    def test_qemu_profile_is_schema_valid_and_truthfully_declares_absent_features(self):
        profile = json.loads((ROOT / "nix/profiles/qemu-x86_64-conformance.json").read_text())
        schema = json.loads((ROOT / "contracts/schemas/hardware-profile.schema.json").read_text())

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["profile_id"], "qemu-x86_64-conformance")
        self.assertRegex(profile["firmware"]["digest"],r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(profile["drivers"]["digest"],r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(profile["isolation"]["default"],"DENY")
        self.assertTrue(profile["isolation"]["enforcement"])
        invalid=dict(profile);invalid.pop("gpu");invalid.pop("devices");invalid["capacity"]={"banana":True}
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(invalid)))
        self.assertEqual(profile["trust_root"], "SOFTWARE_DEGRADED")
        self.assertEqual(profile["gpu"]["status"], "absent")
        self.assertEqual(profile["devices"], [])


if __name__ == "__main__":
    unittest.main()
