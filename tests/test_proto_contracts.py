from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.proto_contracts import (
    ProtoContractError,
    create_breaking_fixture,
    source_digest,
    verify_formatted_sources,
    verify_generated,
)


class ProtoContractTests(unittest.TestCase):
    def test_source_digest_is_deterministic_and_inventory_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "b.proto").write_text('syntax = "proto3";\n', encoding="utf-8")
            (root / "a.proto").write_text('syntax = "proto3";\n', encoding="utf-8")
            first = source_digest(root)
            self.assertEqual(first, source_digest(root))
            (root / "a.proto").write_text('syntax = "proto2";\n', encoding="utf-8")
            self.assertNotEqual(first, source_digest(root))

    def test_stale_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected"
            actual = root / "actual"
            expected.mkdir()
            actual.mkdir()
            (expected / "binding.rs").write_text("old", encoding="utf-8")
            (actual / "binding.rs").write_text("new", encoding="utf-8")
            with self.assertRaisesRegex(ProtoContractError, "artifacts are stale"):
                verify_generated(expected, actual)

    def test_stale_inventory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected"
            actual = root / "actual"
            expected.mkdir()
            actual.mkdir()
            (actual / "binding.rs").write_text("new", encoding="utf-8")
            with self.assertRaisesRegex(ProtoContractError, "inventory is stale"):
                verify_generated(expected, actual)

    def test_known_governing_eof_newline_is_the_only_format_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            formatted = root / "formatted"
            source.mkdir()
            formatted.mkdir()
            (source / "contract.proto").write_bytes(b'syntax = "proto3";\n\n')
            (formatted / "contract.proto").write_bytes(b'syntax = "proto3";\n')
            verify_formatted_sources(source, formatted)

            (source / "contract.proto").write_bytes(b'syntax="proto3";\n')
            with self.assertRaisesRegex(ProtoContractError, "not canonically formatted"):
                verify_formatted_sources(source, formatted)

    def test_breaking_fixture_changes_only_the_named_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            candidate = root / "candidate"
            source.mkdir()
            agent = 'message ActivationEnvelope {\n  string activation_id = 2;\n}\n'
            (source / "habitat_agent_v1.proto").write_text(agent, encoding="utf-8")
            (source / "habitat_agent_v1.proto").chmod(0o444)
            (source / "authority.proto").write_text('syntax = "proto3";\n', encoding="utf-8")
            fixture = root / "remove.field"
            fixture.write_text("string activation_id = 2;\n", encoding="utf-8")

            create_breaking_fixture(source, fixture, candidate)

            self.assertEqual(
                (candidate / "habitat_agent_v1.proto").read_text(encoding="utf-8"),
                "message ActivationEnvelope {\n}\n",
            )
            self.assertEqual(
                (candidate / "authority.proto").read_bytes(),
                (source / "authority.proto").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
