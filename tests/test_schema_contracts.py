from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.schema_contracts import SchemaContractError, validate_schema_contracts


FIXTURES = Path(__file__).parent / "fixtures" / "schema-contracts"


class SchemaContractTests(unittest.TestCase):
    def test_valid_local_reference_resolves(self) -> None:
        schemas, instances = validate_schema_contracts(FIXTURES / "valid")
        self.assertEqual((schemas, instances), (2, 1))

    def test_malformed_schema_fails_metaschema_validation(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "declared metaschema"):
            validate_schema_contracts(FIXTURES / "malformed")

    def test_missing_local_reference_is_rejected_without_network(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "unresolved schema reference"):
            validate_schema_contracts(FIXTURES / "missing-reference")

    def test_stale_generated_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "generated"
            shutil.copytree(FIXTURES / "valid", generated)
            path = generated / "schemas" / "child.schema.json"
            path.chmod(path.stat().st_mode | 0o200)
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema["title"] = "Stale generated child"
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(SchemaContractError, "stale generated"):
                validate_schema_contracts(
                    generated, generated_from=FIXTURES / "valid"
                )


if __name__ == "__main__":
    unittest.main()
