#!/usr/bin/env python3
"""Validate JSON Schema contracts without permitting network resolution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import yaml
from jsonschema import RefResolver, validators
from jsonschema.exceptions import RefResolutionError


class SchemaContractError(ValueError):
    """A schema contract or its generated projection is invalid."""


def schema_paths(root: Path) -> list[Path]:
    """Return the complete, stable schema inventory for a contract root."""
    return (
        sorted(root.glob("*.schema.json"))
        + sorted((root / "contracts").glob("*.schema.json"))
        + sorted((root / "schemas").glob("*.schema.json"))
    )


def _projection_name(root: Path, path: Path) -> Path:
    relative = path.relative_to(root)
    if relative.parts and relative.parts[0] == "contracts":
        return Path(*relative.parts[1:])
    return relative


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaContractError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaContractError(f"schema root must be an object: {path}")
    return value


def _reject_remote(uri: str) -> Any:
    raise RefResolutionError(f"schema is not packaged locally: {uri}")


def _validator_for(
    schema: dict[str, Any], schema_store: dict[str, dict[str, Any]]
):
    validator_type = validators.validator_for(schema, default=None)
    if validator_type is None:
        raise SchemaContractError("unsupported declared metaschema")
    resolver = RefResolver.from_schema(
        schema,
        store=schema_store,
        handlers={"http": _reject_remote, "https": _reject_remote},
    )
    return validator_type(schema, resolver=resolver), resolver


def validate_schema_contracts(
    root: Path, *, generated_from: Path | None = None
) -> tuple[int, int]:
    """Validate schemas, local references, instances, and optional projections."""
    root = root.resolve()
    paths = schema_paths(root)
    if not paths:
        raise SchemaContractError(f"no JSON Schemas found under {root}")

    schemas: list[tuple[Path, dict[str, Any]]] = []
    schema_store: dict[str, dict[str, Any]] = {}
    seen_ids: dict[str, Path] = {}
    for path in paths:
        schema = _load_json(path)
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise SchemaContractError(f"schema missing nonempty $id: {path}")
        if schema_id in seen_ids:
            raise SchemaContractError(
                f"duplicate schema $id {schema_id}: {seen_ids[schema_id]} and {path}"
            )
        seen_ids[schema_id] = path
        try:
            validator_type = validators.validator_for(schema, default=None)
            if validator_type is None:
                raise SchemaContractError(
                    f"unsupported declared metaschema: {schema.get('$schema')!r}"
                )
            validator_type.check_schema(schema)
        except Exception as exc:
            raise SchemaContractError(
                f"schema fails its declared metaschema {path}: {exc}"
            ) from exc
        schemas.append((path, schema))
        schema_store[schema_id] = schema

    for path, schema in schemas:
        try:
            validator, resolver = _validator_for(schema, schema_store)
            # Traversing an empty instance does not necessarily visit every branch.
            # Explicitly resolve every reference so missing local contracts fail now.
            for ref in _references(schema):
                with resolver.resolving(ref):
                    pass
            validator.check_schema(schema)
        except Exception as exc:
            raise SchemaContractError(f"unresolved schema reference in {path}: {exc}") from exc

    instance_count = 0
    for schema_path, schema in schemas:
        instance_path = schema_path.with_name(schema_path.name.removesuffix(".schema.json") + ".yaml")
        if not instance_path.is_file():
            continue
        try:
            instance = yaml.safe_load(instance_path.read_text(encoding="utf-8"))
            validator, _ = _validator_for(schema, schema_store)
            validator.validate(instance)
        except Exception as exc:
            raise SchemaContractError(
                f"registry does not satisfy {schema_path.name}: {instance_path}: {exc}"
            ) from exc
        instance_count += 1

    if generated_from is not None:
        source_root = generated_from.resolve()
        source = {
            _projection_name(source_root, path): path.read_bytes()
            for path in schema_paths(source_root)
        }
        generated = {
            _projection_name(root, path): path.read_bytes()
            for path in paths
        }
        if source.keys() != generated.keys():
            raise SchemaContractError("generated schema inventory is stale")
        stale = [str(path) for path in source if source[path] != generated[path]]
        if stale:
            raise SchemaContractError(f"stale generated schema artifacts: {stale}")

    return len(schemas), instance_count


def _references(value: Any):
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            yield ref
        for child in value.values():
            yield from _references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _references(child)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--generated-from", type=Path)
    args = parser.parse_args()
    try:
        schemas, instances = validate_schema_contracts(
            args.root, generated_from=args.generated_from
        )
    except SchemaContractError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {schemas} schemas and {instances} registry instances")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
