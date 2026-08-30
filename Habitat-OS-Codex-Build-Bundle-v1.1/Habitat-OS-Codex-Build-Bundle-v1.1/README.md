# Habitat OS Codex Build Bundle v1.1

This is the corrected implementation-admissible baseline for Habitat OS.

## Contents

- `CODEX-BUILD-SPEC.md`: execution contract for Codex.
- `Habitat-OS-Architecture-Contracts-v1.1/`: governing architecture, schemas, Protobuf contracts, canonical requirement registry, typed work graph and validators.
- `BUNDLE-MANIFEST.sha256`: complete bundle integrity manifest.
- `tests/validate_bundle.py`: nested integrity and contract validation entry point.

## Validate before use

From this directory run:

```bash
python3 tests/validate_bundle.py
```

Implementation SHALL NOT begin unless validation returns `PASS`.

## Begin implementation

Create the implementation repository, place `CODEX-BUILD-SPEC.md` at its root, and copy the architecture package's `contracts`, `proto`, `schemas`, and governing Markdown into the repository paths defined by the build specification. Then instruct Codex to execute W00 and W01 only, using the initial invocation in section 26.
