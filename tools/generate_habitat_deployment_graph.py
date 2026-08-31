#!/usr/bin/env python3
"""Regenerate the Rust projection from the canonical Nix deployment graph."""
import json
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).parents[1]
expression = f"(import {ROOT / 'nix/lib/habitat-deployment-graph.nix'} {{}}).rustProjection"
wire = subprocess.check_output(
    ["nix", "eval", "--impure", "--raw", "--expr", expression], text=True
)
projection = json.loads(wire)
(ROOT / "crates/habitat-runtime/src/deployment_graph.json").write_text(
    json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"
)
