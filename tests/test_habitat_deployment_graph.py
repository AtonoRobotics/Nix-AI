import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).parents[1]
GRAPH = ROOT / "nix/lib/habitat-deployment-graph.nix"
RUST_PROJECTION = ROOT / "crates/habitat-runtime/src/deployment_graph.json"


def evaluate(expr):
    return subprocess.run(
        ["nix", "eval", "--impure", "--json", "--expr", expr], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def canonical():
    result = evaluate(f"import {GRAPH} {{}}")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def rejects(mutation):
    expr = f"let base = import {GRAPH} {{}}; in import {GRAPH} {{ graph = base // ({mutation}); }}"
    result = evaluate(expr)
    assert result.returncode != 0, result.stdout


class DeploymentGraphTests(unittest.TestCase):
    def test_canonical_graph_evaluates_and_projects_all_services(self):
        graph = canonical()
        self.assertEqual(graph["names"], ["abi", "authority", "controller", "effects",
                                          "evaluator", "health", "packages", "provider",
                                          "runtime", "scheduler", "signer", "state"])
        self.assertEqual(graph["readiness"]["runtime"],
                         ["state", "scheduler", "authority", "effects", "packages", "abi"])

    def test_checked_rust_projection_matches_canonical_readiness(self):
        self.assertEqual(json.loads(RUST_PROJECTION.read_text()),
                         json.loads(canonical()["rustProjection"]))

    def test_rejects_cycle(self):
        rejects("{ services = base.services // { state = base.services.state // { dependencies = [ \"habitat-runtime.service\" ]; readiness = [ \"runtime\" ]; }; }; }")

    def test_rejects_missing_identity(self):
        rejects("{ services = base.services // { state = base.services.state // { identity = \"service:missing\"; }; }; }")

    def test_rejects_readiness_mismatch(self):
        rejects("{ services = base.services // { runtime = base.services.runtime // { readiness = [ \"state\" ]; }; }; }")

    def test_rejects_credential_drift(self):
        rejects("{ services = base.services // { runtime = base.services.runtime // { credentials = [ \"notProvisioned\" ]; }; }; }")

    def test_rejects_client_policy_drift(self):
        rejects("{ services = base.services // { runtime = base.services.runtime // { clients = [ \"service:intruder\" ]; }; }; }")
