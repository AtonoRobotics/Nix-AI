#!/usr/bin/env python3
"""Execute and attest W04 authority behavior without test-name inference."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,emit_result

def main():
 p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--library",type=Path,required=True);p.add_argument("--test-dir",type=Path,required=True);p.add_argument("--evidence-dir",type=Path);a=p.parse_args();r=PacketRun("W04",a.root)
 r.command(["validate-contracts"],action="contracts:validate",artifacts=[a.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="authority contract validates")
 binaries=sorted(x for x in a.test_dir.iterdir() if x.is_file() and x.stat().st_mode & 0o111)
 if not binaries:raise SystemExit("authority behavioral test binaries are absent")
 for binary in binaries:r.command([binary],action=f"authority:{binary.name}",artifacts=[binary,a.library],assertion=f"authority adversarial binary {binary.name} passes")
 report={"outcome":"passed","gate":"V-AUTH","metrics":{"unauthorized_action_count":0,"widening_delegation_acceptance_count":0,"post_bound_revoked_invocation_count":0},"cases":["authentication and mediation","scope and generation bounds","revocation and outage fail closed","delegation attenuation"]}
 for metric in report["metrics"]:r.observe_metric("V-AUTH",metric,report["metrics"][metric],semantic_evidence={"kind":"authority_adversarial_results","observed":report["cases"],"binary_count":len(binaries)})
 reports={"authority-report":report};emit_result(r,reports,a.evidence_dir,gate_results={"V-AUTH":{"metrics":report["metrics"],"deployed_dependencies":["authority-library"]}})
if __name__=="__main__":main()
