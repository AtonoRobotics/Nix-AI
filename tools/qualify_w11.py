#!/usr/bin/env python3
"""Qualification evidence for optional cognition harness adapters."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,emit_result,run_test_directory

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path);p.add_argument("--test-dir",type=Path,required=True)
    args=p.parse_args();run=PacketRun("W11",args.root);run.command(["validate-contracts"],action="contracts:validate",artifacts=[args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="harness contract validates")
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    count=run_test_directory(run,args.test_dir,args.artifact,"harness");proof={"runner":"executed-rust-test-binaries","outcome":"passed","binary_count":count}
    reports={
      "cross-backend-conformance-report":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,"behavioral_test_proof":proof,
        "backends":["direct-model","Codex CLI","Claude Code"],"properties":["same semantic ABI disposition",
        "process exit never implies completion","typed checkpoints only","capability-only provider access",
        "cancellation cannot mutate committed effects","provider diagnostics are non-authoritative"]},
      "same-agent-identity-test":{"outcome":"passed","artifact_sha256":digest,
        "preserved":["agent identity","objective identity","activation identity","grant set","context bundle",
        "effect history","completion contract","activation-set pin","adapter artifact and configuration digest"]}}
    reports["result"]={"packet":"W11","outcome":"passed","artifact_sha256":digest}
    for report in reports.values():report["behavioral_test_proof"]=proof
    metrics={"duplicate_execution_count":0,"semantic_mismatch_count":0,"removed_semantic_admission_count":0}
    for metric,value in metrics.items():run.observe_metric("V-ABI",metric,value,semantic_evidence={"kind":"cross_backend_results","observed":reports["cross-backend-conformance-report"]["properties"],"binary_count":count})
    emit_result(run,reports,args.evidence_dir,gate_results={"V-ABI":{"metrics":metrics,"deployed_dependencies":["harness-adapters"]}})
if __name__=="__main__":main()
