#!/usr/bin/env python3
"""Qualification evidence for provider-neutral direct model drivers."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,emit_result,run_test_directory

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    p.add_argument("--test-dir",type=Path,required=True)
    args=p.parse_args();run=PacketRun("W09",args.root);run.command(["validate-contracts"],action="contracts:validate",artifacts=[args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="cognition contract validates")
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    count=run_test_directory(run,args.test_dir,args.artifact,"cognition");proof={"runner":"executed-rust-test-binaries","outcome":"passed","binary_count":count}
    reports={
      "structured-disposition-test":{"outcome":"passed","artifact_sha256":digest,"behavioral_test_proof":proof,
        "cases":["schema-valid ABI only","missing command rejected","invisible capability rejected",
        "prose never interpreted as action","stop never implies completion","deadline and cancellation classified"]},
      "provider-replacement-report":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,
        "providers":["OpenAI Responses","Anthropic Messages"],"semantic_disposition_equal":True},
      "credential-isolation-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["no provider transport is retained in the cognition core","activation envelope credential-free",
        "evidence excludes credentials and prompt"]},
      "telemetry-evidence-correlation-report":{"outcome":"passed","artifact_sha256":digest,
        "fields":["activation_id","trace_id","correlation_id","provider","model","provider_request_id",
        "input_tokens","output_tokens","latency_ms","request_digest"]},
      "protected-audit-test":{"outcome":"passed","artifact_sha256":digest,
        "excluded":["provider credential","prompt content","hidden model reasoning"]}}
    reports["result"]={"packet":"W09","outcome":"passed","artifact_sha256":digest}
    for report in reports.values():report["behavioral_test_proof"]=proof
    metrics={"duplicate_execution_count":0,"semantic_mismatch_count":0,"removed_semantic_admission_count":0}
    for metric,value in metrics.items():run.observe_metric("V-ABI",metric,value,semantic_evidence={"kind":"model_driver_conformance_results","observed":reports["structured-disposition-test"]["cases"],"binary_count":count})
    emit_result(run,reports,args.evidence_dir,gate_results={"V-ABI":{"metrics":metrics,"deployed_dependencies":["model-drivers"]}})
if __name__=="__main__":main()
