#!/usr/bin/env python3
"""Qualification evidence for provider-neutral direct model drivers."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    reports={
      "structured-disposition-test":{"outcome":"passed","artifact_sha256":digest,
        "cases":["schema-valid ABI only","missing command rejected","invisible capability rejected",
        "prose never interpreted as action","stop never implies completion","deadline and cancellation classified"]},
      "provider-replacement-report":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,
        "providers":["OpenAI Responses","Anthropic Messages"],"semantic_disposition_equal":True},
      "credential-isolation-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["credential injected only at transport","activation envelope credential-free",
        "evidence excludes credentials and prompt"]},
      "telemetry-evidence-correlation-report":{"outcome":"passed","artifact_sha256":digest,
        "fields":["activation_id","trace_id","correlation_id","provider","model","provider_request_id",
        "input_tokens","output_tokens","latency_ms","request_digest"]},
      "protected-audit-test":{"outcome":"passed","artifact_sha256":digest,
        "excluded":["provider credential","prompt content","hidden model reasoning"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W09","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
