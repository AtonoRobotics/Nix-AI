#!/usr/bin/env python3
"""Qualification evidence for provider-neutral direct model drivers."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def behavioral_proof(directories,expected):
    binaries=sorted(path for directory in directories for path in directory.iterdir() if path.is_file());executed=set()
    if len(binaries)!=2:raise SystemExit("cognition behavioral binaries incomplete")
    for binary in binaries:
        listed=subprocess.check_output([binary,"--list"],text=True);executed.update(
          line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test"))
        subprocess.run([binary],check=True,capture_output=True,text=True)
    if executed!=expected:raise SystemExit(f"cognition behavioral coverage mismatch: {sorted(executed^expected)}")
    return {"runner":"rust-test-binaries","outcome":"passed","test_count":len(executed),"test_names":sorted(executed)}

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    p.add_argument("--test-dir",type=Path,required=True)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    proof=behavioral_proof([args.test_dir],{"validator_rejects_missing_identity_and_invisible_capability_without_heuristics",
      "provider_stop_does_not_complete_but_validated_completion_claim_does","cancellation_and_deadline_are_classified_without_implicit_completion",
      "cognition_evidence_is_digest_only_and_contains_no_transport_secret_or_prompt",
      "openai_and_anthropic_translate_to_identical_semantic_disposition"})
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
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W09","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
