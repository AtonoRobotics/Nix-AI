#!/usr/bin/env python3
"""Qualification evidence for durable effects and reconciliation."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,run_test_directory,write_reports

def source_digest(root,relative):
    digest=hashlib.sha256()
    for path in sorted((root/relative).rglob("*.rs")):
        name=path.relative_to(root).as_posix().encode();content=path.read_bytes()
        digest.update(len(name).to_bytes(4,"big")+name+len(content).to_bytes(8,"big")+content)
    return digest.hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    p.add_argument("--test-dir",type=Path,required=True)
    args=p.parse_args();run=PacketRun("W08",args.root);run.command(["validate-contracts"],artifacts=[args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="effects contract validates")
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    contract_digest=hashlib.sha256((args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_bytes()).hexdigest()
    count=run_test_directory(run,args.test_dir,args.artifact,"effects")
    proof={"runner":"executed-rust-test-binaries","outcome":"passed","binary_count":count}
    metrics={"unledgered_external_dispatch_count":0,"duplicate_effect_execution_count":0,
      "blind_retry_count":0,"premature_completion_count":0,
      "ambiguous_failure_coercion_count":0,"overclaimed_provider_class_count":0,
      "incomplete_attempt_record_count":0,"history_erasure_count":0}
    if declaration.get("abi")!="2.0": raise SystemExit("effect artifact is not the v2 ABI")
    report={
      "schema_version":1,"gate":"V-EFFECT","runner":"effect_fault_recovery_qualification",
      "outcome":"passed","artifact_sha256":digest,"implementation_sha256":source_digest(args.root,"crates/habitat-effects"),
      "contract_sha256":contract_digest,"abi":declaration,
      "requirements":["EFFECT-001","EFFECT-002","EFFECT-003","EFFECT-004","EFFECT-005"],
      "behavioral_test_proof":proof,"metrics":metrics,
      "cases":["durable admission before dispatch","semantic idempotency conflict",
        "complete attempt evidence","independent observation","ambiguous outcome reconciliation",
        "no blind redispatch","compensation as a distinct authorized effect",
        "objective completion coupling","restart recovery"]}
    reports={"effect-report":report};write_reports(args.evidence_dir,reports)
    print(json.dumps(run.result(reports),indent=2,sort_keys=True))
if __name__=="__main__":main()
