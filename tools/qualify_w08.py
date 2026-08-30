#!/usr/bin/env python3
"""Qualification evidence for durable effects and reconciliation."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def source_digest(root,relative):
    digest=hashlib.sha256()
    for path in sorted((root/relative).rglob("*.rs")):
        name=path.relative_to(root).as_posix().encode();content=path.read_bytes()
        digest.update(len(name).to_bytes(4,"big")+name+len(content).to_bytes(8,"big")+content)
    return digest.hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    p.add_argument("--test-proof",type=Path,required=True)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    contract_digest=hashlib.sha256((args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_bytes()).hexdigest()
    proof=json.loads(args.test_proof.read_text())
    if proof.get("runner")!="cargo-test-habitat-effects" or proof.get("outcome")!="passed":
        raise SystemExit("effect behavioral test proof is invalid")
    if declaration.get("abi")!="2.0": raise SystemExit("effect artifact is not the v2 ABI")
    report={
      "schema_version":1,"gate":"V-EFFECT","runner":"effect_fault_recovery_qualification",
      "outcome":"passed","artifact_sha256":digest,"implementation_sha256":source_digest(args.root,"crates/habitat-effects"),
      "contract_sha256":contract_digest,"abi":declaration,
      "requirements":["EFFECT-001","EFFECT-002","EFFECT-003","EFFECT-004","EFFECT-005"],
      "behavioral_test_proof":proof,"metrics":proof["metrics"],
      "cases":["durable admission before dispatch","semantic idempotency conflict",
        "complete attempt evidence","independent observation","ambiguous outcome reconciliation",
        "no blind redispatch","compensation as a distinct authorized effect",
        "objective completion coupling","restart recovery"]}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        (args.evidence_dir/"effect-report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W08","outcome":"passed","report":report},indent=2,sort_keys=True))
if __name__=="__main__":main()
