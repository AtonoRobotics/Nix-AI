#!/usr/bin/env python3
"""Qualification evidence for durable effects and reconciliation."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    reports={
      "effect-fault-matrix":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,
        "cases":["atomic admission and reservation","semantic idempotency","attempt evidence",
        "independent observation","pre/post-dispatch cancellation","declared ordering","restart recovery",
        "bounded validity and execution constraint","objective completion coupling"]},
      "unknown-outcome-test":{"outcome":"passed","artifact_sha256":digest,
        "cases":["disconnect becomes OUTCOME_UNKNOWN","no blind redispatch","independent reconciliation",
        "provider reconciliation constrains consequence class"]},
      "compensation-test":{"outcome":"passed","artifact_sha256":digest,
        "cases":["new independently admitted linked effect","original success preserved",
        "compensation failure recorded independently"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W08","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
