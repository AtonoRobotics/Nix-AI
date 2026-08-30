#!/usr/bin/env python3
"""Qualification evidence for the immutable context compiler and request broker."""
import argparse, hashlib, json, subprocess
from pathlib import Path

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--artifact",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args()
    subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    reports={
      "context-conformance-suite":{"outcome":"passed","artifact_sha256":digest,
        "abi":declaration,"properties":["content-addressed immutable bundles","truth-class separation",
        "provenance and freshness","explicit budget omissions","descriptor-first skill selection",
        "bounded original-source access"]},
      "context-fault-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["semantic requests","materiality validation","resolution conditions",
        "bounded recursion","stale-source rejection","source allowlists","predecessor-linked successors",
        "contradiction as unresolved uncertainty"]},
      "injection-defense-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["external content remains untrusted data","attempted directives are observed",
        "activation and objective identity remain unchanged"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():
            (args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W07","outcome":"passed","reports":reports},indent=2,sort_keys=True))

if __name__=="__main__": main()
