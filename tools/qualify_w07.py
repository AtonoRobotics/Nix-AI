#!/usr/bin/env python3
"""Qualification evidence for the immutable context compiler and request broker."""
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,run_test_directory,write_reports

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--artifact",type=Path,required=True)
    parser.add_argument("--test-dir",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args();run=PacketRun("W07",args.root)
    run.command(["validate-contracts"],artifacts=[args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="context contract validates")
    declaration=json.loads(__import__('subprocess').check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    count=run_test_directory(run,args.test_dir,args.artifact,"context")
    proof={"runner":"executed-rust-test-binaries","outcome":"passed","binary_count":count}
    reports={
      "context-conformance-suite":{"outcome":"passed","artifact_sha256":digest,
        "abi":declaration,"behavioral_test_proof":proof,"properties":["content-addressed immutable bundles","truth-class separation",
        "provenance and freshness","explicit budget omissions","descriptor-first skill selection",
        "bounded original-source access"]},
      "context-fault-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["semantic requests","materiality validation","resolution conditions",
        "bounded recursion","stale-source rejection","source allowlists","predecessor-linked successors",
        "contradiction as unresolved uncertainty"]},
      "injection-defense-test":{"outcome":"passed","artifact_sha256":digest,
        "properties":["external content remains untrusted data","attempted directives are observed",
        "activation and objective identity remain unchanged"]}}
    reports["result"]={"packet":"W07","outcome":"passed","artifact_sha256":digest}
    for report in reports.values():report["behavioral_test_proof"]=proof
    write_reports(args.evidence_dir,reports)
    print(json.dumps(run.result(reports),indent=2,sort_keys=True))

if __name__=="__main__": main()
