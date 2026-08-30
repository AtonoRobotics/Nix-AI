#!/usr/bin/env python3
"""Qualification evidence for the immutable context compiler and request broker."""
import argparse, hashlib, json, subprocess
from pathlib import Path

def behavioral_proof(directory,expected):
    binaries=sorted(path for path in directory.iterdir() if path.is_file());executed=set()
    if len(binaries)!=2:raise SystemExit("context behavioral binaries incomplete")
    for binary in binaries:
        listed=subprocess.check_output([binary,"--list"],text=True)
        executed.update(line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test"))
        subprocess.run([binary],check=True,capture_output=True,text=True)
    if executed!=expected:raise SystemExit(f"context behavioral coverage mismatch: {sorted(executed^expected)}")
    return {"runner":"rust-test-binaries","outcome":"passed","test_count":len(executed),"test_names":sorted(executed)}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--artifact",type=Path,required=True)
    parser.add_argument("--test-dir",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args()
    subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    proof=behavioral_proof(args.test_dir,{"bundle_is_immutable_provenance_bearing_and_separates_truth_classes",
      "descriptor_first_skill_selection_does_not_load_procedure","budget_and_contradictions_are_explicit",
      "semantic_request_creates_linked_successor_and_bounds_access",
      "faults_reject_stale_forbidden_nonmaterial_and_recursive_requests","hostile_content_is_data_and_cannot_mutate_bundle_identity"})
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
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():
            (args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W07","outcome":"passed","reports":reports},indent=2,sort_keys=True))

if __name__=="__main__": main()
