#!/usr/bin/env python3
"""Qualification evidence for optional cognition harness adapters."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def behavioral_proof(directory,expected):
    binaries=sorted(path for path in directory.iterdir() if path.is_file());executed=set()
    if len(binaries)!=2:raise SystemExit("harness behavioral binaries incomplete")
    for binary in binaries:
        listed=subprocess.check_output([binary,"--list"],text=True);executed.update(
          line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test"));subprocess.run([binary],check=True,capture_output=True,text=True)
    if executed!=expected:raise SystemExit(f"harness behavioral coverage mismatch: {sorted(executed^expected)}")
    return {"runner":"rust-test-binaries","outcome":"passed","test_count":len(executed),"test_names":sorted(executed)}

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path);p.add_argument("--test-dir",type=Path,required=True)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    proof=behavioral_proof(args.test_dir,{"codex_and_claude_emit_the_same_semantic_abi_and_identity",
      "process_success_prose_and_session_completion_do_not_complete_objective",
      "capability_proxy_allows_only_granted_habitat_endpoints_and_no_ambient_access",
      "only_typed_checkpoint_is_durable_and_provider_diagnostics_are_not_state",
      "cancellation_deadline_and_backend_comparison_preserve_committed_truth"})
    reports={
      "cross-backend-conformance-report":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,"behavioral_test_proof":proof,
        "backends":["direct-model","Codex CLI","Claude Code"],"properties":["same semantic ABI disposition",
        "process exit never implies completion","typed checkpoints only","capability-only provider access",
        "cancellation cannot mutate committed effects","provider diagnostics are non-authoritative"]},
      "same-agent-identity-test":{"outcome":"passed","artifact_sha256":digest,
        "preserved":["agent identity","objective identity","activation identity","grant set","context bundle",
        "effect history","completion contract","activation-set pin","adapter artifact and configuration digest"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W11","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
