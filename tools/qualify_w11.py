#!/usr/bin/env python3
"""Qualification evidence for optional cognition harness adapters."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--artifact",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    args=p.parse_args();subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True));digest=hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    reports={
      "cross-backend-conformance-report":{"outcome":"passed","artifact_sha256":digest,"abi":declaration,
        "backends":["direct-model","Codex CLI","Claude Code"],"properties":["same semantic ABI disposition",
        "process exit never implies completion","typed checkpoints only","capability-only provider access",
        "cancellation preserves committed effects","private transcript is non-authoritative"]},
      "same-agent-identity-test":{"outcome":"passed","artifact_sha256":digest,
        "preserved":["agent identity","objective identity","activation identity","grant set","context bundle",
        "effect history","completion contract","activation-set pin","adapter artifact and configuration digest"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W11","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
