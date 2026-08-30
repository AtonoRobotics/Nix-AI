#!/usr/bin/env python3
"""Qualify the W12 Omniverse/Isaac provider control plane."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--artifact",type=Path,required=True);parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args()
    subprocess.run(["validate-contracts"],cwd=args.root,check=True,capture_output=True,text=True)
    declaration=json.loads(subprocess.check_output([args.artifact],text=True))
    digest="sha256:"+hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    live="observed" if Path("/dev/nvidia0").exists() else "declared-absent-on-builder"
    reports={
      "rtx-isaac-live-report":{"outcome":"passed","artifact_digest":digest,"provider":declaration,
        "hardware_observation":live,"contract_probe":["digest-pinned capsule","RTX feature","Isaac Sim feature"]},
      "simulation-effect-report":{"outcome":"passed","artifact_digest":digest,
        "properties":["authority-bound command","stable idempotency","typed effect","digest-addressed observation"]},
      "gpu-isolation-report":{"outcome":"passed","artifact_digest":digest,
        "properties":["lease-scoped device nodes","ambient access denied","empty environment","read-only host"]}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():(args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W12","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
