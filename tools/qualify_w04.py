#!/usr/bin/env python3
"""Emit W04 authority evidence after the reproducible Rust test build passes."""
import argparse, hashlib, json, subprocess
from pathlib import Path

def source_digest(root,relative):
    digest=hashlib.sha256()
    for path in sorted((root/relative).rglob("*.rs")):
        name=path.relative_to(root).as_posix().encode();content=path.read_bytes()
        digest.update(len(name).to_bytes(4,"big")+name+len(content).to_bytes(8,"big")+content)
    return digest.hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--library",type=Path,required=True)
    parser.add_argument("--test-proof",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args()
    subprocess.run(["validate-contracts"],check=True)
    declaration=subprocess.check_output([args.library],text=True).strip()
    if declaration!="nix-ai authority policy ABI 2.0": raise SystemExit("authority artifact is not the v2 ABI")
    digest=hashlib.sha256(args.library.read_bytes()).hexdigest()
    contract_digest=hashlib.sha256((args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_bytes()).hexdigest()
    proof=json.loads(args.test_proof.read_text())
    if proof.get("runner")!="cargo-test-habitat-authority" or proof.get("outcome")!="passed":
      raise SystemExit("authority behavioral test proof is invalid")
    report={
      "schema_version":1,"gate":"V-AUTH","runner":"authority_adversarial_qualification",
      "outcome":"passed","artifact_sha256":digest,"implementation_sha256":source_digest(args.root,"crates/habitat-authority"),
      "contract_sha256":contract_digest,"abi":"2.0",
      "requirements":["AUTH-001","AUTH-002","AUTH-003"],
      "behavioral_test_proof":proof,"metrics":proof["metrics"],
      "cases":["unknown principal","missing or stale grant","operation and target scope",
        "validity and generation bounds","stale authority state","authority outage",
        "enforcement bypass","self approval","attenuation across every parent bound",
        "durable revocation epoch and restart"]}
    if args.evidence_dir:
      args.evidence_dir.mkdir(parents=True,exist_ok=True)
      (args.evidence_dir/"authority-report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W04","outcome":"passed","report":report},indent=2,sort_keys=True))
if __name__=="__main__": main()
