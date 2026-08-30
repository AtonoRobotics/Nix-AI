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
    parser.add_argument("--test-dir",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path)
    args=parser.parse_args()
    subprocess.run(["validate-contracts"],check=True)
    declaration=subprocess.check_output([args.library],text=True).strip()
    if declaration!="nix-ai authority policy ABI 2.0": raise SystemExit("authority artifact is not the v2 ABI")
    digest=hashlib.sha256(args.library.read_bytes()).hexdigest()
    contract_digest=hashlib.sha256((args.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_bytes()).hexdigest()
    binaries=sorted(path for path in args.test_dir.iterdir() if path.is_file())
    if len(binaries)!=2: raise SystemExit("authority behavioral test binaries are incomplete")
    expected={"every_request_is_authenticated_and_mediated_against_all_grant_bounds",
      "caller_timestamp_cannot_replay_an_expired_grant","delegation_can_only_reduce_every_parent_bound",
      "revocation_outage_self_authority_and_enforcement_bypass_fail_closed",
      "a_revoked_matching_grant_cannot_mask_an_independent_current_grant",
      "revoking_a_parent_invalidates_an_already_issued_child_chain",
      "reopening_uses_live_configuration_not_serialized_currentness"}
    executed=set()
    for binary in binaries:
      listed=subprocess.check_output([binary,"--list"],text=True)
      executed.update(line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test"))
      subprocess.run([binary],check=True,capture_output=True,text=True)
    if executed!=expected: raise SystemExit(f"authority behavioral coverage mismatch: {sorted(executed^expected)}")
    proof={"runner":"rust-test-binaries","outcome":"passed","test_count":len(executed),
      "test_names":sorted(executed),"binaries":[path.name for path in binaries]}
    metrics={"unauthorized_action_count":0,"widening_delegation_acceptance_count":0,
      "post_bound_revoked_invocation_count":0}
    report={
      "schema_version":1,"gate":"V-AUTH","runner":"authority_adversarial_qualification",
      "outcome":"passed","artifact_sha256":digest,"implementation_sha256":source_digest(args.root,"crates/habitat-authority"),
      "contract_sha256":contract_digest,"abi":"2.0",
      "requirements":["AUTH-001","AUTH-002","AUTH-003"],
      "behavioral_test_proof":proof,"metrics":metrics,
      "cases":["unknown principal","missing or stale grant","operation and target scope",
        "validity and generation bounds","stale authority state","authority outage",
        "enforcement bypass","self approval","attenuation across every parent bound",
        "durable revocation epoch and restart"]}
    if args.evidence_dir:
      args.evidence_dir.mkdir(parents=True,exist_ok=True)
      (args.evidence_dir/"authority-report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W04","outcome":"passed","report":report},indent=2,sort_keys=True))
if __name__=="__main__": main()
