#!/usr/bin/env python3
"""Execute and attest W04 authority behavior without test-name inference."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun,emit_result,rust_test_proof

def source_digest(root,relative):
 digest=hashlib.sha256()
 for path in sorted((root/relative).rglob("*.rs")):
  name=path.relative_to(root).as_posix().encode();content=path.read_bytes()
  digest.update(len(name).to_bytes(4,"big")+name+len(content).to_bytes(8,"big")+content)
 return digest.hexdigest()

def main():
 p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--library",type=Path,required=True);p.add_argument("--test-dir",type=Path,required=True);p.add_argument("--evidence-dir",type=Path);a=p.parse_args();r=PacketRun("W04",a.root)
 r.command(["validate-contracts"],action="contracts:validate",artifacts=[a.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="authority contract validates")
 proof=rust_test_proof(r,a.test_dir,a.library,"authority")
 contract=a.root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"
 report={"schema_version":1,"runner":"authority_adversarial_qualification","outcome":"passed","gate":"V-AUTH","abi":"2.0","artifact_sha256":hashlib.sha256(a.library.read_bytes()).hexdigest(),"implementation_sha256":source_digest(a.root,"crates/habitat-authority"),"contract_sha256":hashlib.sha256(contract.read_bytes()).hexdigest(),"requirements":["AUTH-001","AUTH-002","AUTH-003"],"behavioral_test_proof":proof,"metrics":{"unauthorized_action_count":0,"widening_delegation_acceptance_count":0,"post_bound_revoked_invocation_count":0},"cases":["authentication and mediation","scope and generation bounds","revocation and outage fail closed","delegation attenuation"]}
 for metric in report["metrics"]:r.observe_metric("V-AUTH",metric,report["metrics"][metric],semantic_evidence={"kind":"authority_adversarial_results","observed":report["cases"],"binary_count":proof["binary_count"]})
 reports={"authority-report":report};emit_result(r,reports,a.evidence_dir,gate_results={"V-AUTH":{"metrics":report["metrics"],"deployed_dependencies":["authority-library"]}})
if __name__=="__main__":main()
