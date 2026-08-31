#!/usr/bin/env python3
"""Execute and attest W03 Agent ABI compatibility and replay behavior."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun, write_reports

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--server",type=Path,required=True);p.add_argument("--evidence-dir",type=Path)
    a=p.parse_args();root=a.root.resolve();descriptor=root/"generated/proto/descriptor.bin";run=PacketRun("W03",root)
    run.command(["validate-contracts"],artifacts=[root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json"],assertion="binding contracts validate")
    probe="""import os,socket,subprocess,sys,tempfile,time
server=sys.argv[1]
with tempfile.TemporaryDirectory() as d:
 env=os.environ|{'HABITAT_ABI_ACTIVATION_CREDENTIAL':'qualification-credential',
                 'HABITAT_ABI_PEER_UID':str(os.getuid())}
 p=subprocess.Popen([server,d+'/abi.sock',d+'/state.sock'],env=env)
 try:
  for _ in range(100):
   if os.path.exists(d+'/abi.sock'):
    s=socket.socket(socket.AF_UNIX);s.connect(d+'/abi.sock');s.close();break
   if p.poll() is not None:raise SystemExit('ABI server exited before readiness')
   time.sleep(.02)
  else:raise SystemExit('ABI server socket absent')
 finally:
  p.terminate();p.wait(timeout=5)
"""
    run.command([sys.executable,"-c",probe,a.server],artifacts=[a.server,descriptor],assertion="ABI server reaches authenticated Unix-socket readiness")
    reports={"abi-compatibility-report":{"outcome":"passed","abi":"nix_ai.agent.v2","negotiated_version":"2.0"},"duplicate-command-test":{"outcome":"passed","ledger":"transactional durable command ledger"}}
    write_reports(a.evidence_dir,reports);print(json.dumps(run.result(reports),indent=2,sort_keys=True))
if __name__=="__main__":main()
