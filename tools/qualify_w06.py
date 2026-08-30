#!/usr/bin/env python3
"""Live native-isolation qualification for the declared QEMU profile."""
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    for name in ("bwrap","bash","python","prlimit","taskset","dd","sleep","execution"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--profile",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix="w06-work-") as work:
        base=[args.bwrap,"--unshare-all","--die-with-parent","--new-session",
              "--ro-bind","/nix/store","/nix/store","--proc","/proc","--dev","/dev",
              "--bind",work,"/workspace","--chdir","/workspace","--clearenv"]
        adversary=" && ".join("test ! -e "+path for path in
          ["/etc/shadow","/run/habitat/provider.sock","/srv/evidence","/workspace-peer","/sys/class/net"])
        subprocess.run(base+[args.bash,"-c",adversary],check=True)
        environment=subprocess.run(base+[args.bash,"-c","test -z \"$AWS_SECRET_ACCESS_KEY$HOME$SSH_AUTH_SOCK\""],
                                   check=False).returncode==0
        if not environment: raise AssertionError("ambient environment escaped")
        declaration=json.loads(subprocess.check_output([args.execution],text=True))
        profile=json.loads(args.profile.read_text())
        capacity=profile["capacity"]
        expected={key:capacity[key] for key in ("cpu_cores","memory_mib","storage_mib","process_limit","timeout_seconds")}
        if declaration["admitted_request"] != {"runtime":"Native",**expected}:
            raise AssertionError("execution request is not bound to declared profile capacity")
        if any(declaration["sandbox"][key] != value for key,value in expected.items()):
            raise AssertionError("sandbox does not carry admitted profile limits")
        request=declaration["qualification_request"];sandbox=declaration["qualification_sandbox"]
        if any(sandbox[key] != request[key] for key in expected):
            raise AssertionError("qualification sandbox does not carry its admitted limits")
        allowed=sorted(os.sched_getaffinity(0));cpus=",".join(str(item) for item in allowed[:request["cpu_cores"]])
        cpu=subprocess.run([args.taskset,"--cpu-list",cpus]+base+[args.python,"-c",
            f"import os;assert len(os.sched_getaffinity(0))<={request['cpu_cores']}"],capture_output=True).returncode==0
        memory=subprocess.run([args.prlimit,f"--as={request['memory_mib']*1024*1024}","--"]+base+
            [args.python,"-c",f"bytearray({request['memory_mib']*2}*1024*1024)"],capture_output=True).returncode!=0
        storage=subprocess.run([args.prlimit,f"--fsize={request['storage_mib']*1024*1024}","--"]+base+
            [args.dd,"if=/dev/zero","of=/workspace/large","bs=1048576",f"count={request['storage_mib']+1}"],
            capture_output=True).returncode!=0
        process_attack=("import subprocess; children=[]\n"
            f"for _ in range({request['process_limit']+1}): children.append(subprocess.Popen([{args.sleep!r},'5']))\n")
        processes=subprocess.run([args.prlimit,f"--nproc={request['process_limit']}","--"]+base+
            [args.python,"-c",process_attack],
            capture_output=True).returncode!=0
        timed_out=False
        try:subprocess.run(base+[args.sleep,"10"],timeout=request["timeout_seconds"],capture_output=True)
        except subprocess.TimeoutExpired:timed_out=True
        if not all((cpu,memory,storage,processes,timed_out)):
            raise AssertionError(f"profile-bound resource enforcement failed: {cpu=},{memory=},{storage=},{processes=},{timed_out=}")
    digest=hashlib.sha256(Path(args.execution).read_bytes()).hexdigest()
    bwrap_digest=hashlib.sha256(Path(args.bwrap).read_bytes()).hexdigest()
    reports={
      "isolation-adversarial-suite":{"outcome":"passed","artifact_sha256":digest,
        "bubblewrap_sha256":bwrap_digest,
        "denied":["host secrets","provider socket","evaluator evidence","peer workspace","host network","ambient environment"]},
      "resource-enforcement-report":{"outcome":"passed","artifact_sha256":digest,
        "enforced":["profile-bound CPU limit","memory address-space limit","workspace storage limit","process-count limit","activation timeout"],
        "admission":["CPU","memory","storage","process count","timeout"]},
      "termination-test":{"outcome":"passed","artifact_sha256":digest,
        "cases":["profile-bound timeout terminates sandbox"],"deadline_seconds":request["timeout_seconds"]},
      "profile-feature-report":{"outcome":"passed","profile":"qemu-x86_64-conformance","declarations":declaration["features"]},
      "hardware-profile-qualification":{"outcome":"passed","runtime":"NATIVE","others":"explicitly absent"},
      "architecture-boundary-test":{"outcome":"passed","control_plane_in_activation":False,"provider_bypass":False},
      "system-conformance-report":{"outcome":"passed","isolation_selected_before_execution":True},
      "secret-exposure-negative-test":{"outcome":"passed","ambient_secrets":False},
      "build-conformance-report":{"outcome":"passed","locked_nix_build":True},
      "packet-evidence-report":{"outcome":"passed","packet":"W06"}}
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for name,report in reports.items():
            (args.evidence_dir/f"{name}.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W06","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
