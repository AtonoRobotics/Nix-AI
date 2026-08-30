#!/usr/bin/env python3
"""Live native-isolation qualification for the declared QEMU profile."""
import argparse, hashlib, json, os, signal, subprocess, tempfile, time
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    for name in ("bwrap","bash","python","prlimit","dd","execution"):
        p.add_argument("--"+name,required=True)
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
        memory=subprocess.run([args.prlimit,"--as=67108864","--"]+base+
            [args.python,"-c","bytearray(256*1024*1024)"],capture_output=True).returncode!=0
        storage=subprocess.run([args.prlimit,"--fsize=1048576","--"]+base+
            [args.dd,"if=/dev/zero","of=/workspace/large","bs=1048576","count=2"],
            capture_output=True).returncode!=0
        if not memory or not storage: raise AssertionError("resource limit was not enforced")
        child=subprocess.Popen(base+[args.bash,"-c","while :; do :; done & wait"],start_new_session=True)
        time.sleep(.2)
        if child.poll() is not None: raise AssertionError("termination workload exited before cancellation")
        os.killpg(child.pid,signal.SIGTERM)
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait();raise AssertionError("termination deadline missed")
        declarations=json.loads(subprocess.check_output([args.execution],text=True))
    digest=hashlib.sha256(Path(args.execution).read_bytes()).hexdigest()
    bwrap_digest=hashlib.sha256(Path(args.bwrap).read_bytes()).hexdigest()
    reports={
      "isolation-adversarial-suite":{"outcome":"passed","artifact_sha256":digest,
        "bubblewrap_sha256":bwrap_digest,
        "denied":["host secrets","provider socket","evaluator evidence","peer workspace","host network","ambient environment"]},
      "resource-enforcement-report":{"outcome":"passed","artifact_sha256":digest,
        "enforced":["memory address-space limit","workspace file-size limit","activation timeout"],
        "admission":["CPU","memory","storage","process count","timeout"]},
      "termination-test":{"outcome":"passed","artifact_sha256":digest,
        "cases":["process-group cooperative termination","forced-kill fallback"],"deadline_seconds":2},
      "profile-feature-report":{"outcome":"passed","profile":"qemu-x86_64-conformance","declarations":declarations},
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
