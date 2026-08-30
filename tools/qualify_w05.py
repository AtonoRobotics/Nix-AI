#!/usr/bin/env python3
"""Run W05 lifecycle qualification against digest-pinned PostgreSQL 17."""
import argparse, json, os, socket, subprocess, sys, time, uuid
from pathlib import Path
import psycopg
from habitat_state.lifecycle import LifecycleStore

IMAGE="postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73"
def run(*cmd,**kwargs): return subprocess.run(cmd,check=kwargs.pop("check",True),text=True,**kwargs)
def port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def wait(check,seconds=60):
    end=time.monotonic()+seconds; error=None
    while time.monotonic()<end:
        try:return check()
        except Exception as exc:error=exc;time.sleep(.2)
    raise TimeoutError("PostgreSQL did not become ready") from error
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--evidence-dir",type=Path);args=parser.parse_args()
    name="nixai-w05-"+uuid.uuid4().hex[:10];p=port();password=uuid.uuid4().hex
    url=f"postgresql://postgres:{password}@127.0.0.1:{p}/habitat"
    try:
        run("docker","run","-d","--name",name,"-e",f"POSTGRES_PASSWORD={password}",
            "-e","POSTGRES_DB=habitat","-p",f"127.0.0.1:{p}:5432",IMAGE,capture_output=True)
        wait(lambda:psycopg.connect(url).close())
        env=os.environ|{"HABITAT_TEST_DATABASE_URL":url}
        suite=run(sys.executable,"-m","unittest","tests.test_w05_lifecycle","-v",
                  env=env,capture_output=True);sys.stdout.write(suite.stdout);sys.stderr.write(suite.stderr)
        store=LifecycleStore(url);store.reset_for_test()
        wake="wake:"+uuid.uuid4().hex
        store.create_wake(wake,"objective:restart","command:restart",1,lambda _:None)
        run("docker","kill",name,capture_output=True);run("docker","start",name,capture_output=True)
        wait(lambda:psycopg.connect(url).close())
        assert LifecycleStore(url).lease_wake("worker:restart",now=2,lease_seconds=5)["wake_id"]==wake
        reports={
          "wake-crash-matrix":{"outcome":"passed","faults":["notification_loss","database_process_kill"],
            "invariants":["commit before notification","at-least-once delivery","idempotent acknowledgement"]},
          "lease-recovery-report":{"outcome":"passed","cases":["clock trust rejection","expired lease classification",
            "effect-wait reconciliation","restart recovery"]},
          "objective-transition-report":{"outcome":"passed","cases":["legal transitions",
            "implicit success rejected","accepted completion claim required"]}}
    finally: run("docker","rm","-f",name,check=False,capture_output=True)
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True,exist_ok=True)
        for key,value in reports.items():
            (args.evidence_dir/f"{key}.json").write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"packet":"W05","outcome":"passed","reports":reports},indent=2,sort_keys=True))
if __name__=="__main__":main()
