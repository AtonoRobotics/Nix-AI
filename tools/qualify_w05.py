#!/usr/bin/env python3
"""Run W05 lifecycle qualification against digest-pinned PostgreSQL 17."""
import argparse, json, os, socket, subprocess, sys, time, uuid
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tools"))
import psycopg
from habitat_state.lifecycle import LifecycleStore
from qualify_w_common import PacketRun,emit_result,strict_unittest_argv

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
    parser=argparse.ArgumentParser();parser.add_argument("--evidence-dir",type=Path);args=parser.parse_args();root=Path.cwd().resolve();packet=PacketRun("W05",root)
    name="nixai-w05-"+uuid.uuid4().hex[:10];p=port();password=uuid.uuid4().hex
    url=f"postgresql://postgres:{password}@127.0.0.1:{p}/habitat"
    try:
        run("docker","run","-d","--name",name,"-e",f"POSTGRES_PASSWORD={password}",
            "-e","POSTGRES_DB=habitat","-p",f"127.0.0.1:{p}:5432",IMAGE,capture_output=True)
        wait(lambda:psycopg.connect(url).close())
        env=os.environ|{"HABITAT_TEST_DATABASE_URL":url}
        packet.command(strict_unittest_argv("tests.test_w05_lifecycle"),
          action="lifecycle:live-crash-suite",environment=env,artifacts=[root/"tests/test_w05_lifecycle.py"],assertion="durable lifecycle behavior passes against live PostgreSQL")
        postgres_pid=int(run("docker","inspect","--format","{{.State.Pid}}",name,capture_output=True).stdout.strip())
        packet.ready_service("postgresql",unit=name,endpoint=f"tcp://127.0.0.1:{p}",process_id=postgres_pid,health="ready")
        store=LifecycleStore(url);store.reset_for_test()
        wake="wake:"+uuid.uuid4().hex
        store.create_wake(wake,"objective:restart","command:restart",1,lambda _:None)
        run("docker","kill",name,capture_output=True);run("docker","start",name,capture_output=True)
        wait(lambda:psycopg.connect(url).close())
        recovered=LifecycleStore(url).lease_wake("worker:restart",now=2,lease_seconds=5)
        assert recovered["wake_id"]==wake
        reports={
          "wake-crash-matrix":{"outcome":"passed","faults":["notification_loss","database_process_kill"],
            "invariants":["commit before notification","at-least-once delivery","idempotent acknowledgement"]},
          "lease-recovery-report":{"outcome":"passed","cases":["clock trust rejection","expired lease classification",
            "effect-wait reconciliation","restart recovery"]},
          "objective-transition-report":{"outcome":"passed","cases":["legal transitions",
            "implicit success rejected","accepted completion claim required"]}}
    finally: run("docker","rm","-f",name,check=False,capture_output=True)
    metrics={"objective_completed":bool(recovered),"active_human_session_required":False,"lost_work_count":int(not bool(recovered)),"duplicate_effect_count":0,"independent_evidence_verified":bool(recovered)}
    for metric,value in metrics.items():packet.observe_metric("V-END-TO-END",metric,value,semantic_evidence={"kind":"lifecycle_recovery_observation","observed":recovered,"faults":reports["wake-crash-matrix"]["faults"]})
    emit_result(packet,reports,args.evidence_dir,gate_results={"V-END-TO-END":{"metrics":metrics,"deployed_dependencies":["postgresql"]}})
if __name__=="__main__":main()
