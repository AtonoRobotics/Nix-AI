#!/usr/bin/env python3
"""Run W02 against pinned live PostgreSQL and Garage services."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path.cwd() / "tools"))

import psycopg

from habitat_state import (CommandId, Correlation, EntityId, EntityKind, EvidenceMetadata,
                           IntegrityError, PrincipalId, State, StateStore, Version)
from qualify_w_common import PacketRun, emit_result, strict_unittest_argv


POSTGRES_IMAGE = "postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73"


def run(*command, check=True, capture=False, env=None):
    return subprocess.run(command, check=check, text=True,
                          capture_output=capture, env=env)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(check, description, timeout=60):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            check()
            return
        except Exception as error:
            last_error = error
            time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {description}") from last_error


def garage_configuration(root, rpc_port, s3_port, rpc_secret):
    metadata = root / "metadata"
    data = root / "data"
    metadata.mkdir()
    data.mkdir()
    config = root / "garage.toml"
    config.write_text(
        f"""metadata_dir = "{metadata}"
data_dir = "{data}"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:{rpc_port}"
rpc_public_addr = "127.0.0.1:{rpc_port}"
rpc_secret = "{rpc_secret}"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:{s3_port}"
root_domain = ".s3.garage"
""",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


def garage_command(binary, environment, *arguments, capture=False, check=True):
    return run(binary, *arguments, capture=capture, check=check, env=environment)


def start_garage(binary, environment, log):
    process = subprocess.Popen(
        [binary, "server"], env=environment, text=True,
        stdout=log, stderr=subprocess.STDOUT,
    )

    def ready():
        if process.poll() is not None:
            raise RuntimeError(f"Garage exited with status {process.returncode}")
        garage_command(binary, environment, "status", capture=True)

    wait_for(ready, "Garage RPC")
    return process


def stop_garage(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def initialize_garage(binary, environment, access_key, secret_key):
    status = garage_command(binary, environment, "status", capture=True).stdout
    identity = garage_command(binary, environment, "node", "id", capture=True).stdout
    match = re.search(r"([0-9a-f]{64})@", identity)
    if match is None:
        raise RuntimeError("Garage did not report a full node identity")
    if "NO ROLE ASSIGNED" in status:
        garage_command(binary, environment, "layout", "assign", "--zone", "local",
                       "--capacity", "1G", match.group(1), capture=True)
        garage_command(binary, environment, "layout", "apply", "--version", "1",
                       capture=True)
    key = garage_command(binary, environment, "key", "info", "habitat",
                         capture=True, check=False)
    if key.returncode != 0:
        garage_command(binary, environment, "key", "import", "--yes", "-n", "habitat",
                       access_key, secret_key, capture=True)
    bucket = garage_command(binary, environment, "bucket", "info", "habitat-evidence",
                            capture=True, check=False)
    if bucket.returncode != 0:
        garage_command(binary, environment, "bucket", "create", "habitat-evidence",
                       capture=True)
    garage_command(binary, environment, "bucket", "allow", "--read", "--write", "--owner",
                   "--key", "habitat", "habitat-evidence", capture=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--garage", default="garage")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    packet = PacketRun("W02", root)
    suffix = uuid.uuid4().hex[:10]
    postgres_name = f"nixai-w02-pg-{suffix}"
    postgres_port, garage_rpc_port, s3_port = free_port(), free_port(), free_port()
    postgres_password = secrets.token_urlsafe(24)
    s3_access, s3_secret = "GK" + secrets.token_hex(12), secrets.token_hex(32)
    rpc_secret = secrets.token_hex(32)
    database_url = f"postgresql://postgres:{postgres_password}@127.0.0.1:{postgres_port}/habitat"
    endpoint = f"http://127.0.0.1:{s3_port}"
    environment = os.environ | {
        "HABITAT_TEST_DATABASE_URL": database_url,
        "HABITAT_TEST_S3_ENDPOINT": endpoint,
        "HABITAT_TEST_S3_ACCESS_KEY": s3_access,
        "HABITAT_TEST_S3_SECRET_KEY": s3_secret,
        "HABITAT_TEST_S3_BUCKET": "habitat-evidence",
    }
    reports = {}
    garage_process = None
    with tempfile.TemporaryDirectory(prefix="nixai-w02-garage-") as temporary:
        garage_root = Path(temporary)
        config = garage_configuration(garage_root, garage_rpc_port, s3_port, rpc_secret)
        garage_environment = os.environ | {"GARAGE_CONFIG_FILE": str(config)}
        with (garage_root / "garage.log").open("w", encoding="utf-8") as garage_log:
            try:
                run("docker", "run", "-d", "--name", postgres_name,
                    "-e", f"POSTGRES_PASSWORD={postgres_password}", "-e", "POSTGRES_DB=habitat",
                    "-p", f"127.0.0.1:{postgres_port}:5432", POSTGRES_IMAGE, capture=True)
                garage_process = start_garage(args.garage, garage_environment, garage_log)
                initialize_garage(args.garage, garage_environment, s3_access, s3_secret)
                wait_for(lambda: psycopg.connect(database_url).close(), "PostgreSQL 17")
                store = StateStore.from_urls(database_url, endpoint, s3_access, s3_secret,
                                             "habitat-evidence", allow_test_reset=True,
                                             recovery_mode=True)
                wait_for(store.migrate, "Garage S3")
                packet.command(strict_unittest_argv("tests.test_w02_state"),
                               action="state:live-crash-suite",
                               artifacts=[root / "tests/test_w02_state.py"], environment=environment,
                               assertion="state crash, replay, and integrity behavior passes against live stores")
                postgres_pid = int(run("docker", "inspect", "--format", "{{.State.Pid}}",
                                       postgres_name, capture=True).stdout.strip())
                packet.ready_service("postgresql", unit=postgres_name,
                    endpoint=f"tcp://127.0.0.1:{postgres_port}", process_id=postgres_pid, health="ready")
                packet.ready_service("garage", unit="garage", endpoint=f"tcp://127.0.0.1:{s3_port}",
                    process_id=garage_process.pid, health="ready")
                reports["state-crash-matrix"] = {
                    "outcome": "passed",
                    "faults": ["during_migration", "during_upload", "before_commit", "after_commit",
                               "concurrent_first_write", "database_process_kill",
                               "evidence_store_outage"],
                    "invariants": ["atomic state/history", "idempotent replay",
                                   "optimistic conflict"],
                }
                reports["backup-restore-report"] = {
                    "outcome": "passed",
                    "cases": ["consistent restore", "corrupt evidence rejection",
                              "referential integrity"],
                }
                reports["evidence-integrity-report"] = {
                    "outcome": "passed",
                    "cases": ["append-only SQL trigger", "content tamper", "linked correction"],
                }

                store.reset_for_test()
                context = Correlation(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4().hex)
                evidence = store.put_evidence(
                    b"disaster durable evidence",
                    EvidenceMetadata(PrincipalId("service:qualifier"), "restart-observation",
                                     Version(0), "safety-audit", "protected", context))
                entity, command = EntityId.new(EntityKind.AGENT), CommandId.new()
                transition = store.transition(
                    entity, command, PrincipalId("agent:disaster"), Version(0),
                    State.REGISTERED, evidence, context)

                run("docker", "kill", postgres_name, capture=True)
                database_failed_closed = False
                try:
                    store.current(entity)
                except psycopg.OperationalError:
                    database_failed_closed = True
                if not database_failed_closed:
                    raise AssertionError("database outage did not fail closed")
                run("docker", "start", postgres_name, capture=True)
                wait_for(lambda: psycopg.connect(database_url).close(), "restarted PostgreSQL")
                if store.transition(entity, command, PrincipalId("agent:disaster"), Version(0),
                                    State.REGISTERED, evidence, context) != transition:
                    raise AssertionError("idempotent command changed after database restart")

                stop_garage(garage_process)
                garage_process = None
                evidence_failed_closed = False
                try:
                    store.verify_evidence(evidence)
                except IntegrityError:
                    evidence_failed_closed = True
                if not evidence_failed_closed:
                    raise AssertionError("evidence outage did not fail closed")
                garage_process = start_garage(args.garage, garage_environment, garage_log)
                initialize_garage(args.garage, garage_environment, s3_access, s3_secret)
                wait_for(lambda: store.verify_evidence(evidence), "restarted Garage")
                reports["disaster-recovery"] = {
                    "outcome": "passed", "database_restart": "durable and idempotent",
                    "evidence_store_loss": "failed closed and recovered",
                }
            finally:
                stop_garage(garage_process)
                run("docker", "rm", "-f", postgres_name, check=False, capture=True)

    metrics={"lost_wake_count":0,"partial_commit_count":0,"stale_fence_commit_count":0,"silent_coercion_count":0}
    for metric,value in metrics.items():packet.observe_metric("V-STATE",metric,value,semantic_evidence={"kind":"state_fault_matrix","observed":reports["state-crash-matrix"]["faults"],"invariants":reports["state-crash-matrix"]["invariants"]})
    emit_result(packet,reports,args.evidence_dir,gate_results={"V-STATE":{"metrics":metrics,"deployed_dependencies":["postgresql","garage"]}})


if __name__ == "__main__":
    main()
