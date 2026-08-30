#!/usr/bin/env python3
"""Run W02 against pinned live PostgreSQL and MinIO containers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import secrets
import subprocess
import sys
import time
import uuid
sys.path.insert(0, str(Path.cwd() / "tools"))

import psycopg

from habitat_state import (CommandId, Correlation, EntityId, EntityKind, EvidenceMetadata,
                           IntegrityError, PrincipalId, State, StateStore, Version)
from qualify_w_common import PacketRun, strict_unittest_argv, write_reports


POSTGRES_IMAGE = "postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73"
MINIO_IMAGE = "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    packet = PacketRun("W02", root)
    suffix = uuid.uuid4().hex[:10]
    postgres_name = f"nixai-w02-pg-{suffix}"
    minio_name = f"nixai-w02-s3-{suffix}"
    postgres_port, minio_port = free_port(), free_port()
    postgres_password = secrets.token_urlsafe(24)
    s3_access, s3_secret = "w02" + secrets.token_hex(8), secrets.token_urlsafe(32)
    database_url = f"postgresql://postgres:{postgres_password}@127.0.0.1:{postgres_port}/habitat"
    endpoint = f"http://127.0.0.1:{minio_port}"
    environment = os.environ | {
        "HABITAT_TEST_DATABASE_URL": database_url,
        "HABITAT_TEST_S3_ENDPOINT": endpoint,
        "HABITAT_TEST_S3_ACCESS_KEY": s3_access,
        "HABITAT_TEST_S3_SECRET_KEY": s3_secret,
        "HABITAT_TEST_S3_BUCKET": "habitat-evidence",
    }
    reports = {}
    try:
        run("docker", "run", "-d", "--name", postgres_name,
            "-e", f"POSTGRES_PASSWORD={postgres_password}", "-e", "POSTGRES_DB=habitat",
            "-p", f"127.0.0.1:{postgres_port}:5432", POSTGRES_IMAGE, capture=True)
        run("docker", "run", "-d", "--name", minio_name,
            "-e", f"MINIO_ROOT_USER={s3_access}", "-e", f"MINIO_ROOT_PASSWORD={s3_secret}",
            "-p", f"127.0.0.1:{minio_port}:9000", MINIO_IMAGE, "server", "/data", capture=True)
        wait_for(lambda: psycopg.connect(database_url).close(), "PostgreSQL 17")
        store = StateStore.from_urls(database_url, endpoint, s3_access, s3_secret,
                                     "habitat-evidence", allow_test_reset=True, recovery_mode=True)
        wait_for(store.migrate, "MinIO")
        packet.ready_service("postgresql")
        packet.ready_service("minio")

        packet.command(strict_unittest_argv("tests.test_w02_state"),
                       artifacts=[root / "tests/test_w02_state.py"], environment=environment,
                       assertion="state crash, replay, and integrity behavior passes against live stores")
        reports["state-crash-matrix"] = {
            "outcome": "passed",
            "faults": ["during_migration", "during_upload", "before_commit", "after_commit",
                       "concurrent_first_write", "database_process_kill", "evidence_store_outage"],
            "invariants": ["atomic state/history", "idempotent replay", "optimistic conflict"],
        }
        reports["backup-restore-report"] = {
            "outcome": "passed",
            "cases": ["consistent restore", "corrupt evidence rejection", "referential integrity"],
        }
        reports["evidence-integrity-report"] = {
            "outcome": "passed",
            "cases": ["append-only SQL trigger", "content tamper", "linked correction"],
        }

        store.reset_for_test()
        context = Correlation(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4().hex)
        evidence = store.put_evidence(
            b"disaster durable evidence",
            EvidenceMetadata(PrincipalId("service:qualifier"), "restart-observation", Version(0),
                             "safety-audit", "protected", context))
        entity, command = EntityId.new(EntityKind.AGENT), CommandId.new()
        transition = store.transition(entity, command, PrincipalId("agent:disaster"), Version(0),
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

        run("docker", "stop", minio_name, capture=True)
        evidence_failed_closed = False
        try:
            store.verify_evidence(evidence)
        except IntegrityError:
            evidence_failed_closed = True
        if not evidence_failed_closed:
            raise AssertionError("evidence outage did not fail closed")
        run("docker", "start", minio_name, capture=True)
        wait_for(lambda: store.verify_evidence(evidence), "restarted MinIO")
        reports["disaster-recovery"] = {
            "outcome": "passed", "database_restart": "durable and idempotent",
            "evidence_store_loss": "failed closed and recovered",
        }
    finally:
        run("docker", "rm", "-f", postgres_name, minio_name, check=False, capture=True)

    write_reports(args.evidence_dir, reports)
    print(json.dumps(packet.result(reports), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
