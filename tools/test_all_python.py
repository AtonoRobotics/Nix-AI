#!/usr/bin/env python3
"""Run the complete Python suite against provisioned PostgreSQL and Garage."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path.cwd() / "tools"))

import psycopg

from qualify_w02 import (
    POSTGRES_IMAGE,
    free_port,
    garage_configuration,
    initialize_garage,
    run,
    start_garage,
    stop_garage,
    wait_for,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--garage", default="garage")
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:10]
    postgres_name = f"nixai-python-pg-{suffix}"
    postgres_port, garage_rpc_port, s3_port = free_port(), free_port(), free_port()
    postgres_password = secrets.token_urlsafe(24)
    s3_access, s3_secret = "GK" + secrets.token_hex(12), secrets.token_hex(32)
    rpc_secret = secrets.token_hex(32)
    database_url = (
        f"postgresql://postgres:{postgres_password}@127.0.0.1:{postgres_port}/habitat"
    )
    environment = os.environ | {
        "HABITAT_TEST_DATABASE_URL": database_url,
        "HABITAT_TEST_S3_ENDPOINT": f"http://127.0.0.1:{s3_port}",
        "HABITAT_TEST_S3_ACCESS_KEY": s3_access,
        "HABITAT_TEST_S3_SECRET_KEY": s3_secret,
        "HABITAT_TEST_S3_BUCKET": "habitat-evidence",
    }
    garage_process = None
    with tempfile.TemporaryDirectory(prefix="nixai-python-garage-") as temporary:
        garage_root = Path(temporary)
        config = garage_configuration(
            garage_root, garage_rpc_port, s3_port, rpc_secret
        )
        garage_environment = os.environ | {"GARAGE_CONFIG_FILE": str(config)}
        with (garage_root / "garage.log").open("w", encoding="utf-8") as garage_log:
            try:
                run(
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    postgres_name,
                    "-e",
                    f"POSTGRES_PASSWORD={postgres_password}",
                    "-e",
                    "POSTGRES_DB=habitat",
                    "-p",
                    f"127.0.0.1:{postgres_port}:5432",
                    POSTGRES_IMAGE,
                    capture=True,
                )
                garage_process = start_garage(
                    args.garage, garage_environment, garage_log
                )
                initialize_garage(
                    args.garage, garage_environment, s3_access, s3_secret
                )
                wait_for(
                    lambda: psycopg.connect(database_url).close(), "PostgreSQL 17"
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        "tests",
                        "-v",
                    ],
                    cwd=Path.cwd(),
                    env=environment,
                    text=True,
                    capture_output=True,
                )
                sys.stdout.write(completed.stdout)
                sys.stderr.write(completed.stderr)
                if completed.returncode != 0:
                    raise SystemExit(completed.returncode)
                combined = completed.stdout + completed.stderr
                skipped = re.search(r"skipped=(\d+)", combined)
                if skipped and int(skipped.group(1)) != 0:
                    raise RuntimeError(
                        f"full Python suite reported {skipped.group(1)} skips"
                    )
            finally:
                stop_garage(garage_process)
                run(
                    "docker",
                    "rm",
                    "-f",
                    postgres_name,
                    check=False,
                    capture=True,
                )


if __name__ == "__main__":
    main()
