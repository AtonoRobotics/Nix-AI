"""Transactional PostgreSQL command replay ledger and protected UDS adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
from dataclasses import dataclass

import psycopg
from psycopg.rows import dict_row


MIGRATION = """
CREATE TABLE IF NOT EXISTS abi_command_ledger (
  activation_id text NOT NULL,
  command_id text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  committed_result jsonb NOT NULL,
  evidence_ref text NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (activation_id, command_id),
  CHECK (jsonb_typeof(committed_result) = 'object')
);
CREATE OR REPLACE FUNCTION abi_command_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'command ledger is append-only' USING ERRCODE='42501'; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='abi_command_ledger_immutable')
THEN CREATE TRIGGER abi_command_ledger_immutable BEFORE UPDATE OR DELETE ON abi_command_ledger
FOR EACH ROW EXECUTE FUNCTION abi_command_ledger_immutable(); END IF; END $$;
"""


class LedgerUnavailable(RuntimeError):
    pass


class LedgerCorrupt(RuntimeError):
    pass


@dataclass(frozen=True)
class ReplayOutcome:
    result: dict
    duplicate: bool
    digest_mismatch: bool = False


class CommandLedgerStore:
    def __init__(self, database_url: str):
        self.database_url = database_url

    def _connect(self):
        try:
            return psycopg.connect(self.database_url, row_factory=dict_row)
        except psycopg.Error as error:
            raise LedgerUnavailable("PostgreSQL command ledger unavailable") from error

    def migrate(self):
        with self._connect() as connection:
            connection.execute(MIGRATION)

    @staticmethod
    def _validate_result(result, command_id):
        if not isinstance(result, dict) or result.get("command_id") != command_id:
            raise LedgerCorrupt("committed result is not bound to its command")
        if result.get("committed") is not True or not isinstance(result.get("state"), str):
            raise LedgerCorrupt("committed result lacks mandatory disposition fields")
        return result

    def commit(self, activation_id, command_id, request_digest, proposed) -> ReplayOutcome:
        if not all(isinstance(value, str) and value for value in
                   (activation_id, command_id, request_digest)):
            raise ValueError("activation, command, and digest are required")
        if len(request_digest) != 64 or any(c not in "0123456789abcdef" for c in request_digest):
            raise ValueError("request digest must be lowercase sha256")
        self._validate_result(proposed, command_id)
        evidence_ref = proposed.get("durable_record_id")
        if not isinstance(evidence_ref, str) or not evidence_ref:
            raise ValueError("durable record id is required")
        with self._connect() as connection:
            inserted = connection.execute(
                """INSERT INTO abi_command_ledger
                (activation_id,command_id,request_digest,committed_result,evidence_ref)
                VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING 1""",
                (activation_id, command_id, request_digest, json.dumps(proposed), evidence_ref),
            ).fetchone()
            row = connection.execute(
                """SELECT request_digest,committed_result,evidence_ref
                FROM abi_command_ledger WHERE activation_id=%s AND command_id=%s FOR SHARE""",
                (activation_id, command_id),
            ).fetchone()
            if not row:
                raise LedgerCorrupt("committed command disappeared inside transaction")
            result = self._validate_result(row["committed_result"], command_id)
            if row["request_digest"] != request_digest:
                return ReplayOutcome(result, True, True)
            return ReplayOutcome(result, inserted is None, False)

    def get(self, activation_id, command_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT committed_result FROM abi_command_ledger WHERE activation_id=%s AND command_id=%s",
                (activation_id, command_id),
            ).fetchone()
        return None if row is None else self._validate_result(row["committed_result"], command_id)


class _LedgerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", peer)
        if uid not in self.server.allowed_uids:
            self._send({"status": "unavailable", "message": "peer is not authorized"})
            return
        raw = self.rfile.readline(self.server.max_request_bytes + 1)
        if not raw or len(raw) > self.server.max_request_bytes:
            self._send({"status": "corrupt", "message": "invalid request framing"})
            return
        try:
            request = json.loads(raw)
            operation = request.get("operation")
            if operation == "commit_command":
                outcome = self.server.store.commit(
                    request["activation_id"], request["command_id"],
                    request["request_digest"], request["result"])
                status = "digest_mismatch" if outcome.digest_mismatch else "ok"
                self._send({"status": status, "result": outcome.result})
            elif operation == "get_command":
                self._send({"status": "ok", "result": self.server.store.get(
                    request["activation_id"], request["command_id"])})
            else:
                self._send({"status": "corrupt", "message": "unknown operation"})
        except LedgerCorrupt as error:
            self._send({"status": "corrupt", "message": str(error)})
        except (LedgerUnavailable, psycopg.Error) as error:
            self._send({"status": "unavailable", "message": str(error)})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self._send({"status": "corrupt", "message": str(error)})

    def _send(self, response):
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")


class CommandLedgerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, store, *, allowed_uids=None, max_request_bytes=2 * 1024 * 1024):
        self.store = store
        self.allowed_uids = frozenset(allowed_uids or {os.getuid()})
        self.max_request_bytes = max_request_bytes
        super().__init__(path, _LedgerHandler)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="PostgreSQL-backed Habitat ABI command ledger")
    parser.add_argument("socket")
    parser.add_argument("--database-url", default=os.environ.get("HABITAT_DATABASE_URL"))
    parser.add_argument("--mode", type=lambda value: int(value, 8), default=0o660)
    parser.add_argument("--allow-uid", action="append", type=int, default=[])
    arguments = parser.parse_args(argv)
    if not arguments.database_url:
        parser.error("--database-url or HABITAT_DATABASE_URL is required")
    socket_path = Path(arguments.socket)
    if socket_path.exists():
        if not stat.S_ISSOCK(socket_path.lstat().st_mode):
            raise RuntimeError(f"refusing to replace non-socket path: {socket_path}")
        socket_path.unlink()
    store = CommandLedgerStore(arguments.database_url)
    store.migrate()
    try:
        allowed_uids = set(arguments.allow_uid) | {os.getuid()}
        with CommandLedgerServer(str(socket_path), store, allowed_uids=allowed_uids) as server:
            socket_path.chmod(arguments.mode)
            server.serve_forever()
    finally:
        if socket_path.exists() and stat.S_ISSOCK(socket_path.lstat().st_mode):
            socket_path.unlink()


if __name__ == "__main__":
    main()
