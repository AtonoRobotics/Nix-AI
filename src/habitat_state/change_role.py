"""Peer-authenticated governed-change authority service."""
import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import time

from .protocol import observe_process_identity, resolve_principal


ROLE_STATES = {
    "controller": frozenset({"BUILT", "STAGED", "ACTIVATED", "ROLLED_BACK"}),
    "evaluator": frozenset({"EVALUATED", "REJECTED"}),
    "signer": frozenset({"SIGNED"}),
    "health": frozenset({"CONFIRMED", "QUARANTINED"}),
}


def exchange(path, request, maximum=1024 * 1024):
    payload = json.dumps(request, separators=(",", ":")).encode()
    if len(payload) > maximum:
        raise ValueError("change request exceeds configured bound")
    deadline = time.monotonic() + 30
    while True:
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(10)
        try:
            client.connect(path)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with client:
        client.sendall(struct.pack("!I", len(payload)) + payload)
        header = client.recv(4)
        if len(header) != 4:
            raise ConnectionError("truncated response header")
        length = struct.unpack("!I", header)[0]
        if length > maximum:
            raise ValueError("change response exceeds configured bound")
        body = b""
        while len(body) < length:
            chunk = client.recv(length - len(body))
            if not chunk:
                raise ConnectionError("truncated response frame")
            body += chunk
    return json.loads(body)


class ChangeRole:
    def __init__(self, role, state_socket):
        if role not in ROLE_STATES:
            raise ValueError("unknown governed-change role")
        self.role = role
        self.principal = f"service:{role}"
        self.state_socket = state_socket

    def _accepted(self, request):
        response = exchange(self.state_socket, request)
        if response.get("status") != "ok":
            raise ValueError(f"state rejected governed change: {response}")
        return response["result"]

    def dispatch(self, request):
        operation = request.get("operation")
        if operation == "STATUS":
            return {"readiness": "READY", "role": self.principal}
        if operation == "change_get":
            return self._accepted(request)
        if operation == "change_propose":
            if self.role != "controller" or request.get("evaluator") != "service:evaluator":
                raise ValueError("only the controller may bind the protected evaluator")
            disposition, evidence_operation = "PROPOSED", "change.propose"
            evidence_source = request["source_digest"]
            payload = {key: request[key] for key in (
                "dependency_closure_digest", "contract_version", "tests_digest",
                "requested_authority", "signing_key_digest", "live_verification_contract",
                "evaluator", "evaluator_closure", "target_generation",
                "rollback_generation", "threshold")}
        elif operation == "change_transition":
            state = request.get("new_state")
            if state not in ROLE_STATES[self.role] or request.get("actor") != self.principal:
                raise ValueError("governed transition is outside this role's authority")
            disposition, evidence_operation = state, "change." + state.lower()
            evidence_source = request["evidence_source"]
            payload = request.get("observation")
            if not isinstance(payload, dict):
                raise ValueError("governed transition requires an observation")
        else:
            raise ValueError("unsupported governed-change operation")
        evidence = self._accepted({
            "operation": "evidence_put",
            "command_id": "evidence:" + request["command_id"],
            "envelope": {
                "schema_version": "1", "producer": self.principal,
                "subject": request["candidate_id"], "operation": evidence_operation,
                "source": evidence_source,
                "payload": {**payload, "disposition": disposition},
            },
        })
        governed = {key: value for key, value in request.items() if key != "observation"}
        governed["evidence_ref"] = evidence["evidence_ref"]
        governed.setdefault("evidence_source", evidence_source)
        return self._accepted(governed)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        header = self.request.recv(4)
        if len(header) != 4:
            return
        length = struct.unpack("!I", header)[0]
        if length > self.server.maximum:
            return self._send({"status": "invalid", "message": "request exceeds bound"})
        body = b""
        while len(body) < length:
            chunk = self.request.recv(length - len(body))
            if not chunk:
                return
            body += chunk
        try:
            response = self.server.role.dispatch(json.loads(body))
            self._send({"status": "ok", "result": response})
        except (KeyError, TypeError, ValueError, OSError) as error:
            self._send({"status": "rejected", "message": str(error)})

    def _send(self, response):
        payload = json.dumps(response, separators=(",", ":")).encode()
        self.request.sendall(struct.pack("!I", len(payload)) + payload)


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, role, state_socket, principals, maximum=1024 * 1024):
        Path(path).unlink(missing_ok=True)
        self.role, self.principals, self.maximum = ChangeRole(role, state_socket), principals, maximum
        super().__init__(path, Handler)
        os.chmod(path, 0o660)

    def verify_request(self, request, _address):
        pid, uid, gid = struct.unpack("3i", request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return resolve_principal(self.principals, observe_process_identity(pid, uid, gid)) is not None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=sorted(ROLE_STATES))
    parser.add_argument("socket")
    parser.add_argument("state_socket")
    parser.add_argument("peers")
    args = parser.parse_args()
    peers = json.loads(Path(args.peers).read_text())
    principals = {(item["uid"], item["gid"], item["unit"]): item["service_id"] for item in peers}
    with Server(args.socket, args.role, args.state_socket, principals) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
