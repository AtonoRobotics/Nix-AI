"""UDS framing, peer authorization, and protocol-to-repository translation."""
import hmac
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import time

from .errors import EvidenceNotFound, LedgerCorrupt, LedgerUnavailable

def _process_start_time(stat):
    try:return int(stat.rsplit(")",1)[1].split()[19])
    except (IndexError,ValueError):raise RuntimeError("peer process stat is malformed") from None

def observe_process_identity(pid,uid,gid,read_text=None):
    read_text=read_text or (lambda path:Path(path).read_text(encoding="utf-8"))
    before=_process_start_time(read_text(f"/proc/{pid}/stat"));cgroup=read_text(f"/proc/{pid}/cgroup")
    after=_process_start_time(read_text(f"/proc/{pid}/stat"))
    if before!=after:raise RuntimeError("peer process changed during observation")
    units=set()
    for line in cgroup.splitlines():
        fields=line.split(":",2)
        if len(fields)!=3 or not fields[0].isdigit() or "/" in fields[1] or not fields[2].startswith("/") or "//" in fields[2]:
            raise RuntimeError("peer cgroup data is malformed")
        unit=next((part for part in reversed(fields[2].split("/")) if part),None)
        if unit:units.add(unit)
    if len(units)!=1:raise RuntimeError("peer systemd unit is ambiguous")
    return (pid,uid,gid,next(iter(units)))

def resolve_principal(principals,identity):
    _,uid,gid,unit=identity;return principals.get((uid,gid,unit))


class StateProtocol:
    def __init__(self, repository, evidence, recovery):
        self.repository = repository
        if hasattr(repository,"bind_evidence"):repository.bind_evidence(evidence)
        self.recovery = recovery

    def dispatch(self, request, principal=None):
        operation = request.get("operation")
        if operation == "evidence_put":
            return self.repository.put_evidence(request["envelope"],principal,request.get("command_id"))
        if operation == "effect_transition":
            return self.repository.apply_verified_effect_transition(request)
        if operation == "effect_observe":
            return self.repository.observe_verified_effect(request["objective_id"],request["effect_id"])
        if operation == "effect_guard":
            return self.repository.guard_objective_effects(request["objective_id"], request["effect_ids"], request["effect_set_digest"])
        if operation == "effect_guard_invalidate":
            return self.repository.invalidate_objective_effect_guard(request["objective_id"], request["compensates_effect_id"])
        if operation == "commit_command":
            if principal!="service:abi": raise ValueError("command commit requires ABI principal")
            return self.repository.commit_verified_command(request["activation_id"],request["command_id"],request["request_digest"],request["result"],principal)
        if operation == "get_command":
            return self.repository.get_command(request["activation_id"], request["command_id"])
        if operation == "change_propose":
            if principal!="service:controller" or request["evaluator"]!="service:evaluator":
                raise ValueError("governed proposal requires controller and protected evaluator")
            return self.repository.propose_verified_change(request,principal)
        if operation == "change_transition":
            owners={"BUILT":"service:controller","EVALUATED":"service:evaluator",
              "SIGNED":"service:signer","STAGED":"service:controller","ACTIVATED":"service:controller",
              "CONFIRMED":"service:health","REJECTED":"service:evaluator",
              "QUARANTINED":"service:health","ROLLED_BACK":"service:controller"}
            if owners.get(request["new_state"])!=principal or request["actor"]!=principal:
                raise ValueError("governed transition principal mismatch")
            return self.repository.transition_verified_change(request,principal)
        if operation == "change_get":
            limit=request.get("limit",50);cursor=request.get("cursor",0)
            if not isinstance(limit,int) or not 1<=limit<=100 or not isinstance(cursor,int) or cursor<0:
                raise ValueError("invalid pagination")
            return {"record":self.repository.governed_change(request["candidate_id"]),
                    "history":self.repository.governed_change_history(request["candidate_id"],limit,cursor),
                    "next_cursor":cursor+limit}
        if operation == "package_admit":
            return self.repository.admit_verified_package(request)
        if operation == "runtime_status":
            self.recovery=self.repository.recover(now=int(time.time()))
            return {"readiness":"READY" if self.recovery["effects_classified"] else "RECOVERING",
                    "migrations":True,"leases_fenced":True,
                    "effects_classified":self.recovery["effects_classified"],
                    "wakes_redelivered":self.recovery["wakes_redelivered"]}
        if operation == "runtime_schedule":
            objective=request["objective_id"]
            if not objective or len(objective)>128: raise ValueError("invalid objective identity")
            return self.repository.schedule_objective(objective,now=int(time.time()))
        if operation == "runtime_tick":
            return {"completion":self.repository.complete_ready_objective(now=int(time.time()))}
        if operation == "runtime_inspect":
            return self.repository.inspect_objective(request["objective_id"])
        if operation == "runtime_pending":
            return {"objectives":self.repository.pending_objectives(request.get("limit",100))}
        if operation == "authority_get":
            limit=request.get("limit",50);cursor=request.get("cursor",0)
            if not isinstance(limit,int) or not 1<=limit<=100 or not isinstance(cursor,int) or cursor<0:
                raise ValueError("invalid pagination")
            return self.repository.authority_binding(request["binding_id"],limit,cursor)
        if operation == "authority_commit":
            return self.repository.commit_verified_authority(request)
        raise ValueError("unknown operation")

class _StateHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(self.server.io_timeout)
        pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        try:principal=resolve_principal(self.server.principals,self.server.identity_observer(pid,uid,gid))
        except (OSError,RuntimeError):principal=None
        if principal is None: return self._send({"status":"unauthorized","code":"UNAUTHORIZED"})
        header = self.rfile.read(4)
        if len(header)!=4:return self._send({"status":"corrupt","message":"invalid request framing"})
        length=struct.unpack(">I",header)[0]
        if length==0 or length>self.server.max_request_bytes:return self._send({"status":"corrupt","message":"invalid request framing"})
        raw=self.rfile.read(length)
        if len(raw)!=length:return self._send({"status":"corrupt","message":"truncated request frame"})
        try:
            request = json.loads(raw)
            if not isinstance(request,dict): raise ValueError("request must be a JSON object")
            operation = request.get("operation")
            if operation not in self.server.operations.get(principal,frozenset()):
                return self._send({"status":"unauthorized","code":"UNAUTHORIZED"})
            if operation and operation.startswith("effect_") and (uid != self.server.effect_uid or not hmac.compare_digest(str(request.get("admission_token", "")), self.server.effect_token)):
                return self._send({"status":"unauthorized","code":"UNAUTHORIZED"})
            result = self.server.protocol.dispatch(request,principal)
            if isinstance(result, dict) and set(result) == {"status", "result"}: self._send(result)
            else: self._send({"status":"ok","result":result})
            if operation == "effect_transition":
                fault = Path("/run/habitat/state/fault-after-effect-commit")
                if self.server.test_faults and fault.exists(): fault.unlink(); os._exit(86)
        except EvidenceNotFound as error: self._send({"status":"not_found","message":str(error)})
        except LedgerCorrupt as error: self._send({"status":"corrupt","message":str(error)})
        except LedgerUnavailable as error: self._send({"status":"unavailable","message":str(error)})
        except (TimeoutError,socket.timeout): self._send({"status":"unavailable","message":"request deadline exceeded"})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error: self._send({"status":"corrupt","message":str(error)})
    def _send(self, response):
        payload=json.dumps(response,separators=(",", ":")).encode()
        if len(payload)>self.server.max_response_bytes:
            payload=b'{"status":"unavailable","message":"response exceeds configured bound"}'
        self.wfile.write(struct.pack(">I",len(payload))+payload)


class CommandLedgerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    def __init__(self, path, repository, *, recovery=None, evidence=None,
                 principals=None, effect_uid=None, effect_token="", max_request_bytes=2*1024*1024,
                 max_response_bytes=2*1024*1024,io_timeout=10.0,max_workers=32,test_faults=False,
                 identity_observer=observe_process_identity):
        self.protocol = StateProtocol(repository, evidence, recovery or {})
        self.principals=dict(principals or {})
        self.identity_observer=identity_observer
        self.operations={
          "service:abi":frozenset({"evidence_put","commit_command","get_command"}),
          "service:scheduler":frozenset({"runtime_status","runtime_schedule","runtime_tick","runtime_inspect"}),
          "service:runtime":frozenset({"evidence_put","runtime_status","runtime_schedule","runtime_tick","runtime_inspect","runtime_pending","change_propose","change_transition","change_get","package_admit","effect_guard","effect_guard_invalidate"}),
          "service:authority":frozenset({"evidence_put","authority_get","authority_commit"}),
          "service:effects":frozenset({"evidence_put","effect_transition","effect_observe","effect_guard","effect_guard_invalidate","runtime_inspect"}),
          "service:controller":frozenset({"evidence_put","change_propose","change_transition","change_get","package_admit"}),
          "service:evaluator":frozenset({"evidence_put","change_transition","change_get"}),
          "service:signer":frozenset({"evidence_put","change_transition","change_get"}),
          "service:health":frozenset({"evidence_put","change_transition","change_get"}),
        }
        self.effect_uid=effect_uid
        self.effect_token=effect_token; self.max_request_bytes=max_request_bytes
        self.max_response_bytes=max_response_bytes; self.test_faults=test_faults
        self.io_timeout=io_timeout; self._capacity=__import__("threading").BoundedSemaphore(max_workers)
        super().__init__(path, _StateHandler)
    def process_request(self,request,client_address):
        if not self._capacity.acquire(blocking=False):
            payload=json.dumps({"status":"unavailable","message":"state worker capacity exhausted"},separators=(",", ":")).encode()
            try:request.sendall(struct.pack(">I",len(payload))+payload)
            finally:request.close()
            return
        try: super().process_request(request,client_address)
        except Exception:
            self._capacity.release(); raise
    def process_request_thread(self,request,client_address):
        try: super().process_request_thread(request,client_address)
        finally:self._capacity.release()
