"""State process composition, migration, startup recovery, and socket lifecycle."""
import os
from pathlib import Path
import socket
import stat
import time

from .errors import LedgerUnavailable
from .evidence import EvidenceStore
from .protocol import CommandLedgerServer
from .repository import PostgresRepository

def prepare_socket_path(socket_path):
    socket_path=Path(socket_path)
    if not socket_path.exists(): return
    if not stat.S_ISSOCK(socket_path.lstat().st_mode): raise RuntimeError(f"refusing to replace non-socket path: {socket_path}")
    stale_inode=socket_path.lstat().st_ino
    probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); probe.settimeout(0.25)
    try: probe.connect(str(socket_path))
    except (ConnectionRefusedError,FileNotFoundError): pass
    else: raise RuntimeError(f"state socket is already live: {socket_path}")
    finally: probe.close()
    if not socket_path.exists() or socket_path.lstat().st_ino!=stale_inode:
        raise RuntimeError("state socket changed during stale-socket check")
    socket_path.unlink()

def cleanup_owned_socket(socket_path,owned_inode):
    socket_path=Path(socket_path)
    if (socket_path.exists() and stat.S_ISSOCK(socket_path.lstat().st_mode)
            and owned_inode==socket_path.lstat().st_ino): socket_path.unlink()


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description="PostgreSQL-backed Habitat state authority")
    parser.add_argument("socket"); parser.add_argument("--database-url",default=os.environ.get("HABITAT_DATABASE_URL"))
    parser.add_argument("--object-store-credential",default=os.environ.get("HABITAT_OBJECT_STORE_CREDENTIAL"))
    parser.add_argument("--mode",type=lambda value:int(value,8),default=0o660)
    parser.add_argument("--allow-service",action="append",default=[]); parser.add_argument("--effect-uid",type=int)
    parser.add_argument("--effect-token-credential"); arguments=parser.parse_args(argv)
    if not arguments.database_url: parser.error("--database-url or HABITAT_DATABASE_URL is required")
    if not arguments.object_store_credential: parser.error("--object-store-credential or HABITAT_OBJECT_STORE_CREDENTIAL is required")
    socket_path=Path(arguments.socket)
    prepare_socket_path(socket_path)
    repository=PostgresRepository(arguments.database_url); repository.migrate()
    active_generation=os.environ.get("HABITAT_ACTIVE_GENERATION")
    if not active_generation: raise LedgerUnavailable("active system generation is unavailable")
    repository.ensure_active_generation(active_generation)
    recovery=repository.recover(now=int(time.time())); evidence=EvidenceStore(arguments.object_store_credential,repository)
    if arguments.effect_uid is None or not arguments.effect_token_credential:
        parser.error("--effect-uid and --effect-token-credential are required")
    try: effect_token=Path(arguments.effect_token_credential).read_text(encoding="utf-8").strip()
    except OSError as error: raise LedgerUnavailable("effect admission token unavailable") from error
    if len(effect_token)<32: raise LedgerUnavailable("effect admission token is too short")
    principals={}
    for binding in arguments.allow_service:
        try:
            service,identity=binding.rsplit("=",1);uid_text,gid_text,unit=identity.split(":",2)
            uid,gid=int(uid_text),int(gid_text)
        except (ValueError,TypeError): parser.error("--allow-service must be SERVICE=UID:GID:UNIT")
        if service not in {"service:abi","service:scheduler","service:authority","service:effects","service:packages","service:runtime",
                "service:controller","service:evaluator","service:signer","service:health"}:
            parser.error("unknown state service principal")
        if unit != "habitat-"+service.removeprefix("service:")+".service": parser.error("service principal unit mismatch")
        if (uid,gid,unit) in principals: parser.error("a process identity may identify only one state service principal")
        principals[(uid,gid,unit)]=service
    try:
        with CommandLedgerServer(str(socket_path),repository,
            recovery=recovery,evidence=evidence,principals=principals,
            effect_uid=arguments.effect_uid,effect_token=effect_token,
            test_faults=os.getenv("HABITAT_TEST_FAULTS")=="1") as server:
            owned_inode=socket_path.lstat().st_ino
            socket_path.chmod(arguments.mode); server.serve_forever()
    finally:
        cleanup_owned_socket(socket_path,locals().get("owned_inode"))
