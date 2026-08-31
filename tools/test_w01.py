#!/usr/bin/env python3
"""Live UEFI/QEMU qualification for Habitat W01."""

import argparse
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import sys
sys.path.insert(0, str(Path.cwd() / "tools"))
from qualify_w_common import PacketRun


FORBIDDEN = re.compile(r"emergency mode|emergency shell|password:|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", re.I)


def decode_event_line(line: str):
    clean = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|P.*?\\|\].*?\\)", "", line).strip()
    start = clean.find("{")
    end = clean.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        return json.loads(clean[start:end + 1])
    except json.JSONDecodeError:
        return None


def boot(qemu: str, code: str, disk: Path, variables: Path, log: Path, expected: str,
         timeout: int = 120, required_text: str | None = None):
    log.write_text("")
    qmp = log.with_suffix(".qmp")
    with log.open("ab", buffering=0) as serial:
        process = subprocess.Popen(
            [qemu, "-machine", "q35,accel=tcg", "-m", "2048", "-smp", "2",
             "-display", "none", "-monitor", "none", "-qmp", f"unix:{qmp},server=on,wait=off",
             "-serial", "file:" + str(log),
             "-no-reboot", "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
             "-drive", f"if=pflash,format=raw,file={variables}",
             "-drive", f"if=virtio,format=qcow2,file={disk}"],
            stdout=subprocess.DEVNULL, stderr=serial,
        )
        deadline = time.monotonic() + timeout
        event = None
        runtime_event = None
        try:
            while time.monotonic() < deadline:
                text = log.read_text(errors="replace")
                if FORBIDDEN.search(text):
                    raise AssertionError("forbidden interactive/emergency/secret output observed")
                for line in text.splitlines():
                    candidate = decode_event_line(line)
                    if candidate is None:
                        continue
                    if candidate.get("event") == "habitat.bootstrap":
                        event = candidate
                    elif candidate.get("event") == "habitat.runtime":
                        runtime_event = candidate
                if (event and event.get("decision") == expected and runtime_event
                        and runtime_event.get("outcome") == "passed"
                        and (required_text is None or required_text in text)):
                    return event, runtime_event
                if process.poll() is not None:
                    raise AssertionError(f"QEMU exited before {expected}; see {log}")
                time.sleep(0.25)
            raise TimeoutError(f"timed out waiting for {expected}; serial tail:\n{text[-4000:]}")
        finally:
            if process.poll() is None and qmp.exists():
                try:
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(3)
                        client.connect(str(qmp))
                        client.recv(4096)
                        client.sendall(b'{"execute":"qmp_capabilities"}\n')
                        client.recv(4096)
                        client.sendall(b'{"execute":"system_powerdown"}\n')
                except OSError:
                    pass
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait()


def validate_common(event):
    assert event["health_result"] == "PRE_OPERATIONAL"
    assert event["hardware_profile_id"] == "qemu-x86_64-conformance"
    assert event["protections"] == {"nix_store_read_only": True, "recovery_read_only": True}
    assert event["closure_digest"].startswith("sha256:")


def validate_runtime(event):
    assert event["outcome"] == "passed"
    assert event["objective_state"] == "SATISFIED"
    assert event["effect_state"] == "COMMITTED"
    assert event["evidence_ref"].startswith("s3://habitat-evidence/sha256/")
    assert event["interruptions"] == []
    assert event["duplicate_resume"] == "original_disposition"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("boot", "rollback"))
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--code", required=True)
    parser.add_argument("--vars", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--evidence")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    packet = PacketRun("W01", root)

    with tempfile.TemporaryDirectory(prefix="habitat-w01-") as directory:
        work = Path(directory)
        disk = work / "habitat.qcow2"
        variables = work / "OVMF_VARS.fd"
        shutil.copy2(args.disk, disk)
        shutil.copy2(args.vars, variables)
        disk.chmod(0o600)
        variables.chmod(0o600)
        events = []
        runtime_events = []

        first, first_runtime = boot(
            args.qemu, args.code, disk, variables, work / "boot-1.log", "UNCONFIRMED",
            required_text='"event":"habitat.generation.candidate_installed"')
        validate_common(first)
        validate_runtime(first_runtime)
        events.append(first)
        runtime_events.append(first_runtime)

        if args.mode == "boot":
            second, second_runtime = boot(
                args.qemu, args.code, disk, variables, work / "boot-2.log", "ACTIVE_UNCONFIRMED")
            validate_common(second)
            validate_runtime(second_runtime)
            assert second["machine_id"] == first["machine_id"]
            assert second["boot_attempt_id"] != first["boot_attempt_id"]
            assert second["history_count"] >= 1
            events.append(second)
            runtime_events.append(second_runtime)
        else:
            candidate, candidate_runtime = boot(
                args.qemu, args.code, disk, variables, work / "boot-2.log",
                "ACTIVE_UNCONFIRMED",
                required_text='"event":"habitat.generation.candidate_rejected"')
            rollback, rollback_runtime = boot(
                args.qemu, args.code, disk, variables, work / "boot-3.log", "ROLLED_BACK")
            for event in (candidate, rollback):
                validate_common(event)
            for event in (candidate_runtime, rollback_runtime):
                validate_runtime(event)
            assert rollback["machine_id"] == first["machine_id"] == candidate["machine_id"]
            assert rollback["system_generation_id"] == first["system_generation_id"]
            assert candidate["system_generation_id"] != first["system_generation_id"]
            assert candidate["closure_digest"] != first["closure_digest"]
            assert rollback["previous_confirmed_generation_id"] == first["system_generation_id"]
            assert rollback["operational_state"] == "baseline-durable-state"
            assert rollback["history_count"] >= 2
            events.extend((candidate, rollback))
            runtime_events.extend((candidate_runtime, rollback_runtime))

        report = {"schema_version": "1.0", "gate": "V-BOOT" if args.mode == "boot" else "V-ROLLBACK",
                  "result": "pass", "events": events, "runtime_events": runtime_events}
        observed = work / "observed-events.json";observed.write_text(json.dumps(report,sort_keys=True)+"\n")
        verifier="""import json,sys
d=json.load(open(sys.argv[1]));assert d['result']=='pass' and len(d['events'])>=2
assert all(e['health_result']=='PRE_OPERATIONAL' and e['closure_digest'].startswith('sha256:') for e in d['events'])
assert len(d['runtime_events'])==len(d['events'])
assert all(e['outcome']=='passed' and e['objective_state']=='SATISFIED' for e in d['runtime_events'])
"""
        packet.command([sys.executable,"-c",verifier,observed],artifacts=[observed,Path(args.disk)],assertion="fresh QEMU boots produced valid generation events")
        packet.ready_service("qemu-guest")
        envelope=packet.result({"qemu-observation":report})
        envelope.update({"schema_version":"2.0","gate":report["gate"],"result":"pass","events":events})
        rendered=json.dumps(envelope,indent=2,sort_keys=True)+"\n"
        if args.evidence:Path(args.evidence).write_text(rendered)
        print(rendered,end="")


if __name__ == "__main__":
    main()
