import inspect
import socket
import tempfile
from pathlib import Path
import unittest

from habitat_state import command_ledger


class StateArchitectureTests(unittest.TestCase):
    def test_service_identity_requires_uid_gid_and_observed_systemd_unit(self):
        from habitat_state.protocol import observe_process_identity, resolve_principal
        stat=lambda start:"77 (worker) S "+" ".join(["1"]*18+[str(start),"0"])+"\n"
        snapshots=iter([stat(900),"0::/system.slice/habitat-effects.service\n",stat(900)])
        identity=observe_process_identity(77,100,200,read_text=lambda _:next(snapshots))
        allow={(100,200,"habitat-effects.service"):"service:effects"}
        self.assertEqual(resolve_principal(allow,identity),"service:effects")
        self.assertIsNone(resolve_principal(allow,(77,100,200,"habitat-runtime.service")))

    def test_process_identity_rejects_pid_reuse_during_observation(self):
        from habitat_state.protocol import observe_process_identity
        stat=lambda start:"77 (worker) S "+" ".join(["1"]*18+[str(start),"0"])+"\n"
        snapshots=iter([stat(900),"0::/system.slice/habitat-effects.service\n",stat(901)])
        with self.assertRaisesRegex(RuntimeError,"changed during observation"):
            observe_process_identity(77,100,200,read_text=lambda _:next(snapshots))

    def test_repository_never_mutates_domain_state_when_evidence_verification_faults(self):
        from habitat_state.repository import PostgresRepository
        class Evidence:
            def verify_record(self,*args,**kwargs): raise RuntimeError("injected evidence fault")
        class Lifecycle:
            calls=0
            def propose_governed_change(self,*args):self.calls+=1
        repository=object.__new__(PostgresRepository);repository._evidence=Evidence();repository._lifecycle=Lifecycle()
        request={"evidence_ref":"e","candidate_id":"candidate:1","source_digest":"sha256:a",
          "command_id":"command:1","evaluator":"service:evaluator","evaluator_closure":"sha256:b",
          "target_generation":"generation:2","rollback_generation":"generation:1","threshold":{}}
        with self.assertRaisesRegex(RuntimeError,"injected evidence fault"):
            repository.propose_verified_change(request,"service:controller")
        self.assertEqual(repository._lifecycle.calls,0)
    def test_command_ledger_is_only_a_compatibility_seam(self):
        source = inspect.getsource(command_ledger)
        self.assertNotIn("socketserver", source)
        self.assertNotIn("boto3", source)
        self.assertNotIn("psycopg", source)
        self.assertIs(command_ledger.CommandLedgerStore,
                      __import__("habitat_state.repository", fromlist=["CommandLedgerStore"]).CommandLedgerStore)

    def test_protocol_translation_contains_no_storage_calls(self):
        protocol = __import__("habitat_state.protocol", fromlist=["CommandLedgerServer"])
        source = inspect.getsource(protocol)
        for forbidden in ("psycopg", "boto3", "SELECT ", "INSERT ", "UPDATE ", "get_object", "put_object"):
            self.assertNotIn(forbidden, source)

    def test_protocol_does_not_sequence_evidence_and_lifecycle_adapters(self):
        protocol=inspect.getsource(__import__("habitat_state.protocol",fromlist=["StateProtocol"]).StateProtocol)
        self.assertNotIn("self.evidence",protocol)
        self.assertNotIn("verify_record",protocol)
        self.assertNotIn("put_envelope",protocol)
        repository=inspect.getsource(__import__("habitat_state.repository",fromlist=["PostgresRepository"]).PostgresRepository)
        for use_case in ("put_evidence","commit_verified_command","observe_verified_effect",
                         "propose_verified_change","transition_verified_change",
                         "admit_verified_package","commit_verified_authority"):
            self.assertIn("def "+use_case,repository)
        for deleted in ("def commit_command(","def observe_effect_transition(",
                        "def propose_governed_change(","def admit_package(",
                        "def commit_authority_snapshot("):
            self.assertNotIn(deleted,repository)

    def test_state_rejects_synthetic_effect_completion_and_caller_health_claims(self):
        protocol=inspect.getsource(__import__("habitat_state.protocol",fromlist=["StateProtocol"]))
        lifecycle=inspect.getsource(__import__("habitat_state.lifecycle",fromlist=["LifecycleStore"]))
        self.assertNotIn('operation == "effect_commit"',protocol)
        self.assertIn('operation == "effect_transition"',protocol)
        self.assertNotIn('health_ready=request',protocol)
        self.assertIn('observation.get("health_ready")',lifecycle)
        self.assertNotIn('"nonterminal_effects": 0',lifecycle)

    def test_protocol_has_bounded_framing_deadline_workers_and_object_requests(self):
        protocol=inspect.getsource(__import__("habitat_state.protocol",fromlist=["CommandLedgerServer"]))
        for required in ("max_request_bytes","io_timeout","max_workers","BoundedSemaphore",
                         "max_response_bytes","response exceeds configured bound",
                         "request must be a JSON object"):
            self.assertIn(required,protocol)

    def test_live_socket_is_never_unlinked_and_cleanup_is_inode_owned(self):
        from habitat_state.service import cleanup_owned_socket,prepare_socket_path
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"state.sock"; listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(path)); inode=path.lstat().st_ino; listener.listen()
            with self.assertRaisesRegex(RuntimeError,"already live"):prepare_socket_path(path)
            self.assertEqual(path.lstat().st_ino,inode)
            cleanup_owned_socket(path,inode+1);self.assertTrue(path.exists())
            listener.close();cleanup_owned_socket(path,inode);self.assertFalse(path.exists())

    def test_evidence_and_process_composition_have_single_owners(self):
        store=__import__("habitat_state.store",fromlist=["StateStore"])
        service=__import__("habitat_state.service",fromlist=["main"])
        evidence=__import__("habitat_state.evidence",fromlist=["GarageEvidenceAdapter"])
        self.assertNotIn("boto3",inspect.getsource(store))
        self.assertNotIn("socketserver",inspect.getsource(service))
        self.assertIn("GarageEvidenceAdapter",inspect.getsource(evidence))

    def test_change_protocol_translates_without_owning_repository_meaning(self):
        from habitat_state.protocol import StateProtocol
        class RecordingLifecycle:
            calls = []
            def propose_verified_change(self, request, principal): self.calls.append(("propose",request,principal)); return {"state":"PROPOSED"}
            def transition_verified_change(self, request, principal): self.calls.append(("transition",request,principal)); return {"state":"BUILT"}
            def governed_change(self, candidate): return {"candidate_id":candidate,"state":"BUILT"}
            def governed_change_history(self, candidate, *pagination): return [{"new_state":"PROPOSED"},{"new_state":"BUILT"}]
        class RecordingEvidence:
            def verify_record(self,*args,**kwargs): return {"verified":True}
        lifecycle=RecordingLifecycle(); protocol=StateProtocol(lifecycle,RecordingEvidence(),{})
        proposed=protocol.dispatch({"operation":"change_propose","candidate_id":"candidate:1",
          "command_id":"command:1","source_digest":"sha256:a","evaluator":"service:evaluator",
          "evaluator_closure":"sha256:b","target_generation":"generation:2",
          "rollback_generation":"generation:1","threshold":{"minimum_score":90},
          "evidence_ref":"evidence:1"},"service:controller")
        transitioned=protocol.dispatch({"operation":"change_transition","candidate_id":"candidate:1",
          "command_id":"command:2","new_state":"BUILT","actor":"service:controller","evidence_ref":"evidence:2",
          "evidence_source":"sha256:build-output"},"service:controller")
        self.assertEqual((proposed["state"],transitioned["state"]),("PROPOSED","BUILT"))
        self.assertEqual(protocol.dispatch({"operation":"change_get","candidate_id":"candidate:1"})["history"][-1]["new_state"],"BUILT")


if __name__ == "__main__": unittest.main()
