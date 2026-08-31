import json, os, socket, sys, tempfile, threading, time, unittest, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from habitat_state import Conflict
from habitat_state.lifecycle import LifecycleStore, ClockUntrusted
from habitat_state.command_ledger import CommandLedgerServer, CommandLedgerStore

@unittest.skipUnless(os.getenv("HABITAT_TEST_DATABASE_URL"), "live W05 database not configured")
class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        cls.store.migrate()

    def setUp(self):
        self.store.reset_for_test()

    def test_wake_is_committed_before_notification_and_redelivered_after_signal_loss(self):
        wake = f"wake:{uuid.uuid4()}"
        objective = f"objective:{uuid.uuid4()}"
        observed = []
        self.store.create_wake(wake, objective, "command:create", 100, lambda _: observed.append(wake))
        self.assertEqual(observed, [wake])
        restarted = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        lease = restarted.lease_wake("worker:01", now=101, lease_seconds=10)
        self.assertEqual(lease["wake_id"], wake)
        first = restarted.acknowledge_wake(wake, "command:ack", "worker:01", now=102)
        duplicate = restarted.acknowledge_wake(wake, "command:ack", "worker:01", now=102)
        self.assertEqual(first, duplicate)

    def test_lost_notification_does_not_lose_wake_and_objective_requires_claim(self):
        wake, objective = f"wake:{uuid.uuid4()}", f"objective:{uuid.uuid4()}"
        with self.assertRaises(RuntimeError):
            self.store.create_wake(wake, objective, "command:lost", 10,
                                   lambda _: (_ for _ in ()).throw(RuntimeError("signal lost")))
        self.assertEqual(self.store.lease_wake("worker:02", now=11, lease_seconds=5)["wake_id"], wake)
        self.store.create_objective(objective, "command:objective", "agent:01")
        self.store.transition_objective(objective, "command:active", "agent:01", "ACTIVE")
        with self.assertRaisesRegex(ValueError, "completion claim"):
            self.store.transition_objective(objective, "command:false-success", "agent:01", "SATISFIED")
        result = self.store.transition_objective(objective, "command:complete", "agent:01",
                                                 "SATISFIED", completion_claim_accepted=True)
        self.assertEqual(result["state"], "SATISFIED")

    def test_expired_activation_is_classified_and_untrusted_clock_is_denied(self):
        activation, objective = f"activation:{uuid.uuid4()}", f"objective:{uuid.uuid4()}"
        self.store.create_activation(activation, objective)
        with self.assertRaises(ClockUntrusted):
            self.store.lease_activation(activation, "worker:01", wall_now=100,
                                        monotonic_now=500, lease_seconds=10, clock_skew=6)
        self.store.lease_activation(activation, "worker:01", wall_now=100,
                                    monotonic_now=500, lease_seconds=10)
        self.store.transition_activation(activation, "PREPARING")
        self.store.transition_activation(activation, "RUNNING")
        self.store.transition_activation(activation, "WAITING_EFFECT")
        recovered = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"]).recover_expired(now=111)
        self.assertEqual(recovered, [{"activation_id": activation,
                                     "classification": "RECONCILIATION_REQUIRED",
                                     "state": "FAILED"}])

    def test_effect_recovery_package_and_change_records_are_durable(self):
        effect, activation = f"effect:{uuid.uuid4()}", f"activation:{uuid.uuid4()}"
        self.store.record_effect(effect, activation, f"command:{uuid.uuid4()}", "a" * 64,
                                 "sha256:" + "1" * 64)
        self.store.transition_effect(effect, f"command:{uuid.uuid4()}", "AUTHORIZED",
                                     "sha256:" + "2" * 64)
        self.store.transition_effect(effect, f"command:{uuid.uuid4()}", "DISPATCHED",
                                     "sha256:" + "3" * 64, external_ref="provider:42")
        self.assertEqual(self.store.recover_nonterminal_effects(), [
            {"effect_id": effect, "classification": "RECONCILIATION_REQUIRED"}])
        package = f"package:{uuid.uuid4()}"
        admitted = self.store.admit_package(package, "sha256:" + "a" * 64,
                                            {"abi": "2.0"}, "sha256:" + "4" * 64)
        self.assertEqual(admitted["state"], "VERIFIED")
        candidate = self.store.propose_change(
            f"candidate:{uuid.uuid4()}", "sha256:" + "b" * 64, "generation:evaluator",
            "generation:next", "generation:current", {"minimum_score": 1.0},
            "sha256:" + "5" * 64)
        self.assertEqual(candidate["state"], "PROPOSED")

    def test_runtime_protocol_uses_postgresql_authority_and_evidence(self):
        class Evidence:
            records = []

            def put(self, record):
                self.records.append(record)
                return "s3://habitat-evidence/sha256/" + "a" * 64

        ledger = CommandLedgerStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        ledger.migrate()
        recovery = self.store.recover(now=int(time.time()))
        evidence = Evidence()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sock")
            server = CommandLedgerServer(path, ledger, lifecycle=self.store,
                                         recovery=recovery, evidence=evidence)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def query(request):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(path)
                        client.sendall(request.encode() + b"\n")
                        return client.makefile().readline().strip()

                objective = f"objective:{uuid.uuid4()}"
                self.assertIn("migrations=1", query("STATUS"))
                self.assertEqual(query(f"SCHEDULE {objective}"), "ACCEPTED")
                self.assertEqual(query(f"SCHEDULE {objective}"), "ACCEPTED")
                self.assertEqual(query(f"RECORD_EFFECT {objective}"), "COMMITTED")
                self.assertEqual(query("TICK"), "COMPLETED")
                inspected = json.loads(query(f"INSPECT {objective}"))
                self.assertEqual(inspected["objective_state"], "SATISFIED")
                self.assertEqual(inspected["effect_state"], "COMMITTED")
                self.assertEqual(len(evidence.records), 1)

                command = "runtime-ledger:" + uuid.uuid4().hex
                proposed = {"command_id": command, "committed": True,
                            "state": "COMPLETED", "durable_record_id": "sha256:" + "b" * 64}
                request = json.dumps({"operation": "commit_command",
                                      "activation_id": objective, "command_id": command,
                                      "request_digest": "c" * 64, "result": proposed})
                self.assertEqual(json.loads(query(request))["status"], "ok")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

if __name__ == "__main__":
    unittest.main()
