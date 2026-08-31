import hashlib, json, os, socket, sys, tempfile, threading, time, unittest, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from habitat_state import Conflict
from habitat_state.lifecycle import LifecycleStore, ClockUntrusted
from habitat_state.command_ledger import CommandLedgerServer, CommandLedgerStore
from habitat_state.repository import PostgresRepository

@unittest.skipUnless(os.getenv("HABITAT_TEST_DATABASE_URL"), "live W05 database not configured")
class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        cls.store.migrate()

    def setUp(self):
        self.store.reset_for_test()
        self.store.ensure_active_generation("generation:current")

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

    def test_package_and_change_records_are_durable(self):
        package = f"package:{uuid.uuid4()}"
        admitted = self.store.admit_package(package, "sha256:" + "a" * 64,
                                            {"abi": "2.0"}, "sha256:" + "4" * 64)
        self.assertEqual(admitted["state"], "VERIFIED")
        candidate = self.store.propose_change(
            f"candidate:{uuid.uuid4()}", "sha256:" + "b" * 64, "generation:evaluator",
            "generation:next", "generation:current", {"minimum_score": 1.0},
            "sha256:" + "5" * 64)
        self.assertEqual(candidate["state"], "PROPOSED")

    def test_governed_change_is_replayable_protected_and_restart_recoverable(self):
        candidate = f"candidate:{uuid.uuid4()}"
        self.store.propose_governed_change(candidate, "command:propose:"+candidate,
            "sha256:"+"a"*64, "evaluator:protected", "sha256:"+"b"*64,
            "generation:next", "generation:current", {"minimum_score": 90},
            "evidence:proposal", "sha256:"+"c"*64, "V2.0.1", "sha256:"+"d"*64,
            ["runtime.effect"], "sha256:"+"e"*64, "health:runtime")
        with self.assertRaisesRegex(ValueError,"illegal governed-change transition"):
            self.store.transition_governed_change(candidate,"command:terminal:"+candidate,
                "CONFIRMED","health:independent","evidence:health",observation={"health_ready":True})
        transitions = [
            ("BUILT", "builder:release", "evidence:build"),
            ("EVALUATED", "evaluator:protected", "evidence:evaluation"),
            ("SIGNED", "signer:release", "evidence:signature"),
            ("STAGED", "service:packages", "evidence:stage"),
            ("ACTIVATED", "service:boot", "evidence:activation"),
        ]
        for index, (state, actor, evidence) in enumerate(transitions):
            first = self.store.transition_governed_change(candidate, f"command:{index}:{candidate}",
                state, actor, evidence, observation={"evaluator_closure":"sha256:"+"b"*64,
                  "artifact_digest":"sha256:"+"a"*64,"passed":True})
            replay = self.store.transition_governed_change(candidate, f"command:{index}:{candidate}",
                state, actor, evidence, observation={"evaluator_closure":"sha256:"+"b"*64,
                  "artifact_digest":"sha256:"+"a"*64,"passed":True})
            self.assertEqual(first, replay)
            if state=="BUILT":
                with self.assertRaisesRegex(ValueError,"protected evaluator"):
                    self.store.transition_governed_change(candidate,"command:capture:"+candidate,
                        "EVALUATED","evaluator:captured","evidence:capture",
                        observation={"evaluator_closure":"sha256:"+"c"*64})
        with self.assertRaisesRegex(ValueError, "independent health"):
            self.store.transition_governed_change(candidate, "command:self:"+candidate,
                "CONFIRMED", "evaluator:protected", "evidence:self",
                observation={"health_ready":True})
        confirmed = self.store.transition_governed_change(candidate, "command:confirm:"+candidate,
            "CONFIRMED", "health:independent", "evidence:health", observation={"health_ready":True})
        restarted = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        self.assertEqual(restarted.governed_change(candidate)["state"], "CONFIRMED")
        self.assertEqual(confirmed["active_generation"], "generation:next")
        self.assertEqual(len(restarted.governed_change_history(candidate)), 7)
        rollback_candidate=f"candidate:{uuid.uuid4()}"
        self.store.propose_governed_change(rollback_candidate,"command:propose:"+rollback_candidate,
            "sha256:"+"f"*64,"evaluator:protected","sha256:"+"b"*64,
            "generation:bad","generation:next",{"minimum_score":90},"evidence:proposal",
            "sha256:"+"c"*64,"V2.0.1","sha256:"+"d"*64,["runtime.effect"],
            "sha256:"+"e"*64,"health:runtime")
        for index,(state,actor) in enumerate((("BUILT","builder:release"),
            ("EVALUATED","evaluator:protected"),("SIGNED","signer:release"),
            ("STAGED","service:packages"),("ACTIVATED","service:boot"),
            ("QUARANTINED","health:independent"),("ROLLED_BACK","service:recovery"))):
            rolled=self.store.transition_governed_change(rollback_candidate,
                f"command:rollback:{index}:{rollback_candidate}",state,actor,f"evidence:{state}",
                observation={"evaluator_closure":"sha256:"+"b"*64,
                  "artifact_digest":"sha256:"+"f"*64,"passed":True})
        self.assertEqual((rolled["state"],rolled["active_generation"]),
                         ("ROLLED_BACK","generation:next"))

    def test_authority_binding_replay_and_restart_preserve_version_history(self):
        binding=f"binding:{uuid.uuid4()}";command=f"command:{uuid.uuid4()}"
        first=self.store.record_authority_binding(binding,command,"generation:1",
            "sha256:"+"d"*64,"evidence:authority")
        replay=self.store.record_authority_binding(binding,command,"generation:1",
            "sha256:"+"d"*64,"evidence:authority")
        self.assertEqual(first,replay)
        restarted=LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        self.assertEqual(restarted.authority_binding(binding)["version"],1)
        with self.assertRaisesRegex(ValueError,"command identity reused"):
            restarted.record_authority_binding(binding,command,"generation:2",
                "sha256:"+"e"*64,"evidence:other")

    def test_effect_migration_archives_legacy_history_without_loss(self):
        with self.store._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS effect_history(legacy_id text, payload jsonb)")
            connection.execute("TRUNCATE effect_history")
            connection.execute("INSERT INTO effect_history VALUES(%s,%s)",
                               ("legacy:1", json.dumps({"state": "UNCERTAIN", "n": 7})))
        self.store.migrate()
        with self.store._connect() as connection:
            source = connection.execute(
                "SELECT to_jsonb(h) AS raw FROM effect_history h").fetchall()
            archived = connection.execute("""SELECT raw_record,raw_digest,classification
              FROM effect_migration_archive WHERE source_table='effect_history'
              ORDER BY source_ordinal""").fetchall()
            self.assertEqual([row["raw"] for row in source],
                             [row["raw_record"] for row in archived])
            self.assertTrue(all(row["raw_digest"].startswith("sha256:")
                                for row in archived))
            self.assertEqual([row["classification"] for row in archived], ["UNKNOWN"])
            with self.assertRaises(Exception):
                connection.execute(
                    "UPDATE effect_history SET legacy_id='rewritten' WHERE legacy_id='legacy:1'")

    def test_effect_migration_failure_rolls_back_archive_and_preserves_source(self):
        effect_id = f"effect:legacy:{uuid.uuid4()}"
        with self.store._connect() as connection:
            connection.execute("""INSERT INTO durable_effects
              (effect_id,activation_id,request_digest,state,version)
              VALUES(%s,%s,%s,'OUTCOME_UNKNOWN',1)""",
                               (effect_id, "objective:legacy", "sha256:" + "9" * 64))
        with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
            self.store.migrate(fault_after_archive=True)
        with self.store._connect() as connection:
            self.assertEqual(connection.execute(
                "SELECT count(*) AS n FROM durable_effects WHERE effect_id=%s",
                (effect_id,)).fetchone()["n"], 1)
            self.assertEqual(connection.execute("""SELECT count(*) AS n
              FROM effect_migration_archive WHERE source_table='durable_effects'
                AND raw_record->>'effect_id'=%s""", (effect_id,)).fetchone()["n"], 0)

    def test_runtime_protocol_uses_postgresql_authority_and_evidence(self):
        class Evidence:
            records = []

            def put(self, record):
                self.records.append(record)
                return "s3://habitat-evidence/sha256/" + "a" * 64
            def verify_record(self, reference, **bindings):
                return {**bindings,"verified":True}

        ledger = CommandLedgerStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        ledger.migrate()
        recovery = self.store.recover(now=int(time.time()))
        evidence = Evidence()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sock")
            admission_token = "effect-admission-token-for-runtime-test"
            server = CommandLedgerServer(path, PostgresRepository(os.environ["HABITAT_TEST_DATABASE_URL"]),
                                         recovery=recovery, evidence=evidence,
                                         principals={(os.getuid(),os.getgid(),"habitat-effects.service"):"service:effects"},
                                         effect_uid=os.getuid(),
                                         effect_token=admission_token,
                                         identity_observer=lambda pid,uid,gid:(pid,uid,gid,"habitat-effects.service"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def query(request):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(path)
                        payload=json.dumps(request,separators=(",", ":")).encode()
                        client.sendall(len(payload).to_bytes(4,"big")+payload)
                        size=int.from_bytes(client.recv(4),"big")
                        body=b""
                        while len(body)<size:body+=client.recv(size-len(body))
                        return json.loads(body)

                objective = f"objective:{uuid.uuid4()}"
                self.store.schedule_objective(objective,now=int(time.time()))
                status=query({"operation":"runtime_status"})
                self.assertEqual(status["status"],"ok")
                self.assertIn(status["result"]["readiness"],("READY","RECOVERING"))
                inspection = query({"operation":"runtime_inspect","objective_id":objective})
                self.assertEqual(inspection["status"],"ok")
                self.assertEqual(inspection["result"]["objective_id"],objective)
                self.assertEqual(inspection["result"]["objective_state"],"PROPOSED")
                effect_id = "effect:sha256:" + "d" * 64
                previous=None
                for index,state in enumerate(("PROPOSED","AUTHORIZED","DISPATCHED","OBSERVED_SUCCEEDED")):
                    transition={"operation":"effect_transition","admission_token":admission_token,
                      "transition_id":f"transition:{index}:{effect_id}","effect_id":effect_id,
                      "objective_id":objective,"request_digest":"sha256:"+"e"*64,"previous_state":previous,
                      "new_state":state,"evidence_ref":"s3://habitat-evidence/sha256/"+"a"*64,
                      "external_ref":f"provider://stable/{effect_id}"}
                    self.assertEqual(query(transition)["status"],"ok")
                    self.assertEqual(query(transition)["status"],"ok")
                    previous=state
                canonical = {
                    "effect_id": effect_id,
                    "state": "ObservedSucceeded",
                    "proposal": {"objective_id": objective,
                                 "parameters_digest": "sha256:" + "e" * 64},
                }
                with self.store._connect() as connection:
                    connection.execute("""INSERT INTO effect_records
                      (effect_id,objective_id,request_digest,state,canonical_record,version)
                      VALUES(%s,%s,%s,'ObservedSucceeded',%s,1)""",
                                       (effect_id, objective, "sha256:" + "e" * 64,
                                        json.dumps(canonical)))
                effect_ids = [effect_id]
                effect_set_digest = "sha256:" + hashlib.sha256(
                    json.dumps(effect_ids, separators=(",", ":")).encode()).hexdigest()
                guard = {
                    "operation": "effect_guard",
                    "admission_token": admission_token,
                    "objective_id": objective,
                    "effect_ids": effect_ids,
                    "effect_set_digest": effect_set_digest,
                }
                self.assertTrue(query(guard)["result"]["ready"])
                invalidate = {
                    "operation": "effect_guard_invalidate",
                    "admission_token": admission_token,
                    "objective_id": objective,
                    "compensates_effect_id": effect_id,
                }
                self.assertFalse(query(invalidate)["result"]["ready"])
                with self.assertRaises(ValueError):self.store.complete_ready_objective(now=int(time.time()))
                self.assertTrue(query(guard)["result"]["ready"])
                self.assertIsNotNone(self.store.complete_ready_objective(now=int(time.time())))
                inspected = self.store.inspect_objective(objective)
                self.assertEqual(inspected["objective_state"], "SATISFIED")
                self.assertEqual(inspected["effects"][0]["state"], "COMMITTED")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

if __name__ == "__main__":
    unittest.main()
