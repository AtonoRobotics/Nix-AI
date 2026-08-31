import hashlib, json, os, socket, sys, tempfile, threading, time, unittest, uuid
import psycopg
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
        self.store.migrate()
        with self.store._connect() as connection:
            archived=connection.execute("SELECT classification FROM activation_migration_archive WHERE activation_id=%s",
                                        (activation,)).fetchone()
        self.assertEqual(archived["classification"],"UNKNOWN")
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

    def test_scheduler_claim_binds_current_generation_and_capability_set(self):
        objective = f"objective:{uuid.uuid4()}"
        activation_credential="activation-secret-01"
        credential_digest="sha256:"+hashlib.sha256(activation_credential.encode()).hexdigest()
        scheduled = self.store.schedule_objective(objective, now=100)
        self.store.publish_capability_activation_set(
            "command:set:current", "capability-set:current", "generation:current",
            ["grant:context", "grant:effect"], "evidence:set",None,0)
        claim = self.store.claim_activation(
            command_id=f"command:claim:{objective}",
            activation_id=f"activation:{uuid.uuid4()}",
            objective_id=objective,
            wake_id=scheduled["wake_id"],
            machine_id="machine:test",
            agent_id="agent:test",
            lease_owner="service:runtime",
            lease_seconds=30,
            context_bundle_id="context:compiled",
            isolation_profile_id="isolation:default",
            resource_lease_id="resource-lease:test",
            trace_id="trace:test",
            correlation_id="correlation:test",
            credential_digest=credential_digest,
            credential_key_version=1,
            expected_lease_fence=1,
            evidence_ref="s3://evidence/activation-claim",
        )
        self.assertEqual(claim["lease_fence"], 1)
        self.assertEqual(claim["system_generation_id"], "generation:current")
        self.assertEqual(claim["capability_activation_set_id"], "capability-set:current")
        self.assertEqual(claim["capability_grant_ids"], ["grant:context", "grant:effect"])
        self.assertEqual(claim["objective_id"], objective)
        self.assertEqual(claim["wake_id"], scheduled["wake_id"])
        self.assertGreater(claim["lease_expires_at"], int(time.time()))
        replay = self.store.claim_activation(
            command_id=f"command:claim:{objective}", activation_id=claim["activation_id"],
            objective_id=objective, wake_id=scheduled["wake_id"], machine_id="machine:test",
            agent_id="agent:test", lease_owner="service:runtime", lease_seconds=30,
            context_bundle_id="context:compiled", isolation_profile_id="isolation:default",
            resource_lease_id="resource-lease:test", trace_id="trace:test",
            correlation_id="correlation:test", credential_digest=credential_digest,
            credential_key_version=1,expected_lease_fence=1,
            evidence_ref="s3://evidence/activation-claim")
        self.assertEqual(replay, claim)
        binding={"activation_id":claim["activation_id"],"machine_id":"machine:test",
          "agent_id":"agent:test","objective_id":objective,"lease_fence":1,
          "system_generation_id":"generation:current",
          "capability_activation_set_id":"capability-set:current",
          "deadline":claim["deadline"],"trace_id":"trace:test"}
        resolved=self.store.resolve_activation(binding,activation_credential)
        self.assertEqual(resolved["activation_id"],claim["activation_id"])
        self.assertEqual(resolved["objective_id"],objective)
        self.assertEqual(resolved["capability_grant_ids"],["grant:context","grant:effect"])
        self.assertNotIn("credential_digest",resolved)
        self.assertNotIn("credential_key_version",resolved)
        repository=PostgresRepository(os.environ["HABITAT_TEST_DATABASE_URL"])
        resolution={"binding":binding,"activation_credential":activation_credential}
        with self.assertRaisesRegex(ValueError,"ABI principal"):
            repository.resolve_activation(resolution,"service:runtime")
        self.assertEqual(repository.resolve_activation(resolution,"service:abi")["activation_id"],
                         claim["activation_id"])
        for field,bad_value in (("machine_id","machine:forged"),("agent_id","agent:forged"),
          ("objective_id","objective:forged"),("activation_id","activation:forged"),
          ("lease_fence",2),("system_generation_id","generation:forged"),
          ("capability_activation_set_id","capability-set:forged"),("trace_id","trace:forged")):
            with self.subTest(field=field),self.assertRaises((PermissionError,ValueError)):
                self.store.resolve_activation(binding|{field:bad_value},activation_credential)
        with self.assertRaises(PermissionError):
            self.store.resolve_activation(binding,"forged-credential")
        with self.assertRaises(ValueError):
            self.store.resolve_activation(binding|{"deadline":claim["deadline"]+1},activation_credential)
        with self.assertRaises(ValueError):
            self.store.resolve_activation(binding|{"unexpected":"scope"},activation_credential)
        for field,bad_value in (("lease_fence",True),("lease_fence",0),("lease_fence",-1),
          ("lease_fence",2**64),("deadline",True),("deadline",0),("deadline",-1),
          ("deadline",2**63)):
            with self.subTest(field=field,bad_value=bad_value),self.assertRaises(ValueError):
                self.store.resolve_activation(binding|{field:bad_value},activation_credential)
        with self.assertRaisesRegex(ValueError, "claimable|live objective"):
            self.store.claim_activation(
                command_id=f"command:second:{objective}", activation_id=f"activation:{uuid.uuid4()}",
                objective_id=objective, wake_id=scheduled["wake_id"], machine_id="machine:test",
                agent_id="agent:test", lease_owner="service:runtime", lease_seconds=30,
                context_bundle_id="context:compiled", isolation_profile_id="isolation:default",
                resource_lease_id="resource-lease:test", trace_id="trace:second",
                correlation_id="correlation:second", credential_digest="sha256:" + "b" * 64,
                credential_key_version=1,expected_lease_fence=1,
                evidence_ref="s3://evidence/second-claim")
        def reject_recovery_evidence(_command_id,_payload):
            raise RuntimeError("evidence store unavailable")
        with self.assertRaisesRegex(RuntimeError,"evidence store unavailable"):
            self.store.recover_expired(now=claim["lease_expires_at"]+1,
              publish_recovery_evidence=reject_recovery_evidence)
        with self.store._connect() as connection:
            unchanged_activation=connection.execute("SELECT state,version FROM activations WHERE activation_id=%s",
              (claim["activation_id"],)).fetchone()
            unchanged_wake=connection.execute("SELECT state,version FROM wakes WHERE wake_id=%s",
              (scheduled["wake_id"],)).fetchone()
        self.assertEqual(dict(unchanged_activation),{"state":"LEASED","version":1})
        self.assertEqual(dict(unchanged_wake),{"state":"LEASED","version":2})
        recovery_payloads=[]
        def publish_recovery_evidence(command_id,payload):
            recovery_payloads.append((command_id,payload))
            return "s3://evidence/activation-recovery"
        recovered=self.store.recover_expired(
          now=claim["lease_expires_at"]+1,
          publish_recovery_evidence=publish_recovery_evidence)
        self.assertEqual(recovered,[{"activation_id":claim["activation_id"],
          "classification":"RETRYABLE","state":"REQUESTED"}])
        with self.store._connect() as connection:
            released=connection.execute("SELECT state FROM wakes WHERE wake_id=%s",
                                        (scheduled["wake_id"],)).fetchone()
            recovery_history=connection.execute("""SELECT evidence_ref FROM activation_binding_history
              WHERE activation_id=%s AND version=2""",(claim["activation_id"],)).fetchone()
            wake_history=connection.execute("""SELECT evidence_ref FROM lifecycle_history
              WHERE entity_id=%s AND previous_state='LEASED' AND new_state='RELEASED'""",
              (scheduled["wake_id"],)).fetchone()
        self.assertEqual(released["state"],"RELEASED")
        self.assertEqual(recovery_history["evidence_ref"],"s3://evidence/activation-recovery")
        self.assertEqual(wake_history["evidence_ref"],"s3://evidence/activation-recovery")
        self.assertEqual(len(recovery_payloads),1)
        recovery_command,recovery_payload=recovery_payloads[0]
        self.assertEqual(recovery_payload,{"command_id":recovery_command,
          "activation_id":claim["activation_id"],"wake_id":scheduled["wake_id"],
          "lease_fence":1,"previous_activation_state":"LEASED",
          "new_activation_state":"REQUESTED","previous_activation_version":1,
          "new_activation_version":2,"previous_wake_state":"LEASED",
          "new_wake_state":"RELEASED","previous_wake_version":2,
          "new_wake_version":3})
        reclaimed_credential="activation-secret-02"
        reclaimed=self.store.claim_activation(
            command_id=f"command:reclaim:{objective}",activation_id=claim["activation_id"],
            objective_id=objective,wake_id=scheduled["wake_id"],machine_id="machine:test",
            agent_id="agent:test",lease_owner="service:runtime",lease_seconds=30,
            context_bundle_id="context:compiled",isolation_profile_id="isolation:default",
            resource_lease_id="resource-lease:test",trace_id="trace:reclaimed",
            correlation_id="correlation:reclaimed",credential_digest="sha256:"+
              hashlib.sha256(reclaimed_credential.encode()).hexdigest(),
            credential_key_version=1,expected_lease_fence=2,
            evidence_ref="s3://evidence/activation-reclaim")
        self.assertEqual(reclaimed["lease_fence"],2)
        reclaimed_binding=binding|{"lease_fence":2,"deadline":reclaimed["deadline"],
          "trace_id":"trace:reclaimed"}
        self.assertEqual(self.store.resolve_activation(reclaimed_binding,reclaimed_credential)["state"],
                         "LEASED")
        for invalid_fence in (1,3):
            with self.subTest(invalid_fence=invalid_fence),self.assertRaises(PermissionError):
                self.store.resolve_activation(reclaimed_binding|{"lease_fence":invalid_fence},
                                              reclaimed_credential)
        self.store.transition_activation(claim["activation_id"],"PREPARING")
        self.store.transition_activation(claim["activation_id"],"RUNNING")
        self.assertEqual(self.store.resolve_activation(reclaimed_binding,reclaimed_credential)["state"],
                         "RUNNING")
        self.store.transition_activation(claim["activation_id"],"FAILED")
        with self.assertRaisesRegex(PermissionError,"not active"):
            self.store.resolve_activation(reclaimed_binding,reclaimed_credential)
        with psycopg.connect(os.environ["HABITAT_TEST_DATABASE_URL"]) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("UPDATE activation_binding_history SET evidence_ref='changed'")
        future=f"objective:{uuid.uuid4()}";future_wake=self.store.schedule_objective(future,now=int(time.time())+60)
        common={"command_id":f"command:claim:{future}","activation_id":f"activation:{uuid.uuid4()}",
          "objective_id":future,"wake_id":future_wake["wake_id"],"machine_id":"machine:test",
          "agent_id":"agent:test","lease_owner":"service:runtime","lease_seconds":30,
          "context_bundle_id":"context:test","isolation_profile_id":"isolation:test",
          "resource_lease_id":"resource-lease:test","trace_id":"trace:test",
          "correlation_id":"correlation:test","credential_digest":"sha256:"+"c"*64,
          "credential_key_version":1,"evidence_ref":"s3://evidence/future"}
        common["expected_lease_fence"]=1
        with self.assertRaisesRegex(ValueError,"claimable"):
            self.store.claim_activation(**common)
        with self.assertRaisesRegex(ValueError,"complete typed"):
            self.store.claim_activation(**(common|{"lease_seconds":301}))
        with self.assertRaisesRegex(ValueError,"complete typed"):
            self.store.claim_activation(**(common|{"credential_digest":"sha256:"+"Z"*64}))

    def test_capability_set_publication_replay_and_reactivation_are_auditable(self):
        first=self.store.publish_capability_activation_set("command:set:first","capability-set:first",
          "generation:current",["grant:first"],"evidence:first",None,0)
        self.assertEqual(self.store.publish_capability_activation_set("command:set:first","capability-set:first",
          "generation:current",["grant:first"],"evidence:first",None,0),first)
        with self.assertRaisesRegex(ValueError,"command identity reused"):
            self.store.publish_capability_activation_set("command:set:first","capability-set:other",
              "generation:current",["grant:other"],"evidence:other",None,0)
        self.store.publish_capability_activation_set("command:set:second","capability-set:second",
          "generation:current",["grant:second"],"evidence:second","capability-set:first",1)
        reactivated=self.store.publish_capability_activation_set("command:set:reactivate","capability-set:first",
          "generation:current",["grant:first"],"evidence:reactivated","capability-set:second",1)
        self.assertEqual(reactivated["version"],3)
        with self.store._connect() as connection:
            history=connection.execute("""SELECT set_id,version,active,evidence_ref,command_id
              FROM capability_activation_set_history
              ORDER BY recorded_at,set_id,version""").fetchall()
            active=connection.execute("SELECT set_id FROM capability_activation_sets WHERE active").fetchall()
        self.assertEqual(active,[{"set_id":"capability-set:first"}])
        self.assertIn({"set_id":"capability-set:first","version":3,"active":True,
          "evidence_ref":"evidence:reactivated","command_id":"command:set:reactivate"},history)
        self.assertIn({"set_id":"capability-set:second","version":2,"active":False,
          "evidence_ref":"evidence:reactivated","command_id":"command:set:reactivate:deactivate"},history)
        with self.assertRaisesRegex(ValueError,"active capability set changed"):
            self.store.publish_capability_activation_set("command:set:delayed","capability-set:delayed",
              "generation:current",["grant:delayed"],"evidence:delayed","capability-set:second",1)

    def test_concurrent_activation_claim_commits_one_live_fence(self):
        objective=f"objective:{uuid.uuid4()}";scheduled=self.store.schedule_objective(objective,now=1)
        self.store.publish_capability_activation_set("command:set:race","capability-set:race",
          "generation:current",["grant:race"],"evidence:race",None,0)
        barrier=threading.Barrier(2);outcomes=[]
        def claim(index):
            try:
                barrier.wait()
                outcomes.append(self.store.claim_activation(
                  command_id=f"command:race:{index}",activation_id=f"activation:race:{index}",
                  objective_id=objective,wake_id=scheduled["wake_id"],machine_id="machine:test",
                  agent_id="agent:test",lease_owner="service:runtime",lease_seconds=30,
                  context_bundle_id="context:test",isolation_profile_id="isolation:test",
                  resource_lease_id="resource-lease:test",trace_id=f"trace:{index}",
                  correlation_id=f"correlation:{index}",credential_digest="sha256:"+str(index)*64,
                  credential_key_version=1,expected_lease_fence=1,evidence_ref=f"evidence:race:{index}"))
            except Exception as error:outcomes.append(error)
        workers=[threading.Thread(target=claim,args=(index,)) for index in (1,2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join()
        self.assertEqual(sum(isinstance(outcome,dict) for outcome in outcomes),1)
        self.assertEqual(sum(isinstance(outcome,Exception) for outcome in outcomes),1)
        with self.store._connect() as connection:
            rows=connection.execute("SELECT lease_fence FROM activations WHERE objective_id=%s",
                                    (objective,)).fetchall()
        self.assertEqual(rows,[{"lease_fence":1}])

    def test_capability_set_publication_requires_verified_packages_principal(self):
        request={"command_id":"command:set:verified","set_id":"capability-set:verified",
          "generation_id":"generation:current","grant_ids":["grant:verified"],
          "expected_active_set_id":None,"expected_active_version":0,
          "evidence_ref":"s3://habitat-evidence/sha256/"+"6"*64}
        envelope={"producer":"service:packages","subject":request["set_id"],
          "source":request["generation_id"],"operation":"capability-set.publish",
          "disposition":"ACTIVE","payload":{"command_id":request["command_id"],
            "grant_ids":request["grant_ids"],"expected_active_set_id":None,
            "expected_active_version":0,"deactivates":{"set_id":None,"version":0}}}
        class Evidence:
            def verify_record(self,reference,**bindings):
                if reference!=request["evidence_ref"] or any(envelope.get(key)!=value for key,value in bindings.items()):
                    raise ValueError("evidence binding mismatch")
                return envelope
        repository=PostgresRepository(os.environ["HABITAT_TEST_DATABASE_URL"]);repository.bind_evidence(Evidence())
        with self.assertRaisesRegex(ValueError,"packages principal"):
            repository.publish_verified_capability_set(request,"service:runtime")
        mutations=(
          request|{"command_id":"command:set:forged"},
          request|{"grant_ids":["grant:widened"]},
          request|{"expected_active_set_id":"capability-set:stale"},
          request|{"expected_active_version":9},
        )
        for forged in mutations:
            with self.subTest(forged=forged):
                with self.assertRaisesRegex(Exception,"does not bind"):
                    repository.publish_verified_capability_set(forged,"service:packages")
        published=repository.publish_verified_capability_set(request,"service:packages")
        self.assertEqual(published["set_id"],request["set_id"])

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

    def test_terminal_canonical_effect_keeps_state_ready_after_restart(self):
        objective_id = f"objective:{uuid.uuid4()}"
        effect_id = f"effect:{uuid.uuid4()}"
        request_digest = "sha256:" + "7" * 64
        record = {
            "effect_id": effect_id,
            "state": "ObservedSucceeded",
            "proposal": {
                "objective_id": objective_id,
                "parameters_digest": request_digest,
            },
        }
        canonical = {
            "record": record,
            "attempts": [],
            "reconciliations": [],
        }
        effect_set_digest = "sha256:" + hashlib.sha256(
            json.dumps([effect_id], separators=(",", ":")).encode()
        ).hexdigest()
        with self.store._connect() as connection:
            connection.execute("INSERT INTO objectives VALUES(%s,'SATISFIED',2)",
                               (objective_id,))
            connection.execute("""INSERT INTO durable_effects
              (effect_id,activation_id,request_digest,state,external_ref,evidence_ref,version)
              VALUES(%s,%s,%s,'COMMITTED','transport:1','evidence:1',1)""",
                               (effect_id, objective_id, request_digest))
            connection.execute("""INSERT INTO provider_effect_transitions
              (transition_id,effect_id,previous_state,new_state,request_digest,evidence_ref,sequence)
              VALUES(%s,%s,'DISPATCHED','OBSERVED_SUCCEEDED',%s,'evidence:1',1)""",
                               (f"transition:{uuid.uuid4()}", effect_id, request_digest))
            connection.execute("""INSERT INTO effect_records
              (effect_id,objective_id,request_digest,state,canonical_record,version)
              VALUES(%s,%s,%s,'ObservedSucceeded',%s,1)""",
                               (effect_id, objective_id, request_digest, json.dumps(record)))
            connection.execute("""INSERT INTO effect_transition_history
              (event_id,effect_id,previous_state,new_state,canonical_event,effect_version)
              VALUES(%s,%s,'Executing','ObservedSucceeded',%s,1)""",
                               (f"event:{uuid.uuid4()}", effect_id, json.dumps(canonical)))
            connection.execute("""INSERT INTO objective_effect_guards
              (objective_id,effect_set_digest,effect_count,ready)
              VALUES(%s,%s,1,true)""", (objective_id, effect_set_digest))

        recovery = LifecycleStore(
            os.environ["HABITAT_TEST_DATABASE_URL"]
        ).recover(now=int(time.time()))
        self.assertTrue(recovery["effects_classified"], recovery)
        self.assertEqual(recovery["canonical_inconsistent_effects"], 0)

        for path in (("effect_id",), ("proposal", "objective_id"),
                     ("proposal", "parameters_digest"), ("state",)):
            pg_path = "{" + ",".join(path) + "}"
            malformed = json.loads(json.dumps(record))
            owner = malformed
            for key in path[:-1]:
                owner = owner[key]
            del owner[path[-1]]
            malformed_event = {**canonical, "record": malformed}
            with self.store._connect() as connection:
                version = connection.execute(
                    "UPDATE effect_records SET canonical_record=%s,version=version+1 "
                    "WHERE effect_id=%s RETURNING version",
                    (json.dumps(malformed), effect_id),
                ).fetchone()["version"]
                connection.execute(
                    "INSERT INTO effect_transition_history "
                    "(event_id,effect_id,previous_state,new_state,canonical_event,effect_version) "
                    "VALUES(%s,%s,'ObservedSucceeded','ObservedSucceeded',%s,%s)",
                    (f"event:{uuid.uuid4()}", effect_id,
                     json.dumps(malformed_event), version),
                )
            corrupt = LifecycleStore(
                os.environ["HABITAT_TEST_DATABASE_URL"]
            ).recover(now=int(time.time()))
            self.assertFalse(corrupt["effects_classified"], (pg_path, corrupt))
            self.assertEqual(corrupt["canonical_inconsistent_effects"], 1,
                             (pg_path, corrupt))

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

    def test_scheduler_activation_claim_crosses_authenticated_state_protocol(self):
        objective=f"objective:{uuid.uuid4()}";now=int(time.time())
        scheduled=self.store.schedule_objective(objective,now=now)
        self.store.publish_capability_activation_set("command:set:protocol","capability-set:protocol","generation:current",
          ["grant:abi"],"s3://evidence/capability-set",None,0)
        activation=f"activation:{uuid.uuid4()}";digest="sha256:"+"8"*64
        request={"operation":"activation_claim","command_id":f"command:claim:{activation}",
          "activation_id":activation,"objective_id":objective,"wake_id":scheduled["wake_id"],
          "machine_id":"machine:protocol","agent_id":"agent:protocol","lease_owner":"service:runtime",
          "lease_seconds":30,"context_bundle_id":"context:protocol",
          "isolation_profile_id":"isolation:protocol","resource_lease_id":"resource-lease:protocol",
          "trace_id":"trace:protocol","correlation_id":"correlation:protocol",
          "credential_digest":digest,"credential_key_version":1,
          "expected_lease_fence":1,
          "evidence_ref":"s3://habitat-evidence/sha256/"+"9"*64}
        envelope={"schema_version":"1","producer":"service:scheduler","subject":activation,
          "operation":"activation.claim","source":digest,"disposition":"LEASED",
          "payload":{key:request[key] for key in ("command_id","objective_id","wake_id","machine_id","agent_id",
            "lease_owner","context_bundle_id","isolation_profile_id","resource_lease_id","trace_id",
            "correlation_id","credential_key_version","lease_seconds","expected_lease_fence")}}
        class Evidence:
            def verify_record(self,reference,**bindings):
                if reference!=request["evidence_ref"] or any(envelope.get(key)!=value for key,value in bindings.items()):
                    raise ValueError("evidence binding mismatch")
                return envelope
        repository=PostgresRepository(os.environ["HABITAT_TEST_DATABASE_URL"])
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/"state.sock")
            server=CommandLedgerServer(path,repository,evidence=Evidence(),
              principals={(os.getuid(),os.getgid(),"habitat-scheduler.service"):"service:scheduler"},
              effect_uid=os.getuid(),effect_token="effect-admission-token-for-runtime-test",
              identity_observer=lambda pid,uid,gid:(pid,uid,gid,"habitat-scheduler.service"))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(path);payload=json.dumps(request,separators=(",", ":")).encode()
                    client.sendall(len(payload).to_bytes(4,"big")+payload)
                    size=int.from_bytes(client.recv(4),"big");body=b""
                    while len(body)<size:body+=client.recv(size-len(body))
                response=json.loads(body)
                self.assertEqual(response["status"],"ok")
                self.assertEqual(response["result"]["activation_id"],activation)
                self.assertEqual(response["result"]["lease_fence"],1)
                self.assertEqual(response["result"]["system_generation_id"],"generation:current")
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

if __name__ == "__main__":
    unittest.main()
