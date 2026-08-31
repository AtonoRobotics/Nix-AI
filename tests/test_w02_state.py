import json, os, sys, unittest, uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import boto3, psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from habitat_state import (CommandId, Conflict, Correlation, EntityId, EntityKind,
    EvidenceMetadata, InjectedCrash, IntegrityError, PrincipalId, State, StateStore, Version,
    CommandLedgerStore)
from habitat_state.evidence import EvidenceStore,GarageEvidenceAdapter
from habitat_state.errors import LedgerCorrupt

def correlation():
    return Correlation(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4().hex)

def metadata(context):
    return EvidenceMetadata(PrincipalId("service:evidence"), "qualification-observation",
                            Version(0), "safety-audit", "protected", context)

@unittest.skipUnless(os.getenv("HABITAT_TEST_DATABASE_URL"), "live W02 services not configured")
class TransactionalStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = StateStore.from_urls(
            os.environ["HABITAT_TEST_DATABASE_URL"], os.environ["HABITAT_TEST_S3_ENDPOINT"],
            os.environ["HABITAT_TEST_S3_ACCESS_KEY"], os.environ["HABITAT_TEST_S3_SECRET_KEY"],
            os.environ["HABITAT_TEST_S3_BUCKET"], allow_test_reset=True, recovery_mode=True)
        cls.store.migrate()

    def setUp(self):
        self.store.reset_for_test()

    def put(self, body=b"accepted observation"):
        context = correlation()
        return self.store.put_evidence(body, metadata(context)), context

    def test_transition_is_atomic_conflict_safe_and_replay_idempotent(self):
        evidence, context = self.put()
        entity, command = EntityId.new(EntityKind.AGENT), CommandId.new()
        with self.assertRaises(InjectedCrash):
            self.store.transition(entity, command, PrincipalId("agent:test"), Version(0),
                                  State.REGISTERED, evidence, context, crash_at="after_commit")
        replay = self.store.transition(entity, command, PrincipalId("agent:test"), Version(0),
                                       State.REGISTERED, evidence, context)
        self.assertEqual((replay.previous_version.value, replay.new_version.value), (0, 1))
        self.assertEqual(self.store.history(entity), [replay])
        with self.assertRaises(IntegrityError):
            self.store.transition(entity, command, PrincipalId("agent:other"), Version(1),
                                  State.AVAILABLE, evidence, context)
        with self.assertRaises(Conflict) as conflict:
            self.store.transition(entity, CommandId.new(), PrincipalId("agent:stale"), Version(0),
                                  State.AVAILABLE, evidence, context)
        self.assertEqual(conflict.exception.current_version, 1)
        self.assertTrue(conflict.exception.safe_next_action)

    def test_crash_before_commit_and_upload_leave_no_authoritative_record(self):
        evidence, context = self.put(b"pre-commit")
        entity = EntityId.new(EntityKind.AGENT)
        with self.assertRaises(InjectedCrash):
            self.store.transition(entity, CommandId.new(), PrincipalId("agent:test"), Version(0),
                                  State.REGISTERED, evidence, context, crash_at="before_commit")
        self.assertIsNone(self.store.current(entity))
        self.assertEqual(self.store.history(entity), [])
        with self.assertRaises(InjectedCrash):
            self.store.put_evidence(b"orphan is not authoritative", metadata(correlation()),
                                    crash_at="during_upload")

    def test_history_state_machine_and_evidence_tamper_detection(self):
        evidence, context = self.put(b"original bytes")
        entity = EntityId.new(EntityKind.AGENT)
        first = self.store.transition(entity, CommandId.new(), PrincipalId("agent:test"), Version(0),
                                      State.REGISTERED, evidence, context)
        correction_evidence, correction_context = self.put(b"correction")
        correction = self.store.transition(entity, CommandId.new(), PrincipalId("agent:test"), Version(1),
                                            State.AVAILABLE, correction_evidence, correction_context,
                                            correction_of=first.transition_id)
        self.assertEqual(correction.correction_of, first.transition_id)
        with self.assertRaises(ValueError):
            self.store.transition(EntityId.new(EntityKind.AGENT), CommandId.new(), PrincipalId("agent:test"),
                                  Version(0), State.ACTIVE, evidence, context)
        with psycopg.connect(os.environ["HABITAT_TEST_DATABASE_URL"]) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("UPDATE state_transitions SET actor='attacker' WHERE transition_id=%s",
                                   (first.transition_id,))
        attacker = boto3.client("s3", endpoint_url=os.environ["HABITAT_TEST_S3_ENDPOINT"],
            aws_access_key_id=os.environ["HABITAT_TEST_S3_ACCESS_KEY"],
            aws_secret_access_key=os.environ["HABITAT_TEST_S3_SECRET_KEY"])
        attacker.put_object(Bucket=os.environ["HABITAT_TEST_S3_BUCKET"],
            Key="sha256/" + evidence.value.removeprefix("sha256:"), Body=b"tampered")
        with self.assertRaises(IntegrityError):
            self.store.verify_evidence(evidence)

    def test_consistent_backup_restores_state_and_rejects_corruption(self):
        evidence, context = self.put(b"durable payload")
        entity = EntityId.new(EntityKind.AGENT)
        original = self.store.transition(entity, CommandId.new(), PrincipalId("agent:backup"), Version(0),
                                         State.REGISTERED, evidence, context)
        backup = self.store.backup()
        self.store.reset_for_test(); self.store.restore(backup)
        self.assertEqual(self.store.current(entity)["version"], 1)
        self.assertEqual(self.store.history(entity), [original])
        self.assertEqual(self.store.verify_evidence(evidence), b"durable payload")
        corrupted = json.loads(json.dumps(backup))
        corrupted["evidence"][0]["content_base64"] = "dGFtcGVyZWQ="
        self.store.reset_for_test()
        with self.assertRaises(IntegrityError): self.store.restore(corrupted)
        self.assertIsNone(self.store.current(entity))

    def test_concurrent_writers_clock_projection_and_migration_boundaries(self):
        evidence, context = self.put(b"concurrency")
        entity = EntityId.new(EntityKind.AGENT)
        def write(_):
            try:
                return self.store.transition(entity, CommandId.new(), PrincipalId("agent:race"), Version(0),
                                             State.REGISTERED, evidence, context)
            except Conflict as error: return error
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(write, range(2)))
        self.assertEqual(sum(isinstance(value, Conflict) for value in outcomes), 1)
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            self.store.transition(EntityId.new(EntityKind.AGENT), CommandId.new(), PrincipalId("agent:clock"),
                                  Version(0), State.REGISTERED, evidence, context,
                                  occurred_at=datetime(2026, 1, 1))
        with self.assertRaises(InjectedCrash): self.store.migrate(crash_at="during_migration")
        self.store.report_projection("search", 9, 6)
        self.assertEqual(self.store.projection_status("search")["lag"], 3)
        self.assertEqual(self.store.schema_status()[0]["version"], 1)

    def test_maintenance_authority_and_evidence_bounds(self):
        ordinary = StateStore.from_urls(os.environ["HABITAT_TEST_DATABASE_URL"],
            os.environ["HABITAT_TEST_S3_ENDPOINT"], os.environ["HABITAT_TEST_S3_ACCESS_KEY"],
            os.environ["HABITAT_TEST_S3_SECRET_KEY"], os.environ["HABITAT_TEST_S3_BUCKET"])
        with self.assertRaises(PermissionError): ordinary.reset_for_test()
        with self.assertRaises(PermissionError): ordinary.restore({})
        with self.assertRaises(ValueError):
            self.store.put_evidence(b"x" * (16 * 1024 * 1024 + 1), metadata(correlation()))

    def test_authenticated_evidence_envelope_is_canonical_idempotent_and_fail_closed(self):
        evidence=EvidenceStore.__new__(EvidenceStore);evidence.bucket=os.environ["HABITAT_TEST_S3_BUCKET"]
        evidence.adapter=GarageEvidenceAdapter.from_urls(os.environ["HABITAT_TEST_S3_ENDPOINT"],
          os.environ["HABITAT_TEST_S3_ACCESS_KEY"],os.environ["HABITAT_TEST_S3_SECRET_KEY"],evidence.bucket)
        envelope={"schema_version":"1","producer":"service:authority","subject":"authority:runtime",
          "operation":"authority.snapshot","source":"sha256:"+"a"*64,"payload":{"version":1}}
        first=evidence.put_envelope(envelope,"service:authority")
        self.assertEqual(evidence.put_envelope(envelope,"service:authority"),first)
        self.assertEqual(evidence.verify_record(first["evidence_ref"],subject="authority:runtime",
          producer="service:authority",source="sha256:"+"a"*64),envelope)
        with self.assertRaises(LedgerCorrupt):evidence.put_envelope(envelope,"service:effects")
        forged=envelope|{"source":"sha256:not-a-digest"}
        with self.assertRaises(LedgerCorrupt):evidence.put_envelope(forged,"service:authority")

    def test_command_ledger_exact_replay_and_digest_mismatch(self):
        ledger = CommandLedgerStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        ledger.migrate()
        activation, command = f"activation:{uuid.uuid4()}", f"command:{uuid.uuid4()}"
        result = {"command_id": command, "committed": True,
                  "durable_record_id": "command:sha256:" + "a" * 64,
                  "state": "DISPOSITION_COMMITTED", "error": None, "evidence_refs": []}
        digest = "sha256:" + "a" * 64
        first = ledger.commit(activation, command, digest, result)
        duplicate = ledger.commit(activation, command, digest, result)
        mismatch = ledger.commit(activation, command, "sha256:" + "b" * 64, result)
        self.assertFalse(first.duplicate)
        self.assertTrue(duplicate.duplicate)
        self.assertTrue(mismatch.digest_mismatch)
        self.assertEqual(mismatch.result, first.result)
        with self.assertRaisesRegex(ValueError, "sha256"):
            ledger.commit(f"activation:{uuid.uuid4()}", f"command:{uuid.uuid4()}", "c" * 64, result)
        with psycopg.connect(os.environ["HABITAT_TEST_DATABASE_URL"]) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("UPDATE abi_command_ledger SET request_digest=%s WHERE activation_id=%s",
                                   ("sha256:" + "c" * 64, activation))

if __name__ == "__main__":
    unittest.main()
