from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json
import uuid

import psycopg
from psycopg.rows import dict_row

from .domain import (CommandId, Correlation, EntityId, EntityKind, EvidenceId,
                     EvidenceMetadata, PrincipalId, State, Version, assert_legal)
from .evidence import GarageEvidenceAdapter


MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_BACKUP_BYTES = 64 * 1024 * 1024


class HabitatError(RuntimeError):
    """Failure with the mandatory operational consequence and recovery context."""

    def __init__(self, message, *, cause, consequence, current_state,
                 safe_next_action, correlation_id):
        super().__init__(message)
        self.cause = cause
        self.consequence = consequence
        self.current_state = current_state
        self.safe_next_action = safe_next_action
        self.correlation_id = correlation_id


class Conflict(HabitatError):
    def __init__(self, current_version: int, correlation_id: str):
        super().__init__(f"CONFLICT: current version is {current_version}",
                         cause="stale expected version", consequence="command rejected",
                         current_state={"version": current_version},
                         safe_next_action="reload authoritative state and re-evaluate",
                         correlation_id=correlation_id)
        self.current_version = current_version


class InjectedCrash(RuntimeError):
    pass


class IntegrityError(HabitatError):
    def __init__(self, message, *, correlation_id="unknown", cause="integrity check failed"):
        super().__init__(message, cause=cause, consequence="operation remains unconfirmed",
                         current_state="RECOVERY_REQUIRED",
                         safe_next_action="restore or repair through dedicated recovery authority",
                         correlation_id=correlation_id)


@dataclass(frozen=True)
class Transition:
    transition_id: str
    entity_id: EntityId
    command_id: CommandId
    actor: PrincipalId
    previous_version: Version
    new_version: Version
    new_state: State
    evidence_id: EvidenceId
    correlation: Correlation
    occurred_at: str
    correction_of: str | None


MIGRATION = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(),
  forward_compatible boolean NOT NULL, backward_compatible boolean NOT NULL,
  interruption_behavior text NOT NULL, rollback_limit text NOT NULL
);
INSERT INTO schema_migrations VALUES
  (1, now(), true, false, 'transactional; writers remain fail-closed', 'restore backup before v1')
ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS evidence_refs (
  evidence_id text PRIMARY KEY CHECK (evidence_id ~ '^sha256:[0-9a-f]{64}$'),
  object_key text NOT NULL UNIQUE, size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  producer text NOT NULL, subject text NOT NULL, source_version bigint NOT NULL,
  retention_class text NOT NULL, access_policy text NOT NULL,
  trace_id uuid NOT NULL, agent_id uuid NOT NULL, objective_id uuid NOT NULL,
  generation_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS authoritative_entities (
  entity_id uuid PRIMARY KEY, entity_kind text NOT NULL, version bigint NOT NULL CHECK (version > 0),
  state text NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS state_transitions (
  transition_id uuid PRIMARY KEY, entity_id uuid NOT NULL,
  entity_kind text NOT NULL, command_id uuid NOT NULL UNIQUE, actor text NOT NULL,
  previous_version bigint NOT NULL, new_version bigint NOT NULL,
  new_state text NOT NULL, evidence_id text NOT NULL REFERENCES evidence_refs(evidence_id),
  trace_id uuid NOT NULL, agent_id uuid NOT NULL, objective_id uuid NOT NULL,
  generation_id text NOT NULL, occurred_at timestamptz NOT NULL,
  correction_of uuid REFERENCES state_transitions(transition_id),
  CHECK (new_version = previous_version + 1)
);
CREATE INDEX IF NOT EXISTS state_transitions_entity_version
  ON state_transitions(entity_id, new_version);
CREATE TABLE IF NOT EXISTS projection_status (
  projection_name text PRIMARY KEY, source_version bigint NOT NULL,
  projected_version bigint NOT NULL, updated_at timestamptz NOT NULL,
  CHECK (projected_version <= source_version)
);
CREATE OR REPLACE FUNCTION habitat_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only record mutation denied' USING ERRCODE = '42501'; END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='state_transitions_append_only') THEN
    CREATE TRIGGER state_transitions_append_only BEFORE UPDATE OR DELETE ON state_transitions
      FOR EACH ROW EXECUTE FUNCTION habitat_reject_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='evidence_refs_append_only') THEN
    CREATE TRIGGER evidence_refs_append_only BEFORE UPDATE OR DELETE ON evidence_refs
      FOR EACH ROW EXECUTE FUNCTION habitat_reject_mutation();
  END IF;
END $$;
"""


class StateStore:
    def __init__(self, database_url: str, evidence, bucket=None, *, allow_test_reset=False,
                 recovery_mode=False):
        self.database_url = database_url
        self._evidence = (evidence if isinstance(evidence,GarageEvidenceAdapter)
                          else GarageEvidenceAdapter(evidence,bucket))
        self._allow_test_reset = allow_test_reset
        self._recovery_mode = recovery_mode

    @classmethod
    def from_urls(cls, database_url, endpoint, access_key, secret_key, bucket, *,
                  allow_test_reset=False, recovery_mode=False):
        evidence=GarageEvidenceAdapter.from_urls(endpoint,access_key,secret_key,bucket)
        return cls(database_url, evidence, allow_test_reset=allow_test_reset,
                   recovery_mode=recovery_mode)

    def _connect(self):
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def migrate(self, *, crash_at=None):
        """Apply declared schema migrations atomically; optionally inject a test crash."""
        with self._connect() as conn:
            conn.execute(MIGRATION)
            if crash_at == "during_migration":
                raise InjectedCrash("during_migration")
        self._evidence.ensure_bucket()

    def reset_for_test(self):
        """Erase disposable test state only when construction granted reset authority."""
        if not self._allow_test_reset:
            raise PermissionError("test reset authority was not granted")
        with self._connect() as conn:
            conn.execute("TRUNCATE authoritative_entities, projection_status")
            conn.execute("ALTER TABLE state_transitions DISABLE TRIGGER state_transitions_append_only")
            conn.execute("ALTER TABLE evidence_refs DISABLE TRIGGER evidence_refs_append_only")
            conn.execute("TRUNCATE state_transitions, evidence_refs")
            conn.execute("ALTER TABLE state_transitions ENABLE TRIGGER state_transitions_append_only")
            conn.execute("ALTER TABLE evidence_refs ENABLE TRIGGER evidence_refs_append_only")
        self._evidence.clear()

    def put_evidence(self, content: bytes, metadata: EvidenceMetadata, *, crash_at=None) -> EvidenceId:
        """Persist bounded content, verify it, then append its complete provenance reference."""
        if len(content) > MAX_EVIDENCE_BYTES:
            raise ValueError(f"evidence exceeds {MAX_EVIDENCE_BYTES} byte limit")
        digest = hashlib.sha256(content).hexdigest()
        evidence_id = EvidenceId(f"sha256:{digest}")
        key = f"sha256/{digest}"
        stored=self._evidence.put_content(key,content,
                           {"sha256": digest, "trace-id": str(metadata.correlation.trace_id)})
        if crash_at == "during_upload":
            raise InjectedCrash("during_upload")
        if stored != content:
            raise IntegrityError("evidence verification failed after upload")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO evidence_refs(evidence_id,object_key,size_bytes,producer,subject,source_version,"
                "retention_class,access_policy,trace_id,agent_id,objective_id,generation_id) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(evidence_id) DO NOTHING",
                (evidence_id.value, key, len(content), metadata.producer.value, metadata.subject,
                 metadata.source_version.value, metadata.retention_class, metadata.access_policy,
                 metadata.correlation.trace_id, metadata.correlation.agent_id,
                 metadata.correlation.objective_id, metadata.correlation.generation_id),
            )
        return evidence_id

    def verify_evidence(self, evidence_id: EvidenceId) -> bytes:
        """Read evidence only after independently validating its digest and bounded size."""
        with self._connect() as conn:
            reference = conn.execute(
                "SELECT * FROM evidence_refs WHERE evidence_id=%s", (evidence_id.value,)
            ).fetchone()
        if not reference:
            raise IntegrityError("unknown evidence reference")
        try:
            size,content=self._evidence.get_content(reference["object_key"])
            if size > MAX_EVIDENCE_BYTES or size != reference["size_bytes"]:
                raise IntegrityError("referenced evidence exceeds its declared bound")
        except Exception as error:
            raise IntegrityError("referenced evidence is unavailable") from error
        actual = "sha256:" + hashlib.sha256(content).hexdigest()
        if len(content) > MAX_EVIDENCE_BYTES or actual != evidence_id.value or len(content) != reference["size_bytes"]:
            raise IntegrityError("referenced evidence digest or size mismatch")
        return content

    def transition(self, entity_id: EntityId, command_id: CommandId, actor: PrincipalId,
                   expected_version: Version, new_state: State, evidence_id: EvidenceId,
                   correlation: Correlation, *, correction_of=None,
                   occurred_at=None, crash_at=None) -> Transition:
        """Atomically apply one legal optimistic transition and append its audit record."""
        occurred_at = occurred_at or datetime.now(timezone.utc)
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware UTC")
        occurred_at = occurred_at.astimezone(timezone.utc)
        with self._connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(entity_id.value),))
            existing = conn.execute(
                "SELECT * FROM state_transitions WHERE command_id=%s", (command_id.value,)
            ).fetchone()
            if existing:
                requested = (entity_id.value, entity_id.kind.value, actor.value, new_state.value,
                             evidence_id.value, correlation.trace_id, correlation.agent_id,
                             correlation.objective_id, correlation.generation_id)
                recorded = tuple(existing[key] for key in (
                    "entity_id", "entity_kind", "actor", "new_state", "evidence_id", "trace_id",
                    "agent_id", "objective_id", "generation_id"))
                if requested != recorded:
                    raise IntegrityError("idempotency key reused for a different command",
                                         correlation_id=str(correlation.trace_id),
                                         cause="command identity collision")
                return self._transition(existing)
            current = conn.execute(
                "SELECT version,state,entity_kind FROM authoritative_entities WHERE entity_id=%s FOR UPDATE",
                (entity_id.value,),
            ).fetchone()
            version = current["version"] if current else 0
            if version != expected_version.value:
                raise Conflict(version, str(correlation.trace_id))
            if current and current["entity_kind"] != entity_id.kind.value:
                raise IntegrityError("entity kind conflicts with authoritative identity",
                                     correlation_id=str(correlation.trace_id),
                                     cause="typed entity identity mismatch")
            previous_state = None if not current else State(current["state"])
            assert_legal(entity_id.kind, previous_state, new_state)
            if not conn.execute("SELECT 1 FROM evidence_refs WHERE evidence_id=%s", (evidence_id.value,)).fetchone():
                raise IntegrityError("transition evidence does not exist", correlation_id=str(correlation.trace_id))
            transition_id = str(uuid.uuid4())
            row = conn.execute(
                "INSERT INTO state_transitions(transition_id,entity_id,entity_kind,command_id,actor,"
                "previous_version,new_version,new_state,evidence_id,trace_id,agent_id,objective_id,generation_id,"
                "occurred_at,correction_of) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                (transition_id, entity_id.value, entity_id.kind.value, command_id.value, actor.value,
                 version, version + 1, new_state.value, evidence_id.value, correlation.trace_id,
                 correlation.agent_id, correlation.objective_id, correlation.generation_id,
                 occurred_at, correction_of),
            ).fetchone()
            conn.execute(
                "INSERT INTO authoritative_entities(entity_id,entity_kind,version,state,updated_at) VALUES(%s,%s,%s,%s,%s) "
                "ON CONFLICT(entity_id) DO UPDATE SET version=EXCLUDED.version,state=EXCLUDED.state,updated_at=EXCLUDED.updated_at",
                (entity_id.value, entity_id.kind.value, version + 1, new_state.value, occurred_at),
            )
            if crash_at == "before_commit":
                raise InjectedCrash("before_commit")
        if crash_at == "after_commit":
            raise InjectedCrash("after_commit")
        return self._transition(row)

    def current(self, entity_id: EntityId):
        """Return the current authoritative record, or None when it does not exist."""
        with self._connect() as conn:
            return conn.execute("SELECT * FROM authoritative_entities WHERE entity_id=%s", (entity_id.value,)).fetchone()

    def history(self, entity_id: EntityId):
        """Return ordered immutable history for one typed entity."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM state_transitions WHERE entity_id=%s ORDER BY new_version", (entity_id.value,)
            ).fetchall()
        return [self._transition(row) for row in rows]

    def report_projection(self, projection_name: str, source_version: int, projected_version: int):
        """Record bounded projection lag without treating a projection as authority."""
        if projected_version > source_version:
            raise ValueError("projection cannot be ahead of authoritative state")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO projection_status(projection_name,source_version,projected_version,updated_at) "
                "VALUES(%s,%s,%s,now()) ON CONFLICT(projection_name) DO UPDATE SET "
                "source_version=EXCLUDED.source_version,projected_version=EXCLUDED.projected_version,"
                "updated_at=EXCLUDED.updated_at",
                (projection_name, source_version, projected_version),
            )

    def projection_status(self, projection_name: str):
        """Return source/projected versions and their lag for one projection."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT projection_name,source_version,projected_version FROM projection_status "
                "WHERE projection_name=%s", (projection_name,)
            ).fetchone()
        if not row:
            return None
        return {**row, "lag": row["source_version"] - row["projected_version"]}

    def schema_status(self):
        """Return the compatibility and rollback declaration for applied migrations."""
        with self._connect() as conn:
            return conn.execute(
                "SELECT version,forward_compatible,backward_compatible,interruption_behavior,rollback_limit "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()

    def backup(self) -> dict:
        """Create a bounded, self-contained snapshot from one repeatable-read point."""
        marker = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            estimated = conn.execute(
                "SELECT COALESCE(SUM(size_bytes),0) AS bytes FROM evidence_refs"
            ).fetchone()["bytes"]
            if estimated > MAX_BACKUP_BYTES:
                raise IntegrityError("backup evidence exceeds bounded export size")
            entities = conn.execute(
                "SELECT * FROM authoritative_entities ORDER BY entity_id"
            ).fetchall()
            transitions = conn.execute(
                "SELECT * FROM state_transitions ORDER BY entity_id,new_version"
            ).fetchall()
            references = conn.execute(
                "SELECT * FROM evidence_refs ORDER BY evidence_id"
            ).fetchall()
            migrations = conn.execute(
                "SELECT * FROM schema_migrations ORDER BY version"
            ).fetchall()
        evidence = []
        for reference in references:
            content = self.verify_evidence(EvidenceId(reference["evidence_id"]))
            evidence.append({
                "evidence_id": reference["evidence_id"],
                "object_key": reference["object_key"],
                "size_bytes": reference["size_bytes"],
                **{key: str(reference[key]) if isinstance(reference[key], uuid.UUID) else reference[key]
                   for key in ("producer", "subject", "source_version", "retention_class", "access_policy",
                               "trace_id", "agent_id", "objective_id", "generation_id")},
                "created_at": reference["created_at"].isoformat(),
                "content_base64": base64.b64encode(content).decode(),
                "consistency_marker": marker,
            })
        result = {
            "schema_version": "1.0", "consistency_marker": marker,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "entities": [self._json_row(row) for row in entities],
            "transitions": [self._json_row(row) for row in transitions],
            "evidence": evidence,
            "migrations": [self._json_row(row) for row in migrations],
        }
        if len(json.dumps(result).encode()) > MAX_BACKUP_BYTES:
            raise IntegrityError("backup exceeds bounded export size")
        return result

    def restore(self, backup: dict) -> None:
        """Validate and restore a bounded snapshot under dedicated recovery authority."""
        if not self._recovery_mode:
            raise PermissionError("restore requires dedicated recovery mode")
        if len(json.dumps(backup).encode()) > MAX_BACKUP_BYTES:
            raise IntegrityError("backup exceeds bounded restore size")
        marker = backup.get("consistency_marker")
        try:
            uuid.UUID(marker)
        except (ValueError, TypeError) as error:
            raise IntegrityError("invalid backup consistency marker") from error
        evidence_by_id = {}
        for item in backup.get("evidence", []):
            if item.get("consistency_marker") != marker:
                raise IntegrityError("evidence consistency marker mismatch")
            try:
                content = base64.b64decode(item["content_base64"], validate=True)
            except Exception as error:
                raise IntegrityError("invalid evidence encoding") from error
            actual = "sha256:" + hashlib.sha256(content).hexdigest()
            if actual != item.get("evidence_id") or len(content) != item.get("size_bytes"):
                raise IntegrityError("backup evidence digest or size mismatch")
            evidence_by_id[actual] = (item, content)
        transition_ids = {row["transition_id"] for row in backup.get("transitions", [])}
        versions = {}
        for row in backup.get("transitions", []):
            if row["evidence_id"] not in evidence_by_id:
                raise IntegrityError("transition references missing evidence")
            if row.get("correction_of") and row["correction_of"] not in transition_ids:
                raise IntegrityError("correction references missing history")
            versions[row["entity_id"]] = max(versions.get(row["entity_id"], 0), row["new_version"])
        for row in backup.get("entities", []):
            if versions.get(row["entity_id"]) != row["version"]:
                raise IntegrityError("entity and history versions disagree")

        for item, content in evidence_by_id.values():
            self._evidence.put_content(item["object_key"],content,{"consistency-marker":marker})
        with self._connect() as conn:
            conn.execute("TRUNCATE state_transitions, authoritative_entities, evidence_refs")
            for item, _ in evidence_by_id.values():
                conn.execute(
                    "INSERT INTO evidence_refs(evidence_id,object_key,size_bytes,producer,subject,source_version,"
                    "retention_class,access_policy,trace_id,agent_id,objective_id,generation_id,created_at) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    tuple(item[key] for key in ("evidence_id", "object_key", "size_bytes", "producer", "subject",
                                                "source_version", "retention_class", "access_policy", "trace_id",
                                                "agent_id", "objective_id", "generation_id", "created_at")),
                )
            for row in backup.get("entities", []):
                conn.execute(
                    "INSERT INTO authoritative_entities(entity_id,entity_kind,version,state,updated_at) VALUES(%s,%s,%s,%s,%s)",
                    (row["entity_id"], row["entity_kind"], row["version"], row["state"], row["updated_at"]),
                )
            for row in backup.get("transitions", []):
                conn.execute(
                    "INSERT INTO state_transitions(transition_id,entity_id,entity_kind,command_id,actor,previous_version,"
                    "new_version,new_state,evidence_id,trace_id,agent_id,objective_id,generation_id,occurred_at,correction_of) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    tuple(row[key] for key in (
                        "transition_id", "entity_id", "entity_kind", "command_id", "actor", "previous_version",
                        "new_version", "new_state", "evidence_id", "trace_id", "agent_id", "objective_id",
                        "generation_id", "occurred_at", "correction_of")),
                )

    @staticmethod
    def _json_row(row):
        return {
            key: value.isoformat() if isinstance(value, datetime) else str(value) if isinstance(value, uuid.UUID) else value
            for key, value in row.items()
        }

    @staticmethod
    def _transition(row):
        return Transition(
            transition_id=str(row["transition_id"]),
            entity_id=EntityId(EntityKind(row["entity_kind"]), row["entity_id"]),
            command_id=CommandId(row["command_id"]), actor=PrincipalId(row["actor"]),
            previous_version=Version(row["previous_version"]), new_version=Version(row["new_version"]),
            new_state=State(row["new_state"]), evidence_id=EvidenceId(row["evidence_id"]),
            correlation=Correlation(row["trace_id"], row["agent_id"], row["objective_id"], row["generation_id"]),
            occurred_at=row["occurred_at"].isoformat(),
            correction_of=str(row["correction_of"]) if row["correction_of"] else None,
        )
