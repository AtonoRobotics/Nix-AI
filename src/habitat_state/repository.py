"""Authoritative transactional PostgreSQL repository."""
import hashlib
import json
from dataclasses import dataclass

import psycopg
from psycopg.rows import dict_row

from .errors import LedgerCorrupt, LedgerUnavailable
from .lifecycle import LifecycleStore

MIGRATION = """
CREATE TABLE IF NOT EXISTS abi_command_ledger (
 activation_id text NOT NULL, command_id text NOT NULL,
 request_digest text NOT NULL,
 committed_result jsonb NOT NULL, evidence_ref text NOT NULL,
 committed_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (activation_id, command_id),
 CHECK (jsonb_typeof(committed_result) = 'object'));
ALTER TABLE abi_command_ledger DROP CONSTRAINT IF EXISTS abi_command_ledger_request_digest_check;
ALTER TABLE abi_command_ledger ADD CONSTRAINT abi_command_ledger_request_digest_check
 CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$');
CREATE OR REPLACE FUNCTION abi_command_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'command ledger is append-only' USING ERRCODE='42501'; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='abi_command_ledger_immutable')
THEN CREATE TRIGGER abi_command_ledger_immutable BEFORE UPDATE OR DELETE ON abi_command_ledger
FOR EACH ROW EXECUTE FUNCTION abi_command_ledger_immutable(); END IF; END $$;
CREATE TABLE IF NOT EXISTS evidence_admissions(
 producer text NOT NULL, command_id text NOT NULL, content_digest text NOT NULL,
 evidence_ref text, admitted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(producer,command_id));
"""


@dataclass(frozen=True)
class ReplayOutcome:
    result: dict
    duplicate: bool
    digest_mismatch: bool = False


class CommandLedgerStore:
    def __init__(self, database_url): self.database_url = database_url
    def _connect(self):
        try: return psycopg.connect(self.database_url, row_factory=dict_row)
        except psycopg.Error as error: raise LedgerUnavailable("PostgreSQL command ledger unavailable") from error
    def migrate(self):
        with self._connect() as connection: connection.execute(MIGRATION)
    @staticmethod
    def _validate_result(result, command_id):
        if not isinstance(result, dict) or result.get("command_id") != command_id:
            raise LedgerCorrupt("committed result is not bound to its command")
        if result.get("committed") is not True or not isinstance(result.get("state"), str):
            raise LedgerCorrupt("committed result lacks mandatory disposition fields")
        return result
    def commit(self, activation_id, command_id, request_digest, proposed):
        if not all(isinstance(value, str) and value for value in (activation_id, command_id, request_digest)):
            raise ValueError("activation, command, and digest are required")
        digest = request_digest.removeprefix("sha256:")
        if not request_digest.startswith("sha256:") or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("request digest must be canonical sha256:<lowercase-hex>")
        self._validate_result(proposed, command_id)
        evidence_ref = proposed.get("durable_record_id")
        if not isinstance(evidence_ref, str) or not evidence_ref: raise ValueError("durable record id is required")
        with self._connect() as connection:
            inserted = connection.execute("""INSERT INTO abi_command_ledger
              (activation_id,command_id,request_digest,committed_result,evidence_ref)
              VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING 1""",
              (activation_id, command_id, request_digest, json.dumps(proposed), evidence_ref)).fetchone()
            row = connection.execute("""SELECT request_digest,committed_result,evidence_ref
              FROM abi_command_ledger WHERE activation_id=%s AND command_id=%s FOR SHARE""",
              (activation_id, command_id)).fetchone()
            if not row: raise LedgerCorrupt("committed command disappeared inside transaction")
            result = self._validate_result(row["committed_result"], command_id)
            if row["request_digest"] != request_digest: return ReplayOutcome(result, True, True)
            return ReplayOutcome(result, inserted is None, False)
    def get(self, activation_id, command_id):
        with self._connect() as connection:
            row = connection.execute("SELECT request_digest,committed_result,evidence_ref FROM abi_command_ledger WHERE activation_id=%s AND command_id=%s", (activation_id, command_id)).fetchone()
        return None if row is None else self._validate_result(row["committed_result"], command_id)
    def get_bound(self, activation_id, command_id):
        with self._connect() as connection:
            row = connection.execute("SELECT request_digest,committed_result,evidence_ref FROM abi_command_ledger WHERE activation_id=%s AND command_id=%s", (activation_id, command_id)).fetchone()
        if row is None:return None
        return {"request_digest":row["request_digest"],"evidence_ref":row["evidence_ref"],
                "result":self._validate_result(row["committed_result"],command_id)}


class PostgresRepository:
    """Single PostgreSQL seam for replay and all lifecycle-owned state."""
    def __init__(self, database_url):
        self._commands = CommandLedgerStore(database_url)
        self._lifecycle = LifecycleStore(database_url)
        self._evidence = None
    def bind_evidence(self,evidence): self._evidence=evidence; return self
    def _verified(self,reference,**bindings):
        if self._evidence is None: raise LedgerUnavailable("evidence authority is not bound")
        return self._evidence.verify_record(reference,**bindings)
    def put_evidence(self,envelope,principal,command_id):
        if self._evidence is None: raise LedgerUnavailable("evidence authority is not bound")
        return self._evidence.put_envelope(envelope,principal,command_id)
    def commit_verified_command(self,activation_id,command_id,request_digest,result,principal):
        self._verified(result["durable_record_id"],subject=command_id,producer=principal,
          source=request_digest,operation="command.commit",disposition=result["state"])
        outcome=self._commands.commit(activation_id,command_id,request_digest,result)
        return {"status":"digest_mismatch" if outcome.digest_mismatch else "ok","result":outcome.result}
    def observe_verified_effect(self,objective_id,effect_id):
        projection=self._lifecycle.inspect_effect_projection(objective_id,effect_id)
        if not projection:raise ValueError("effect projection not found")
        evidence=self._verified(projection["evidence_ref"],subject=effect_id,producer="service:effects",
          source=projection["external_ref"],operation="effect.transition")
        return {"projection":projection,"evidence":evidence}
    def apply_verified_effect_transition(self,request):
        self._verified(request["evidence_ref"],subject=request["effect_id"],producer="service:effects",
          source=request["external_ref"],operation="effect.transition",disposition=request["new_state"])
        return self._lifecycle.observe_effect_transition(request["transition_id"],request["effect_id"],
          request["objective_id"],request["request_digest"],request.get("previous_state"),
          request["new_state"],request["evidence_ref"],request.get("external_ref"))
    def propose_verified_change(self,request,principal):
        evidence=self._verified(request["evidence_ref"],subject=request["candidate_id"],producer=principal,
          source=request["source_digest"],operation="change.propose",disposition="PROPOSED")
        payload=evidence.get("payload",{})
        for field in ("dependency_closure_digest","contract_version","tests_digest",
                      "requested_authority","signing_key_digest","live_verification_contract",
                      "evaluator","evaluator_closure","target_generation","rollback_generation","threshold"):
            if payload.get(field)!=request.get(field):
                raise LedgerCorrupt(f"change proposal evidence does not bind {field}")
        return self._lifecycle.propose_governed_change(request["candidate_id"],request["command_id"],
          request["source_digest"],request["evaluator"],request["evaluator_closure"],request["target_generation"],
          request["rollback_generation"],request["threshold"],request["evidence_ref"],
          request["dependency_closure_digest"],request["contract_version"],request["tests_digest"],
          request["requested_authority"],request["signing_key_digest"],request["live_verification_contract"])
    def transition_verified_change(self,request,principal):
        observation=self._verified(request["evidence_ref"],subject=request["candidate_id"],producer=principal,
          source=request["evidence_source"],operation="change."+request["new_state"].lower(),disposition=request["new_state"])
        return self._lifecycle.transition_governed_change(request["candidate_id"],request["command_id"],
          request["new_state"],request["actor"],request["evidence_ref"],observation=observation)
    def admit_verified_package(self,request):
        evidence=self._verified(request["evidence_ref"],subject=request["package_id"],producer="service:packages",
          source=request["content_digest"],operation="package.admit",disposition="VERIFIED")
        payload=evidence.get("payload",{})
        required=("manifest","manifest_digest","bundle_digest","signature_digest",
          "provenance_digest","sbom_digest","dependency_closure","admission_evidence")
        if payload.get("manifest")!=request["manifest"] or any(key not in payload for key in required):
            raise LedgerCorrupt("package evidence does not bind the admitted manifest and materials")
        if payload.get("bundle_digest")!=request["content_digest"]:
            raise LedgerCorrupt("package evidence bundle digest mismatch")
        for key in ("manifest_digest","signature_digest","provenance_digest","sbom_digest","admission_evidence"):
            value=payload.get(key)
            if not isinstance(value,str) or not value.startswith("sha256:") or len(value)!=71:
                raise LedgerCorrupt("package evidence material digest is invalid")
        if not isinstance(payload.get("dependency_closure"),list):
            raise LedgerCorrupt("package evidence dependency closure is invalid")
        return self._lifecycle.admit_package(request["package_id"],request["content_digest"],request["manifest"],request["evidence_ref"])
    def commit_verified_authority(self,request):
        self._verified(request["evidence_ref"],subject=request["binding_id"],producer="service:authority",
          source=request["snapshot_digest"],operation="authority.snapshot")
        return self._lifecycle.commit_authority_snapshot(request["binding_id"],request["command_id"],
          request["expected_version"],request["generation"],request["snapshot"],request["snapshot_digest"],request["evidence_ref"])
    def claim_verified_activation(self,request,principal):
        if principal!="service:scheduler":raise ValueError("activation claim requires scheduler principal")
        evidence=self._verified(request["evidence_ref"],subject=request["activation_id"],producer=principal,
          source=request["credential_digest"],operation="activation.claim",disposition="LEASED")
        payload=evidence.get("payload",{})
        bound_fields=("command_id","objective_id","wake_id","machine_id","agent_id","lease_owner",
          "context_bundle_id","isolation_profile_id","resource_lease_id","trace_id",
          "correlation_id","credential_key_version","lease_seconds","expected_lease_fence")
        if any(payload.get(field)!=request.get(field) for field in bound_fields):
            raise LedgerCorrupt("activation claim evidence does not bind the complete request")
        return self._lifecycle.claim_activation(
          command_id=request["command_id"],activation_id=request["activation_id"],
          objective_id=request["objective_id"],wake_id=request["wake_id"],
          machine_id=request["machine_id"],agent_id=request["agent_id"],
          lease_owner=request["lease_owner"],lease_seconds=request["lease_seconds"],
          context_bundle_id=request["context_bundle_id"],isolation_profile_id=request["isolation_profile_id"],
          resource_lease_id=request["resource_lease_id"],trace_id=request["trace_id"],
          correlation_id=request["correlation_id"],credential_digest=request["credential_digest"],
          credential_key_version=request["credential_key_version"],
          expected_lease_fence=request["expected_lease_fence"],evidence_ref=request["evidence_ref"])
    def publish_verified_capability_set(self,request,principal):
        if principal!="service:packages":raise ValueError("capability set publication requires packages principal")
        evidence=self._verified(request["evidence_ref"],subject=request["set_id"],producer=principal,
          source=request["generation_id"],operation="capability-set.publish",disposition="ACTIVE")
        payload=evidence.get("payload",{})
        for field in ("command_id","grant_ids","expected_active_set_id","expected_active_version"):
            if payload.get(field)!=request.get(field):
                raise LedgerCorrupt(f"capability-set evidence does not bind {field}")
        expected_deactivation={"set_id":request.get("expected_active_set_id"),
          "version":request["expected_active_version"]}
        if payload.get("deactivates")!=expected_deactivation:
            raise LedgerCorrupt("capability-set evidence does not bind deactivation")
        return self._lifecycle.publish_capability_activation_set(request["command_id"],request["set_id"],
          request["generation_id"],request["grant_ids"],request["evidence_ref"],
          request.get("expected_active_set_id"),request["expected_active_version"])
    def migrate(self, **kwargs):
        self._commands.migrate(); self._lifecycle.migrate(**kwargs)
    def reserve_evidence(self,producer,command_id,content_digest,quota=1000):
        if not all(isinstance(v,str) and v for v in (producer,command_id,content_digest)):
            raise ValueError("evidence admission identity is required")
        with self._commands._connect() as c:
            # Serialize quota accounting per producer. PostgreSQL cannot apply
            # FOR UPDATE to an aggregate, and locking only existing rows leaves
            # the zero-row case racy.
            c.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 19088743))",(producer,))
            row=c.execute("SELECT content_digest,evidence_ref FROM evidence_admissions WHERE producer=%s AND command_id=%s FOR UPDATE",(producer,command_id)).fetchone()
            if row:
                if row["content_digest"]!=content_digest:raise ValueError("CONFLICT: evidence command identity reused")
                return row["evidence_ref"]
            count=c.execute("SELECT count(*) AS count FROM evidence_admissions WHERE producer=%s",(producer,)).fetchone()["count"]
            if count>=quota:raise ValueError("evidence producer quota exceeded")
            c.execute("INSERT INTO evidence_admissions(producer,command_id,content_digest) VALUES(%s,%s,%s)",(producer,command_id,content_digest))
            return None
    def finalize_evidence(self,producer,command_id,content_digest,evidence_ref):
        with self._commands._connect() as c:
            row=c.execute("UPDATE evidence_admissions SET evidence_ref=%s WHERE producer=%s AND command_id=%s AND content_digest=%s AND (evidence_ref IS NULL OR evidence_ref=%s) RETURNING evidence_ref",(evidence_ref,producer,command_id,content_digest,evidence_ref)).fetchone()
            if not row:raise ValueError("CONFLICT: evidence admission changed")
            return row["evidence_ref"]
    def recover(self, now):
        if self._evidence is None: raise LedgerUnavailable("evidence authority is not bound")
        def publish(command_id,payload):
            canonical=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
            source="sha256:"+hashlib.sha256(canonical).hexdigest()
            envelope={"schema_version":"1","producer":"service:state",
              "subject":payload["activation_id"],"operation":"activation.recover",
              "source":source,"payload":payload}
            return self.put_evidence(envelope,"service:state",command_id)["evidence_ref"]
        return self._lifecycle.recover(now=now,publish_recovery_evidence=publish)
    def ensure_active_generation(self,generation): return self._lifecycle.ensure_active_generation(generation)
    def get_command(self,activation_id,command_id):
        bound=self._commands.get_bound(activation_id,command_id)
        if bound is None:return None
        self._verified(bound["evidence_ref"],subject=command_id,producer="service:abi",
          source=bound["request_digest"],operation="command.commit",
          disposition=bound["result"]["state"])
        return bound["result"]
    def guard_objective_effects(self,*args): return self._lifecycle.guard_objective_effects(*args)
    def invalidate_objective_effect_guard(self,*args): return self._lifecycle.invalidate_objective_effect_guard(*args)
    def governed_change(self,*args): return self._lifecycle.governed_change(*args)
    def governed_change_history(self,*args): return self._lifecycle.governed_change_history(*args)
    def schedule_objective(self,*args,**kwargs): return self._lifecycle.schedule_objective(*args,**kwargs)
    def complete_ready_objective(self,*args,**kwargs): return self._lifecycle.complete_ready_objective(*args,**kwargs)
    def inspect_objective(self,*args): return self._lifecycle.inspect_objective(*args)
    def pending_objectives(self,*args): return self._lifecycle.pending_objectives(*args)
    def authority_binding(self,*args): return self._lifecycle.authority_binding(*args)
