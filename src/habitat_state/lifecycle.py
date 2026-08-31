"""PostgreSQL-owned objective, durable-wake, and activation-lease lifecycle."""
from __future__ import annotations
import hashlib, json
import psycopg
from psycopg.rows import dict_row

class ClockUntrusted(RuntimeError): pass

class LifecycleStore:
    def __init__(self, database_url, *, max_clock_skew=5):
        self.database_url, self.max_clock_skew = database_url, max_clock_skew

    def _connect(self):
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def migrate(self, *, fault_after_archive=False):
        with self._connect() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS lifecycle_commands(
              command_id text PRIMARY KEY, fingerprint text NOT NULL, result jsonb NOT NULL);
            CREATE TABLE IF NOT EXISTS objectives(
              objective_id text PRIMARY KEY, state text NOT NULL, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS wakes(
              wake_id text PRIMARY KEY, objective_id text NOT NULL, state text NOT NULL,
              due_at bigint NOT NULL, lease_owner text, lease_expires_at bigint,
              version bigint NOT NULL, created_command text NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS activations(
              activation_id text PRIMARY KEY, objective_id text NOT NULL, state text NOT NULL,
              lease_owner text, lease_expires_at bigint, monotonic_started bigint,
              version bigint NOT NULL);
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS wake_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS machine_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS agent_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS lease_fence bigint;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS system_generation_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS capability_activation_set_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS context_bundle_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS capability_grant_ids jsonb;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS isolation_profile_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS resource_lease_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS deadline bigint;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS trace_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS correlation_id text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS credential_digest text;
            ALTER TABLE activations ADD COLUMN IF NOT EXISTS credential_key_version bigint;
            DROP INDEX IF EXISTS activations_one_live_objective;
            CREATE UNIQUE INDEX activations_one_live_objective
              ON activations(objective_id) WHERE state IN
              ('LEASED','PREPARING','RUNNING','WAITING_CONTEXT','WAITING_EFFECT','SLEEPING')
              AND lease_fence IS NOT NULL;
            CREATE TABLE IF NOT EXISTS activation_migration_archive(
              activation_id text PRIMARY KEY, raw_record jsonb NOT NULL,
              classification text NOT NULL, archived_at timestamptz NOT NULL DEFAULT now());
            CREATE TABLE IF NOT EXISTS activation_binding_history(
              activation_id text NOT NULL, version bigint NOT NULL, command_id text NOT NULL UNIQUE,
              binding jsonb NOT NULL, evidence_ref text NOT NULL,
              recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(activation_id,version));
            CREATE TABLE IF NOT EXISTS capability_activation_sets(
              set_id text PRIMARY KEY, generation_id text NOT NULL, grant_ids jsonb NOT NULL,
              evidence_ref text NOT NULL, active boolean NOT NULL, version bigint NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS capability_activation_sets_one_active
              ON capability_activation_sets(active) WHERE active;
            CREATE TABLE IF NOT EXISTS capability_activation_set_history(
              set_id text NOT NULL, version bigint NOT NULL, generation_id text NOT NULL,
              grant_ids jsonb NOT NULL, evidence_ref text NOT NULL,
              recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(set_id,version));
            ALTER TABLE capability_activation_set_history ADD COLUMN IF NOT EXISTS command_id text;
            ALTER TABLE capability_activation_set_history ADD COLUMN IF NOT EXISTS active boolean;
            CREATE UNIQUE INDEX IF NOT EXISTS capability_activation_set_history_command
              ON capability_activation_set_history(command_id) WHERE command_id IS NOT NULL;
            INSERT INTO activation_migration_archive(activation_id,raw_record,classification)
              SELECT activation_id,to_jsonb(a),'UNKNOWN' FROM activations a
              WHERE lease_fence IS NULL OR wake_id IS NULL OR machine_id IS NULL OR agent_id IS NULL
                OR system_generation_id IS NULL OR capability_activation_set_id IS NULL
                OR credential_digest IS NULL
              ON CONFLICT(activation_id) DO NOTHING;
            CREATE TABLE IF NOT EXISTS lifecycle_history(
              record_id bigserial PRIMARY KEY, entity_id text NOT NULL, previous_state text,
              new_state text NOT NULL, command_id text NOT NULL UNIQUE, actor text NOT NULL,
              occurred_at timestamptz NOT NULL DEFAULT now(), evidence_ref text NOT NULL);
            CREATE TABLE IF NOT EXISTS durable_effects(
              effect_id text PRIMARY KEY, activation_id text NOT NULL, request_digest text NOT NULL,
              state text NOT NULL,
              external_ref text, evidence_ref text, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS provider_effect_transitions(
              transition_id text PRIMARY KEY, effect_id text NOT NULL,
              previous_state text, new_state text NOT NULL,
              request_digest text NOT NULL, evidence_ref text,
              occurred_at timestamptz NOT NULL DEFAULT now());
            ALTER TABLE provider_effect_transitions ADD COLUMN IF NOT EXISTS sequence bigint;
            -- Never drop a legacy effect table here.  Migrations are deliberately
            -- additive because PostgreSQL is the operational truth for effects.
            ALTER TABLE durable_effects DROP CONSTRAINT IF EXISTS durable_effects_state_check;
            ALTER TABLE durable_effects ADD CONSTRAINT durable_effects_state_check
              CHECK(state IN ('PROPOSED','REJECTED','RESERVED','EXECUTING',
                'OBSERVED_SUCCEEDED','OBSERVED_FAILED','OUTCOME_UNKNOWN','RECONCILING',
                'RESOLVED_SUCCEEDED','RESOLVED_FAILED','AUTHORITY_REQUIRED','COMMITTED'));
            CREATE TABLE IF NOT EXISTS effect_records(
              effect_id text PRIMARY KEY, objective_id text NOT NULL,
              request_digest text NOT NULL, state text NOT NULL,
              canonical_record jsonb NOT NULL, version bigint NOT NULL,
              updated_at timestamptz NOT NULL DEFAULT now());
            CREATE TABLE IF NOT EXISTS effect_attempts(
              effect_id text NOT NULL, attempt_number bigint NOT NULL,
              kind text NOT NULL CHECK(kind IN ('DISPATCH','RECONCILIATION')),
              request_digest text NOT NULL, provider_id text NOT NULL,
              transport_id text NOT NULL, dispatched_at bigint NOT NULL,
              response text, observation_source text, terminal_classification text,
              PRIMARY KEY(effect_id,kind,attempt_number));
            CREATE TABLE IF NOT EXISTS effect_transition_history(
              event_id text PRIMARY KEY, effect_id text NOT NULL, previous_state text,
              new_state text NOT NULL, canonical_event jsonb NOT NULL,
              effect_version bigint NOT NULL DEFAULT 1,
              occurred_at timestamptz NOT NULL DEFAULT now());
            ALTER TABLE effect_transition_history ADD COLUMN IF NOT EXISTS
              effect_version bigint NOT NULL DEFAULT 1;
            CREATE EXTENSION IF NOT EXISTS pgcrypto;
            CREATE TABLE IF NOT EXISTS effect_migration_archive(
              source_table text NOT NULL, source_ordinal bigint NOT NULL,
              raw_record jsonb NOT NULL, raw_digest text NOT NULL,
              classification text NOT NULL CHECK(classification IN
                ('V2_COMPATIBLE','UNKNOWN','REJECTED_DOMAIN_STATE')),
              PRIMARY KEY(source_table,source_ordinal));
            -- durable_effects is the current V2 projection, never legacy input.
            -- Remove rows produced by the earlier faulty migration rather than
            -- poisoning readiness on every subsequent boot.
            DELETE FROM effect_migration_archive WHERE source_table='durable_effects';
            DO $$ BEGIN IF to_regclass('effect_history') IS NOT NULL THEN
              EXECUTE $archive$INSERT INTO effect_migration_archive
                (source_table,source_ordinal,raw_record,raw_digest,classification)
                SELECT 'effect_history',row_number() OVER (ORDER BY ctid),to_jsonb(h),
                  'sha256:'||encode(digest(convert_to(to_jsonb(h)::text,'UTF8'),'sha256'),'hex'),
                  'UNKNOWN' FROM effect_history h ON CONFLICT DO NOTHING$archive$;
            END IF; END $$;
            CREATE TABLE IF NOT EXISTS objective_effect_guards(
              objective_id text PRIMARY KEY, effect_set_digest text NOT NULL,
              effect_count bigint NOT NULL CHECK(effect_count > 0), ready boolean NOT NULL,
              recorded_at timestamptz NOT NULL DEFAULT now());
            CREATE TABLE IF NOT EXISTS admitted_packages(
              package_id text PRIMARY KEY, content_digest text NOT NULL UNIQUE,
              manifest jsonb NOT NULL, state text NOT NULL CHECK(state IN ('VERIFIED','STAGED','ACTIVE','QUARANTINED')),
              evidence_ref text NOT NULL, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS change_candidates(
              candidate_id text PRIMARY KEY, source_digest text NOT NULL, evaluator_generation text NOT NULL,
              target_generation text NOT NULL, rollback_generation text NOT NULL,
              threshold jsonb NOT NULL, state text NOT NULL, evidence_ref text NOT NULL,
              version bigint NOT NULL);
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS evaluator_closure text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS active_generation text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS dependency_closure_digest text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS contract_version text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS tests_digest text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS requested_authority jsonb;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS signing_key_digest text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS live_verification_contract text;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS expected_active_version bigint;
            ALTER TABLE change_candidates ADD COLUMN IF NOT EXISTS activation_binding_version bigint;
            CREATE TABLE IF NOT EXISTS change_history(
              candidate_id text NOT NULL, version bigint NOT NULL, previous_state text,
              new_state text NOT NULL, command_id text NOT NULL UNIQUE, actor text NOT NULL,
              evidence_ref text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY(candidate_id,version));
            ALTER TABLE change_history ADD COLUMN IF NOT EXISTS observation jsonb;
            CREATE TABLE IF NOT EXISTS active_generation_binding(
              singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
              active_generation text NOT NULL, previous_generation text,
              candidate_id text NOT NULL, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_bindings(
              binding_id text PRIMARY KEY, generation text NOT NULL,
              grants_digest text NOT NULL, evidence_ref text NOT NULL, version bigint NOT NULL,
              snapshot jsonb, snapshot_digest text);
            CREATE TABLE IF NOT EXISTS authority_binding_history(
              binding_id text NOT NULL, version bigint NOT NULL, command_id text NOT NULL UNIQUE,
              generation text NOT NULL, grants_digest text NOT NULL, evidence_ref text NOT NULL,
              snapshot jsonb, snapshot_digest text,
              PRIMARY KEY(binding_id,version));
            ALTER TABLE authority_bindings ADD COLUMN IF NOT EXISTS snapshot jsonb;
            ALTER TABLE authority_bindings ADD COLUMN IF NOT EXISTS snapshot_digest text;
            ALTER TABLE authority_binding_history ADD COLUMN IF NOT EXISTS snapshot jsonb;
            ALTER TABLE authority_binding_history ADD COLUMN IF NOT EXISTS snapshot_digest text;
            CREATE OR REPLACE FUNCTION lifecycle_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'lifecycle history is append-only' USING ERRCODE='42501'; END $$;
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='lifecycle_history_immutable')
            THEN CREATE TRIGGER lifecycle_history_immutable BEFORE UPDATE OR DELETE ON lifecycle_history
            FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='activation_binding_history_immutable')
            THEN CREATE TRIGGER activation_binding_history_immutable BEFORE UPDATE OR DELETE ON activation_binding_history
            FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capability_activation_set_history_immutable')
            THEN CREATE TRIGGER capability_activation_set_history_immutable BEFORE UPDATE OR DELETE ON capability_activation_set_history
            FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            DO $$ BEGIN IF to_regclass('effect_history') IS NOT NULL AND NOT EXISTS
              (SELECT 1 FROM pg_trigger WHERE tgname='legacy_effect_history_immutable') THEN
              CREATE TRIGGER legacy_effect_history_immutable BEFORE UPDATE OR DELETE
                ON effect_history FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable();
            END IF; END $$;
            DROP TRIGGER IF EXISTS durable_effects_immutable ON durable_effects;
            CREATE TRIGGER durable_effects_immutable BEFORE DELETE ON durable_effects
              FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable();
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='provider_effect_transitions_immutable')
            THEN CREATE TRIGGER provider_effect_transitions_immutable BEFORE UPDATE OR DELETE
              ON provider_effect_transitions FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='effect_transition_history_immutable')
            THEN CREATE TRIGGER effect_transition_history_immutable BEFORE UPDATE OR DELETE ON effect_transition_history
            FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='habitat-effects') THEN
              GRANT SELECT,INSERT,UPDATE ON effect_records,effect_attempts TO "habitat-effects";
              GRANT SELECT,INSERT ON effect_transition_history TO "habitat-effects";
            END IF; END $$;
            DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='habitat-verifier') THEN
              GRANT SELECT ON objectives,wakes,objective_effect_guards,durable_effects,
                effect_records,effect_attempts,effect_transition_history,
                authority_bindings,authority_binding_history
                TO "habitat-verifier";
            END IF; END $$;
            CREATE OR REPLACE FUNCTION effects_reserve_compensation(
              requested_objective text, original_effect text) RETURNS void
              LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM public.objectives WHERE objective_id=requested_objective
                             AND state IN ('PROPOSED','SATISFIED') FOR UPDATE)
                 OR NOT EXISTS (SELECT 1 FROM public.durable_effects
                    WHERE effect_id=original_effect AND activation_id=requested_objective
                    AND state='COMMITTED' FOR SHARE) THEN
                RAISE EXCEPTION 'compensation precondition failed';
              END IF;
              UPDATE public.objective_effect_guards SET ready=false,recorded_at=now()
                WHERE objective_id=requested_objective;
              IF NOT FOUND THEN RAISE EXCEPTION 'compensation blocker missing'; END IF;
            END $$;
            REVOKE ALL ON FUNCTION effects_reserve_compensation(text,text) FROM PUBLIC;
            DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='habitat-effects') THEN
              GRANT EXECUTE ON FUNCTION effects_reserve_compensation(text,text) TO "habitat-effects";
            END IF; END $$;
            """)
            if fault_after_archive:
                raise RuntimeError("injected migration failure after legacy archive")

    def reset_for_test(self):
        with self._connect() as c:
            c.execute("TRUNCATE lifecycle_commands, objectives, wakes, activations, activation_binding_history, activation_migration_archive, capability_activation_sets, capability_activation_set_history, durable_effects, effect_records, effect_attempts, effect_migration_archive, objective_effect_guards, admitted_packages, change_candidates, change_history, active_generation_binding, authority_bindings, authority_binding_history")
            c.execute("ALTER TABLE provider_effect_transitions DISABLE TRIGGER provider_effect_transitions_immutable")
            c.execute("TRUNCATE provider_effect_transitions")
            c.execute("ALTER TABLE provider_effect_transitions ENABLE TRIGGER provider_effect_transitions_immutable")
            c.execute("ALTER TABLE effect_transition_history DISABLE TRIGGER effect_transition_history_immutable")
            c.execute("TRUNCATE effect_transition_history")
            c.execute("ALTER TABLE effect_transition_history ENABLE TRIGGER effect_transition_history_immutable")
            c.execute("ALTER TABLE lifecycle_history DISABLE TRIGGER lifecycle_history_immutable")
            c.execute("TRUNCATE lifecycle_history")
            c.execute("ALTER TABLE lifecycle_history ENABLE TRIGGER lifecycle_history_immutable")

    @staticmethod
    def _fingerprint(operation, values):
        return hashlib.sha256(json.dumps([operation, *values], sort_keys=True).encode()).hexdigest()

    def _replay(self, c, command_id, fingerprint):
        row=c.execute("SELECT fingerprint,result FROM lifecycle_commands WHERE command_id=%s",
                      (command_id,)).fetchone()
        if not row: return None
        if row["fingerprint"] != fingerprint: raise ValueError("CONFLICT: command identity reused")
        return row["result"]

    def _record(self,c,command_id,fingerprint,result):
        c.execute("INSERT INTO lifecycle_commands VALUES(%s,%s,%s)",
                  (command_id,fingerprint,json.dumps(result)))

    def create_wake(self,wake_id,objective_id,command_id,due_at,notify):
        fp=self._fingerprint("create_wake",[wake_id,objective_id,due_at])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay: result=replay
            else:
                result={"wake_id":wake_id,"state":"PENDING","version":1}
                c.execute("INSERT INTO wakes VALUES(%s,%s,'PENDING',%s,NULL,NULL,1,%s)",
                          (wake_id,objective_id,due_at,command_id))
                c.execute("INSERT INTO lifecycle_history(entity_id,previous_state,new_state,command_id,actor,evidence_ref)"
                          " VALUES(%s,NULL,'PENDING',%s,'service:wake-scheduler',%s)",
                          (wake_id,command_id,f"evidence:{fp}"))
                self._record(c,command_id,fp,result)
        notify(result)
        return result

    def lease_wake(self,worker,*,now,lease_seconds):
        with self._connect() as c:
            row=c.execute("""SELECT * FROM wakes WHERE due_at<=%s AND
              (state IN ('PENDING','RELEASED') OR (state='LEASED' AND lease_expires_at<=%s))
              ORDER BY due_at,wake_id FOR UPDATE SKIP LOCKED LIMIT 1""",(now,now)).fetchone()
            if not row:return None
            c.execute("UPDATE wakes SET state='LEASED',lease_owner=%s,lease_expires_at=%s,"
                      "version=version+1 WHERE wake_id=%s",(worker,now+lease_seconds,row["wake_id"]))
            return {**row,"state":"LEASED","lease_owner":worker,
                    "lease_expires_at":now+lease_seconds,"version":row["version"]+1}

    def acknowledge_wake(self,wake_id,command_id,worker,*,now):
        fp=self._fingerprint("ack_wake",[wake_id,worker])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT * FROM wakes WHERE wake_id=%s FOR UPDATE",(wake_id,)).fetchone()
            if not row or row["state"]!="LEASED" or row["lease_owner"]!=worker:
                raise ValueError("CONFLICT: wake lease is not owned")
            if row["lease_expires_at"]<=now: raise ValueError("CONFLICT: wake lease expired")
            result={"wake_id":wake_id,"state":"ACKNOWLEDGED","version":row["version"]+1}
            c.execute("UPDATE wakes SET state='ACKNOWLEDGED',version=version+1 WHERE wake_id=%s",(wake_id,))
            c.execute("INSERT INTO lifecycle_history(entity_id,previous_state,new_state,command_id,actor,evidence_ref)"
                      " VALUES(%s,'LEASED','ACKNOWLEDGED',%s,%s,%s)",
                      (wake_id,command_id,worker,f"evidence:{fp}"))
            self._record(c,command_id,fp,result)
            return result

    def create_objective(self,objective_id,command_id,actor):
        return self._objective_transition(objective_id,command_id,actor,None,"PROPOSED",False)

    def transition_objective(self,objective_id,command_id,actor,new_state,*,completion_claim_accepted=False):
        return self._objective_transition(objective_id,command_id,actor,None,new_state,
                                          completion_claim_accepted)

    def _objective_transition(self,objective_id,command_id,actor,expected,new_state,accepted):
        fp=self._fingerprint("objective",[objective_id,new_state,accepted])
        legal={None:{"PROPOSED"},"PROPOSED":{"ACTIVE","CANCELLED"},
               "ACTIVE":{"WAITING","SATISFIED","FAILED","CANCELLED"},
               "WAITING":{"ACTIVE","FAILED","CANCELLED"}}
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT * FROM objectives WHERE objective_id=%s FOR UPDATE",
                          (objective_id,)).fetchone()
            previous=row["state"] if row else None
            if new_state not in legal.get(previous,set()): raise ValueError("illegal objective transition")
            if new_state=="SATISFIED" and not accepted: raise ValueError("accepted completion claim required")
            version=(row["version"] if row else 0)+1
            c.execute("""INSERT INTO objectives VALUES(%s,%s,%s) ON CONFLICT(objective_id)
              DO UPDATE SET state=EXCLUDED.state,version=EXCLUDED.version""",
                      (objective_id,new_state,version))
            result={"objective_id":objective_id,"state":new_state,"version":version}
            c.execute("INSERT INTO lifecycle_history(entity_id,previous_state,new_state,command_id,actor,evidence_ref)"
                      " VALUES(%s,%s,%s,%s,%s,%s)",(objective_id,previous,new_state,command_id,
                      actor,f"evidence:{fp}"))
            self._record(c,command_id,fp,result); return result

    def create_activation(self,activation_id,objective_id):
        with self._connect() as c:
            c.execute("INSERT INTO activations VALUES(%s,%s,'REQUESTED',NULL,NULL,NULL,1)",
                      (activation_id,objective_id))

    def lease_activation(self,activation_id,worker,*,wall_now,monotonic_now,lease_seconds,clock_skew=0):
        if abs(clock_skew)>self.max_clock_skew: raise ClockUntrusted("clock outside trust bound")
        with self._connect() as c:
            row=c.execute("SELECT * FROM activations WHERE activation_id=%s FOR UPDATE",
                          (activation_id,)).fetchone()
            if not row or row["state"]!="REQUESTED": raise ValueError("CONFLICT: activation unavailable")
            c.execute("UPDATE activations SET state='LEASED',lease_owner=%s,lease_expires_at=%s,"
                      "monotonic_started=%s,version=version+1 WHERE activation_id=%s",
                      (worker,wall_now+lease_seconds,monotonic_now,activation_id))

    def transition_activation(self,activation_id,new_state):
        legal={"LEASED":{"PREPARING"},"PREPARING":{"RUNNING"},
               "RUNNING":{"WAITING_CONTEXT","WAITING_EFFECT","SLEEPING","COMPLETED","FAILED","CANCELLED"}}
        with self._connect() as c:
            row=c.execute("SELECT state FROM activations WHERE activation_id=%s FOR UPDATE",
                          (activation_id,)).fetchone()
            if not row or new_state not in legal.get(row["state"],set()):
                raise ValueError("illegal activation transition")
            c.execute("UPDATE activations SET state=%s,version=version+1 WHERE activation_id=%s",
                      (new_state,activation_id))

    def recover_expired(self,*,now,publish_recovery_evidence=None):
        with self._connect() as c:
            rows=c.execute("SELECT * FROM activations WHERE lease_expires_at<=%s AND state NOT IN "
                           "('COMPLETED','FAILED','CANCELLED') FOR UPDATE",(now,)).fetchall()
            result=[]
            for row in rows:
                classification="RECONCILIATION_REQUIRED" if row["state"]=="WAITING_EFFECT" else "RETRYABLE"
                new_state="FAILED" if classification=="RECONCILIATION_REQUIRED" else "REQUESTED"
                next_version=row["version"]+1
                evidence=None
                command_id=f"recovery:{row['activation_id']}:{next_version}"
                wake=None
                if row["lease_fence"] is not None:
                    history=c.execute("""SELECT evidence_ref FROM activation_binding_history
                      WHERE activation_id=%s ORDER BY version DESC LIMIT 1 FOR SHARE""",
                                      (row["activation_id"],)).fetchone()
                    if not history:raise ValueError("activation binding history is missing during recovery")
                    if publish_recovery_evidence is None:
                        raise ValueError("protected activation recovery evidence publisher is unavailable")
                if row.get("wake_id"):
                    wake=c.execute("SELECT * FROM wakes WHERE wake_id=%s FOR UPDATE",
                                   (row["wake_id"],)).fetchone()
                    if row["lease_fence"] is not None and (not wake or wake["state"]!="LEASED"
                            or wake["lease_owner"]!=row["lease_owner"]):
                        raise ValueError("activation wake lease disagrees during recovery")
                if row["lease_fence"] is not None:
                    if wake is None:
                        raise ValueError("activation binding has no recoverable wake")
                    payload={"command_id":command_id,"activation_id":row["activation_id"],
                      "wake_id":row["wake_id"],"lease_fence":row["lease_fence"],
                      "previous_activation_state":row["state"],"new_activation_state":new_state,
                      "previous_activation_version":row["version"],"new_activation_version":next_version,
                      "previous_wake_state":wake["state"],"new_wake_state":"RELEASED",
                      "previous_wake_version":wake["version"],"new_wake_version":wake["version"]+1}
                    evidence=publish_recovery_evidence(command_id,payload)
                    if not isinstance(evidence,str) or not evidence.startswith("s3://"):
                        raise ValueError("protected activation recovery evidence is invalid")
                if row.get("wake_id"):
                    released=c.execute("""UPDATE wakes SET state='RELEASED',lease_owner=NULL,
                      lease_expires_at=NULL,version=version+1 WHERE wake_id=%s AND state='LEASED'
                      AND lease_owner=%s RETURNING version""",(row["wake_id"],row["lease_owner"])).fetchone()
                    if row["lease_fence"] is not None and not released:
                        raise ValueError("activation wake lease disagrees during recovery")
                c.execute("UPDATE activations SET state=%s,lease_owner=NULL,lease_expires_at=NULL,"
                          "version=%s WHERE activation_id=%s",(new_state,next_version,row["activation_id"]))
                if evidence:
                    binding=dict(row);binding.update({"state":new_state,"lease_owner":None,
                      "lease_expires_at":None,"version":next_version})
                    c.execute("""INSERT INTO activation_binding_history
                      (activation_id,version,command_id,binding,evidence_ref) VALUES(%s,%s,%s,%s,%s)""",
                      (row["activation_id"],next_version,command_id,json.dumps(binding,default=str),evidence))
                    c.execute("""INSERT INTO lifecycle_history
                      (entity_id,previous_state,new_state,command_id,actor,evidence_ref)
                      VALUES(%s,'LEASED','RELEASED',%s,'service:state-recovery',%s)""",
                      (row["wake_id"],command_id+":wake",evidence))
                result.append({"activation_id":row["activation_id"],"classification":classification,
                               "state":new_state})
            return result

    def recover(self, *, now, publish_recovery_evidence=None):
        """Run boot recovery from authoritative PostgreSQL rows."""
        expired = self.recover_expired(now=now,
          publish_recovery_evidence=publish_recovery_evidence)
        with self._connect() as c:
            wakes = c.execute("""SELECT count(*) AS count FROM wakes WHERE
              state IN ('PENDING','RELEASED') OR
              (state='LEASED' AND lease_expires_at<=%s)""", (now,)).fetchone()["count"]
            unclassified = c.execute("""SELECT count(*) AS count FROM effect_migration_archive
              WHERE classification <> 'V2_COMPATIBLE'""").fetchone()["count"]
            unclassified_activations=c.execute("""SELECT count(*) AS count FROM activation_migration_archive
              WHERE classification <> 'V2_COMPATIBLE'""").fetchone()["count"]
            nonterminal=c.execute("""SELECT count(*) AS count FROM durable_effects
              WHERE state NOT IN ('COMMITTED','FAILED','CANCELLED')""").fetchone()["count"]
            inconsistent=c.execute("""SELECT count(*) AS count FROM durable_effects d
              WHERE NOT EXISTS (SELECT 1 FROM provider_effect_transitions t
                WHERE t.effect_id=d.effect_id)
              OR EXISTS (SELECT 1 FROM provider_effect_transitions t
                WHERE t.effect_id=d.effect_id AND t.request_digest<>d.request_digest)
              OR d.state<>(SELECT CASE t.new_state
                  WHEN 'AUTHORIZED' THEN 'PROPOSED' WHEN 'DISPATCHED' THEN 'PROPOSED'
                  WHEN 'UNCERTAIN' THEN 'PROPOSED'
                  WHEN 'OBSERVED_SUCCEEDED' THEN 'COMMITTED' WHEN 'RESOLVED_SUCCEEDED' THEN 'COMMITTED'
                  WHEN 'OBSERVED_FAILED' THEN 'FAILED' WHEN 'RESOLVED_FAILED' THEN 'FAILED'
                  ELSE t.new_state END FROM provider_effect_transitions t
                WHERE t.effect_id=d.effect_id ORDER BY t.sequence DESC LIMIT 1)""").fetchone()["count"]
            canonical_inconsistent=c.execute("""SELECT count(*) AS count FROM effect_records r
              WHERE jsonb_typeof(r.canonical_record) IS DISTINCT FROM 'object'
                 OR jsonb_typeof(r.canonical_record->'proposal') IS DISTINCT FROM 'object'
                 OR r.canonical_record->>'effect_id' IS DISTINCT FROM r.effect_id
                 OR r.canonical_record->'proposal'->>'objective_id' IS DISTINCT FROM r.objective_id
                 OR r.canonical_record->'proposal'->>'parameters_digest' IS DISTINCT FROM r.request_digest
                 OR r.canonical_record->>'state' IS DISTINCT FROM r.state
                 OR NOT EXISTS (SELECT 1 FROM effect_transition_history h
                    WHERE h.effect_id=r.effect_id AND h.effect_version=r.version
                      AND h.new_state=r.state AND h.canonical_event->'record'=r.canonical_record
                      AND (SELECT count(*) FROM effect_attempts a WHERE a.effect_id=r.effect_id)
                        = jsonb_array_length(COALESCE(h.canonical_event->'attempts','[]'::jsonb))
                         +jsonb_array_length(COALESCE(h.canonical_event->'reconciliations','[]'::jsonb)))
                 OR NOT EXISTS (SELECT 1 FROM durable_effects d WHERE d.effect_id=r.effect_id
                    AND d.activation_id=r.objective_id
                    AND d.request_digest=r.request_digest)""").fetchone()["count"]
            missing_guards=c.execute("""SELECT count(DISTINCT r.objective_id) AS count
              FROM effect_records r WHERE r.state IN ('ObservedSucceeded','ResolvedSucceeded')
              AND NOT EXISTS (SELECT 1 FROM objective_effect_guards g
                WHERE g.objective_id=r.objective_id AND g.ready)""").fetchone()["count"]
        return {"migrations": True, "leases_fenced": True,
                "activations_classified":unclassified_activations==0,
                "effects_classified": unclassified == 0 and nonterminal == 0 and inconsistent == 0
                  and canonical_inconsistent == 0 and missing_guards == 0,
                "expired_activations": len(expired),
                "unclassified_activations":unclassified_activations,
                "nonterminal_effects": nonterminal,"inconsistent_effects":inconsistent,
                "canonical_inconsistent_effects":canonical_inconsistent,
                "missing_effect_guards":missing_guards,
                "wakes_redelivered": wakes}

    def schedule_objective(self, objective_id, *, now):
        """Atomically create an objective and its durable wake."""
        command_id = f"schedule:{objective_id}"
        fingerprint = self._fingerprint("schedule_objective", [objective_id])
        with self._connect() as c:
            replay = self._replay(c, command_id, fingerprint)
            if replay:
                return replay
            if c.execute("SELECT 1 FROM objectives WHERE objective_id=%s",
                         (objective_id,)).fetchone():
                raise ValueError("CONFLICT: objective identity reused")
            wake_id = f"wake:{objective_id}"
            c.execute("INSERT INTO objectives VALUES(%s,'PROPOSED',1)", (objective_id,))
            c.execute("INSERT INTO wakes VALUES(%s,%s,'PENDING',%s,NULL,NULL,1,%s)",
                      (wake_id, objective_id, now, command_id))
            c.execute("""INSERT INTO lifecycle_history
              (entity_id,previous_state,new_state,command_id,actor,evidence_ref)
              VALUES(%s,NULL,'PROPOSED',%s,'service:runtime-coordinator',%s)""",
                      (objective_id, command_id, f"evidence:{fingerprint}"))
            result = {"objective_id": objective_id, "wake_id": wake_id,
                      "state": "PROPOSED", "version": 1}
            self._record(c, command_id, fingerprint, result)
            return result

    def complete_ready_objective(self, *, now):
        """Atomically lease/ack one wake and satisfy its committed-effect objective."""
        with self._connect() as c:
            wake = c.execute("""SELECT * FROM wakes WHERE due_at<=%s AND
              (state IN ('PENDING','RELEASED') OR
               (state='LEASED' AND lease_expires_at<=%s))
              ORDER BY due_at,wake_id FOR UPDATE SKIP LOCKED LIMIT 1""",
                             (now, now)).fetchone()
            if not wake:
                return None
            objective_id = wake["objective_id"]
            objective = c.execute("SELECT * FROM objectives WHERE objective_id=%s FOR UPDATE",
                                  (objective_id,)).fetchone()
            guard = c.execute("""SELECT effect_set_digest,effect_count,ready
              FROM objective_effect_guards WHERE objective_id=%s FOR SHARE""",
                              (objective_id,)).fetchone()
            effects = c.execute("""SELECT d.effect_id,d.state,d.request_digest,d.evidence_ref,
              r.state AS canonical_state FROM durable_effects d JOIN effect_records r
              ON r.effect_id=d.effect_id WHERE d.activation_id=%s ORDER BY d.effect_id FOR SHARE""",
                                (objective_id,)).fetchall()
            current_ids = [effect["effect_id"] for effect in effects]
            current_digest = "sha256:" + hashlib.sha256(
                json.dumps(current_ids, separators=(",", ":")).encode()).hexdigest()
            if not objective or objective["state"] != "PROPOSED":
                raise ValueError("CONFLICT: objective is not schedulable")
            if (not guard or not guard["ready"] or not effects
                    or len(effects) != guard["effect_count"]
                    or guard["effect_set_digest"] != current_digest
                    or any(effect["state"] != "COMMITTED" or effect["canonical_state"]
                           not in ("ObservedSucceeded", "ResolvedSucceeded")
                           for effect in effects)):
                raise ValueError("CONFLICT: completion lacks effect-service guard")
            command_id = f"complete:{wake['wake_id']}"
            evidence_ref = effects[0]["evidence_ref"]
            fingerprint = self._fingerprint(
                "complete_objective", [objective_id, guard["effect_set_digest"]])
            c.execute("UPDATE wakes SET state='ACKNOWLEDGED',version=version+1 WHERE wake_id=%s",
                      (wake["wake_id"],))
            c.execute("UPDATE objectives SET state='SATISFIED',version=version+1 WHERE objective_id=%s",
                      (objective_id,))
            c.execute("""INSERT INTO lifecycle_history
              (entity_id,previous_state,new_state,command_id,actor,evidence_ref)
              VALUES(%s,'PROPOSED','SATISFIED',%s,'service:runtime-coordinator',%s)""",
                      (objective_id, command_id, evidence_ref))
            result = {"objective_id": objective_id, "wake_id": wake["wake_id"],
                      "state": "SATISFIED", "version": objective["version"] + 1}
            self._record(c, command_id, fingerprint, result)
            return result

    def observe_effect_transition(self, transition_id, effect_id, objective_id, request_digest,
                                  previous_state, new_state, evidence_ref, external_ref=None):
        """Persist exactly one provider-observed transition with replay identity."""
        if (not isinstance(request_digest,str) or not request_digest.startswith("sha256:")
                or len(request_digest)!=71
                or any(character not in "0123456789abcdef" for character in request_digest[7:])):
            raise ValueError("effect request digest must be canonical sha256")
        legal={None:{"PROPOSED","REJECTED"},"PROPOSED":{"AUTHORIZED"},
               "AUTHORIZED":{"DISPATCHED"},
               "DISPATCHED":{"OBSERVED_SUCCEEDED","OBSERVED_FAILED","UNCERTAIN"},
               "UNCERTAIN":{"RESOLVED_SUCCEEDED","RESOLVED_FAILED"}}
        if new_state not in legal.get(previous_state,set()):
            raise ValueError("illegal provider effect transition")
        if new_state in {"DISPATCHED","OBSERVED_SUCCEEDED","OBSERVED_FAILED","UNCERTAIN",
                         "RESOLVED_SUCCEEDED","RESOLVED_FAILED"} and not external_ref:
            raise ValueError("provider transition requires stable external identity")
        if new_state.startswith("OBSERVED_") or new_state.startswith("RESOLVED_"):
            if not evidence_ref: raise ValueError("terminal provider observation requires evidence")
        command_id = f"effect-transition:{transition_id}"
        fingerprint = self._fingerprint(
            "observe_effect_transition", [effect_id, objective_id, request_digest,previous_state,
                                           new_state,evidence_ref,external_ref])
        with self._connect() as c:
            replay = self._replay(c, command_id, fingerprint)
            if replay:
                return replay
            objective = c.execute("SELECT state FROM objectives WHERE objective_id=%s FOR SHARE",
                                  (objective_id,)).fetchone()
            if not objective or objective["state"] not in ("PROPOSED", "SATISFIED"):
                raise ValueError("CONFLICT: effect has no live objective projection")
            row=c.execute("SELECT * FROM durable_effects WHERE effect_id=%s FOR UPDATE",(effect_id,)).fetchone()
            if previous_state is None:
                if row: raise ValueError("effect identity already exists")
                initial_state = "REJECTED" if new_state == "REJECTED" else "PROPOSED"
                c.execute("""INSERT INTO durable_effects
                  (effect_id,activation_id,request_digest,state,external_ref,evidence_ref,version)
                  VALUES(%s,%s,%s,%s,%s,%s,1)""",
                  (effect_id,objective_id,request_digest,initial_state,external_ref,evidence_ref))
                version=1
            else:
                if not row or row["activation_id"]!=objective_id or row["request_digest"]!=request_digest:
                    raise ValueError("provider transition binding mismatch")
                latest=c.execute("SELECT new_state FROM provider_effect_transitions WHERE effect_id=%s ORDER BY sequence DESC FOR SHARE LIMIT 1",(effect_id,)).fetchone()
                if not latest or latest["new_state"]!=previous_state:
                    raise ValueError("provider transition predecessor history mismatch")
                projected={"PROPOSED":"PROPOSED","AUTHORIZED":"PROPOSED","DISPATCHED":"PROPOSED",
                  "UNCERTAIN":"PROPOSED","OBSERVED_SUCCEEDED":"COMMITTED","RESOLVED_SUCCEEDED":"COMMITTED",
                  "OBSERVED_FAILED":"FAILED","RESOLVED_FAILED":"FAILED"}
                if row["state"] != projected[previous_state]: raise ValueError("provider transition predecessor mismatch")
                version=row["version"]+1
                c.execute("UPDATE durable_effects SET state=%s,external_ref=COALESCE(%s,external_ref),evidence_ref=COALESCE(%s,evidence_ref),version=%s WHERE effect_id=%s",
                          (projected[new_state],external_ref,evidence_ref,version,effect_id))
            c.execute("""INSERT INTO provider_effect_transitions
              (transition_id,effect_id,previous_state,new_state,request_digest,evidence_ref,sequence)
              VALUES(%s,%s,%s,%s,%s,%s,%s)""",(transition_id,effect_id,previous_state,new_state,request_digest,evidence_ref,version))
            result = {"effect_id": effect_id, "state": new_state, "version": version,
                      "external_ref": external_ref,
                      "evidence_ref": evidence_ref}
            self._record(c, command_id, fingerprint, result)
            return result

    def guard_objective_effects(self, objective_id, effect_ids, effect_set_digest):
        """Accept the complete effect set only from the effect-service boundary."""
        if not effect_ids or effect_ids != sorted(set(effect_ids)):
            raise ValueError("effect set must be nonempty, sorted, and unique")
        expected = "sha256:" + hashlib.sha256(
            json.dumps(effect_ids, separators=(",", ":")).encode()).hexdigest()
        if effect_set_digest != expected:
            raise ValueError("effect set digest mismatch")
        with self._connect() as c:
            rows = c.execute("""SELECT d.effect_id,d.state,d.evidence_ref,r.state AS canonical_state,
              r.canonical_record #>> '{proposal,compensates_effect_id}' AS compensates_effect_id
              FROM durable_effects d JOIN effect_records r ON r.effect_id=d.effect_id
              WHERE d.activation_id=%s ORDER BY d.effect_id FOR SHARE""",
                             (objective_id,)).fetchall()
            if [row["effect_id"] for row in rows] != effect_ids:
                raise ValueError("effect set does not match PostgreSQL")
            compensation_succeeded = any(
                row["compensates_effect_id"] and row["state"] == "COMMITTED"
                and row["canonical_state"] in ("ObservedSucceeded", "ResolvedSucceeded")
                for row in rows)
            ready = (not compensation_succeeded and all(
                row["state"] == "COMMITTED" and row["canonical_state"]
                in ("ObservedSucceeded", "ResolvedSucceeded") for row in rows))
            if compensation_succeeded:
                prior = c.execute("SELECT state FROM objectives WHERE objective_id=%s FOR UPDATE",
                                  (objective_id,)).fetchone()
                if prior and prior["state"] != "COMPENSATED":
                    c.execute("UPDATE objectives SET state='COMPENSATED',version=version+1 WHERE objective_id=%s",
                              (objective_id,))
                    c.execute("""INSERT INTO lifecycle_history
                      (entity_id,previous_state,new_state,command_id,actor,evidence_ref)
                      VALUES(%s,%s,'COMPENSATED',%s,'service:effects',%s)""",
                              (objective_id, prior["state"],
                               f"compensated:{objective_id}:{effect_set_digest}",
                               next(row["evidence_ref"] for row in rows
                                    if row["compensates_effect_id"])))
            c.execute("""INSERT INTO objective_effect_guards
              (objective_id,effect_set_digest,effect_count,ready) VALUES(%s,%s,%s,%s)
              ON CONFLICT(objective_id) DO UPDATE SET
              effect_set_digest=EXCLUDED.effect_set_digest,
              effect_count=EXCLUDED.effect_count,ready=EXCLUDED.ready,
              recorded_at=now()""",
                      (objective_id, effect_set_digest, len(effect_ids), ready))
            return {"objective_id": objective_id, "effect_count": len(effect_ids),
                    "effect_set_digest": effect_set_digest, "ready": ready}

    def invalidate_objective_effect_guard(self, objective_id, compensates_effect_id):
        """Fail closed before compensation admission; only the effect service may call this."""
        with self._connect() as c:
            original = c.execute("""SELECT 1 FROM durable_effects
              WHERE activation_id=%s AND effect_id=%s AND state='COMMITTED' FOR SHARE""",
                                 (objective_id, compensates_effect_id)).fetchone()
            if not original:
                raise ValueError("compensation original is not a committed objective effect")
            changed = c.execute("""UPDATE objective_effect_guards SET ready=false, recorded_at=now()
              WHERE objective_id=%s RETURNING effect_set_digest,effect_count""",
                                (objective_id,)).fetchone()
            if not changed:
                raise ValueError("objective has no completion guard to invalidate")
            return {"objective_id": objective_id,
                    "compensates_effect_id": compensates_effect_id, "ready": False}

    def inspect_objective(self, objective_id):
        with self._connect() as c:
            objective = c.execute("SELECT state FROM objectives WHERE objective_id=%s",
                                  (objective_id,)).fetchone()
            effects = c.execute("""SELECT effect_id,state,request_digest,evidence_ref FROM durable_effects
              WHERE activation_id=%s ORDER BY effect_id""", (objective_id,)).fetchall()
            guard = c.execute("""SELECT effect_set_digest,effect_count,ready
              FROM objective_effect_guards WHERE objective_id=%s""", (objective_id,)).fetchone()
        if not objective:
            return None
        response = {"objective_id": objective_id, "objective_state": objective["state"],
                    "effects": effects, "guard": guard}
        # Legacy V2 INSPECT compatibility: retain the original top-level fields
        # while the structured list remains canonical for multi-effect callers.
        if effects:
            response["effect_state"] = effects[0]["state"]
            response["evidence_ref"] = effects[0]["evidence_ref"]
        else:
            response["effect_state"] = None
            response["evidence_ref"] = None
        return response

    def pending_objectives(self, limit=100):
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("invalid pending objective limit")
        with self._connect() as connection:
            rows = connection.execute("""SELECT objective_id FROM objectives
              WHERE state NOT IN ('SATISFIED','COMPENSATED','FAILED','CANCELLED')
              ORDER BY objective_id LIMIT %s""", (limit,)).fetchall()
        return [row["objective_id"] for row in rows]

    def inspect_effect_projection(self, objective_id, effect_id):
        with self._connect() as c:
            return c.execute("""SELECT effect_id,activation_id AS objective_id,
              request_digest,state,external_ref,evidence_ref,
              (SELECT new_state FROM provider_effect_transitions t
               WHERE t.effect_id=durable_effects.effect_id
               ORDER BY sequence DESC LIMIT 1) AS provider_state
              FROM durable_effects
              WHERE activation_id=%s AND effect_id=%s""",
                             (objective_id, effect_id)).fetchone()

    def admit_package(self, package_id, content_digest, manifest, evidence_ref):
        if not content_digest.startswith("sha256:") or len(content_digest) != 71:
            raise ValueError("content-bound sha256 digest required")
        with self._connect() as c:
            c.execute("INSERT INTO admitted_packages VALUES(%s,%s,%s,'VERIFIED',%s,1)",
                      (package_id,content_digest,json.dumps(manifest),evidence_ref))
        return {"package_id":package_id,"state":"VERIFIED","version":1}

    def propose_change(self, candidate_id, source_digest, evaluator_generation,
                       target_generation, rollback_generation, threshold, evidence_ref):
        if target_generation == rollback_generation:
            raise ValueError("rollback generation must precede candidate generation")
        with self._connect() as c:
            c.execute("INSERT INTO change_candidates VALUES(%s,%s,%s,%s,%s,%s,'PROPOSED',%s,1)",
                      (candidate_id,source_digest,evaluator_generation,target_generation,
                       rollback_generation,json.dumps(threshold),evidence_ref))
        return {"candidate_id":candidate_id,"state":"PROPOSED","version":1}

    def ensure_active_generation(self,generation):
        if not isinstance(generation,str) or not generation.startswith("generation:"):
            raise ValueError("active generation identity is invalid")
        with self._connect() as c:
            c.execute("""INSERT INTO active_generation_binding
              (singleton,active_generation,previous_generation,candidate_id,version)
              VALUES(true,%s,NULL,'system:boot',1) ON CONFLICT(singleton) DO NOTHING""",(generation,))

    def publish_capability_activation_set(self,command_id,set_id,generation_id,grant_ids,evidence_ref,
                                          expected_active_set_id,expected_active_version):
        if (not isinstance(set_id,str) or not set_id.startswith("capability-set:")
                or not isinstance(generation_id,str) or not generation_id.startswith("generation:")
                or not isinstance(grant_ids,list) or not grant_ids
                or any(not isinstance(grant,str) or not grant.startswith("grant:") for grant in grant_ids)
                or not isinstance(command_id,str) or not command_id.startswith("command:")
                or not isinstance(expected_active_version,int) or expected_active_version<0
                or (expected_active_set_id is not None and (not isinstance(expected_active_set_id,str)
                    or not expected_active_set_id.startswith("capability-set:")))
                or not isinstance(evidence_ref,str) or not evidence_ref):
            raise ValueError("complete capability activation-set binding is required")
        grants=sorted(set(grant_ids))
        fingerprint=self._fingerprint("capability_activation_set",[set_id,generation_id,grants,evidence_ref,
                                      expected_active_set_id,expected_active_version])
        with self._connect() as c:
            replay=self._replay(c,command_id,fingerprint)
            if replay:return replay
            generation=c.execute("SELECT active_generation FROM active_generation_binding WHERE singleton FOR SHARE").fetchone()
            if not generation or generation["active_generation"]!=generation_id:
                raise ValueError("capability set must bind the active generation")
            existing=c.execute("SELECT * FROM capability_activation_sets WHERE set_id=%s FOR UPDATE",(set_id,)).fetchone()
            if existing:
                if existing["generation_id"]!=generation_id or existing["grant_ids"]!=grants:
                    raise ValueError("CONFLICT: capability activation-set identity reused")
            active=c.execute("SELECT * FROM capability_activation_sets WHERE active FOR UPDATE").fetchone()
            actual_active_id=active["set_id"] if active else None
            actual_active_version=active["version"] if active else 0
            if actual_active_id!=expected_active_set_id or actual_active_version!=expected_active_version:
                raise ValueError("CONFLICT: active capability set changed")
            if active and active["set_id"]!=set_id:
                old_version=active["version"]+1
                c.execute("UPDATE capability_activation_sets SET active=false,version=%s WHERE set_id=%s",
                          (old_version,active["set_id"]))
                c.execute("""INSERT INTO capability_activation_set_history
                  (set_id,version,generation_id,grant_ids,evidence_ref,command_id,active)
                  VALUES(%s,%s,%s,%s,%s,%s,false)""",
                  (active["set_id"],old_version,active["generation_id"],json.dumps(active["grant_ids"]),
                   evidence_ref,command_id+":deactivate"))
            version=(existing["version"]+1) if existing else 1
            c.execute("""INSERT INTO capability_activation_sets
              (set_id,generation_id,grant_ids,evidence_ref,active,version)
              VALUES(%s,%s,%s,%s,true,%s) ON CONFLICT(set_id) DO UPDATE SET
              active=true,evidence_ref=EXCLUDED.evidence_ref,version=EXCLUDED.version""",
                      (set_id,generation_id,json.dumps(grants),evidence_ref,version))
            c.execute("""INSERT INTO capability_activation_set_history
              (set_id,version,generation_id,grant_ids,evidence_ref,command_id,active)
              VALUES(%s,%s,%s,%s,%s,%s,true)""",
                      (set_id,version,generation_id,json.dumps(grants),evidence_ref,command_id))
            result={"set_id":set_id,"generation_id":generation_id,"grant_ids":grants,
                    "evidence_ref":evidence_ref,"active":True,"version":version}
            self._record(c,command_id,fingerprint,result)
            return result

    def claim_activation(self,*,command_id,activation_id,objective_id,wake_id,machine_id,agent_id,
                         lease_owner,lease_seconds,context_bundle_id,isolation_profile_id,
                         resource_lease_id,trace_id,correlation_id,credential_digest,
                         credential_key_version,expected_lease_fence,evidence_ref):
        identifiers=((activation_id,"activation:"),(objective_id,"objective:"),(wake_id,"wake:"),
                     (machine_id,"machine:"),(agent_id,"agent:"),(lease_owner,"service:"),
                     (context_bundle_id,"context:"),(isolation_profile_id,"isolation:"),
                     (resource_lease_id,"resource-lease:"),(trace_id,"trace:"),
                     (correlation_id,"correlation:"))
        if (not isinstance(command_id,str) or not command_id.startswith("command:")
                or any(not isinstance(value,str) or not value.startswith(prefix)
                       for value,prefix in identifiers)
                or not isinstance(lease_seconds,int) or not 1<=lease_seconds<=300
                or not isinstance(credential_key_version,int) or credential_key_version<=0
                or not isinstance(expected_lease_fence,int) or expected_lease_fence<=0
                or not isinstance(credential_digest,str) or not credential_digest.startswith("sha256:")
                or len(credential_digest)!=71
                or any(character not in "0123456789abcdef" for character in credential_digest[7:])
                or not isinstance(evidence_ref,str) or not evidence_ref):
            raise ValueError("complete typed activation claim is required")
        values=[activation_id,objective_id,wake_id,machine_id,agent_id,lease_owner,lease_seconds,
                context_bundle_id,isolation_profile_id,resource_lease_id,trace_id,correlation_id,
                credential_digest,credential_key_version,expected_lease_fence,evidence_ref]
        fingerprint=self._fingerprint("activation_claim",values)
        with self._connect() as c:
            replay=self._replay(c,command_id,fingerprint)
            if replay:return replay
            now=c.execute("SELECT extract(epoch FROM clock_timestamp())::bigint AS now").fetchone()["now"]
            wake=c.execute("SELECT * FROM wakes WHERE wake_id=%s AND objective_id=%s FOR UPDATE",
                           (wake_id,objective_id)).fetchone()
            objective=c.execute("SELECT state FROM objectives WHERE objective_id=%s FOR SHARE",
                                (objective_id,)).fetchone()
            prior=c.execute("SELECT * FROM activations WHERE objective_id=%s FOR UPDATE",
                            (objective_id,)).fetchone()
            generation=c.execute("SELECT active_generation FROM active_generation_binding WHERE singleton FOR SHARE").fetchone()
            capability_set=c.execute("""SELECT set_id,generation_id,grant_ids FROM capability_activation_sets
              WHERE active FOR SHARE""").fetchone()
            if (not wake or wake["state"] not in ("PENDING","RELEASED") or wake["due_at"]>now
                    or not objective or objective["state"]!="PROPOSED"):
                raise ValueError("CONFLICT: activation wake is not claimable")
            if not generation or not capability_set or capability_set["generation_id"]!=generation["active_generation"]:
                raise ValueError("active generation capability set is unavailable")
            if prior:
                if (prior["activation_id"]!=activation_id or prior["state"]!="REQUESTED"
                        or prior["wake_id"]!=wake_id):
                    raise ValueError("CONFLICT: objective activation is not reclaimable")
                required_fence=(prior["lease_fence"] or 0)+1
            else:required_fence=1
            if expected_lease_fence!=required_fence:
                raise ValueError("CONFLICT: activation lease fence changed")
            deadline=now+lease_seconds
            result={"activation_id":activation_id,"objective_id":objective_id,"wake_id":wake_id,
                    "machine_id":machine_id,"agent_id":agent_id,"lease_owner":lease_owner,
                    "lease_fence":required_fence,"lease_expires_at":deadline,"state":"LEASED",
                    "system_generation_id":generation["active_generation"],
                    "capability_activation_set_id":capability_set["set_id"],
                    "capability_grant_ids":capability_set["grant_ids"],
                    "context_bundle_id":context_bundle_id,"isolation_profile_id":isolation_profile_id,
                    "resource_lease_id":resource_lease_id,"deadline":deadline,"trace_id":trace_id,
                    "correlation_id":correlation_id,"credential_digest":credential_digest,
                    "credential_key_version":credential_key_version,
                    "version":prior["version"]+1 if prior else 1}
            if prior:
                c.execute("""UPDATE activations SET state='LEASED',lease_owner=%s,lease_expires_at=%s,
                  version=%s,wake_id=%s,machine_id=%s,agent_id=%s,lease_fence=%s,
                  system_generation_id=%s,capability_activation_set_id=%s,context_bundle_id=%s,
                  capability_grant_ids=%s,isolation_profile_id=%s,resource_lease_id=%s,deadline=%s,
                  trace_id=%s,correlation_id=%s,credential_digest=%s,credential_key_version=%s
                  WHERE activation_id=%s""",
                  (lease_owner,deadline,result["version"],wake_id,machine_id,agent_id,required_fence,
                   generation["active_generation"],capability_set["set_id"],context_bundle_id,
                   json.dumps(capability_set["grant_ids"]),isolation_profile_id,resource_lease_id,
                   deadline,trace_id,correlation_id,credential_digest,credential_key_version,activation_id))
            else:c.execute("""INSERT INTO activations
              (activation_id,objective_id,state,lease_owner,lease_expires_at,monotonic_started,version,
               wake_id,machine_id,agent_id,lease_fence,system_generation_id,
               capability_activation_set_id,context_bundle_id,capability_grant_ids,
               isolation_profile_id,resource_lease_id,deadline,trace_id,correlation_id,
               credential_digest,credential_key_version)
              VALUES(%s,%s,'LEASED',%s,%s,NULL,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
              (activation_id,objective_id,lease_owner,deadline,wake_id,machine_id,agent_id,
               required_fence,generation["active_generation"],capability_set["set_id"],context_bundle_id,
               json.dumps(capability_set["grant_ids"]),isolation_profile_id,resource_lease_id,
               deadline,trace_id,correlation_id,credential_digest,credential_key_version))
            c.execute("UPDATE wakes SET state='LEASED',lease_owner=%s,lease_expires_at=%s,version=version+1 WHERE wake_id=%s",
                      (lease_owner,deadline,wake_id))
            c.execute("""INSERT INTO activation_binding_history
              (activation_id,version,command_id,binding,evidence_ref) VALUES(%s,%s,%s,%s,%s)""",
                      (activation_id,result["version"],command_id,json.dumps(result),evidence_ref))
            self._record(c,command_id,fingerprint,result)
            return result

    def propose_governed_change(self, candidate_id, command_id, source_digest, evaluator,
                                evaluator_closure, target_generation, rollback_generation,
                                threshold, evidence_ref, dependency_closure_digest,
                                contract_version, tests_digest, requested_authority,
                                signing_key_digest, live_verification_contract):
        if (not evaluator or not evaluator_closure.startswith("sha256:")
                or not source_digest.startswith("sha256:") or len(source_digest)!=71):
            raise ValueError("protected evaluator identity and closure are required")
        digests=(dependency_closure_digest,tests_digest,signing_key_digest)
        if (contract_version!="V2.0.1" or any(not isinstance(value,str) or
                not value.startswith("sha256:") or len(value)!=71 for value in digests)
                or not isinstance(requested_authority,list)
                or not all(isinstance(value,str) and value for value in requested_authority)
                or not isinstance(live_verification_contract,str)
                or not live_verification_contract):
            raise ValueError("governed candidate immutable bindings are incomplete")
        if target_generation == rollback_generation:
            raise ValueError("rollback generation must precede candidate generation")
        fp=self._fingerprint("propose_governed_change",[candidate_id,source_digest,evaluator,
            evaluator_closure,target_generation,rollback_generation,threshold,evidence_ref,
            dependency_closure_digest,contract_version,tests_digest,requested_authority,
            signing_key_digest,live_verification_contract])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            binding=c.execute("SELECT active_generation,version FROM active_generation_binding WHERE singleton FOR UPDATE").fetchone()
            if not binding or binding["active_generation"]!=rollback_generation:
                raise ValueError("rollback generation is not the active generation")
            c.execute("""INSERT INTO change_candidates
              (candidate_id,source_digest,evaluator_generation,target_generation,
               rollback_generation,threshold,state,evidence_ref,version,evaluator_closure,
               dependency_closure_digest,contract_version,tests_digest,requested_authority,
               signing_key_digest,live_verification_contract,expected_active_version)
              VALUES(%s,%s,%s,%s,%s,%s,'PROPOSED',%s,1,%s,%s,%s,%s,%s,%s,%s,%s)""",
              (candidate_id,source_digest,evaluator,target_generation,rollback_generation,
               json.dumps(threshold),evidence_ref,evaluator_closure,dependency_closure_digest,
               contract_version,tests_digest,json.dumps(requested_authority),signing_key_digest,
               live_verification_contract,binding["version"]))
            c.execute("INSERT INTO change_history(candidate_id,version,previous_state,new_state,command_id,actor,evidence_ref) VALUES(%s,1,NULL,'PROPOSED',%s,%s,%s)",
                      (candidate_id,command_id,evaluator,evidence_ref))
            result={"candidate_id":candidate_id,"state":"PROPOSED","version":1,
                    "target_generation":target_generation,"rollback_generation":rollback_generation}
            self._record(c,command_id,fp,result);return result

    def transition_governed_change(self,candidate_id,command_id,new_state,actor,evidence_ref,
                                   *,observation):
        legal={"PROPOSED":{"BUILT","REJECTED"},"BUILT":{"EVALUATED","REJECTED","QUARANTINED"},
          "EVALUATED":{"SIGNED","REJECTED","QUARANTINED"},"SIGNED":{"STAGED","QUARANTINED"},
          "STAGED":{"ACTIVATED","QUARANTINED"},"ACTIVATED":{"CONFIRMED","QUARANTINED","ROLLED_BACK"},
          "QUARANTINED":{"ROLLED_BACK"}}
        fp=self._fingerprint("transition_governed_change",[candidate_id,new_state,actor,evidence_ref,
                                                            observation])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT * FROM change_candidates WHERE candidate_id=%s FOR UPDATE",(candidate_id,)).fetchone()
            if not row or new_state not in legal.get(row["state"],set()):
                raise ValueError("illegal governed-change transition")
            if new_state=="EVALUATED" and (actor!=row["evaluator_generation"]
                    or observation.get("evaluator_closure")!=row["evaluator_closure"]
                    or observation.get("artifact_digest")!=row["source_digest"]
                    or observation.get("passed") is not True):
                raise ValueError("protected evaluator identity or closure mismatch")
            if new_state in {"BUILT","EVALUATED","SIGNED","STAGED","ACTIVATED"}:
                artifact=observation.get("artifact_digest")
                if not isinstance(artifact,str) or not artifact.startswith("sha256:") or len(artifact)!=71:
                    raise ValueError("digest-addressed measured artifact is required")
                if new_state!="BUILT":
                    prior=c.execute("SELECT observation FROM change_history WHERE candidate_id=%s AND new_state=%s FOR SHARE",
                      (candidate_id,row["state"])).fetchone()
                    if not prior or prior["observation"].get("artifact_digest")!=artifact:
                        raise ValueError("measured artifact changed between governed stages")
            if new_state=="CONFIRMED":
                if actor==row["evaluator_generation"] or observation.get("health_ready") is not True:
                    raise ValueError("independent health confirmation required")
            version=row["version"]+1
            active=row["active_generation"]
            binding_version=row["activation_binding_version"]
            if new_state=="ACTIVATED":
                changed=c.execute("""UPDATE active_generation_binding SET
                  previous_generation=active_generation,active_generation=%s,candidate_id=%s,
                  version=version+1 WHERE singleton AND active_generation=%s AND version=%s
                  RETURNING version""",(row["target_generation"],candidate_id,
                  row["rollback_generation"],row["expected_active_version"])).fetchone()
                if not changed:raise ValueError("active generation changed during staging")
                active=row["target_generation"];binding_version=changed["version"]
            if new_state=="ROLLED_BACK":
                changed=c.execute("""UPDATE active_generation_binding SET
                  previous_generation=active_generation,active_generation=%s,candidate_id=%s,
                  version=version+1 WHERE singleton AND active_generation=%s
                  AND candidate_id=%s AND version=%s RETURNING version""",
                  (row["rollback_generation"],candidate_id,row["target_generation"],
                   candidate_id,row["activation_binding_version"])).fetchone()
                if not changed:raise ValueError("candidate no longer owns active generation")
                active=row["rollback_generation"];binding_version=changed["version"]
            c.execute("UPDATE change_candidates SET state=%s,version=%s,active_generation=%s WHERE candidate_id=%s",
                      (new_state,version,active,candidate_id))
            if new_state in ("ACTIVATED","ROLLED_BACK"):
                c.execute("UPDATE change_candidates SET activation_binding_version=%s WHERE candidate_id=%s",
                          (binding_version,candidate_id))
            c.execute("INSERT INTO change_history(candidate_id,version,previous_state,new_state,command_id,actor,evidence_ref,observation) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                      (candidate_id,version,row["state"],new_state,command_id,actor,evidence_ref,json.dumps(observation)))
            result={"candidate_id":candidate_id,"state":new_state,"version":version,
                    "active_generation":active,"rollback_generation":row["rollback_generation"]}
            self._record(c,command_id,fp,result);return result

    def governed_change(self,candidate_id):
        with self._connect() as c:
            return c.execute("SELECT * FROM change_candidates WHERE candidate_id=%s",(candidate_id,)).fetchone()

    def governed_change_history(self,candidate_id,limit=100,cursor=0):
        with self._connect() as c:
            return c.execute("SELECT version,previous_state,new_state,command_id,actor,evidence_ref,observation FROM change_history WHERE candidate_id=%s ORDER BY version LIMIT %s OFFSET %s",(candidate_id,limit,cursor)).fetchall()

    def record_authority_binding(self,binding_id,command_id,generation,grants_digest,evidence_ref):
        if not grants_digest.startswith("sha256:") or not evidence_ref:
            raise ValueError("authority binding requires digest and evidence")
        fp=self._fingerprint("record_authority_binding",[binding_id,generation,grants_digest,evidence_ref])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT version FROM authority_bindings WHERE binding_id=%s FOR UPDATE",(binding_id,)).fetchone()
            version=(row["version"] if row else 0)+1
            c.execute("""INSERT INTO authority_bindings(binding_id,generation,grants_digest,evidence_ref,version) VALUES(%s,%s,%s,%s,%s)
              ON CONFLICT(binding_id) DO UPDATE SET generation=EXCLUDED.generation,
              grants_digest=EXCLUDED.grants_digest,evidence_ref=EXCLUDED.evidence_ref,
              version=EXCLUDED.version""",(binding_id,generation,grants_digest,evidence_ref,version))
            c.execute("INSERT INTO authority_binding_history(binding_id,version,command_id,generation,grants_digest,evidence_ref) VALUES(%s,%s,%s,%s,%s,%s)",
                      (binding_id,version,command_id,generation,grants_digest,evidence_ref))
            result={"binding_id":binding_id,"generation":generation,"grants_digest":grants_digest,
                    "evidence_ref":evidence_ref,"version":version}
            self._record(c,command_id,fp,result);return result

    def authority_binding(self,binding_id,limit=100,cursor=0):
        with self._connect() as c:
            current=c.execute("SELECT * FROM authority_bindings WHERE binding_id=%s",(binding_id,)).fetchone()
            history=c.execute("SELECT version,command_id,generation,snapshot_digest,evidence_ref FROM authority_binding_history WHERE binding_id=%s ORDER BY version LIMIT %s OFFSET %s",(binding_id,limit,cursor)).fetchall()
            return None if current is None else {**current,"current":current,"history":history,"next_cursor":cursor+limit}

    def commit_authority_snapshot(self,binding_id,command_id,expected_version,generation,
                                  snapshot,snapshot_digest,evidence_ref):
        if not isinstance(snapshot,dict) or not snapshot_digest.startswith("sha256:") or not evidence_ref:
            raise ValueError("authority snapshot requires object, digest, and evidence")
        canonical=json.dumps(snapshot,sort_keys=True,separators=(",", ":")).encode()
        actual="sha256:"+hashlib.sha256(canonical).hexdigest()
        if actual != snapshot_digest: raise ValueError("authority snapshot digest mismatch")
        if snapshot.get("generation") != generation:
            raise ValueError("authority snapshot generation mismatch")
        grants_digest=snapshot.get("configuration_digest")
        if (not isinstance(grants_digest,str) or not grants_digest.startswith("sha256:")
                or len(grants_digest)!=71):
            raise ValueError("authority snapshot grants digest is invalid")
        fp=self._fingerprint("commit_authority_snapshot",[binding_id,expected_version,generation,snapshot_digest,evidence_ref])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT version FROM authority_bindings WHERE binding_id=%s FOR UPDATE",(binding_id,)).fetchone()
            version=row["version"] if row else 0
            if version != expected_version: raise ValueError("authority snapshot version conflict")
            next_version=version+1
            c.execute("""INSERT INTO authority_bindings(binding_id,generation,grants_digest,evidence_ref,version,snapshot,snapshot_digest)
              VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(binding_id) DO UPDATE SET
              generation=EXCLUDED.generation,grants_digest=EXCLUDED.grants_digest,
              evidence_ref=EXCLUDED.evidence_ref,version=EXCLUDED.version,
              snapshot=EXCLUDED.snapshot,snapshot_digest=EXCLUDED.snapshot_digest""",
              (binding_id,generation,grants_digest,evidence_ref,next_version,json.dumps(snapshot),snapshot_digest))
            c.execute("""INSERT INTO authority_binding_history
              (binding_id,version,command_id,generation,grants_digest,evidence_ref,snapshot,snapshot_digest)
              VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
              (binding_id,next_version,command_id,generation,grants_digest,evidence_ref,json.dumps(snapshot),snapshot_digest))
            result={"binding_id":binding_id,"generation":generation,"snapshot_digest":snapshot_digest,
                    "evidence_ref":evidence_ref,"version":next_version}
            self._record(c,command_id,fp,result);return result
