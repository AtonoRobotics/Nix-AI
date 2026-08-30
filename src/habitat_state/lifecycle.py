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

    def migrate(self):
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
            CREATE TABLE IF NOT EXISTS lifecycle_history(
              record_id bigserial PRIMARY KEY, entity_id text NOT NULL, previous_state text,
              new_state text NOT NULL, command_id text NOT NULL UNIQUE, actor text NOT NULL,
              occurred_at timestamptz NOT NULL DEFAULT now(), evidence_ref text NOT NULL);
            CREATE TABLE IF NOT EXISTS durable_effects(
              effect_id text PRIMARY KEY, activation_id text NOT NULL, request_digest text NOT NULL,
              state text NOT NULL CHECK(state IN ('PROPOSED','AUTHORIZED','DISPATCHED','COMMITTED','FAILED','UNCERTAIN')),
              external_ref text, evidence_ref text NOT NULL, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS admitted_packages(
              package_id text PRIMARY KEY, content_digest text NOT NULL UNIQUE,
              manifest jsonb NOT NULL, state text NOT NULL CHECK(state IN ('VERIFIED','STAGED','ACTIVE','QUARANTINED')),
              evidence_ref text NOT NULL, version bigint NOT NULL);
            CREATE TABLE IF NOT EXISTS change_candidates(
              candidate_id text PRIMARY KEY, source_digest text NOT NULL, evaluator_generation text NOT NULL,
              target_generation text NOT NULL, rollback_generation text NOT NULL,
              threshold jsonb NOT NULL, state text NOT NULL, evidence_ref text NOT NULL,
              version bigint NOT NULL);
            CREATE OR REPLACE FUNCTION lifecycle_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'lifecycle history is append-only' USING ERRCODE='42501'; END $$;
            DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='lifecycle_history_immutable')
            THEN CREATE TRIGGER lifecycle_history_immutable BEFORE UPDATE OR DELETE ON lifecycle_history
            FOR EACH ROW EXECUTE FUNCTION lifecycle_immutable(); END IF; END $$;
            """)

    def reset_for_test(self):
        with self._connect() as c:
            c.execute("TRUNCATE lifecycle_commands, objectives, wakes, activations, durable_effects, admitted_packages, change_candidates")
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

    def recover_expired(self,*,now):
        with self._connect() as c:
            rows=c.execute("SELECT * FROM activations WHERE lease_expires_at<=%s AND state NOT IN "
                           "('COMPLETED','FAILED','CANCELLED') FOR UPDATE",(now,)).fetchall()
            result=[]
            for row in rows:
                classification="RECONCILIATION_REQUIRED" if row["state"]=="WAITING_EFFECT" else "RETRYABLE"
                new_state="FAILED" if classification=="RECONCILIATION_REQUIRED" else "REQUESTED"
                c.execute("UPDATE activations SET state=%s,lease_owner=NULL,lease_expires_at=NULL,"
                          "version=version+1 WHERE activation_id=%s",(new_state,row["activation_id"]))
                result.append({"activation_id":row["activation_id"],"classification":classification,
                               "state":new_state})
            return result

    def record_effect(self, effect_id, activation_id, command_id, request_digest, evidence_ref):
        """Create an effect before dispatch; replay is digest-bound and transactional."""
        fp=self._fingerprint("record_effect",[effect_id,activation_id,request_digest,evidence_ref])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            result={"effect_id":effect_id,"state":"PROPOSED","version":1}
            c.execute("INSERT INTO durable_effects VALUES(%s,%s,%s,'PROPOSED',NULL,%s,1)",
                      (effect_id,activation_id,request_digest,evidence_ref))
            self._record(c,command_id,fp,result)
            return result

    def transition_effect(self, effect_id, command_id, new_state, evidence_ref, *, external_ref=None):
        legal={"PROPOSED":{"AUTHORIZED","FAILED"},"AUTHORIZED":{"DISPATCHED","FAILED"},
               "DISPATCHED":{"COMMITTED","FAILED","UNCERTAIN"},
               "UNCERTAIN":{"COMMITTED","FAILED"}}
        fp=self._fingerprint("transition_effect",[effect_id,new_state,external_ref,evidence_ref])
        with self._connect() as c:
            replay=self._replay(c,command_id,fp)
            if replay:return replay
            row=c.execute("SELECT * FROM durable_effects WHERE effect_id=%s FOR UPDATE",(effect_id,)).fetchone()
            if not row or new_state not in legal.get(row["state"],set()):
                raise ValueError("illegal effect transition")
            version=row["version"]+1
            c.execute("UPDATE durable_effects SET state=%s,external_ref=%s,evidence_ref=%s,version=%s WHERE effect_id=%s",
                      (new_state,external_ref,evidence_ref,version,effect_id))
            result={"effect_id":effect_id,"state":new_state,"version":version,
                    "external_ref":external_ref}
            self._record(c,command_id,fp,result)
            return result

    def recover_nonterminal_effects(self):
        with self._connect() as c:
            rows=c.execute("SELECT effect_id,state FROM durable_effects WHERE state IN ('AUTHORIZED','DISPATCHED','UNCERTAIN') ORDER BY effect_id").fetchall()
        return [{"effect_id":row["effect_id"],"classification":
                 "RECONCILIATION_REQUIRED" if row["state"] in ("DISPATCHED","UNCERTAIN") else "RETRYABLE"}
                for row in rows]

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
