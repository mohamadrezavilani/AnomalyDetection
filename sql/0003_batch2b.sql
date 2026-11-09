-- Additive Batch 2B lineage, fenced work, source-backed reads and access trail.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2B requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

CREATE TABLE foundation_source_replacement (
  namespace_id uuid NOT NULL,
  revision_id uuid NOT NULL DEFAULT gen_random_uuid(),
  prior_snapshot_id uuid NOT NULL,
  replacement_snapshot_id uuid NOT NULL,
  prior_intake_revision bigint NOT NULL CHECK(prior_intake_revision>0),
  replacement_intake_revision bigint NOT NULL CHECK(replacement_intake_revision>prior_intake_revision),
  reason_key text NOT NULL,
  declared_by text NOT NULL,
  declared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,revision_id),
  UNIQUE(namespace_id,prior_snapshot_id),
  UNIQUE(namespace_id,replacement_snapshot_id),
  FOREIGN KEY(namespace_id,prior_snapshot_id) REFERENCES source_snapshot(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,replacement_snapshot_id) REFERENCES source_snapshot(namespace_id,snapshot_id),
  CHECK(reason_key IN ('corrected_export','late_evidence_supersedes_partial','producer_reissued','operator_reconciled')),
  CHECK(declared_by ~ '^[A-Za-z0-9_.@:-]{1,100}$')
);
CREATE INDEX foundation_source_replacement_child ON foundation_source_replacement(namespace_id,replacement_snapshot_id,prior_snapshot_id);

CREATE TABLE foundation_projection_source_choice (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, snapshot_id uuid NOT NULL,
  choice text NOT NULL, replaced_by_snapshot_id uuid, reason_key text,
  PRIMARY KEY(namespace_id,run_id,snapshot_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run(namespace_id,run_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,replaced_by_snapshot_id) REFERENCES source_snapshot(namespace_id,snapshot_id),
  CHECK(choice IN ('included','replaced_by_selected_descendant')),
  CHECK((choice='included' AND replaced_by_snapshot_id IS NULL AND reason_key IS NULL)
     OR (choice='replaced_by_selected_descendant' AND replaced_by_snapshot_id IS NOT NULL AND reason_key IS NOT NULL))
);

CREATE TABLE foundation_access_audit (
  namespace_id uuid NOT NULL, audit_id uuid NOT NULL DEFAULT gen_random_uuid(), run_id uuid NOT NULL,
  principal_claim text NOT NULL, authentication_state text NOT NULL DEFAULT 'unverified_local_identity',
  purpose_key text NOT NULL, object_kind text NOT NULL, object_token text NOT NULL,
  accessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,audit_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run(namespace_id,run_id),
  CHECK(principal_claim ~ '^[A-Za-z0-9_.@:-]{1,100}$'),
  CHECK(authentication_state='unverified_local_identity'),
  CHECK(purpose_key IN ('request_investigation','session_investigation','registration_review','evidence_page','test')),
  CHECK(object_kind IN ('request','session','registration_candidates','request_evidence')),
  CHECK(length(object_token)>=12 AND object_token !~ '^(0|1|[a-fA-F0-9]{32})$')
);
CREATE INDEX foundation_access_audit_run_time ON foundation_access_audit(namespace_id,run_id,accessed_at DESC);

CREATE TABLE foundation_work_item (
  namespace_id uuid NOT NULL, work_id uuid NOT NULL, work_kind text NOT NULL,
  dedupe_token text NOT NULL, payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending', result_run_id uuid, attempt_count integer NOT NULL DEFAULT 0,
  lease_generation integer NOT NULL DEFAULT 0, lease_owner text, lease_until timestamptz,
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_error_code text,
  PRIMARY KEY(namespace_id,work_id), UNIQUE(namespace_id,work_kind,dedupe_token),
  FOREIGN KEY(namespace_id) REFERENCES namespace,
  FOREIGN KEY(namespace_id,result_run_id) REFERENCES projection_run(namespace_id,run_id),
  CHECK(work_kind IN ('project_sources')),
  CHECK(dedupe_token ~ '^[a-f0-9]{64}$'),
  CHECK(octet_length(payload::text)<=32768),
  CHECK(state IN ('pending','leased','retry','completed','dead')),
  CHECK((state='completed' AND result_run_id IS NOT NULL) OR (state<>'completed' AND result_run_id IS NULL)),
  CHECK(attempt_count BETWEEN 0 AND 8 AND lease_generation>=0),
  CHECK(state='leased' OR (lease_owner IS NULL AND lease_until IS NULL)),
  CHECK(state<>'leased' OR (lease_owner ~ '^[A-Za-z0-9_.:-]{1,100}$' AND lease_until IS NOT NULL)),
  CHECK(last_error_code IS NULL OR last_error_code ~ '^[a-z0-9_]{1,80}$')
);
CREATE INDEX foundation_work_claim ON foundation_work_item(namespace_id,state,available_at,created_at,work_id);
CREATE INDEX foundation_work_expired_lease ON foundation_work_item(namespace_id,lease_until,created_at,work_id) WHERE state='leased';

CREATE TABLE foundation_work_attempt (
  namespace_id uuid NOT NULL, attempt_id uuid NOT NULL DEFAULT gen_random_uuid(), work_id uuid NOT NULL,
  lease_generation integer NOT NULL, action text NOT NULL, worker_claim text,
  error_code text, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,attempt_id),
  FOREIGN KEY(namespace_id,work_id) REFERENCES foundation_work_item(namespace_id,work_id),
  CHECK(action IN ('claimed','renewed','completed','retry_scheduled','dead_lettered','lease_exhausted')),
  CHECK(worker_claim IS NULL OR worker_claim ~ '^[A-Za-z0-9_.:-]{1,100}$'),
  CHECK(error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,80}$')
);
CREATE INDEX foundation_work_attempt_lookup ON foundation_work_attempt(namespace_id,work_id,recorded_at);

CREATE FUNCTION guard_source_replacement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_window text; new_window text; old_revision bigint; new_revision bigint;
BEGIN
  SELECT window_key,intake_revision INTO old_window,old_revision FROM p24_next.source_snapshot
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.prior_snapshot_id FOR UPDATE;
  SELECT window_key,intake_revision INTO new_window,new_revision FROM p24_next.source_snapshot
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.replacement_snapshot_id FOR SHARE;
  IF old_window IS NULL OR new_window IS DISTINCT FROM old_window OR old_revision IS DISTINCT FROM NEW.prior_intake_revision
     OR new_revision IS DISTINCT FROM NEW.replacement_intake_revision OR new_revision<=old_revision
    THEN RAISE EXCEPTION 'Source replacement must advance the same logical source window'; END IF;
  IF EXISTS(SELECT 1 FROM p24_next.foundation_source_replacement r WHERE r.namespace_id=NEW.namespace_id
      AND r.prior_snapshot_id=NEW.replacement_snapshot_id)
    THEN RAISE EXCEPTION 'A source replacement must extend the latest declared revision'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER source_replacement_guard BEFORE INSERT ON foundation_source_replacement
  FOR EACH ROW EXECUTE FUNCTION guard_source_replacement();
CREATE TRIGGER source_replacement_immutable BEFORE UPDATE OR DELETE ON foundation_source_replacement
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE FUNCTION guard_work_item() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (OLD.namespace_id,OLD.work_id,OLD.work_kind,OLD.dedupe_token,OLD.payload,OLD.created_at)
      IS DISTINCT FROM (NEW.namespace_id,NEW.work_id,NEW.work_kind,NEW.dedupe_token,NEW.payload,NEW.created_at)
    THEN RAISE EXCEPTION 'Work identity and payload are immutable'; END IF;
  IF OLD.state IN ('completed','dead') THEN RAISE EXCEPTION 'Terminal work state is immutable'; END IF;
  IF NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1
      OR NEW.lease_generation<OLD.lease_generation OR NEW.lease_generation>OLD.lease_generation+1
    THEN RAISE EXCEPTION 'Work fencing counters cannot move backwards or skip'; END IF;
  IF NEW.lease_generation=OLD.lease_generation AND NEW.attempt_count<>OLD.attempt_count
    THEN RAISE EXCEPTION 'Only a new lease generation may add an attempt'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER work_item_guard BEFORE UPDATE ON foundation_work_item
  FOR EACH ROW EXECUTE FUNCTION guard_work_item();
CREATE TRIGGER work_attempt_immutable BEFORE UPDATE OR DELETE ON foundation_work_attempt
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

DO $$ DECLARE table_key text; BEGIN
  FOREACH table_key IN ARRAY ARRAY['foundation_projection_source_choice','foundation_access_audit'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',table_key);
  END LOOP;
  FOREACH table_key IN ARRAY ARRAY['foundation_projection_source_choice'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_run BEFORE INSERT OR UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.guard_run_child()',table_key);
  END LOOP;
END $$;
REVOKE ALL ON foundation_source_replacement,foundation_projection_source_choice,foundation_access_audit,
  foundation_work_item,foundation_work_attempt FROM PUBLIC;
COMMIT;
