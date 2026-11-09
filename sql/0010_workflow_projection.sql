-- Isolated workflow persistence; preserve all earlier migration bytes/rows.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Workflow integration requires a disposable database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

ALTER TABLE foundation_access_decision DROP CONSTRAINT foundation_access_decision_action_key_check;
ALTER TABLE foundation_access_decision ADD CONSTRAINT foundation_access_decision_action_key_check
  CHECK(action_key IN ('read_run','read_publication','read_request','read_requests','read_session',
    'read_candidates','read_evidence','read_access_audit','place_hold','read_sensitive_archive','read_workflows'));
ALTER TABLE foundation_access_decision DROP CONSTRAINT foundation_access_decision_policy_version_check;
ALTER TABLE foundation_access_decision ADD CONSTRAINT foundation_access_decision_policy_version_check
  CHECK(policy_version IN ('p24-access.2','p24-access.3'));

-- One content revision can have several immutable source witnesses. The
-- logical identity/content key is unchanged; individual provenance is retained.
DO $$ DECLARE constraint_name text; BEGIN
  SELECT conname INTO STRICT constraint_name FROM pg_constraint
    WHERE conrelid='p24_next.external_event_revision'::regclass AND contype='u'
      AND pg_get_constraintdef(oid)='UNIQUE (namespace_id, external_event_key, content_sha256, schema_version)';
  EXECUTE format('ALTER TABLE p24_next.external_event_revision DROP CONSTRAINT %I',constraint_name);
END $$;
ALTER TABLE external_event_revision ADD CONSTRAINT external_revision_source_identity
  UNIQUE(namespace_id,external_event_key,content_sha256,schema_version,source_event_version_id);

CREATE TABLE foundation_workflow_contract (
  namespace_id uuid NOT NULL REFERENCES namespace,
  contract_version text NOT NULL, content_sha256 text NOT NULL,
  definition jsonb NOT NULL, registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,contract_version),
  CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=262144)
);
CREATE TRIGGER immutable_workflow_contract BEFORE UPDATE OR DELETE ON foundation_workflow_contract
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TABLE foundation_workflow_run (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, base_run_id uuid NOT NULL,
  input_manifest jsonb NOT NULL, input_sha256 text NOT NULL,
  result jsonb NOT NULL, result_sha256 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,run_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,base_run_id) REFERENCES projection_run,
  CHECK(input_sha256 ~ '^[a-f0-9]{64}$' AND result_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(jsonb_typeof(input_manifest)='object' AND octet_length(input_manifest::text)<=4194304),
  CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=8388608)
);
CREATE FUNCTION guard_foundation_workflow_run() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r p24_next.projection_run%ROWTYPE; b p24_next.projection_run%ROWTYPE;
BEGIN
  SELECT * INTO r FROM p24_next.projection_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  SELECT * INTO b FROM p24_next.projection_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.base_run_id;
  IF r.state IS DISTINCT FROM 'sealed' OR b.state IS DISTINCT FROM 'sealed'
     OR r.event_cutoff IS DISTINCT FROM b.event_cutoff OR r.knowledge_snapshot_at IS DISTINCT FROM b.knowledge_snapshot_at
     OR r.mode IS DISTINCT FROM b.mode OR r.input_manifest_sha256 IS DISTINCT FROM NEW.input_sha256
     OR EXISTS(SELECT 1 FROM p24_next.foundation_projection_request_scope WHERE namespace_id=NEW.namespace_id AND run_id=NEW.base_run_id)
  THEN RAISE EXCEPTION 'Workflow result needs sealed, matching full-source evidence'; END IF;
  IF EXISTS((SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
             EXCEPT SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.base_run_id)
            UNION ALL
            (SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.base_run_id
             EXCEPT SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id))
  THEN RAISE EXCEPTION 'Workflow sources differ from evidence run'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_run_guard BEFORE INSERT ON foundation_workflow_run
  FOR EACH ROW EXECUTE FUNCTION guard_foundation_workflow_run();
CREATE TRIGGER immutable_workflow_run BEFORE UPDATE OR DELETE ON foundation_workflow_run
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TABLE foundation_observation_workflow (
  namespace_id uuid NOT NULL, publication_id uuid NOT NULL, run_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,publication_id),
  FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication,
  FOREIGN KEY(namespace_id,run_id) REFERENCES foundation_workflow_run
);
CREATE FUNCTION guard_workflow_pin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p p24_next.foundation_observation_publication%ROWTYPE; r p24_next.projection_run%ROWTYPE;
  result_digest text;
BEGIN
  SELECT * INTO p FROM p24_next.foundation_observation_publication WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id FOR SHARE;
  SELECT * INTO r FROM p24_next.projection_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  SELECT result_sha256 INTO result_digest FROM p24_next.foundation_workflow_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  IF p.state IS DISTINCT FROM 'draft' OR r.state IS DISTINCT FROM 'sealed'
     OR p.input_manifest->'workflow_projection'->>'run_id' IS DISTINCT FROM NEW.run_id::text
     OR p.input_manifest->'workflow_projection'->>'result_sha256' IS DISTINCT FROM result_digest
     OR (p.input_manifest->>'event_cutoff_ns')::numeric IS DISTINCT FROM extract(epoch FROM r.event_cutoff)*1000000000
     OR (p.input_manifest->>'knowledge_at_ns')::numeric IS DISTINCT FROM extract(epoch FROM r.knowledge_snapshot_at)*1000000000
  THEN RAISE EXCEPTION 'Workflow pin does not match publication bounds/result'; END IF;
  IF EXISTS((SELECT snapshot_id::text FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
             EXCEPT SELECT jsonb_array_elements_text(p.input_manifest->'effective_sources'))
            UNION ALL
            (SELECT jsonb_array_elements_text(p.input_manifest->'effective_sources')
             EXCEPT SELECT snapshot_id::text FROM p24_next.projection_source WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id))
  THEN RAISE EXCEPTION 'Workflow pin source vector differs from publication'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_pin_guard BEFORE INSERT ON foundation_observation_workflow
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_pin();
CREATE TRIGGER immutable_workflow_pin BEFORE UPDATE OR DELETE ON foundation_observation_workflow
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE FUNCTION guard_complete_workflow_pin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state='sealed' AND ((NEW.input_manifest ? 'workflow_projection') IS DISTINCT FROM
      EXISTS(SELECT 1 FROM p24_next.foundation_observation_workflow WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id))
  THEN RAISE EXCEPTION 'Publication workflow manifest and pin must agree'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_pin_at_seal BEFORE UPDATE ON foundation_observation_publication
  FOR EACH ROW EXECUTE FUNCTION guard_complete_workflow_pin();
COMMIT;
