-- Batch 2E: immutable, source-bound capture consistency assessments.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2E requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;
CREATE TABLE foundation_acquisition_assessment (
  namespace_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  assessment_version text NOT NULL,
  source_digest text NOT NULL,
  capture_claim_state text NOT NULL,
  query_traversal_complete boolean NOT NULL,
  source_window_complete boolean NOT NULL DEFAULT false,
  assessment jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(source_digest ~ '^[a-f0-9]{64}$'),
  CHECK(capture_claim_state='unverified_local_capture'),
  CHECK(source_window_complete=false),
  CHECK(jsonb_typeof(assessment)='object'),
  CHECK((assessment->'query_traversal_complete') IS NOT NULL AND
        assessment->'query_traversal_complete'=to_jsonb(query_traversal_complete)),
  CHECK((assessment->'source_window_complete') IS NOT NULL AND
        assessment->'source_window_complete'='false'::jsonb),
  CHECK((assessment->>'contract_version') IS NOT NULL AND assessment->>'contract_version'=assessment_version),
  CHECK((assessment->>'source_claim_state') IS NOT NULL AND assessment->>'source_claim_state'=capture_claim_state),
  CHECK((assessment->>'source_finality') IS NOT NULL AND assessment->>'source_finality'='not_established'),
  CHECK(octet_length(assessment::text)<=2097152)
);
CREATE FUNCTION check_acquisition_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE digest text;
BEGIN
  SELECT source_digest INTO digest FROM p24_next.source_snapshot
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.snapshot_id;
  IF digest IS DISTINCT FROM NEW.source_digest THEN
    RAISE EXCEPTION 'Acquisition assessment is bound to another source object';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER acquisition_source_binding BEFORE INSERT ON foundation_acquisition_assessment
  FOR EACH ROW EXECUTE FUNCTION check_acquisition_source();
CREATE TRIGGER immutable_acquisition BEFORE UPDATE OR DELETE ON foundation_acquisition_assessment
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE INDEX acquisition_consistency ON foundation_acquisition_assessment(namespace_id,query_traversal_complete,snapshot_id);
REVOKE ALL ON foundation_acquisition_assessment FROM PUBLIC;
COMMIT;
