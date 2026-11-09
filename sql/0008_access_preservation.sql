-- Batch 2G: signed investigation authorization and monotonic source holds.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2G requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

ALTER TABLE foundation_access_audit DROP CONSTRAINT IF EXISTS foundation_access_audit_authentication_state_check;
ALTER TABLE foundation_access_audit ADD CONSTRAINT foundation_access_audit_authentication_state_check
  CHECK(authentication_state IN ('unverified_local_identity','verified_signed_credential'));
ALTER TABLE foundation_observation_access DROP CONSTRAINT IF EXISTS foundation_observation_access_authentication_state_check;
ALTER TABLE foundation_observation_access ADD CONSTRAINT foundation_observation_access_authentication_state_check
  CHECK(authentication_state IN ('unverified_local_identity','verified_signed_credential'));
ALTER TABLE foundation_access_audit DROP CONSTRAINT IF EXISTS foundation_access_audit_object_kind_check;
ALTER TABLE foundation_access_audit ADD CONSTRAINT foundation_access_audit_object_kind_check
  CHECK(object_kind IN ('request','session','registration_candidates','request_evidence','projection_run'));
ALTER TABLE foundation_access_audit DROP CONSTRAINT IF EXISTS foundation_access_audit_purpose_key_check;
ALTER TABLE foundation_access_audit ADD CONSTRAINT foundation_access_audit_purpose_key_check
  CHECK(purpose_key IN ('request_investigation','session_investigation','registration_review','evidence_page','run_inspection','test'));
ALTER TABLE foundation_observation_access DROP CONSTRAINT IF EXISTS foundation_observation_access_object_kind_check;
ALTER TABLE foundation_observation_access ADD CONSTRAINT foundation_observation_access_object_kind_check
  CHECK(object_kind IN ('request','requests','session','request_evidence','registration_candidates','publication'));

CREATE TABLE foundation_access_decision (
  namespace_id uuid NOT NULL REFERENCES namespace,
  decision_id uuid NOT NULL DEFAULT gen_random_uuid(),
  principal_key text,
  credential_fingerprint text,
  action_key text NOT NULL,
  resource_kind text NOT NULL,
  resource_key text NOT NULL,
  authentication_state text NOT NULL,
  decision text NOT NULL,
  reason_key text NOT NULL,
  policy_version text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,decision_id),
  CHECK(principal_key IS NULL OR principal_key ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(credential_fingerprint IS NULL OR credential_fingerprint ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(action_key IN ('read_run','read_publication','read_request','read_requests','read_session','read_candidates','read_evidence','read_access_audit','place_hold','read_sensitive_archive')),
  CHECK(resource_kind IN ('request','requests','session','registration_candidates','request_evidence','projection_run','publication','source_snapshot','raw_object','access_audit')),
  CHECK(resource_key ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(authentication_state IN ('verified','missing','invalid','expired','misbound','role_insufficient','policy_unavailable')),
  CHECK(decision IN ('allowed','denied')),
  CHECK(reason_key IN ('authorized','missing_credential','invalid_credential','expired_credential','wrong_namespace','insufficient_role','policy_unavailable')),
  CHECK((decision='allowed' AND authentication_state='verified' AND reason_key='authorized' AND principal_key IS NOT NULL)
     OR (decision='denied' AND reason_key<>'authorized')),
  CHECK(policy_version='p24-access.2')
);
CREATE INDEX foundation_access_decision_lookup ON foundation_access_decision(namespace_id,occurred_at DESC,decision);
CREATE TRIGGER immutable_access_decision BEFORE UPDATE OR DELETE ON foundation_access_decision
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TABLE foundation_evidence_hold (
  namespace_id uuid NOT NULL,
  hold_id uuid NOT NULL DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL,
  object_id uuid,
  reason_key text NOT NULL,
  reference_key text,
  placed_by_key text NOT NULL,
  authentication_state text NOT NULL DEFAULT 'verified_signed_credential',
  placed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,hold_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,snapshot_id,object_id) REFERENCES raw_object(namespace_id,snapshot_id,object_id),
  CHECK(object_id IS NULL OR snapshot_id IS NOT NULL),
  CHECK(reason_key IN ('incident_review','security_investigation','legal_preservation','regulatory_preservation','operator_request','other')),
  CHECK(reference_key IS NULL OR reference_key ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(placed_by_key ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(authentication_state='verified_signed_credential')
);
CREATE INDEX foundation_evidence_hold_snapshot ON foundation_evidence_hold(namespace_id,snapshot_id,placed_at);
CREATE INDEX foundation_evidence_hold_object ON foundation_evidence_hold(namespace_id,object_id) WHERE object_id IS NOT NULL;
CREATE TRIGGER immutable_evidence_hold BEFORE UPDATE OR DELETE ON foundation_evidence_hold
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE VIEW foundation_active_evidence_hold AS
  SELECT namespace_id,hold_id,snapshot_id,object_id,reason_key,reference_key,placed_by_key,placed_at
  FROM foundation_evidence_hold;

CREATE FUNCTION guard_foundation_retention_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy_state text; snapshot uuid; has_hold boolean;
BEGIN
  IF NEW.state='executed' THEN
    RAISE EXCEPTION 'Physical evidence disposition is disabled in the foundation component';
  END IF;
  IF NEW.state='approved' THEN
    SELECT state INTO policy_state FROM p24_next.retention_policy
      WHERE namespace_id=NEW.namespace_id AND policy_version=NEW.policy_version AND data_class=NEW.data_class;
    IF policy_state IS DISTINCT FROM 'approved' THEN
      RAISE EXCEPTION 'Retention disposition requires an approved retention policy';
    END IF;
    SELECT snapshot_id INTO snapshot FROM p24_next.raw_object
      WHERE namespace_id=NEW.namespace_id AND object_id=NEW.object_id;
    SELECT EXISTS(SELECT 1 FROM p24_next.foundation_evidence_hold h
      WHERE h.namespace_id=NEW.namespace_id AND h.snapshot_id=snapshot
        AND (h.object_id IS NULL OR h.object_id=NEW.object_id)) INTO has_hold;
    IF has_hold THEN RAISE EXCEPTION 'Active preservation hold blocks retention approval'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER retention_disposition_guard BEFORE INSERT OR UPDATE ON retention_disposition
  FOR EACH ROW EXECUTE FUNCTION guard_foundation_retention_disposition();

REVOKE ALL ON foundation_access_decision,foundation_evidence_hold,foundation_active_evidence_hold FROM PUBLIC;
COMMIT;
