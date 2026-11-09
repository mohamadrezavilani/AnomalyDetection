-- Isolated incident recurrence/review slice. Existing evidence remains intact.
BEGIN;
DO $$ BEGIN
 IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN RAISE EXCEPTION 'Disposable database required'; END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

-- Selected-event fact joins previously had only the fact UUID primary key.
CREATE INDEX extracted_fact_selected_event ON extracted_fact(namespace_id,event_version_id,request_key,fact_id);

ALTER TABLE foundation_access_decision DROP CONSTRAINT foundation_access_decision_action_key_check;
ALTER TABLE foundation_access_decision ADD CONSTRAINT foundation_access_decision_action_key_check CHECK(action_key IN
 ('read_run','read_publication','read_request','read_requests','read_session','read_candidates','read_evidence',
  'read_access_audit','place_hold','read_sensitive_archive','read_workflows','read_incidents','review_incidents'));
ALTER TABLE foundation_access_decision DROP CONSTRAINT foundation_access_decision_policy_version_check;
ALTER TABLE foundation_access_decision ADD CONSTRAINT foundation_access_decision_policy_version_check
 CHECK(policy_version IN ('p24-access.2','p24-access.3','p24-access.4'));
ALTER TABLE foundation_access_decision DROP CONSTRAINT foundation_access_decision_resource_kind_check;
ALTER TABLE foundation_access_decision ADD CONSTRAINT foundation_access_decision_resource_kind_check CHECK(resource_kind IN
 ('request','requests','session','registration_candidates','request_evidence','projection_run','publication',
  'source_snapshot','raw_object','access_audit','incident'));

CREATE TABLE foundation_incident_contract (
 namespace_id uuid NOT NULL, incident_id uuid NOT NULL,
 pattern_key text NOT NULL, grouping_version text NOT NULL,
 PRIMARY KEY(namespace_id,incident_id),
 FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
 CHECK(pattern_key ~ '^[A-Za-z0-9_.:-]{1,160}$')
);
CREATE TABLE foundation_incident_revision (
 namespace_id uuid NOT NULL, revision_id uuid NOT NULL, incident_id uuid NOT NULL,
 publication_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0), parent_revision_id uuid,
 input_sha256 text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(namespace_id,revision_id), UNIQUE(namespace_id,incident_id,generation),
 UNIQUE(namespace_id,incident_id,revision_id),
 FOREIGN KEY(namespace_id,incident_id) REFERENCES foundation_incident_contract,
 FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication,
 FOREIGN KEY(namespace_id,incident_id,parent_revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id),
 CHECK((generation=1)=(parent_revision_id IS NULL)),
 CHECK(input_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=4194304)
);
CREATE TABLE foundation_incident_revision_finding (
 namespace_id uuid NOT NULL, incident_id uuid NOT NULL, revision_id uuid NOT NULL, finding_id uuid NOT NULL,
 PRIMARY KEY(namespace_id,revision_id,finding_id),
 FOREIGN KEY(namespace_id,incident_id,revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id),
 FOREIGN KEY(namespace_id,incident_id,finding_id) REFERENCES incident_finding
);
CREATE TABLE foundation_incident_head (
 namespace_id uuid NOT NULL, incident_id uuid NOT NULL, revision_id uuid NOT NULL, generation bigint NOT NULL,
 PRIMARY KEY(namespace_id,incident_id),
 FOREIGN KEY(namespace_id,incident_id,revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id)
);
CREATE FUNCTION guard_incident_head() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r p24_next.foundation_incident_revision%ROWTYPE;
BEGIN
 SELECT * INTO r FROM p24_next.foundation_incident_revision WHERE namespace_id=NEW.namespace_id AND revision_id=NEW.revision_id;
 IF r.generation IS DISTINCT FROM NEW.generation OR (TG_OP='UPDATE' AND
    (NEW.generation<>OLD.generation+1 OR r.parent_revision_id IS DISTINCT FROM OLD.revision_id OR
     NEW.namespace_id<>OLD.namespace_id OR NEW.incident_id<>OLD.incident_id))
    OR (TG_OP='INSERT' AND NEW.generation<>1)
 THEN RAISE EXCEPTION 'Incident head must advance by one matching revision'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER incident_head_guard BEFORE INSERT OR UPDATE ON foundation_incident_head FOR EACH ROW EXECUTE FUNCTION guard_incident_head();
CREATE FUNCTION guard_incident_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM p24_next.foundation_observation_publication WHERE namespace_id=NEW.namespace_id
    AND publication_id=NEW.publication_id AND state='sealed') THEN RAISE EXCEPTION 'Incident needs sealed evidence'; END IF;
 IF NEW.parent_revision_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM p24_next.foundation_incident_revision
   WHERE namespace_id=NEW.namespace_id AND revision_id=NEW.parent_revision_id AND generation=NEW.generation-1)
 THEN RAISE EXCEPTION 'Incident parent generation mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER incident_revision_guard BEFORE INSERT ON foundation_incident_revision FOR EACH ROW EXECUTE FUNCTION guard_incident_revision();
CREATE TABLE foundation_review_head (
 namespace_id uuid NOT NULL REFERENCES namespace, subject_kind text NOT NULL, subject_key text NOT NULL,
 pattern_key text NOT NULL, generation bigint NOT NULL CHECK(generation>0), decision_id uuid NOT NULL,
 PRIMARY KEY(namespace_id,subject_kind,subject_key,pattern_key),
 FOREIGN KEY(namespace_id,decision_id) REFERENCES operator_decision
);
CREATE FUNCTION guard_review_head() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d p24_next.operator_decision%ROWTYPE;
BEGIN
 SELECT * INTO d FROM p24_next.operator_decision WHERE namespace_id=NEW.namespace_id AND decision_id=NEW.decision_id;
 IF (d.subject_kind,d.subject_key,d.pattern_key) IS DISTINCT FROM (NEW.subject_kind,NEW.subject_key,NEW.pattern_key)
   OR (TG_OP='INSERT' AND (NEW.generation<>1 OR d.supersedes_decision_id IS NOT NULL))
   OR (TG_OP='UPDATE' AND (NEW.generation<>OLD.generation+1 OR d.supersedes_decision_id IS DISTINCT FROM OLD.decision_id
     OR (NEW.namespace_id,NEW.subject_kind,NEW.subject_key,NEW.pattern_key) IS DISTINCT FROM (OLD.namespace_id,OLD.subject_kind,OLD.subject_key,OLD.pattern_key)))
 THEN RAISE EXCEPTION 'Review head must advance matching scope and predecessor'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER review_head_guard BEFORE INSERT OR UPDATE ON foundation_review_head FOR EACH ROW EXECUTE FUNCTION guard_review_head();
CREATE TABLE foundation_review_receipt (
 namespace_id uuid NOT NULL, command_id uuid NOT NULL, decision_id uuid NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(namespace_id,command_id), FOREIGN KEY(namespace_id,decision_id) REFERENCES operator_decision
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['foundation_incident_contract','foundation_incident_revision','foundation_incident_revision_finding','foundation_review_receipt'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',t);
 END LOOP;
END $$;
CREATE INDEX incident_revision_publication ON foundation_incident_revision(namespace_id,publication_id,incident_id,generation DESC);
CREATE INDEX incident_subject_scope ON incident(namespace_id,scope_kind,subject_key,incident_id);
CREATE FUNCTION freeze_managed_incident() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM p24_next.foundation_incident_contract WHERE namespace_id=OLD.namespace_id AND incident_id=OLD.incident_id)
 THEN RAISE EXCEPTION 'Managed incident identity/membership is append-only'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER managed_incident_immutable BEFORE UPDATE OR DELETE ON incident FOR EACH ROW EXECUTE FUNCTION freeze_managed_incident();
CREATE TRIGGER managed_incident_finding_immutable BEFORE UPDATE OR DELETE ON incident_finding FOR EACH ROW EXECUTE FUNCTION freeze_managed_incident();
COMMIT;
