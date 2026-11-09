-- Batch 2U: evidence-proven incident links and revision-bound priority.
BEGIN;
DO $$ BEGIN
 IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN RAISE EXCEPTION 'Disposable database required'; END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

CREATE TABLE foundation_investigation_link_proof (
 namespace_id uuid NOT NULL, investigation_id uuid NOT NULL, incident_id uuid NOT NULL,
 publication_id uuid NOT NULL, incident_revision_id uuid NOT NULL,
 linked_incident_id uuid NOT NULL, linked_revision_id uuid NOT NULL,
 shared_request_keys jsonb NOT NULL, proof_sha256 text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(namespace_id,investigation_id,incident_id),
 FOREIGN KEY(namespace_id,investigation_id,incident_id) REFERENCES investigation_link,
 FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication,
 FOREIGN KEY(namespace_id,incident_id,incident_revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id),
 FOREIGN KEY(namespace_id,linked_incident_id,linked_revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id),
 CHECK(incident_id<>linked_incident_id),
 CHECK(jsonb_typeof(shared_request_keys)='array' AND jsonb_array_length(shared_request_keys)>0),
 CHECK(proof_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE foundation_priority_head (
 namespace_id uuid NOT NULL, incident_id uuid NOT NULL, decision_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), revision_id uuid NOT NULL,
 PRIMARY KEY(namespace_id,incident_id),
 FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
 FOREIGN KEY(namespace_id,decision_id) REFERENCES priority_decision,
 FOREIGN KEY(namespace_id,incident_id,revision_id) REFERENCES foundation_incident_revision(namespace_id,incident_id,revision_id)
);
CREATE FUNCTION guard_investigation_link_proof() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE left_result jsonb; right_result jsonb; item text;
BEGIN
 SELECT result INTO left_result FROM p24_next.foundation_incident_revision
  WHERE namespace_id=NEW.namespace_id AND incident_id=NEW.incident_id AND revision_id=NEW.incident_revision_id
    AND publication_id=NEW.publication_id;
 SELECT result INTO right_result FROM p24_next.foundation_incident_revision
  WHERE namespace_id=NEW.namespace_id AND incident_id=NEW.linked_incident_id AND revision_id=NEW.linked_revision_id
    AND publication_id=NEW.publication_id;
 IF left_result IS NULL OR right_result IS NULL THEN RAISE EXCEPTION 'Investigation proof must pin both incidents to the same publication'; END IF;
 FOR item IN SELECT jsonb_array_elements_text(NEW.shared_request_keys) LOOP
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(left_result->'requests') x WHERE x->>'request_key'=item)
     OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(right_result->'requests') x WHERE x->>'request_key'=item)
  THEN RAISE EXCEPTION 'Investigation proof RequestID is absent from a pinned incident revision'; END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER investigation_link_proof_guard BEFORE INSERT ON foundation_investigation_link_proof
 FOR EACH ROW EXECUTE FUNCTION guard_investigation_link_proof();
CREATE FUNCTION guard_priority_decision_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected text;
BEGIN
 SELECT r.input_sha256 INTO expected FROM p24_next.foundation_incident_head h
 JOIN p24_next.foundation_incident_revision r USING(namespace_id,incident_id,revision_id)
 WHERE h.namespace_id=NEW.namespace_id AND h.incident_id=NEW.incident_id;
 IF expected IS NULL OR expected IS DISTINCT FROM NEW.evidence_manifest_sha256 THEN
  RAISE EXCEPTION 'Priority decision must cite the current incident evidence revision';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER priority_decision_evidence_guard BEFORE INSERT ON priority_decision
 FOR EACH ROW EXECUTE FUNCTION guard_priority_decision_evidence();
CREATE FUNCTION guard_priority_head() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d p24_next.priority_decision%ROWTYPE; rh uuid;
BEGIN
 SELECT * INTO d FROM p24_next.priority_decision WHERE namespace_id=NEW.namespace_id AND decision_id=NEW.decision_id;
 SELECT revision_id INTO rh FROM p24_next.foundation_incident_head WHERE namespace_id=NEW.namespace_id AND incident_id=NEW.incident_id;
 IF d.incident_id IS DISTINCT FROM NEW.incident_id OR
   d.evidence_manifest_sha256 IS DISTINCT FROM (SELECT input_sha256 FROM p24_next.foundation_incident_revision WHERE namespace_id=NEW.namespace_id AND incident_id=NEW.incident_id AND revision_id=NEW.revision_id) OR
   rh IS DISTINCT FROM NEW.revision_id OR
   (TG_OP='INSERT' AND NEW.generation<>1) OR
   (TG_OP='UPDATE' AND (NEW.generation<>OLD.generation+1 OR NEW.namespace_id<>OLD.namespace_id OR NEW.incident_id<>OLD.incident_id))
 THEN RAISE EXCEPTION 'Priority head must advance one revision for the same incident'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER priority_head_guard BEFORE INSERT OR UPDATE ON foundation_priority_head FOR EACH ROW EXECUTE FUNCTION guard_priority_head();
CREATE FUNCTION immutable_priority_decision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Priority decisions are append-only'; END $$;
CREATE TRIGGER priority_decision_immutable BEFORE UPDATE OR DELETE ON priority_decision FOR EACH ROW EXECUTE FUNCTION immutable_priority_decision();
CREATE FUNCTION immutable_investigation_link() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Evidence-backed investigation links are append-only'; END $$;
CREATE TRIGGER investigation_link_immutable BEFORE UPDATE OR DELETE ON investigation_link FOR EACH ROW EXECUTE FUNCTION immutable_investigation_link();
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['foundation_investigation_link_proof'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',t);
 END LOOP;
END $$;
CREATE INDEX investigation_link_lookup ON investigation_link(namespace_id,incident_id,investigation_id);
COMMIT;
