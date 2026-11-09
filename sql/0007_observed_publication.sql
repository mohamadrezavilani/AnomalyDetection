-- Batch 2F: scoped reconstruction and atomic publication of observed evidence.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2F requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

CREATE TABLE foundation_projection_request_scope (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,request_key),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request
);
CREATE TRIGGER frozen_scope BEFORE INSERT OR UPDATE OR DELETE ON foundation_projection_request_scope
  FOR EACH ROW EXECUTE FUNCTION guard_run_child();
CREATE FUNCTION guard_scoped_request_projection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM p24_next.foundation_projection_request_scope WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id)
     AND NOT EXISTS(SELECT 1 FROM p24_next.foundation_projection_request_scope
         WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND request_key=NEW.request_key)
    THEN RAISE EXCEPTION 'Request lies outside this reconstruction scope'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scoped_request_membership BEFORE INSERT OR UPDATE ON request_projection
  FOR EACH ROW EXECUTE FUNCTION guard_scoped_request_projection();
CREATE FUNCTION guard_full_projection_work_result() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state='completed' AND EXISTS(SELECT 1 FROM p24_next.foundation_projection_request_scope
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.result_run_id)
    THEN RAISE EXCEPTION 'Scoped reconstruction cannot complete full-source work'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER full_projection_work_result BEFORE UPDATE ON foundation_work_item
  FOR EACH ROW EXECUTE FUNCTION guard_full_projection_work_result();

CREATE TABLE foundation_observation_publication (
  namespace_id uuid NOT NULL REFERENCES namespace, publication_id uuid NOT NULL,
  base_publication_id uuid, expected_generation bigint NOT NULL CHECK(expected_generation>=0),
  state text NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','sealed')),
  is_checkpoint boolean NOT NULL, overlay_depth integer NOT NULL CHECK(overlay_depth BETWEEN 0 AND 63),
  input_manifest jsonb NOT NULL, input_sha256 text NOT NULL, request_heads_sha256 text NOT NULL,
  coverage jsonb NOT NULL, statistics jsonb NOT NULL,
  entry_count bigint NOT NULL CHECK(entry_count BETWEEN 0 AND 100000),
  request_count bigint NOT NULL CHECK(request_count BETWEEN 0 AND 100000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,publication_id),
  FOREIGN KEY(namespace_id,base_publication_id) REFERENCES foundation_observation_publication,
  CHECK((expected_generation=0)=(base_publication_id IS NULL)),
  CHECK(is_checkpoint=(overlay_depth=0)),
  CHECK(input_sha256 ~ '^[a-f0-9]{64}$' AND request_heads_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(jsonb_typeof(input_manifest)='object' AND octet_length(input_manifest::text)<=262144),
  CHECK(jsonb_typeof(coverage)='object' AND coverage ?& ARRAY['evidence_scope','source_window_complete','authoritative_source_heads_published']),
  CHECK(coverage->'evidence_scope'='"observed_only"'::jsonb),
  CHECK(coverage->'source_window_complete'='false'::jsonb AND coverage->'authoritative_source_heads_published'='false'::jsonb),
  CHECK(jsonb_typeof(statistics)='object' AND octet_length(statistics::text)<=65536)
);
CREATE TABLE foundation_observation_entry (
  namespace_id uuid NOT NULL, publication_id uuid NOT NULL, request_key text NOT NULL,
  run_id uuid, entry_kind text NOT NULL, write_reason text NOT NULL,
  PRIMARY KEY(namespace_id,publication_id,request_key),
  FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication,
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  CHECK((entry_kind='upsert' AND run_id IS NOT NULL AND write_reason IN ('recomputed','checkpoint_reuse'))
     OR (entry_kind='remove' AND run_id IS NULL AND write_reason='removed'))
);
CREATE TABLE foundation_observation_commit (
  namespace_id uuid NOT NULL, publication_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
  published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,publication_id), UNIQUE(namespace_id,generation),
  UNIQUE(namespace_id,publication_id,generation),
  FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication
);
CREATE TABLE foundation_observation_current (
  namespace_id uuid PRIMARY KEY REFERENCES namespace, publication_id uuid NOT NULL, generation bigint NOT NULL,
  FOREIGN KEY(namespace_id,publication_id,generation) REFERENCES foundation_observation_commit(namespace_id,publication_id,generation)
);
CREATE TABLE foundation_observation_access (
  namespace_id uuid NOT NULL, audit_id uuid NOT NULL DEFAULT gen_random_uuid(), publication_id uuid NOT NULL,
  object_kind text NOT NULL, object_token text NOT NULL, principal_claim text NOT NULL,
  authentication_state text NOT NULL DEFAULT 'unverified_local_identity',
  accessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,audit_id),
  FOREIGN KEY(namespace_id,publication_id) REFERENCES foundation_observation_publication,
  CHECK(object_kind IN ('request','requests','session','request_evidence','registration_candidates')),
  CHECK(object_token ~ '^[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}$'),
  CHECK(principal_claim ~ '^[A-Za-z0-9_.@:-]{1,100}$'),
  CHECK(authentication_state='unverified_local_identity')
);
CREATE TRIGGER immutable_observation_access BEFORE UPDATE OR DELETE ON foundation_observation_access
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- A checkpoint terminates overlay traversal, not retained audit history.
-- Optional request filtering applies before choosing its latest delta, so a
-- point lookup does not materialize every request in a publication.
CREATE FUNCTION foundation_observation_heads(n uuid,p uuid,q text DEFAULT NULL)
RETURNS TABLE(request_key text,run_id uuid) LANGUAGE sql STABLE AS $$
  WITH RECURSIVE chain AS (
    SELECT x.publication_id,x.base_publication_id,x.is_checkpoint,0 AS depth
      FROM p24_next.foundation_observation_publication x WHERE x.namespace_id=n AND x.publication_id=p
    UNION ALL
    SELECT x.publication_id,x.base_publication_id,x.is_checkpoint,c.depth+1 FROM chain c
      JOIN p24_next.foundation_observation_publication x ON x.namespace_id=n AND x.publication_id=c.base_publication_id
      WHERE NOT c.is_checkpoint AND c.depth<63
  ), latest AS (
    SELECT DISTINCT ON(e.request_key) e.request_key,e.run_id,e.entry_kind FROM chain c
      JOIN p24_next.foundation_observation_entry e ON e.namespace_id=n AND e.publication_id=c.publication_id
      WHERE q IS NULL OR e.request_key=q ORDER BY e.request_key,c.depth
  ) SELECT latest.request_key,latest.run_id FROM latest WHERE latest.entry_kind='upsert';
$$;

CREATE FUNCTION guard_observation_entry() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s text; checkpoint boolean; run_state text;
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Publication entries are append-only'; END IF;
  SELECT state,is_checkpoint INTO s,checkpoint FROM p24_next.foundation_observation_publication
    WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id FOR SHARE;
  IF s IS DISTINCT FROM 'draft' THEN RAISE EXCEPTION 'Publication entries are frozen or absent'; END IF;
  IF NEW.entry_kind='upsert' THEN
    SELECT state INTO run_state FROM p24_next.projection_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
    IF run_state IS DISTINCT FROM 'sealed' THEN RAISE EXCEPTION 'A request head must reference a sealed reconstruction'; END IF;
  END IF;
  IF (checkpoint AND NEW.entry_kind='remove') OR (NOT checkpoint AND NEW.write_reason='checkpoint_reuse')
    THEN RAISE EXCEPTION 'Entry kind is incompatible with checkpoint semantics'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER observation_entry_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation_observation_entry
  FOR EACH ROW EXECUTE FUNCTION guard_observation_entry();

CREATE FUNCTION guard_observation_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_generation bigint; parent_depth integer; actual_entries bigint; actual_requests bigint;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Publication history is immutable'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.state<>'draft' THEN RAISE EXCEPTION 'Publication must start as a draft'; END IF;
    IF NEW.base_publication_id IS NOT NULL THEN
      SELECT c.generation,p.overlay_depth INTO parent_generation,parent_depth
        FROM p24_next.foundation_observation_commit c JOIN p24_next.foundation_observation_publication p USING(namespace_id,publication_id)
        WHERE c.namespace_id=NEW.namespace_id AND c.publication_id=NEW.base_publication_id;
      IF parent_generation IS DISTINCT FROM NEW.expected_generation
        THEN RAISE EXCEPTION 'Base generation is absent or mismatched'; END IF;
      IF NOT NEW.is_checkpoint AND NEW.overlay_depth<>parent_depth+1
        THEN RAISE EXCEPTION 'Overlay depth must extend the committed base'; END IF;
    ELSIF NOT NEW.is_checkpoint THEN RAISE EXCEPTION 'Initial publication must be a checkpoint'; END IF;
    RETURN NEW;
  END IF;
  IF OLD.state<>'draft' OR NEW.state<>'sealed' OR (to_jsonb(OLD)-'state') IS DISTINCT FROM (to_jsonb(NEW)-'state')
    THEN RAISE EXCEPTION 'Only sealing an unchanged draft is permitted'; END IF;
  SELECT count(*) INTO actual_entries FROM p24_next.foundation_observation_entry
    WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id;
  SELECT count(*) INTO actual_requests FROM p24_next.foundation_observation_heads(NEW.namespace_id,NEW.publication_id);
  IF actual_entries<>NEW.entry_count OR actual_requests<>NEW.request_count
    THEN RAISE EXCEPTION 'Publication manifest counts do not match entries'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER observation_publication_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation_observation_publication
  FOR EACH ROW EXECUTE FUNCTION guard_observation_publication();

CREATE FUNCTION guard_observation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key text; actual_generation bigint; actual_id uuid; p p24_next.foundation_observation_publication%ROWTYPE;
BEGIN
  SELECT application_key INTO key FROM p24_next.namespace WHERE namespace_id=NEW.namespace_id;
  PERFORM pg_advisory_xact_lock(hashtextextended('p24-foundation:'||key,0));
  SELECT * INTO p FROM p24_next.foundation_observation_publication WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id;
  SELECT generation,publication_id INTO actual_generation,actual_id FROM p24_next.foundation_observation_current WHERE namespace_id=NEW.namespace_id;
  actual_generation:=coalesce(actual_generation,0);
  IF p.state IS DISTINCT FROM 'sealed' OR p.expected_generation<>actual_generation
     OR p.base_publication_id IS DISTINCT FROM actual_id OR NEW.generation<>actual_generation+1
    THEN RAISE EXCEPTION 'Publication generation is stale or unsealed'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER observation_commit_guard BEFORE INSERT ON foundation_observation_commit
  FOR EACH ROW EXECUTE FUNCTION guard_observation_commit();
CREATE TRIGGER immutable_observation_commit BEFORE UPDATE OR DELETE ON foundation_observation_commit
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE FUNCTION guard_observation_current() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p p24_next.foundation_observation_publication%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Current publication cannot be deleted'; END IF;
  SELECT * INTO p FROM p24_next.foundation_observation_publication WHERE namespace_id=NEW.namespace_id AND publication_id=NEW.publication_id;
  IF p.state IS DISTINCT FROM 'sealed' OR NEW.generation<>p.expected_generation+1
    THEN RAISE EXCEPTION 'Current publication must reference its committed generation'; END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.namespace_id<>OLD.namespace_id OR p.base_publication_id IS DISTINCT FROM OLD.publication_id OR p.expected_generation<>OLD.generation
      THEN RAISE EXCEPTION 'Current publication must advance from its exact base'; END IF;
  ELSIF p.expected_generation<>0 THEN RAISE EXCEPTION 'Initial current publication needs generation one'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER observation_current_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation_observation_current
  FOR EACH ROW EXECUTE FUNCTION guard_observation_current();
CREATE FUNCTION validate_observation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.foundation_observation_current
      WHERE namespace_id=NEW.namespace_id AND generation>=NEW.generation)
    THEN RAISE EXCEPTION 'A committed publication must become current atomically'; END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER observation_commit_is_published AFTER INSERT ON foundation_observation_commit
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_observation_commit();

REVOKE ALL ON foundation_projection_request_scope,foundation_observation_publication,foundation_observation_entry,
  foundation_observation_commit,foundation_observation_current,foundation_observation_access FROM PUBLIC;
REVOKE ALL ON FUNCTION foundation_observation_heads(uuid,uuid,text) FROM PUBLIC;
COMMIT;
