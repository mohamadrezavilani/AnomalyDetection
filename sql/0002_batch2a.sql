-- Additive isolated Batch 2A contract. Base p24-domain.3 remains unchanged.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2A requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

CREATE TABLE foundation_namespace_contract (
  namespace_id uuid PRIMARY KEY REFERENCES namespace,
  equality_key_version text NOT NULL, equality_key_fingerprint text NOT NULL, encryption_key_fingerprint text NOT NULL,
  extraction_version text NOT NULL, catalog_sha256 text NOT NULL,
  CHECK(equality_key_fingerprint ~ '^[a-f0-9]{64}$'),
  CHECK(encryption_key_fingerprint ~ '^[a-f0-9]{64}$'),
  CHECK(catalog_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE foundation_snapshot_metadata (
  namespace_id uuid NOT NULL, snapshot_id uuid NOT NULL,
  input_format text NOT NULL, coverage jsonb NOT NULL,
  archive_cipher_sha256 text NOT NULL, receive_time_basis text NOT NULL,
  PRIMARY KEY(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(archive_cipher_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(receive_time_basis IN ('intake_clock','synthetic_fixture','producer_manifest'))
);
CREATE TABLE foundation_row_membership (
  namespace_id uuid NOT NULL, snapshot_id uuid NOT NULL,
  row_ordinal bigint NOT NULL CHECK(row_ordinal>=0), event_version_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,snapshot_id,row_ordinal),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version
);
CREATE TABLE foundation_event_descriptor (
  namespace_id uuid NOT NULL, event_version_id uuid NOT NULL,
  extraction_version text NOT NULL, descriptor jsonb NOT NULL,
  PRIMARY KEY(namespace_id,event_version_id),
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version,
  CHECK(octet_length(descriptor::text)<=65536)
);
CREATE TABLE foundation_request_summary (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  summary jsonb NOT NULL,
  PRIMARY KEY(namespace_id,run_id,request_key),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection
);
CREATE TABLE foundation_registration_candidate (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL,
  registration_request_key text NOT NULL, session_key text NOT NULL,
  support_request_key text NOT NULL, basis jsonb NOT NULL,
  PRIMARY KEY(namespace_id,run_id,registration_request_key,session_key),
  FOREIGN KEY(namespace_id,run_id,registration_request_key) REFERENCES request_projection(namespace_id,run_id,request_key),
  FOREIGN KEY(namespace_id,run_id,support_request_key) REFERENCES request_projection(namespace_id,run_id,request_key),
  FOREIGN KEY(namespace_id,session_key) REFERENCES user_session
);
CREATE INDEX foundation_row_event_lookup ON foundation_row_membership(namespace_id,event_version_id,snapshot_id);
CREATE INDEX event_request_lookup_2a ON event_version(namespace_id,request_key,source_event_time,event_version_id);
CREATE INDEX event_source_version_lookup_2a ON event_source(namespace_id,event_version_id,snapshot_id);

-- Revised-history runs also have a declared knowledge snapshot. They can use
-- later knowledge than the original run, not sources beyond their own bound.
CREATE OR REPLACE FUNCTION guard_original_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM p24_next.projection_run r JOIN p24_next.source_snapshot s
      ON s.namespace_id=r.namespace_id WHERE r.namespace_id=NEW.namespace_id AND r.run_id=NEW.run_id
      AND s.snapshot_id=NEW.snapshot_id AND r.mode IN ('online_original','historical_revised')
      AND s.observed_at>r.knowledge_snapshot_at)
    THEN RAISE EXCEPTION 'Snapshot exceeds this run knowledge bound'; END IF;
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION guard_selected_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE at_time timestamptz; at_ns numeric; cutoff_time timestamptz; known_at timestamptz; mode_key text; received timestamptz;
BEGIN
  IF NEW.event_version_id IS NULL THEN RETURN NEW; END IF;
  SELECT source_event_time,source_time_epoch_ns,received_at INTO at_time,at_ns,received FROM p24_next.event_version
    WHERE namespace_id=NEW.namespace_id AND event_version_id=NEW.event_version_id;
  SELECT event_cutoff,knowledge_snapshot_at,mode INTO cutoff_time,known_at,mode_key FROM p24_next.projection_run
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  IF at_time IS NULL OR at_ns IS NULL OR at_ns>=extract(epoch FROM cutoff_time)*1000000000
    THEN RAISE EXCEPTION 'Event is not eligible before this cutoff'; END IF;
  IF mode_key IN ('online_original','historical_revised') AND received>known_at
    THEN RAISE EXCEPTION 'Evidence exceeds this run knowledge bound'; END IF;
  IF NOT EXISTS(SELECT 1 FROM p24_next.event_source es JOIN p24_next.projection_source ps
      ON ps.namespace_id=es.namespace_id AND ps.snapshot_id=es.snapshot_id
      WHERE ps.namespace_id=NEW.namespace_id AND ps.run_id=NEW.run_id AND es.event_version_id=NEW.event_version_id)
    THEN RAISE EXCEPTION 'Event has no support in this frozen input set'; END IF;
  RETURN NEW;
END $$;

DO $$ DECLARE table_key text; BEGIN
  FOREACH table_key IN ARRAY ARRAY['foundation_namespace_contract','foundation_snapshot_metadata',
                                  'foundation_row_membership','foundation_event_descriptor'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',table_key);
  END LOOP;
  FOREACH table_key IN ARRAY ARRAY['foundation_request_summary','foundation_registration_candidate'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_run BEFORE INSERT OR UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.guard_run_child()',table_key);
  END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA p24_next FROM PUBLIC;
COMMIT;

