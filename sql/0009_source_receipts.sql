-- Batch 2H: source-bound safe manifests and append-only local receipt events.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2H requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

CREATE TABLE foundation_source_manifest (
  namespace_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  source_digest text NOT NULL,
  manifest_version text NOT NULL,
  source_kind text NOT NULL,
  manifest_sha256 text NOT NULL,
  producer_authority text NOT NULL DEFAULT 'unverified',
  source_window_complete boolean NOT NULL DEFAULT false,
  source_finality text NOT NULL DEFAULT 'not_established',
  safe_manifest jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,snapshot_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(source_digest ~ '^[a-f0-9]{64}$' AND manifest_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(source_kind IN ('scroll_capture','legacy_unassessed')),
  CHECK(producer_authority='unverified' AND source_window_complete=false AND source_finality='not_established'),
  CHECK(jsonb_typeof(safe_manifest)='object' AND octet_length(safe_manifest::text)<=8388608),
  CHECK(NOT (safe_manifest::text ~ '"(scroll_id|request_cursor|response_cursor)"[[:space:]]*:'))
);

CREATE FUNCTION check_foundation_source_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE digest text;
BEGIN
  SELECT source_digest INTO digest FROM p24_next.source_snapshot
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.snapshot_id;
  IF digest IS DISTINCT FROM NEW.source_digest THEN
    RAISE EXCEPTION 'Source manifest is bound to another source object';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER source_manifest_binding BEFORE INSERT ON foundation_source_manifest
  FOR EACH ROW EXECUTE FUNCTION check_foundation_source_manifest();
CREATE TRIGGER source_manifest_immutable BEFORE UPDATE OR DELETE ON foundation_source_manifest
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE INDEX foundation_source_manifest_digest ON foundation_source_manifest(namespace_id,manifest_sha256,snapshot_id);

CREATE TABLE foundation_source_receipt (
  namespace_id uuid NOT NULL,
  receipt_id uuid NOT NULL DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL,
  source_digest text NOT NULL,
  manifest_sha256 text NOT NULL,
  received_at timestamptz NOT NULL,
  receipt_time_basis text NOT NULL,
  disposition text NOT NULL,
  input_bytes bigint NOT NULL CHECK(input_bytes>=0),
  row_count bigint NOT NULL CHECK(row_count>=0),
  interval_start timestamptz NOT NULL,
  interval_end timestamptz NOT NULL,
  PRIMARY KEY(namespace_id,receipt_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(source_digest ~ '^[a-f0-9]{64}$' AND manifest_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(receipt_time_basis IN ('intake_clock','synthetic_fixture','producer_manifest_unverified')),
  CHECK(disposition IN ('accepted','reused_identical')),
  CHECK(interval_start<interval_end)
);
CREATE FUNCTION check_foundation_source_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE digest text; manifest_digest text;
BEGIN
  SELECT source_digest INTO digest FROM p24_next.source_snapshot
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.snapshot_id;
  SELECT manifest_sha256 INTO manifest_digest FROM p24_next.foundation_source_manifest
    WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.snapshot_id;
  IF digest IS DISTINCT FROM NEW.source_digest OR manifest_digest IS DISTINCT FROM NEW.manifest_sha256 THEN
    RAISE EXCEPTION 'Source receipt is bound to another source or manifest';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER source_receipt_binding BEFORE INSERT ON foundation_source_receipt
  FOR EACH ROW EXECUTE FUNCTION check_foundation_source_receipt();
CREATE TRIGGER source_receipt_immutable BEFORE UPDATE OR DELETE ON foundation_source_receipt
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE UNIQUE INDEX foundation_source_receipt_first_only
  ON foundation_source_receipt(namespace_id,snapshot_id) WHERE disposition='accepted';
CREATE INDEX foundation_source_receipt_asof
  ON foundation_source_receipt(namespace_id,snapshot_id,received_at,receipt_id);

REVOKE ALL ON foundation_source_manifest,foundation_source_receipt FROM PUBLIC;
COMMIT;
