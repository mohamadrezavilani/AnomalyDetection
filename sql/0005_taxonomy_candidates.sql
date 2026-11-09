-- Batch 2D: source-backed taxonomy candidates without inferred semantics.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2D requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;
ALTER TABLE service_mapping ALTER COLUMN exact_endpoint DROP NOT NULL;
CREATE TABLE catalog_code_entry (
  namespace_id uuid NOT NULL,
  taxonomy_id uuid NOT NULL,
  entry_id uuid NOT NULL,
  code_system text NOT NULL,
  code text NOT NULL,
  user_message_fa text,
  technical_symbol text,
  definition_state text NOT NULL,
  meaning_authority text NOT NULL,
  operation_binding_state text NOT NULL,
  document_id uuid NOT NULL,
  source_sheet text NOT NULL,
  source_row integer NOT NULL CHECK(source_row>0),
  source_cells jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY(namespace_id,taxonomy_id,entry_id),
  UNIQUE(namespace_id,taxonomy_id,code_system,code,document_id,source_sheet,source_row),
  FOREIGN KEY(namespace_id,taxonomy_id) REFERENCES taxonomy_release,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(definition_state IN ('complete_definition','partial_definition','code_only','reserved_marker')),
  CHECK(meaning_authority IN ('supplied_catalog_definition','no_definition_supplied')),
  CHECK(operation_binding_state='not_established_by_workbook'),
  CHECK(user_message_fa IS NULL OR octet_length(user_message_fa)<=4096),
  CHECK(technical_symbol IS NULL OR octet_length(technical_symbol)<=256),
  CHECK(octet_length(source_cells::text)<=8192)
);
CREATE INDEX catalog_code_lookup ON catalog_code_entry(namespace_id,taxonomy_id,code_system,code);
CREATE TRIGGER frozen_catalog_code_entry BEFORE INSERT OR UPDATE OR DELETE ON catalog_code_entry
  FOR EACH ROW EXECUTE FUNCTION guard_catalog_child();
REVOKE ALL ON catalog_code_entry FROM PUBLIC;
COMMIT;
