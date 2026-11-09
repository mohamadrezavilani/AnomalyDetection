-- Batch 2C: stable oldest-event scheduling for the bounded projection queue.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Batch 2C requires a disposable p24_design_* database';
  END IF;
END $$;
SET LOCAL search_path=p24_next,pg_catalog;

-- Every queued projection has a source-event cutoff. Materializing it makes
-- fairness explicit and indexable; the guarded payload remains immutable.
ALTER TABLE foundation_work_item
  ADD COLUMN event_cutoff_ns numeric GENERATED ALWAYS AS ((payload->>'event_cutoff_ns')::numeric) STORED;
ALTER TABLE foundation_work_item
  ADD CONSTRAINT foundation_work_projection_contract CHECK (
    jsonb_typeof(payload)='object'
    AND payload ? 'source_snapshot_ids'
    AND payload ? 'event_cutoff_ns'
    AND payload ? 'knowledge_at_ns'
    AND payload ? 'mode'
    AND payload->>'event_cutoff_ns' ~ '^-?[0-9]{1,30}$'
    AND payload->>'knowledge_at_ns' ~ '^-?[0-9]{1,30}$'
    AND payload->>'mode' IN ('online_original','historical_revised')
    AND jsonb_typeof(payload->'source_snapshot_ids')='array'
  );
CREATE INDEX foundation_work_oldest_cutoff
  ON foundation_work_item(namespace_id,event_cutoff_ns,available_at,created_at,work_id)
  WHERE state IN ('pending','retry','leased');

COMMIT;
