-- DESIGN PROPOSAL p24-domain.3. Not a production migration or updater.
-- The guard deliberately permits only disposable design databases.
BEGIN;
DO $$ BEGIN
  IF current_database() !~ '^p24_design_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'Design DDL refuses this database; use a disposable p24_design_* database';
  END IF;
END $$;
CREATE SCHEMA p24_next;
REVOKE ALL ON SCHEMA p24_next FROM PUBLIC;
SET LOCAL search_path = p24_next, pg_catalog;

CREATE TABLE namespace (
  namespace_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_key text NOT NULL UNIQUE, identity_contract_version text NOT NULL,
  CHECK (length(application_key)>0)
);
CREATE TABLE design_version (
  version_key text PRIMARY KEY, content_sha256 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (content_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE taxonomy_release (
  namespace_id uuid NOT NULL REFERENCES namespace, taxonomy_id uuid NOT NULL DEFAULT gen_random_uuid(),
  version_key text NOT NULL, state text NOT NULL DEFAULT 'draft',
  content_sha256 text NOT NULL, published_at timestamptz, reviewed_by text,
  PRIMARY KEY(namespace_id,taxonomy_id), UNIQUE(namespace_id,version_key),
  CHECK(state IN ('draft','reviewed','published','retired')),
  CHECK(state<>'published' OR (published_at IS NOT NULL AND reviewed_by IS NOT NULL))
);
CREATE TABLE documentation_source (
  namespace_id uuid NOT NULL REFERENCES namespace, document_id uuid NOT NULL DEFAULT gen_random_uuid(),
  title text NOT NULL, source_locator text NOT NULL, content_sha256 text NOT NULL,
  source_kind text NOT NULL, imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,document_id), UNIQUE(namespace_id,content_sha256),
  CHECK(source_kind IN ('official_document','postman_example','platform_contract','retained_log','operator_review','error_catalog'))
);
CREATE TABLE service_definition (
  namespace_id uuid NOT NULL, taxonomy_id uuid NOT NULL, service_key text NOT NULL,
  display_fa text NOT NULL, purpose text NOT NULL,
  initiation text NOT NULL DEFAULT 'unknown', security_tags text[] NOT NULL DEFAULT '{}',
  criticality text NOT NULL DEFAULT 'unknown', validation_state text NOT NULL DEFAULT 'unresolved',
  document_id uuid, document_anchor text, owner_key text,
  PRIMARY KEY(namespace_id,taxonomy_id,service_key),
  FOREIGN KEY(namespace_id,taxonomy_id) REFERENCES taxonomy_release,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(initiation IN ('customer','application','scheduled','context_dependent','unknown')),
  CHECK(criticality IN ('ordinary','important','critical','unknown')),
  CHECK(validation_state IN ('unresolved','candidate','reviewed','authoritative')),
  CHECK(validation_state<>'authoritative' OR document_id IS NOT NULL)
);
CREATE TABLE service_mapping (
  namespace_id uuid NOT NULL, taxonomy_id uuid NOT NULL, mapping_id uuid NOT NULL DEFAULT gen_random_uuid(),
  service_key text, source_role text NOT NULL, exact_endpoint text NOT NULL,
  method text, service_selector text, logged_action text, phase_key text NOT NULL DEFAULT 'unknown',
  match_contract jsonb NOT NULL DEFAULT '{}', status text NOT NULL DEFAULT 'unresolved',
  document_id uuid, rationale text NOT NULL,
  PRIMARY KEY(namespace_id,taxonomy_id,mapping_id),
  FOREIGN KEY(namespace_id,taxonomy_id) REFERENCES taxonomy_release,
  FOREIGN KEY(namespace_id,taxonomy_id,service_key) REFERENCES service_definition,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(source_role IN ('client_http','sql','internal','provider','cache','background','unknown')),
  CHECK(status IN ('unresolved','candidate','reviewed','authoritative')),
  CHECK(status<>'authoritative' OR (service_key IS NOT NULL AND document_id IS NOT NULL))
);
CREATE TABLE dependency_definition (
  namespace_id uuid NOT NULL, taxonomy_id uuid NOT NULL, dependency_id uuid NOT NULL DEFAULT gen_random_uuid(),
  service_key text NOT NULL, operation_endpoint text NOT NULL, source_role text NOT NULL,
  dependency_kind text NOT NULL, document_id uuid, validation_state text NOT NULL,
  PRIMARY KEY(namespace_id,taxonomy_id,dependency_id),
  FOREIGN KEY(namespace_id,taxonomy_id,service_key) REFERENCES service_definition,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(source_role IN ('sql','internal','provider','cache','background','unknown')),
  CHECK(validation_state IN ('candidate','reviewed','authoritative'))
);
CREATE TABLE field_semantics (
  namespace_id uuid NOT NULL, taxonomy_id uuid NOT NULL, field_contract_id uuid NOT NULL DEFAULT gen_random_uuid(),
  service_key text, operation_endpoint text NOT NULL, source_role text NOT NULL,
  direction text NOT NULL, field_path text NOT NULL, semantic_key text,
  required_in_contract boolean, sensitivity text NOT NULL DEFAULT 'restricted',
  normalization_version text, equality_domain text, document_id uuid,
  PRIMARY KEY(namespace_id,taxonomy_id,field_contract_id),
  UNIQUE(namespace_id,taxonomy_id,operation_endpoint,source_role,direction,field_path),
  FOREIGN KEY(namespace_id,taxonomy_id,service_key) REFERENCES service_definition,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(direction IN ('input','output','sql_parameter','metadata')),
  CHECK(sensitivity IN ('public','operational','personal','financial','secret','restricted'))
);
CREATE TABLE outcome_semantics (
  namespace_id uuid NOT NULL, taxonomy_id uuid NOT NULL, outcome_contract_id uuid NOT NULL DEFAULT gen_random_uuid(),
  operation_endpoint text NOT NULL, source_role text NOT NULL, phase_key text NOT NULL,
  code text NOT NULL, outcome_class text NOT NULL, failure_family text,
  meaning_fa text NOT NULL, document_id uuid, validation_state text NOT NULL,
  code_system text NOT NULL DEFAULT 'unspecified', code_layer text NOT NULL DEFAULT 'unknown',
  field_path text NOT NULL DEFAULT 'unknown', technical_symbol text, document_anchor text,
  PRIMARY KEY(namespace_id,taxonomy_id,outcome_contract_id),
  UNIQUE(namespace_id,taxonomy_id,operation_endpoint,source_role,phase_key,code_system,code_layer,field_path,code),
  FOREIGN KEY(namespace_id,taxonomy_id) REFERENCES taxonomy_release,
  FOREIGN KEY(namespace_id,document_id) REFERENCES documentation_source,
  CHECK(source_role IN ('client_http','sql','internal','provider','cache','background','unknown')),
  CHECK(outcome_class IN ('success','failure','unknown')),
  CHECK(validation_state IN ('unresolved','candidate','reviewed','authoritative')),
  CHECK(code_layer IN ('platform_log','client_body','sql_result','provider_http_envelope','provider_body','workflow_body','unknown')),
  CHECK(validation_state<>'authoritative' OR (document_id IS NOT NULL AND document_anchor IS NOT NULL
    AND code_system<>'unspecified' AND code_layer<>'unknown' AND field_path<>'unknown'))
);

CREATE TABLE source_window (
  namespace_id uuid NOT NULL REFERENCES namespace, window_key text NOT NULL,
  window_start timestamptz NOT NULL, window_end timestamptz NOT NULL,
  PRIMARY KEY(namespace_id,window_key), CHECK(window_end>window_start)
);
CREATE TABLE source_snapshot (
  namespace_id uuid NOT NULL, window_key text NOT NULL, snapshot_id uuid NOT NULL DEFAULT gen_random_uuid(),
  intake_revision bigint NOT NULL CHECK(intake_revision>0), source_digest text NOT NULL,
  producer_revision text, observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  source_complete boolean NOT NULL, raw_event_count bigint NOT NULL CHECK(raw_event_count>=0),
  ordering_status text NOT NULL DEFAULT 'unverified',
  PRIMARY KEY(namespace_id,snapshot_id), UNIQUE(namespace_id,window_key,snapshot_id),
  UNIQUE(namespace_id,window_key,intake_revision), UNIQUE(namespace_id,window_key,source_digest),
  FOREIGN KEY(namespace_id,window_key) REFERENCES source_window,
  CHECK(ordering_status IN ('authoritative','unverified','conflicting'))
);
CREATE TABLE source_head (
  namespace_id uuid NOT NULL, window_key text NOT NULL, snapshot_id uuid NOT NULL,
  generation bigint NOT NULL CHECK(generation>0), published_at timestamptz NOT NULL,
  PRIMARY KEY(namespace_id,window_key),
  FOREIGN KEY(namespace_id,window_key,snapshot_id) REFERENCES source_snapshot(namespace_id,window_key,snapshot_id)
);
CREATE TABLE raw_object (
  namespace_id uuid NOT NULL, object_id uuid NOT NULL DEFAULT gen_random_uuid(), snapshot_id uuid NOT NULL,
  storage_key text NOT NULL, content_sha256 text NOT NULL, format_key text NOT NULL,
  byte_count bigint NOT NULL CHECK(byte_count>=0), row_count bigint NOT NULL CHECK(row_count>=0),
  encryption_key_ref text, manifest_key text NOT NULL,
  PRIMARY KEY(namespace_id,object_id), UNIQUE(namespace_id,storage_key),
  UNIQUE(namespace_id,snapshot_id,object_id),
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(format_key IN ('parquet','json','json_gzip','record_manifest'))
);
CREATE TABLE evidence_availability (
  namespace_id uuid NOT NULL, object_id uuid NOT NULL, status text NOT NULL,
  checked_at timestamptz NOT NULL, reason_key text,
  PRIMARY KEY(namespace_id,object_id), FOREIGN KEY(namespace_id,object_id) REFERENCES raw_object,
  CHECK(status IN ('available','expired','unavailable','quarantined'))
);
CREATE TABLE user_session (
  namespace_id uuid NOT NULL REFERENCES namespace, session_key text NOT NULL,
  key_version text NOT NULL, lifecycle_state text NOT NULL DEFAULT 'observed',
  PRIMARY KEY(namespace_id,session_key),
  CHECK(lifecycle_state IN ('observed','login_observed','logout_observed','conflicting'))
);
CREATE TABLE logical_request (
  namespace_id uuid NOT NULL REFERENCES namespace, request_key text NOT NULL,
  key_version text NOT NULL, first_indexed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,request_key), CHECK(length(request_key)>0)
);
CREATE TABLE event_identity (
  namespace_id uuid NOT NULL REFERENCES namespace, event_key text NOT NULL,
  identity_kind text NOT NULL, identity_contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,event_key),
  CHECK(identity_kind IN ('origin_document','verified_span_event','fingerprint_ambiguous'))
);
CREATE TABLE event_version (
  namespace_id uuid NOT NULL, event_version_id uuid NOT NULL DEFAULT gen_random_uuid(), event_key text NOT NULL,
  content_sha256 text NOT NULL, source_event_time timestamptz, timestamp_precision text NOT NULL,
  request_key text, source_role text NOT NULL, endpoint text,
  event_kind text NOT NULL, traffic_context text NOT NULL DEFAULT 'unknown',
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  source_time_epoch_ns numeric(30,0), source_time_fraction_digits smallint,
  PRIMARY KEY(namespace_id,event_version_id), UNIQUE(namespace_id,event_key,event_version_id),
  UNIQUE(namespace_id,event_key,content_sha256),
  FOREIGN KEY(namespace_id,event_key) REFERENCES event_identity,
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  CHECK(source_role IN ('client_http','sql','internal','provider','cache','background','unknown')),
  CHECK(event_kind IN ('client_start','client_completion','operation_observation','external_notification','delivery_observation','diagnostic','unknown')),
  CHECK(traffic_context IN ('customer_application','partner_notification','background','integration_transport','unknown')),
  CHECK(timestamp_precision IN ('submicrosecond','microsecond','millisecond','second','unknown')),
  CHECK(source_time_fraction_digits BETWEEN 0 AND 9),
  CHECK(event_kind<>'client_completion' OR source_role='client_http')
);
-- Keep original timestamp text in the restricted raw source. source_event_time
-- is a microsecond FLOOR for PostgreSQL/UI compatibility; the exact integer
-- source_time_epoch_ns drives causal eligibility and fine-grained ordering.
CREATE FUNCTION guard_source_event_time() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE floor_ns numeric; digits smallint;
BEGIN
  IF NEW.source_event_time IS NULL THEN
    IF NEW.source_time_epoch_ns IS NOT NULL OR NEW.source_time_fraction_digits IS NOT NULL
      THEN RAISE EXCEPTION 'Exact source time needs its microsecond floor'; END IF;
    RETURN NEW;
  END IF;
  floor_ns:=extract(epoch FROM NEW.source_event_time)*1000000000;
  IF NEW.source_time_epoch_ns IS NULL THEN
    IF NEW.timestamp_precision='submicrosecond' OR NEW.source_time_fraction_digits>6
      THEN RAISE EXCEPTION 'Submicrosecond source time requires an exact integer nanosecond value'; END IF;
    NEW.source_time_epoch_ns:=floor_ns;
  END IF;
  IF NEW.source_time_epoch_ns<floor_ns OR NEW.source_time_epoch_ns>=floor_ns+1000
    THEN RAISE EXCEPTION 'source_event_time must be the floor, never a rounded source timestamp'; END IF;
  IF mod(NEW.source_time_epoch_ns,1000)<>0 AND NEW.timestamp_precision<>'submicrosecond'
    THEN RAISE EXCEPTION 'Submicrosecond digits require explicit precision'; END IF;
  digits:=NEW.source_time_fraction_digits;
  IF digits IS NULL THEN
    digits:=CASE NEW.timestamp_precision WHEN 'second' THEN 0 WHEN 'millisecond' THEN 3 WHEN 'microsecond' THEN 6 ELSE NULL END;
    NEW.source_time_fraction_digits:=digits;
  END IF;
  IF NEW.timestamp_precision='submicrosecond' AND (digits IS NULL OR digits<7 OR digits>9)
    THEN RAISE EXCEPTION 'Submicrosecond source precision needs seven to nine fractional digits'; END IF;
  IF digits>6 AND NEW.timestamp_precision<>'submicrosecond'
    THEN RAISE EXCEPTION 'Source precision conflicts with fractional digits'; END IF;
  IF digits IS NOT NULL AND mod(NEW.source_time_epoch_ns,power(10::numeric,9-digits))<>0
    THEN RAISE EXCEPTION 'Source time contains digits beyond its declared precision'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER precise_source_time BEFORE INSERT ON event_version FOR EACH ROW EXECUTE FUNCTION guard_source_event_time();
-- This indexes selected evidence-bearing events, not every raw log row.
-- The immutable raw manifest must cover ALL rows, including unindexed rows.
CREATE TABLE event_source (
  namespace_id uuid NOT NULL, snapshot_id uuid NOT NULL, event_version_id uuid NOT NULL,
  object_id uuid NOT NULL, row_group_no integer NOT NULL CHECK(row_group_no>=0),
  row_ordinal bigint NOT NULL CHECK(row_ordinal>=0),
  PRIMARY KEY(namespace_id,snapshot_id,event_version_id),
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version,
  FOREIGN KEY(namespace_id,snapshot_id,object_id) REFERENCES raw_object(namespace_id,snapshot_id,object_id)
);
CREATE TABLE request_source (
  namespace_id uuid NOT NULL, request_key text NOT NULL, snapshot_id uuid NOT NULL,
  raw_record_count bigint NOT NULL CHECK(raw_record_count>0), indexed_event_count bigint NOT NULL CHECK(indexed_event_count>=0),
  PRIMARY KEY(namespace_id,request_key,snapshot_id),
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot,
  CHECK(indexed_event_count<=raw_record_count)
);
CREATE TABLE session_user_link (
  namespace_id uuid NOT NULL, link_id uuid NOT NULL DEFAULT gen_random_uuid(), session_key text NOT NULL,
  user_equality_token text NOT NULL, token_key_version text NOT NULL,
  evidence_event_version_id uuid NOT NULL, contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,link_id),
  FOREIGN KEY(namespace_id,session_key) REFERENCES user_session,
  FOREIGN KEY(namespace_id,evidence_event_version_id) REFERENCES event_version
);
CREATE TABLE operation_identity (
  namespace_id uuid NOT NULL, request_key text NOT NULL, operation_key text NOT NULL,
  identity_basis text NOT NULL,
  PRIMARY KEY(namespace_id,operation_key), UNIQUE(namespace_id,request_key,operation_key),
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  CHECK(identity_basis IN ('verified_span','execution_record','unresolved_observation'))
);
CREATE TABLE operation_event (
  namespace_id uuid NOT NULL, operation_key text NOT NULL, event_version_id uuid NOT NULL,
  link_basis text NOT NULL,
  PRIMARY KEY(namespace_id,operation_key,event_version_id),
  FOREIGN KEY(namespace_id,operation_key) REFERENCES operation_identity,
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version
);
CREATE TABLE extracted_fact (
  namespace_id uuid NOT NULL, fact_id uuid NOT NULL DEFAULT gen_random_uuid(),
  event_version_id uuid NOT NULL, request_key text NOT NULL, operation_key text,
  fact_key text NOT NULL, field_path text NOT NULL, direction text NOT NULL,
  sensitivity text NOT NULL DEFAULT 'restricted', public_value jsonb,
  equality_token text, token_key_version text, extraction_version text NOT NULL,
  completeness text NOT NULL,
  PRIMARY KEY(namespace_id,fact_id),
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version,
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  FOREIGN KEY(namespace_id,request_key,operation_key) REFERENCES operation_identity(namespace_id,request_key,operation_key),
  CHECK(direction IN ('input','output','sql_parameter','metadata')),
  CHECK(sensitivity IN ('public','operational','personal','financial','secret','restricted')),
  CHECK(sensitivity NOT IN ('personal','financial','secret','restricted') OR public_value IS NULL),
  CHECK(sensitivity NOT IN ('secret','restricted') OR equality_token IS NULL),
  CHECK(equality_token IS NULL OR token_key_version IS NOT NULL),
  CHECK(public_value IS NULL OR octet_length(public_value::text)<=4096),
  CHECK(completeness IN ('complete','truncated','parse_error','unlogged','unknown'))
);

CREATE TABLE projection_run (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL DEFAULT gen_random_uuid(),
  mode text NOT NULL, event_cutoff timestamptz NOT NULL, knowledge_snapshot_at timestamptz NOT NULL,
  taxonomy_id uuid NOT NULL, resolver_version text NOT NULL, privacy_version text NOT NULL,
  input_manifest_sha256 text NOT NULL, state text NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,run_id),
  FOREIGN KEY(namespace_id,taxonomy_id) REFERENCES taxonomy_release,
  CHECK(mode IN ('online_original','historical_revised','design_fixture')),
  CHECK(state IN ('draft','sealed','failed'))
);
CREATE TABLE projection_source (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, snapshot_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,run_id,snapshot_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,snapshot_id) REFERENCES source_snapshot
);
CREATE TABLE projection_event (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, event_key text NOT NULL,
  event_version_id uuid, selection_state text NOT NULL, selection_reason text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,event_key), UNIQUE(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,event_key,event_version_id) REFERENCES event_version(namespace_id,event_key,event_version_id),
  CHECK(selection_state IN ('selected','ambiguous','unavailable')),
  CHECK((selection_state='selected')=(event_version_id IS NOT NULL))
);
CREATE TABLE request_projection (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  session_key text, identity_state text NOT NULL, activity_time timestamptz,
  client_event_version_id uuid, client_completion_state text NOT NULL,
  service_key text, initiation text NOT NULL, phase_key text NOT NULL,
  classification_state text NOT NULL, presence_state text NOT NULL DEFAULT 'present',
  final_outcome text NOT NULL, outcome_code text,
  first_observed_event_at timestamptz, last_observed_event_at timestamptz,
  PRIMARY KEY(namespace_id,run_id,request_key),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,request_key) REFERENCES logical_request,
  FOREIGN KEY(namespace_id,session_key) REFERENCES user_session,
  FOREIGN KEY(namespace_id,client_event_version_id) REFERENCES event_version,
  CHECK(identity_state IN ('known','missing','conflicting')),
  CHECK((identity_state='known')=(session_key IS NOT NULL)),
  CHECK(client_completion_state IN ('observed','not_observed','conflicting')),
  CHECK((client_completion_state='observed')=(client_event_version_id IS NOT NULL)),
  CHECK(initiation IN ('customer','application','scheduled','context_dependent','unknown')),
  CHECK(classification_state IN ('authoritative','reviewed','candidate','unknown','conflicting')),
  CHECK(presence_state IN ('present','retired')),
  CHECK(final_outcome IN ('success','failure','unknown','conflicting')),
  CHECK(last_observed_event_at IS NULL OR first_observed_event_at<=last_observed_event_at)
);
CREATE INDEX request_projection_session_time ON request_projection(namespace_id,run_id,session_key,activity_time,request_key);
-- Bounded reconciliation runs publish changed heads; they do not rewrite all
-- historical request projections every five minutes. Old head sets are kept
-- in the immutable publication manifest for historical reconstruction.
CREATE TABLE serving_publication (
  namespace_id uuid NOT NULL REFERENCES namespace, publication_id uuid NOT NULL DEFAULT gen_random_uuid(),
  generation bigint NOT NULL CHECK(generation>0), source_heads_sha256 text NOT NULL,
  request_heads_manifest_key text NOT NULL, request_heads_sha256 text NOT NULL,
  published_at timestamptz NOT NULL, coverage_manifest_key text NOT NULL,
  PRIMARY KEY(namespace_id,publication_id), UNIQUE(namespace_id,generation)
);
CREATE TABLE serving_request_head (
  namespace_id uuid NOT NULL, request_key text NOT NULL, run_id uuid NOT NULL, publication_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,request_key),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,publication_id) REFERENCES serving_publication
);
CREATE TABLE current_serving_publication (
  namespace_id uuid PRIMARY KEY REFERENCES namespace, publication_id uuid NOT NULL,
  FOREIGN KEY(namespace_id,publication_id) REFERENCES serving_publication
);
CREATE TABLE projection_fact (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL, fact_id uuid NOT NULL,
  use_kind text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,request_key,fact_id,use_kind),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,fact_id) REFERENCES extracted_fact
);
CREATE TABLE operation_projection (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL, operation_key text NOT NULL,
  source_role text NOT NULL, endpoint text NOT NULL, outcome text NOT NULL,
  chain_coverage text NOT NULL, parent_operation_key text, parent_link_basis text,
  PRIMARY KEY(namespace_id,run_id,operation_key),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,request_key,operation_key) REFERENCES operation_identity(namespace_id,request_key,operation_key),
  FOREIGN KEY(namespace_id,run_id,parent_operation_key) REFERENCES operation_projection(namespace_id,run_id,operation_key) DEFERRABLE INITIALLY DEFERRED,
  CHECK(outcome IN ('success','failure','unknown','conflicting')),
  CHECK(source_role IN ('client_http','sql','internal','provider','cache','background','unknown')),
  CHECK(chain_coverage IN ('observed_only','partial','contract_complete','unknown')),
  CHECK(parent_operation_key IS NULL OR parent_link_basis='verified_parent_span')
);
CREATE TABLE business_workflow (
  namespace_id uuid NOT NULL REFERENCES namespace, workflow_key text NOT NULL,
  equality_domain text NOT NULL, token_key_version text NOT NULL, identity_contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,workflow_key)
);
CREATE TABLE workflow_request (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, workflow_key text NOT NULL, request_key text NOT NULL,
  phase_key text NOT NULL, evidence_fact_id uuid NOT NULL, link_basis text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,workflow_key,request_key,phase_key),
  FOREIGN KEY(namespace_id,workflow_key) REFERENCES business_workflow,
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,evidence_fact_id) REFERENCES extracted_fact,
  CHECK(link_basis='verified_documented_identifier')
);
CREATE TABLE feature_definition (
  feature_version text PRIMARY KEY, feature_key text NOT NULL, observation_unit text NOT NULL,
  value_unit text NOT NULL, causal_contract jsonb NOT NULL, eligibility_contract jsonb NOT NULL,
  exposure_definition text NOT NULL, source_role_contract text NOT NULL
);
CREATE TABLE feature_observation (
  namespace_id uuid NOT NULL, observation_id uuid NOT NULL DEFAULT gen_random_uuid(), run_id uuid NOT NULL,
  feature_version text NOT NULL REFERENCES feature_definition,
  subject_kind text NOT NULL, subject_key text NOT NULL,
  interval_start timestamptz NOT NULL, interval_end timestamptz NOT NULL,
  value_numeric numeric, exposure_numeric numeric, support_state text NOT NULL,
  evidence_manifest_sha256 text NOT NULL,
  PRIMARY KEY(namespace_id,observation_id),
  UNIQUE(namespace_id,run_id,feature_version,subject_kind,subject_key,interval_start,interval_end),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  CHECK(interval_end>interval_start), CHECK(exposure_numeric IS NULL OR exposure_numeric>=0),
  CHECK(support_state IN ('supported','partial','unsupported','not_applicable'))
);
CREATE TABLE reference_publication (
  namespace_id uuid NOT NULL, reference_id uuid NOT NULL DEFAULT gen_random_uuid(),
  model_version text NOT NULL, feature_contract_version text NOT NULL,
  trained_before timestamptz NOT NULL, max_training_event_at timestamptz,
  max_training_interval_end timestamptz, source_manifest_sha256 text NOT NULL,
  artifact_key text NOT NULL, calibration_contract jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,reference_id),
  CHECK(max_training_event_at IS NULL OR max_training_event_at<trained_before),
  CHECK(max_training_interval_end IS NULL OR max_training_interval_end<=trained_before)
);
CREATE TABLE reference_input (
  namespace_id uuid NOT NULL, reference_id uuid NOT NULL, observation_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,reference_id,observation_id),
  FOREIGN KEY(namespace_id,reference_id) REFERENCES reference_publication,
  FOREIGN KEY(namespace_id,observation_id) REFERENCES feature_observation
);
CREATE TABLE detector_run (
  namespace_id uuid NOT NULL, detector_run_id uuid NOT NULL DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL, detector_key text NOT NULL, detector_version text NOT NULL,
  reference_id uuid, target_start timestamptz NOT NULL, target_end timestamptz NOT NULL,
  status text NOT NULL, applicable_units bigint NOT NULL, evaluated_units bigint NOT NULL,
  unsupported_units bigint NOT NULL, reason_counts jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY(namespace_id,detector_run_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,reference_id) REFERENCES reference_publication,
  CHECK(target_end>target_start),
  CHECK(status IN ('complete','partial','insufficient_history','not_applicable','waiting','failed')),
  CHECK(applicable_units>=0 AND evaluated_units>=0 AND unsupported_units>=0),
  CHECK(evaluated_units+unsupported_units<=applicable_units)
);
CREATE TABLE finding (
  namespace_id uuid NOT NULL, finding_id uuid NOT NULL DEFAULT gen_random_uuid(),
  detector_run_id uuid NOT NULL, finding_key text NOT NULL, scope_kind text NOT NULL,
  subject_key text NOT NULL, score_numeric numeric, score_unit text NOT NULL,
  evidence_manifest_sha256 text NOT NULL, measurements jsonb NOT NULL,
  supersedes_finding_id uuid, assessment_state text NOT NULL,
  PRIMARY KEY(namespace_id,finding_id), UNIQUE(namespace_id,detector_run_id,finding_key),
  FOREIGN KEY(namespace_id,detector_run_id) REFERENCES detector_run,
  FOREIGN KEY(namespace_id,supersedes_finding_id) REFERENCES finding,
  CHECK(scope_kind IN ('session','user','service','entity','network','data_quality','observability')),
  CHECK(assessment_state IN ('observation','supported_deviation','invalidated'))
);
CREATE TABLE finding_request (
  namespace_id uuid NOT NULL, finding_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  role_key text NOT NULL, proof jsonb NOT NULL,
  PRIMARY KEY(namespace_id,finding_id,request_key,role_key),
  FOREIGN KEY(namespace_id,finding_id) REFERENCES finding,
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection
);
CREATE TABLE incident (
  namespace_id uuid NOT NULL, incident_id uuid NOT NULL DEFAULT gen_random_uuid(), issue_identity text NOT NULL,
  scope_kind text NOT NULL, subject_key text NOT NULL, failure_family text,
  status text NOT NULL DEFAULT 'open', created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,incident_id), UNIQUE(namespace_id,issue_identity),
  CHECK(status IN ('open','monitoring','resolved','reviewed','legacy'))
);
CREATE TABLE incident_finding (
  namespace_id uuid NOT NULL, incident_id uuid NOT NULL, finding_id uuid NOT NULL,
  link_reason text NOT NULL, PRIMARY KEY(namespace_id,incident_id,finding_id),
  FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
  FOREIGN KEY(namespace_id,finding_id) REFERENCES finding
);
CREATE TABLE occurrence (
  namespace_id uuid NOT NULL, occurrence_id uuid NOT NULL DEFAULT gen_random_uuid(), incident_id uuid NOT NULL,
  first_event_at timestamptz NOT NULL, last_event_at timestamptz NOT NULL,
  clustering_policy_version text NOT NULL, evidence_manifest_sha256 text NOT NULL,
  PRIMARY KEY(namespace_id,occurrence_id), FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
  CHECK(last_event_at>=first_event_at)
);
CREATE TABLE investigation (
  namespace_id uuid NOT NULL, investigation_id uuid NOT NULL DEFAULT gen_random_uuid(), title_fa text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), status text NOT NULL,
  PRIMARY KEY(namespace_id,investigation_id), CHECK(status IN ('open','monitoring','closed'))
);
CREATE TABLE investigation_link (
  namespace_id uuid NOT NULL, investigation_id uuid NOT NULL, incident_id uuid NOT NULL,
  basis_key text NOT NULL, proof_manifest_sha256 text NOT NULL,
  PRIMARY KEY(namespace_id,investigation_id,incident_id),
  FOREIGN KEY(namespace_id,investigation_id) REFERENCES investigation,
  FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
  CHECK(basis_key IN ('shared_request','verified_dependency_failure','verified_workflow','operator_link'))
);
CREATE TABLE priority_decision (
  namespace_id uuid NOT NULL, decision_id uuid NOT NULL DEFAULT gen_random_uuid(), incident_id uuid NOT NULL,
  priority text NOT NULL, policy_version text NOT NULL, impact_factors jsonb NOT NULL,
  evidence_manifest_sha256 text NOT NULL, actor_key text NOT NULL, reason_fa text NOT NULL,
  supersedes_decision_id uuid, decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,decision_id), FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
  FOREIGN KEY(namespace_id,supersedes_decision_id) REFERENCES priority_decision,
  CHECK(priority IN ('unrated','low','medium','high','critical'))
);
CREATE TABLE operator_decision (
  namespace_id uuid NOT NULL, decision_id uuid NOT NULL DEFAULT gen_random_uuid(), incident_id uuid,
  subject_kind text NOT NULL, subject_key text NOT NULL, pattern_key text NOT NULL,
  verdict text NOT NULL, scope_contract jsonb NOT NULL, reason text NOT NULL, actor_key text NOT NULL,
  taxonomy_compatibility text NOT NULL, effective_from timestamptz NOT NULL, expires_at timestamptz,
  supersedes_decision_id uuid, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,decision_id), FOREIGN KEY(namespace_id,incident_id) REFERENCES incident,
  FOREIGN KEY(namespace_id,supersedes_decision_id) REFERENCES operator_decision,
  CHECK(verdict IN ('confirmed','benign','false_positive','undo')),
  CHECK(expires_at IS NULL OR expires_at>effective_from)
);
CREATE TABLE report_snapshot (
  namespace_id uuid NOT NULL, report_id uuid NOT NULL DEFAULT gen_random_uuid(), incident_id uuid NOT NULL,
  evidence_manifest_sha256 text NOT NULL, privacy_version text NOT NULL, prompt_version text NOT NULL,
  content_fa text NOT NULL, generated_at timestamptz NOT NULL, ai_provider text,
  paid_usage jsonb NOT NULL DEFAULT '{}', coverage jsonb NOT NULL,
  PRIMARY KEY(namespace_id,report_id), FOREIGN KEY(namespace_id,incident_id) REFERENCES incident
);
CREATE TABLE report_claim (
  namespace_id uuid NOT NULL, report_id uuid NOT NULL, claim_key text NOT NULL,
  claim_kind text NOT NULL, text_fa text NOT NULL, fact_manifest_sha256 text NOT NULL,
  verification_state text NOT NULL,
  PRIMARY KEY(namespace_id,report_id,claim_key), FOREIGN KEY(namespace_id,report_id) REFERENCES report_snapshot,
  CHECK(claim_kind IN ('observed_fact','analysis','hypothesis','action')),
  CHECK(verification_state IN ('verified','qualified','rejected'))
);

CREATE TABLE preservation_hold (
  namespace_id uuid NOT NULL REFERENCES namespace, hold_id uuid NOT NULL DEFAULT gen_random_uuid(),
  scope_manifest_key text NOT NULL, reason text NOT NULL, created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), release_after timestamptz,
  PRIMARY KEY(namespace_id,hold_id)
);
CREATE TABLE retention_policy (
  namespace_id uuid NOT NULL REFERENCES namespace, policy_version text NOT NULL,
  data_class text NOT NULL, proposed_days integer, approved_at timestamptz, approved_by text,
  state text NOT NULL DEFAULT 'draft', PRIMARY KEY(namespace_id,policy_version,data_class),
  CHECK(proposed_days IS NULL OR proposed_days>0), CHECK(state IN ('draft','approved','retired')),
  CHECK(state<>'approved' OR (proposed_days IS NOT NULL AND approved_at IS NOT NULL AND approved_by IS NOT NULL))
);
CREATE TABLE retention_disposition (
  namespace_id uuid NOT NULL, disposition_id uuid NOT NULL DEFAULT gen_random_uuid(), object_id uuid NOT NULL,
  policy_version text NOT NULL, data_class text NOT NULL, dry_run boolean NOT NULL,
  state text NOT NULL, hold_check_manifest_sha256 text NOT NULL, actor_key text NOT NULL,
  PRIMARY KEY(namespace_id,disposition_id), FOREIGN KEY(namespace_id,object_id) REFERENCES raw_object,
  FOREIGN KEY(namespace_id,policy_version,data_class) REFERENCES retention_policy,
  CHECK(state IN ('proposed','held','approved','executed','failed'))
);
CREATE TABLE access_audit (
  namespace_id uuid NOT NULL REFERENCES namespace, audit_id uuid NOT NULL DEFAULT gen_random_uuid(),
  actor_key text NOT NULL, role_key text NOT NULL, action_key text NOT NULL,
  resource_kind text NOT NULL, resource_key text NOT NULL, purpose_key text NOT NULL,
  result text NOT NULL, policy_version text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,audit_id), CHECK(result IN ('allowed','denied','failed'))
);
CREATE TABLE sensitive_access_grant (
  namespace_id uuid NOT NULL REFERENCES namespace, grant_id uuid NOT NULL DEFAULT gen_random_uuid(),
  actor_key text NOT NULL, resource_manifest_key text NOT NULL, purpose_key text NOT NULL,
  approved_by text NOT NULL, expires_at timestamptz NOT NULL, granted_at timestamptz NOT NULL,
  PRIMARY KEY(namespace_id,grant_id), CHECK(expires_at>granted_at)
);
CREATE TABLE work_item (
  namespace_id uuid NOT NULL REFERENCES namespace, work_id uuid NOT NULL DEFAULT gen_random_uuid(),
  work_kind text NOT NULL, dedupe_key text NOT NULL, desired_generation bigint NOT NULL CHECK(desired_generation>0),
  acknowledged_generation bigint NOT NULL DEFAULT 0 CHECK(acknowledged_generation>=0),
  status text NOT NULL, lease_owner text, lease_until timestamptz, lease_token uuid,
  leased_generation bigint, retry_after timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), payload_manifest_key text NOT NULL,
  PRIMARY KEY(namespace_id,work_id), UNIQUE(namespace_id,work_kind,dedupe_key),
  CHECK(acknowledged_generation<=desired_generation),
  CHECK(status IN ('pending','leased','retry','complete','failed')),
  CHECK(status<>'complete' OR acknowledged_generation=desired_generation),
  CHECK(status<>'leased' OR (lease_owner IS NOT NULL AND lease_until IS NOT NULL
    AND lease_token IS NOT NULL AND leased_generation IS NOT NULL AND leased_generation<=desired_generation))
);
CREATE INDEX work_item_due ON work_item(namespace_id,status,retry_after,lease_until);
CREATE TABLE migration_ledger (
  migration_key text PRIMARY KEY, schema_checksum text NOT NULL, source_release text NOT NULL,
  state text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  validation_manifest_key text NOT NULL, CHECK(state IN ('design_test','shadow','approved_cutover','rolled_back'))
);
CREATE TABLE legacy_crosswalk (
  namespace_id uuid NOT NULL REFERENCES namespace, source_release text NOT NULL,
  legacy_table text NOT NULL, legacy_key text NOT NULL, target_kind text NOT NULL, target_key text,
  disposition text NOT NULL, original_manifest_key text NOT NULL, reason text NOT NULL,
  PRIMARY KEY(namespace_id,source_release,legacy_table,legacy_key,target_kind),
  CHECK(disposition IN ('preserved','mapped','regenerated','needs_review'))
);

CREATE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Immutable evidence/decision row: append a new revision'; END $$;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['source_snapshot','raw_object','event_version','event_source','request_source',
    'extracted_fact','operation_event','session_user_link','serving_publication','reference_publication','reference_input','finding',
    'finding_request','priority_decision','operator_decision','report_snapshot','report_claim','access_audit'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',t);
  END LOOP;
END $$;

CREATE FUNCTION guard_run_child() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n uuid; r uuid; s text;
BEGIN
  IF TG_OP='UPDATE' AND (OLD.namespace_id,OLD.run_id) IS DISTINCT FROM (NEW.namespace_id,NEW.run_id)
    THEN RAISE EXCEPTION 'Projection rows cannot move between runs'; END IF;
  IF TG_OP='DELETE' THEN n:=OLD.namespace_id; r:=OLD.run_id;
  ELSE n:=NEW.namespace_id; r:=NEW.run_id; END IF;
  SELECT state INTO s FROM p24_next.projection_run WHERE namespace_id=n AND run_id=r FOR SHARE;
  IF s IS DISTINCT FROM 'draft' THEN RAISE EXCEPTION 'Projection input/output is frozen or absent'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['projection_source','projection_event','request_projection','projection_fact','operation_projection','workflow_request','feature_observation'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_run BEFORE INSERT OR UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.guard_run_child()',t);
  END LOOP;
END $$;
CREATE FUNCTION guard_run_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state<>'draft' THEN RAISE EXCEPTION 'A sealed/failed run is immutable'; END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
    THEN RAISE EXCEPTION 'Run definition is immutable; create a different run'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER frozen_run BEFORE UPDATE OR DELETE ON projection_run FOR EACH ROW EXECUTE FUNCTION guard_run_row();

CREATE FUNCTION guard_selected_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE at_time timestamptz; at_ns numeric; cutoff_time timestamptz; known_at timestamptz; mode_key text; received timestamptz;
BEGIN
  IF NEW.event_version_id IS NULL THEN RETURN NEW; END IF;
  SELECT source_event_time,source_time_epoch_ns,received_at INTO at_time,at_ns,received FROM p24_next.event_version
    WHERE namespace_id=NEW.namespace_id AND event_version_id=NEW.event_version_id;
  SELECT event_cutoff,knowledge_snapshot_at,mode INTO cutoff_time,known_at,mode_key FROM p24_next.projection_run
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  IF at_time IS NULL OR at_ns IS NULL OR at_ns>=extract(epoch FROM cutoff_time)*1000000000
    THEN RAISE EXCEPTION 'Event is not eligible before this cutoff'; END IF;
  IF mode_key='online_original' AND received>known_at THEN RAISE EXCEPTION 'Evidence was not known to the original online run'; END IF;
  IF NOT EXISTS(SELECT 1 FROM p24_next.event_source es JOIN p24_next.projection_source ps
      ON ps.namespace_id=es.namespace_id AND ps.snapshot_id=es.snapshot_id
      WHERE ps.namespace_id=NEW.namespace_id AND ps.run_id=NEW.run_id AND es.event_version_id=NEW.event_version_id)
    THEN RAISE EXCEPTION 'Event has no source support in this frozen input set'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER selected_event BEFORE INSERT OR UPDATE ON projection_event FOR EACH ROW EXECUTE FUNCTION guard_selected_event();

CREATE FUNCTION guard_projected_fact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.extracted_fact f JOIN p24_next.projection_event pe
    ON pe.namespace_id=f.namespace_id AND pe.event_version_id=f.event_version_id AND pe.selection_state='selected'
    WHERE f.namespace_id=NEW.namespace_id AND f.fact_id=NEW.fact_id AND f.request_key=NEW.request_key AND pe.run_id=NEW.run_id)
  THEN RAISE EXCEPTION 'Projected fact is not supported by eligible selected evidence for this request'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER projected_fact BEFORE INSERT OR UPDATE ON projection_fact FOR EACH ROW EXECUTE FUNCTION guard_projected_fact();

CREATE FUNCTION guard_workflow_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.projection_fact pf WHERE pf.namespace_id=NEW.namespace_id
      AND pf.run_id=NEW.run_id AND pf.request_key=NEW.request_key AND pf.fact_id=NEW.evidence_fact_id
      AND pf.use_kind='workflow_identifier')
    THEN RAISE EXCEPTION 'Workflow link lacks an eligible projected identifier fact'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_evidence BEFORE INSERT OR UPDATE ON workflow_request FOR EACH ROW EXECUTE FUNCTION guard_workflow_evidence();

CREATE FUNCTION guard_client_completion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.client_event_version_id IS NOT NULL AND NOT EXISTS(
    SELECT 1 FROM p24_next.event_version ev JOIN p24_next.projection_event pe
      ON pe.namespace_id=ev.namespace_id AND pe.event_version_id=ev.event_version_id
    WHERE ev.namespace_id=NEW.namespace_id AND pe.run_id=NEW.run_id AND ev.request_key=NEW.request_key
      AND ev.event_version_id=NEW.client_event_version_id AND ev.source_role='client_http'
      AND ev.event_kind='client_completion' AND pe.selection_state='selected')
  THEN RAISE EXCEPTION 'Only selected client completion evidence can complete a client request'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER client_completion BEFORE INSERT OR UPDATE ON request_projection FOR EACH ROW EXECUTE FUNCTION guard_client_completion();

CREATE FUNCTION guard_fact_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.event_version WHERE namespace_id=NEW.namespace_id
    AND event_version_id=NEW.event_version_id AND request_key=NEW.request_key)
  THEN RAISE EXCEPTION 'Fact RequestID differs from its source event'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fact_request BEFORE INSERT ON extracted_fact FOR EACH ROW EXECUTE FUNCTION guard_fact_request();
CREATE FUNCTION guard_operation_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.event_version ev JOIN p24_next.operation_identity op
    ON op.namespace_id=ev.namespace_id AND op.request_key=ev.request_key
    WHERE ev.namespace_id=NEW.namespace_id AND ev.event_version_id=NEW.event_version_id AND op.operation_key=NEW.operation_key)
  THEN RAISE EXCEPTION 'Operation and event belong to different requests'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operation_request BEFORE INSERT OR UPDATE ON operation_event FOR EACH ROW EXECUTE FUNCTION guard_operation_request();
CREATE FUNCTION guard_source_head() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rev bigint; old_rev bigint; complete boolean; ordering text;
BEGIN
  SELECT intake_revision,source_complete,ordering_status INTO rev,complete,ordering
    FROM p24_next.source_snapshot WHERE namespace_id=NEW.namespace_id AND snapshot_id=NEW.snapshot_id;
  IF NOT complete OR ordering<>'authoritative' THEN RAISE EXCEPTION 'Only ordered complete snapshots can become current'; END IF;
  IF TG_OP='UPDATE' THEN
    IF (OLD.namespace_id,OLD.window_key) IS DISTINCT FROM (NEW.namespace_id,NEW.window_key)
      THEN RAISE EXCEPTION 'Source heads cannot move between windows'; END IF;
    SELECT intake_revision INTO old_rev FROM p24_next.source_snapshot
      WHERE namespace_id=OLD.namespace_id AND snapshot_id=OLD.snapshot_id;
    IF rev<=old_rev OR NEW.generation<>OLD.generation+1 THEN RAISE EXCEPTION 'Head must advance with a new generation'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER source_head_guard BEFORE INSERT OR UPDATE ON source_head FOR EACH ROW EXECUTE FUNCTION guard_source_head();

CREATE FUNCTION guard_original_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM p24_next.projection_run r JOIN p24_next.source_snapshot s
    ON s.namespace_id=r.namespace_id WHERE r.namespace_id=NEW.namespace_id AND r.run_id=NEW.run_id
      AND s.snapshot_id=NEW.snapshot_id AND r.mode='online_original' AND s.observed_at>r.knowledge_snapshot_at)
    THEN RAISE EXCEPTION 'Snapshot was not known to the original online run'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER original_source BEFORE INSERT OR UPDATE ON projection_source FOR EACH ROW EXECUTE FUNCTION guard_original_source();

CREATE FUNCTION guard_catalog_child() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n uuid; r uuid; s text;
BEGIN
  IF TG_OP='UPDATE' AND (OLD.namespace_id,OLD.taxonomy_id) IS DISTINCT FROM (NEW.namespace_id,NEW.taxonomy_id)
    THEN RAISE EXCEPTION 'Catalog rows cannot move between releases'; END IF;
  IF TG_OP='DELETE' THEN n:=OLD.namespace_id; r:=OLD.taxonomy_id;
  ELSE n:=NEW.namespace_id; r:=NEW.taxonomy_id; END IF;
  SELECT state INTO s FROM p24_next.taxonomy_release WHERE namespace_id=n AND taxonomy_id=r FOR SHARE;
  IF s IS DISTINCT FROM 'draft' THEN RAISE EXCEPTION 'Catalog version is frozen'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;

CREATE FUNCTION guard_catalog_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state<>'draft' THEN RAISE EXCEPTION 'Reviewed catalog releases are immutable; append another version'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER frozen_catalog_release BEFORE UPDATE OR DELETE ON taxonomy_release FOR EACH ROW EXECUTE FUNCTION guard_catalog_release();
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['service_definition','service_mapping','dependency_definition','field_semantics','outcome_semantics'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_catalog BEFORE INSERT OR UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.guard_catalog_child()',t);
  END LOOP;
END $$;

CREATE FUNCTION guard_reference_input() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b timestamptz; e timestamptz;
BEGIN
  SELECT trained_before INTO b FROM p24_next.reference_publication WHERE namespace_id=NEW.namespace_id AND reference_id=NEW.reference_id;
  SELECT interval_end INTO e FROM p24_next.feature_observation WHERE namespace_id=NEW.namespace_id AND observation_id=NEW.observation_id;
  IF e>b THEN RAISE EXCEPTION 'Reference includes a future observation interval'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER causal_reference_input BEFORE INSERT ON reference_input FOR EACH ROW EXECUTE FUNCTION guard_reference_input();
CREATE FUNCTION guard_detector_reference() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b timestamptz;
BEGIN
  IF NEW.reference_id IS NOT NULL THEN
    SELECT trained_before INTO b FROM p24_next.reference_publication WHERE namespace_id=NEW.namespace_id AND reference_id=NEW.reference_id;
    IF b>NEW.target_start THEN RAISE EXCEPTION 'Detector reference is from the future'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER causal_detector_reference BEFORE INSERT OR UPDATE ON detector_run FOR EACH ROW EXECUTE FUNCTION guard_detector_reference();

CREATE FUNCTION guard_finding_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.finding f JOIN p24_next.detector_run d
    ON d.namespace_id=f.namespace_id AND d.detector_run_id=f.detector_run_id
    WHERE f.namespace_id=NEW.namespace_id AND f.finding_id=NEW.finding_id AND d.run_id=NEW.run_id)
    THEN RAISE EXCEPTION 'Finding evidence differs from its detector projection run'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER finding_request_run BEFORE INSERT ON finding_request FOR EACH ROW EXECUTE FUNCTION guard_finding_request();

-- Phase 1 extension: source-event facts and asynchronous workflow evidence.
-- These rows keep partner callbacks, delivery acknowledgements and per-subject
-- outcomes distinct from customer RequestIDs and workflow completion.
CREATE TABLE source_event_fact (
  namespace_id uuid NOT NULL, fact_id uuid NOT NULL DEFAULT gen_random_uuid(),
  event_version_id uuid NOT NULL, fact_key text NOT NULL, field_path text NOT NULL,
  direction text NOT NULL, sensitivity text NOT NULL DEFAULT 'restricted',
  public_value jsonb, equality_token text, token_key_version text,
  extraction_version text NOT NULL, completeness text NOT NULL,
  PRIMARY KEY(namespace_id,fact_id), UNIQUE(namespace_id,event_version_id,fact_id),
  FOREIGN KEY(namespace_id,event_version_id) REFERENCES event_version,
  CHECK(direction IN ('input','output','sql_parameter','metadata')),
  CHECK(sensitivity IN ('public','operational','personal','financial','secret','restricted')),
  CHECK(sensitivity NOT IN ('personal','financial','secret','restricted') OR public_value IS NULL),
  CHECK(sensitivity NOT IN ('secret','restricted') OR equality_token IS NULL),
  CHECK(equality_token IS NULL OR token_key_version IS NOT NULL),
  CHECK(public_value IS NULL OR octet_length(public_value::text)<=4096),
  CHECK(completeness IN ('complete','truncated','parse_error','unlogged','unknown'))
);
CREATE TABLE event_fact_projection (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, event_version_id uuid NOT NULL,
  fact_id uuid NOT NULL, use_kind text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,event_version_id,fact_id,use_kind),
  FOREIGN KEY(namespace_id,run_id,event_version_id) REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,event_version_id,fact_id) REFERENCES source_event_fact(namespace_id,event_version_id,fact_id)
);
CREATE FUNCTION guard_event_fact_projection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM p24_next.projection_event pe WHERE pe.namespace_id=NEW.namespace_id
    AND pe.run_id=NEW.run_id AND pe.event_version_id=NEW.event_version_id AND pe.selection_state='selected')
  THEN RAISE EXCEPTION 'Source-event fact is not supported by selected evidence in this run'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER selected_event_fact BEFORE INSERT OR UPDATE ON event_fact_projection
  FOR EACH ROW EXECUTE FUNCTION guard_event_fact_projection();

CREATE TABLE request_context_assertion (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  assertion_id uuid NOT NULL DEFAULT gen_random_uuid(), context_kind text NOT NULL,
  initiator_kind text NOT NULL, actor_session_key text,
  evidence_fact_id uuid NOT NULL, evidence_use_kind text NOT NULL DEFAULT 'request_context',
  assertion_state text NOT NULL, contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,assertion_id), UNIQUE(namespace_id,run_id,assertion_id),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,actor_session_key) REFERENCES user_session,
  FOREIGN KEY(namespace_id,run_id,request_key,evidence_fact_id,evidence_use_kind)
    REFERENCES projection_fact(namespace_id,run_id,request_key,fact_id,use_kind),
  CHECK(context_kind IN ('customer_application','partner_notification','background','integration_transport','unknown')),
  CHECK(initiator_kind IN ('human','application','partner','scheduler','unknown')),
  CHECK(evidence_use_kind='request_context'),
  CHECK(assertion_state IN ('verified','candidate','ambiguous','conflicting'))
);
CREATE FUNCTION guard_context_actor_session() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE projected_session text;
BEGIN
  IF NEW.actor_session_key IS NOT NULL THEN
    SELECT session_key INTO projected_session FROM p24_next.request_projection
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND request_key=NEW.request_key;
    IF projected_session IS DISTINCT FROM NEW.actor_session_key
    THEN RAISE EXCEPTION 'Actor Session must match the authenticated request Session; target identity belongs elsewhere'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER context_actor_session BEFORE INSERT OR UPDATE ON request_context_assertion
  FOR EACH ROW EXECUTE FUNCTION guard_context_actor_session();

CREATE TABLE subject_identity_assertion (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, request_key text NOT NULL,
  assertion_id uuid NOT NULL DEFAULT gen_random_uuid(), identity_role text NOT NULL,
  identifier_kind text NOT NULL, equality_domain text NOT NULL,
  equality_token text NOT NULL, token_key_version text NOT NULL,
  evidence_fact_id uuid NOT NULL, evidence_use_kind text NOT NULL DEFAULT 'identity_assertion',
  assertion_state text NOT NULL, contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,assertion_id), UNIQUE(namespace_id,run_id,assertion_id),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,run_id,request_key,evidence_fact_id,evidence_use_kind)
    REFERENCES projection_fact(namespace_id,run_id,request_key,fact_id,use_kind),
  CHECK(identity_role IN ('authenticated_actor','target_session','target_user','queried_subject','payer','payee','device','unknown')),
  CHECK(evidence_use_kind='identity_assertion'),
  CHECK(assertion_state IN ('verified','candidate','ambiguous','conflicting'))
);

CREATE TABLE workflow_identifier_assertion (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL,
  assertion_id uuid NOT NULL DEFAULT gen_random_uuid(), request_key text,
  source_event_version_id uuid NOT NULL, workflow_key text,
  phase_key text NOT NULL, identifier_role text NOT NULL, identifier_kind text NOT NULL,
  equality_domain text NOT NULL, equality_token text NOT NULL, token_key_version text NOT NULL,
  request_fact_id uuid, request_fact_use_kind text,
  event_fact_id uuid, event_fact_use_kind text,
  assertion_state text NOT NULL, contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,assertion_id), UNIQUE(namespace_id,run_id,assertion_id,workflow_key),
  FOREIGN KEY(namespace_id,run_id,source_event_version_id)
    REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,run_id,request_key) REFERENCES request_projection,
  FOREIGN KEY(namespace_id,workflow_key) REFERENCES business_workflow,
  FOREIGN KEY(namespace_id,run_id,request_key,request_fact_id,request_fact_use_kind)
    REFERENCES projection_fact(namespace_id,run_id,request_key,fact_id,use_kind),
  FOREIGN KEY(namespace_id,run_id,source_event_version_id,event_fact_id,event_fact_use_kind)
    REFERENCES event_fact_projection(namespace_id,run_id,event_version_id,fact_id,use_kind),
  CHECK(identifier_role IN ('request','order','payment','bill_subject','actor','target','external_event','unknown')),
  CHECK(assertion_state IN ('accepted','candidate','ambiguous','conflicting','rejected')),
  CHECK((assertion_state='accepted')=(workflow_key IS NOT NULL)),
  CHECK((request_key IS NOT NULL AND request_fact_id IS NOT NULL AND request_fact_use_kind='workflow_identifier' AND event_fact_id IS NULL AND event_fact_use_kind IS NULL)
     OR (request_key IS NULL AND request_fact_id IS NULL AND request_fact_use_kind IS NULL AND event_fact_id IS NOT NULL AND event_fact_use_kind='workflow_identifier'))
);
CREATE FUNCTION guard_workflow_identifier_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.request_fact_id IS NOT NULL AND NOT EXISTS(
    SELECT 1 FROM p24_next.extracted_fact f WHERE f.namespace_id=NEW.namespace_id
      AND f.fact_id=NEW.request_fact_id AND f.request_key=NEW.request_key
      AND f.event_version_id=NEW.source_event_version_id)
  THEN RAISE EXCEPTION 'Workflow identifier fact must belong to this source event and request'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_identifier_source BEFORE INSERT OR UPDATE ON workflow_identifier_assertion
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_identifier_source();

CREATE TABLE external_event_identity (
  namespace_id uuid NOT NULL REFERENCES namespace, external_event_key uuid NOT NULL DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,external_event_key)
);
CREATE TABLE external_event_identity_assertion (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, assertion_id uuid NOT NULL DEFAULT gen_random_uuid(),
  external_event_key uuid NOT NULL, issuer_key text NOT NULL, topic_key text NOT NULL,
  identity_state text NOT NULL, identifier_domain text, equality_token text, token_key_version text,
  source_event_version_id uuid NOT NULL, evidence_fact_id uuid,
  evidence_use_kind text NOT NULL DEFAULT 'external_event_identity', contract_version text NOT NULL,
  PRIMARY KEY(namespace_id,assertion_id),
  UNIQUE(namespace_id,run_id,assertion_id,external_event_key),
  UNIQUE(namespace_id,run_id,assertion_id,external_event_key,source_event_version_id),
  FOREIGN KEY(namespace_id,run_id,source_event_version_id)
    REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,external_event_key) REFERENCES external_event_identity,
  FOREIGN KEY(namespace_id,run_id,source_event_version_id,evidence_fact_id,evidence_use_kind)
    REFERENCES event_fact_projection(namespace_id,run_id,event_version_id,fact_id,use_kind),
  CHECK(identity_state IN ('verified','unresolved','conflicting','rejected')),
  CHECK((identity_state='verified')=(identifier_domain IS NOT NULL AND equality_token IS NOT NULL AND token_key_version IS NOT NULL AND evidence_fact_id IS NOT NULL)),
  CHECK(evidence_use_kind='external_event_identity')
);
CREATE UNIQUE INDEX external_event_verified_identity ON external_event_identity_assertion
  (namespace_id,run_id,issuer_key,topic_key,identifier_domain,token_key_version,equality_token)
  WHERE identity_state='verified';
CREATE FUNCTION guard_external_event_identity_assertion() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source_token text; source_key_version text;
BEGIN
  IF NEW.identity_state='verified' THEN
    SELECT equality_token,token_key_version INTO source_token,source_key_version
      FROM p24_next.source_event_fact
      WHERE namespace_id=NEW.namespace_id AND event_version_id=NEW.source_event_version_id
        AND fact_id=NEW.evidence_fact_id;
    IF source_token IS NULL OR source_key_version IS NULL
      OR NEW.equality_token IS DISTINCT FROM source_token
      OR NEW.token_key_version IS DISTINCT FROM source_key_version
      THEN RAISE EXCEPTION 'Verified external event identity must match its source-bound keyed equality token'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER external_event_identity_fact BEFORE INSERT OR UPDATE ON external_event_identity_assertion
  FOR EACH ROW EXECUTE FUNCTION guard_external_event_identity_assertion();

CREATE TABLE external_event_revision (
  namespace_id uuid NOT NULL, external_revision_id uuid NOT NULL DEFAULT gen_random_uuid(),
  external_event_key uuid NOT NULL, content_sha256 text NOT NULL,
  source_event_version_id uuid NOT NULL, event_time timestamptz,
  event_time_precision text NOT NULL DEFAULT 'unknown', event_time_fact_id uuid,
  first_received_at timestamptz NOT NULL, schema_version text NOT NULL,
  authenticity_state text NOT NULL, outcome_code text, outcome_contract_version text,
  completeness text NOT NULL,
  PRIMARY KEY(namespace_id,external_revision_id),
  UNIQUE(namespace_id,external_event_key,content_sha256,schema_version),
  UNIQUE(namespace_id,external_revision_id,external_event_key),
  UNIQUE(namespace_id,external_revision_id,external_event_key,source_event_version_id),
  FOREIGN KEY(namespace_id,external_event_key) REFERENCES external_event_identity,
  FOREIGN KEY(namespace_id,source_event_version_id) REFERENCES event_version,
  FOREIGN KEY(namespace_id,source_event_version_id,event_time_fact_id)
    REFERENCES source_event_fact(namespace_id,event_version_id,fact_id),
  CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK(event_time_precision IN ('microsecond','millisecond','second','unknown')),
  CHECK((event_time IS NULL)=(event_time_fact_id IS NULL)),
  CHECK(authenticity_state IN ('verified','unverified','rejected','unknown')),
  CHECK(completeness IN ('complete','partial','parse_error','unlogged','unknown')),
  CHECK(outcome_code IS NULL OR outcome_contract_version IS NOT NULL)
);
CREATE TABLE external_event_support (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, external_revision_id uuid NOT NULL,
  external_event_key uuid NOT NULL, event_version_id uuid NOT NULL, identity_domain text,
  identity_assertion_id uuid, identity_fact_id uuid, identity_fact_use_kind text,
  support_state text NOT NULL, support_basis text NOT NULL,
  PRIMARY KEY(namespace_id,run_id,external_revision_id,event_version_id),
  UNIQUE(namespace_id,run_id,external_revision_id,event_version_id,external_event_key),
  FOREIGN KEY(namespace_id,run_id,event_version_id)
    REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,external_revision_id,external_event_key)
    REFERENCES external_event_revision(namespace_id,external_revision_id,external_event_key),
  FOREIGN KEY(namespace_id,run_id,identity_assertion_id,external_event_key)
    REFERENCES external_event_identity_assertion(namespace_id,run_id,assertion_id,external_event_key),
  FOREIGN KEY(namespace_id,run_id,event_version_id,identity_fact_id,identity_fact_use_kind)
    REFERENCES event_fact_projection(namespace_id,run_id,event_version_id,fact_id,use_kind),
  CHECK(support_state IN ('verified','candidate','conflicting','unresolved')),
  CHECK(support_basis IN ('verified_identifier','content_fingerprint_candidate','source_correction','operator_review','unknown')),
  CHECK((identity_fact_id IS NULL AND identity_fact_use_kind IS NULL) OR
    (identity_fact_id IS NOT NULL AND identity_fact_use_kind='external_event_identity')),
  CHECK(support_state<>'verified' OR (support_basis IN ('verified_identifier','operator_review')
    AND identity_assertion_id IS NOT NULL AND identity_fact_id IS NOT NULL))
);
CREATE FUNCTION guard_external_event_support() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected_state text; source_version uuid; time_fact uuid; asserted_state text;
  asserted_domain text; asserted_token text; asserted_key_version text; support_token text; support_key_version text;
BEGIN
  SELECT selection_state INTO selected_state FROM p24_next.projection_event
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND event_version_id=NEW.event_version_id;
  IF selected_state IS DISTINCT FROM 'selected'
    THEN RAISE EXCEPTION 'External event support must cite a selected source event in this run'; END IF;
  SELECT source_event_version_id,event_time_fact_id INTO source_version,time_fact
    FROM p24_next.external_event_revision
    WHERE namespace_id=NEW.namespace_id AND external_revision_id=NEW.external_revision_id
      AND external_event_key=NEW.external_event_key;
  IF NOT EXISTS(SELECT 1 FROM p24_next.projection_event
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
        AND event_version_id=source_version AND selection_state='selected')
    THEN RAISE EXCEPTION 'External event revision provenance is absent from the selected run'; END IF;
  IF time_fact IS NOT NULL AND NOT EXISTS(SELECT 1 FROM p24_next.event_fact_projection
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
        AND event_version_id=source_version AND fact_id=time_fact AND use_kind='external_event_time')
    THEN RAISE EXCEPTION 'External event time must be selected from its retained source fact'; END IF;
  IF NEW.support_state='verified' THEN
    SELECT identity_state,identifier_domain,equality_token,token_key_version
      INTO asserted_state,asserted_domain,asserted_token,asserted_key_version
      FROM p24_next.external_event_identity_assertion
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
        AND assertion_id=NEW.identity_assertion_id AND external_event_key=NEW.external_event_key;
    SELECT equality_token,token_key_version INTO support_token,support_key_version
      FROM p24_next.source_event_fact
      WHERE namespace_id=NEW.namespace_id AND event_version_id=NEW.event_version_id
        AND fact_id=NEW.identity_fact_id;
    IF asserted_state IS DISTINCT FROM 'verified' OR NEW.identity_domain IS DISTINCT FROM asserted_domain
      OR support_token IS DISTINCT FROM asserted_token
      OR support_key_version IS DISTINCT FROM asserted_key_version OR asserted_domain IS NULL
      THEN RAISE EXCEPTION 'Verified support must prove the same typed external event identifier from this source'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER external_event_support_guard BEFORE INSERT OR UPDATE ON external_event_support
  FOR EACH ROW EXECUTE FUNCTION guard_external_event_support();

CREATE FUNCTION guard_external_event_revision() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE seen_at timestamptz;
BEGIN
  SELECT received_at INTO seen_at FROM p24_next.event_version
    WHERE namespace_id=NEW.namespace_id AND event_version_id=NEW.source_event_version_id;
  IF seen_at IS NULL OR NEW.first_received_at<seen_at
    THEN RAISE EXCEPTION 'External event receipt time predates its retained source evidence'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER external_event_revision_source BEFORE INSERT ON external_event_revision
  FOR EACH ROW EXECUTE FUNCTION guard_external_event_revision();

CREATE TABLE delivery_attempt (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, delivery_attempt_id uuid NOT NULL DEFAULT gen_random_uuid(),
  event_version_id uuid NOT NULL, external_revision_id uuid,
  transport_request_key text,
  received_at timestamptz NOT NULL, acknowledgement_state text NOT NULL,
  identity_state text NOT NULL, coverage_state text NOT NULL,
  PRIMARY KEY(namespace_id,delivery_attempt_id), UNIQUE(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,run_id,event_version_id)
    REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,run_id,external_revision_id,event_version_id)
    REFERENCES external_event_support(namespace_id,run_id,external_revision_id,event_version_id),
  FOREIGN KEY(namespace_id,transport_request_key) REFERENCES logical_request,
  CHECK(acknowledgement_state IN ('http_accepted','http_rejected','not_observed','unknown')),
  CHECK(identity_state IN ('verified_attempt','source_observation_only','ambiguous')),
  CHECK(coverage_state IN ('complete','partial','unlogged','unknown')),
  CHECK(external_revision_id IS NULL OR identity_state='verified_attempt')
);
CREATE FUNCTION guard_delivery_attempt_support() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE linked_support_state text; selected_state text; received timestamptz;
BEGIN
  SELECT pe.selection_state,ev.received_at INTO selected_state,received
    FROM p24_next.projection_event pe JOIN p24_next.event_version ev
      ON ev.namespace_id=pe.namespace_id AND ev.event_version_id=pe.event_version_id
    WHERE pe.namespace_id=NEW.namespace_id AND pe.run_id=NEW.run_id AND pe.event_version_id=NEW.event_version_id;
  IF selected_state IS DISTINCT FROM 'selected'
    THEN RAISE EXCEPTION 'Delivery attempt must cite selected source evidence'; END IF;
  IF NEW.received_at IS DISTINCT FROM received
    THEN RAISE EXCEPTION 'Delivery receipt time must match immutable source receipt time'; END IF;
  IF NEW.external_revision_id IS NOT NULL THEN
    SELECT es.support_state INTO linked_support_state FROM p24_next.external_event_support es
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id
        AND external_revision_id=NEW.external_revision_id AND event_version_id=NEW.event_version_id;
    IF linked_support_state IS DISTINCT FROM 'verified'
      THEN RAISE EXCEPTION 'A verified delivery attempt needs verified event support for the same source event'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE FUNCTION guard_delivery_transport_key() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE observed_request text; selected_state text; received timestamptz;
BEGIN
  SELECT pe.selection_state,ev.received_at INTO selected_state,received
    FROM p24_next.projection_event pe JOIN p24_next.event_version ev
      ON ev.namespace_id=pe.namespace_id AND ev.event_version_id=pe.event_version_id
    WHERE pe.namespace_id=NEW.namespace_id AND pe.run_id=NEW.run_id AND pe.event_version_id=NEW.event_version_id;
  IF selected_state IS DISTINCT FROM 'selected'
    THEN RAISE EXCEPTION 'Delivery attempt must cite selected source evidence'; END IF;
  IF NEW.received_at IS DISTINCT FROM received
    THEN RAISE EXCEPTION 'Delivery receipt time must match immutable source receipt time'; END IF;
  IF NEW.transport_request_key IS NOT NULL THEN
    SELECT ev.request_key INTO observed_request FROM p24_next.event_version ev
      WHERE ev.namespace_id=NEW.namespace_id AND ev.event_version_id=NEW.event_version_id;
    IF observed_request IS DISTINCT FROM NEW.transport_request_key
    THEN RAISE EXCEPTION 'A transport RequestID must come from this delivery source event'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delivery_transport_key BEFORE INSERT OR UPDATE ON delivery_attempt
  FOR EACH ROW EXECUTE FUNCTION guard_delivery_transport_key();
CREATE TRIGGER delivery_attempt_support BEFORE INSERT OR UPDATE ON delivery_attempt
  FOR EACH ROW EXECUTE FUNCTION guard_delivery_attempt_support();

CREATE TABLE workflow_state_observation (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, observation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  workflow_key text, workflow_assertion_id uuid,
  event_version_id uuid NOT NULL, state_fact_id uuid NOT NULL, state_fact_use_kind text NOT NULL,
  phase_key text NOT NULL, state_scope text NOT NULL, subject_domain text, subject_token text,
  state_key text NOT NULL, state_contract_version text NOT NULL,
  outcome_state text NOT NULL, source_event_time timestamptz, received_at timestamptz NOT NULL,
  business_event_time timestamptz, business_time_fact_id uuid, business_time_fact_use_kind text,
  source_role text NOT NULL, completeness text NOT NULL,
  PRIMARY KEY(namespace_id,observation_id),
  FOREIGN KEY(namespace_id,run_id,event_version_id)
    REFERENCES projection_event(namespace_id,run_id,event_version_id),
  FOREIGN KEY(namespace_id,workflow_key) REFERENCES business_workflow,
  FOREIGN KEY(namespace_id,run_id,workflow_assertion_id,workflow_key)
    REFERENCES workflow_identifier_assertion(namespace_id,run_id,assertion_id,workflow_key),
  FOREIGN KEY(namespace_id,run_id,event_version_id,state_fact_id,state_fact_use_kind)
    REFERENCES event_fact_projection(namespace_id,run_id,event_version_id,fact_id,use_kind),
  FOREIGN KEY(namespace_id,run_id,event_version_id,business_time_fact_id,business_time_fact_use_kind)
    REFERENCES event_fact_projection(namespace_id,run_id,event_version_id,fact_id,use_kind),
  CHECK((workflow_key IS NULL AND workflow_assertion_id IS NULL) OR (workflow_key IS NOT NULL AND workflow_assertion_id IS NOT NULL)),
  CHECK((state_scope='workflow' AND subject_domain IS NULL AND subject_token IS NULL)
     OR (state_scope='subject' AND subject_domain IS NOT NULL AND subject_token IS NOT NULL)),
  CHECK(outcome_state IN ('success','failure','pending','partial','unknown','conflicting')),
  CHECK(source_role IN ('client_http','sql','internal','provider','cache','background','unknown')),
  CHECK(completeness IN ('complete','partial','parse_error','unlogged','unknown')),
  CHECK(state_fact_use_kind='workflow_state'),
  CHECK((business_event_time IS NULL AND business_time_fact_id IS NULL AND business_time_fact_use_kind IS NULL) OR
    (business_event_time IS NOT NULL AND business_time_fact_id IS NOT NULL AND business_time_fact_use_kind='business_event_time'))
);
CREATE FUNCTION guard_workflow_state_link() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE link_state text; source_time timestamptz; source_received timestamptz;
  cutoff_time timestamptz; known_at timestamptz;
BEGIN
  IF NEW.workflow_assertion_id IS NOT NULL THEN
    SELECT assertion_state INTO link_state FROM p24_next.workflow_identifier_assertion
      WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND assertion_id=NEW.workflow_assertion_id
        AND workflow_key=NEW.workflow_key;
    IF link_state IS DISTINCT FROM 'accepted'
    THEN RAISE EXCEPTION 'Workflow state requires a verified, accepted typed identifier assertion'; END IF;
  END IF;
  SELECT pe.selection_state,ev.source_event_time,ev.received_at,pr.event_cutoff,pr.knowledge_snapshot_at
    INTO link_state,source_time,source_received,cutoff_time,known_at
    FROM p24_next.projection_event pe
    JOIN p24_next.event_version ev ON ev.namespace_id=pe.namespace_id AND ev.event_version_id=pe.event_version_id
    JOIN p24_next.projection_run pr ON pr.namespace_id=pe.namespace_id AND pr.run_id=pe.run_id
    WHERE pe.namespace_id=NEW.namespace_id AND pe.run_id=NEW.run_id AND pe.event_version_id=NEW.event_version_id;
  IF link_state IS DISTINCT FROM 'selected'
    THEN RAISE EXCEPTION 'Workflow state source event is not selected in this projection run'; END IF;
  IF NEW.source_event_time IS DISTINCT FROM source_time OR NEW.received_at IS DISTINCT FROM source_received
    THEN RAISE EXCEPTION 'Workflow observation timestamps must match immutable source evidence'; END IF;
  IF NEW.business_event_time IS NOT NULL AND NEW.business_event_time>=cutoff_time
    THEN RAISE EXCEPTION 'A future effective/business event time cannot enter an earlier state projection'; END IF;
  IF source_received>known_at AND (SELECT mode FROM p24_next.projection_run WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id)='online_original'
    THEN RAISE EXCEPTION 'Evidence was not known to the original online run'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_state_link BEFORE INSERT OR UPDATE ON workflow_state_observation
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_state_link();

CREATE TABLE workflow_state_publication (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, state_publication_id uuid NOT NULL DEFAULT gen_random_uuid(),
  workflow_key text NOT NULL, state_contract_version text NOT NULL, state_scope text NOT NULL,
  subject_domain text, subject_token text, published_state text NOT NULL,
  coverage_state text NOT NULL, observation_count bigint NOT NULL CHECK(observation_count>=0),
  conflict_count bigint NOT NULL CHECK(conflict_count>=0),
  event_cutoff timestamptz NOT NULL, knowledge_snapshot_at timestamptz NOT NULL,
  input_manifest_sha256 text NOT NULL, built_at timestamptz NOT NULL,
  PRIMARY KEY(namespace_id,state_publication_id),
  UNIQUE(namespace_id,run_id,state_publication_id),
  FOREIGN KEY(namespace_id,run_id) REFERENCES projection_run,
  FOREIGN KEY(namespace_id,workflow_key) REFERENCES business_workflow,
  CHECK((state_scope='workflow' AND subject_domain IS NULL AND subject_token IS NULL)
     OR (state_scope='subject' AND subject_domain IS NOT NULL AND subject_token IS NOT NULL)),
  CHECK(published_state IN ('success','failure','pending','partial','unknown','conflicting')),
  CHECK(coverage_state IN ('complete','partial','unavailable','unknown')),
  CHECK(input_manifest_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE UNIQUE INDEX workflow_state_publication_key ON workflow_state_publication
  (namespace_id,run_id,workflow_key,state_contract_version,state_scope,
   COALESCE(subject_domain,''),COALESCE(subject_token,''));

CREATE TABLE workflow_state_publication_input (
  namespace_id uuid NOT NULL, run_id uuid NOT NULL, state_publication_id uuid NOT NULL, observation_id uuid NOT NULL,
  PRIMARY KEY(namespace_id,run_id,state_publication_id,observation_id),
  FOREIGN KEY(namespace_id,run_id,state_publication_id) REFERENCES workflow_state_publication(namespace_id,run_id,state_publication_id),
  FOREIGN KEY(namespace_id,observation_id) REFERENCES workflow_state_observation
);
CREATE FUNCTION guard_workflow_state_publication_input_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected_count bigint; already_linked bigint;
BEGIN
  SELECT observation_count INTO expected_count FROM p24_next.workflow_state_publication
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND state_publication_id=NEW.state_publication_id FOR UPDATE;
  SELECT count(*) INTO already_linked FROM p24_next.workflow_state_publication_input
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id AND state_publication_id=NEW.state_publication_id;
  IF expected_count IS NULL OR already_linked>=expected_count
    THEN RAISE EXCEPTION 'Workflow state publication input manifest is already complete or absent'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_state_publication_input_capacity BEFORE INSERT ON workflow_state_publication_input
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_state_publication_input_capacity();
CREATE FUNCTION guard_workflow_state_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r p24_next.projection_run%ROWTYPE;
BEGIN
  SELECT * INTO r FROM p24_next.projection_run
    WHERE namespace_id=NEW.namespace_id AND run_id=NEW.run_id;
  IF NOT FOUND OR NEW.event_cutoff IS DISTINCT FROM r.event_cutoff
    OR NEW.knowledge_snapshot_at IS DISTINCT FROM r.knowledge_snapshot_at
    OR NEW.built_at<r.created_at
    THEN RAISE EXCEPTION 'Workflow state publication must use the exact projection run time bounds'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_state_publication_bounds BEFORE INSERT OR UPDATE ON workflow_state_publication
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_state_publication();
CREATE FUNCTION guard_workflow_state_publication_input() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p p24_next.workflow_state_publication%ROWTYPE; o p24_next.workflow_state_observation%ROWTYPE;
BEGIN
  SELECT * INTO p FROM p24_next.workflow_state_publication
    WHERE namespace_id=NEW.namespace_id AND state_publication_id=NEW.state_publication_id;
  SELECT * INTO o FROM p24_next.workflow_state_observation
    WHERE namespace_id=NEW.namespace_id AND observation_id=NEW.observation_id;
  IF NOT FOUND OR NEW.run_id IS DISTINCT FROM p.run_id OR o.run_id IS DISTINCT FROM p.run_id OR o.workflow_key IS DISTINCT FROM p.workflow_key
    OR o.state_contract_version IS DISTINCT FROM p.state_contract_version
    OR o.state_scope IS DISTINCT FROM p.state_scope
    OR COALESCE(o.subject_domain,'') IS DISTINCT FROM COALESCE(p.subject_domain,'')
    OR COALESCE(o.subject_token,'') IS DISTINCT FROM COALESCE(p.subject_token,'')
    OR o.source_event_time IS NULL OR o.source_event_time>=p.event_cutoff OR o.received_at>p.knowledge_snapshot_at
    OR (o.business_event_time IS NOT NULL AND o.business_event_time>=p.event_cutoff)
    THEN RAISE EXCEPTION 'Workflow publication input does not match the state key or is outside its causal bounds'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_state_publication_input_guard BEFORE INSERT OR UPDATE ON workflow_state_publication_input
  FOR EACH ROW EXECUTE FUNCTION guard_workflow_state_publication_input();
CREATE FUNCTION validate_workflow_state_publication_inputs() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actual_count bigint; actual_conflicts bigint;
BEGIN
  SELECT count(*),count(*) FILTER (WHERE o.outcome_state='conflicting')
    INTO actual_count,actual_conflicts
    FROM p24_next.workflow_state_publication_input i
    JOIN p24_next.workflow_state_observation o USING(namespace_id,observation_id)
    WHERE i.namespace_id=NEW.namespace_id AND i.state_publication_id=NEW.state_publication_id;
  IF actual_count<>NEW.observation_count OR actual_conflicts<>NEW.conflict_count
    THEN RAISE EXCEPTION 'Workflow state publication counts do not match its retained input manifest'; END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER workflow_state_publication_counts
  AFTER INSERT OR UPDATE ON workflow_state_publication DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION validate_workflow_state_publication_inputs();
CREATE TRIGGER immutable_state_publication BEFORE UPDATE OR DELETE ON workflow_state_publication
  FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation();
CREATE TRIGGER immutable_state_publication_input BEFORE UPDATE OR DELETE ON workflow_state_publication_input
  FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation();

-- Facts, source versions, delivery attempts and state observations are
-- append-only. Run-scoped assertions/projections freeze when their run seals.
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['source_event_fact','external_event_identity','external_event_revision'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.reject_mutation()',t);
  END LOOP;
END $$;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['event_fact_projection','request_context_assertion','subject_identity_assertion',
    'workflow_identifier_assertion','external_event_identity_assertion','external_event_support',
    'delivery_attempt','workflow_state_observation','workflow_state_publication','workflow_state_publication_input'] LOOP
    EXECUTE format('CREATE TRIGGER frozen_run BEFORE INSERT OR UPDATE OR DELETE ON p24_next.%I FOR EACH ROW EXECUTE FUNCTION p24_next.guard_run_child()',t);
  END LOOP;
END $$;

-- A run selects exact versions. Current heads cannot leak into this query.
CREATE FUNCTION facts_for_run(n uuid,r uuid,q text)
RETURNS SETOF p24_next.extracted_fact LANGUAGE sql STABLE AS $$
  SELECT f.* FROM p24_next.extracted_fact f JOIN p24_next.projection_event pe
    ON pe.namespace_id=f.namespace_id AND pe.event_version_id=f.event_version_id
  WHERE f.namespace_id=n AND pe.run_id=r AND f.request_key=q AND pe.selection_state='selected'
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA p24_next FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA p24_next FROM PUBLIC;
COMMIT;
