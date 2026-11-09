"""Deterministic, data-free PostgreSQL product bundle (explicit allowlist)."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
BUILD='AD-20261108-WINSTART'
MODULES=('viewer_raw_retention','windows_viewer_control','history_scope','history_reset','longitudinal','noc_evidence','sql_budget','web_diagnostics','schema_setup','runtime_lanes','service_sampling','unified_review','acceptance_report','runtime_statistics','request_profiles','scenario_models','scenario_store','scenario_traffic','scenario_worker','scenario_web','primary_pipeline','model_queue','audit_scope','presentation_proof','case_summary','review_policy','case_export','cases','case_web','continuous','population','owned_sql','job_scope','__init__','snapshot','pg_source','process_control','files_io','temporal','native_pg',
    'service_reference','window_migration','product_dependencies','product_pipeline','product_enrichment','viewer_bridge','context_models','product_store','product_source','product_engine','product_models','product_control','product_worker','product_scheduling','source_scheduling','product_priority','product_diagnostics','product_evaluations','product_web','product_cli')
TESTS=('test_longitudinal','test_noc_evidence','test_web_diagnostics','test_schema_setup','test_acceptance_report','test_scenarios','test_review_policy','test_continuous_cases','test_owned_sql','test_source_scheduling','test_rank_screen','__init__','fixture_factory','test_service_reference','test_product_scheduling','test_product_diagnostics','test_product_models','test_product_contract','test_product_engine','test_product_evaluations','test_context_models','test_temporal')
DOCS=('RELEASE_NOTES_28_FA.md','RELEASE_NOTES_27_FA.md','RELEASE_NOTES_26_FA.md','RELEASE_NOTES_25_FA.md','MEETING_REQUIREMENTS_25_FA.md','ACCEPTANCE_SCENARIOS_25_FA.md','RELEASE_NOTES_24_FA.md','RELEASE_NOTES_23_FA.md','RELEASE_NOTES_22_FA.md','RELEASE_NOTES_21_FA.md','RELEASE_NOTES_20_FA.md','RELEASE_NOTES_19_FA.md','SCENARIO_COVERAGE_19_FA.md','RELEASE_NOTES_18_FA.md','PRESENTATION_GUIDE_FA.md','RELEASE_NOTES_17_FA.md','RELEASE_NOTES_16_FA.md','RELEASE_NOTES_15_FA.md','RELEASE_NOTES_14_FA.md','RELEASE_NOTES_13_FA.md','FINAL_TESTS_FA.md','RELEASE_NOTES_12_FA.md','RELEASE_NOTES_11_FA.md','RELEASE_NOTES_10_FA.md','RELEASE_NOTES_09_FA.md','RELEASE_NOTES_08_FA.md','RELEASE_NOTES_07_FA.md','RELEASE_NOTES_06_FA.md','README_FA.md','PROJECT_MAP_FA.md','COVERAGE_MATRIX_FA.md','METHODS_AND_LATE_DATA_FA.md','AGENTS.md')
VALIDATION=('PRODUCT_stop28.json','check_stop28.py','PRODUCT_joint28.json','PRODUCT_scoped_source27.json','PRODUCT_raw27.json','PRODUCT_joint27.json','check_joint27.py','check_raw27.py','PRODUCT_history26.json','check_history26.py','PRODUCT_revision25.json','pg_engine/check_revision25.py','PRODUCT_revision24.json','pg_engine/check_revision24.py','PRODUCT_revision23.json','pg_engine/check_revision23.py','pg_engine/review_sql22_reference.py','PRODUCT_revision22.json','pg_engine/check_revision22.py','PRODUCT_revision21.json','pg_engine/check_revision21.py','PRODUCT_revision20.json','pg_engine/check_revision20.py','PRODUCT_revision19.json','PRODUCT_scenarios19.json','pg_engine/check_revision19.py','PRODUCT_revision18.json','pg_engine/check_revision18.py','PRODUCT_revision17.json','pg_engine/check_revision17.py','PRODUCT_export17.json','pg_engine/check_export17.py','PRODUCT_revision16.json','pg_engine/check_revision16.py','PRODUCT_population16.json','pg_engine/check_population16.py','PRODUCT_bounds16.json','pg_engine/check_bounds16.py','PRODUCT_revision15.json','pg_engine/check_revision15.py','PRODUCT_revision14.json','pg_engine/check_revision14.py','PRODUCT_engine_contract.json','PRODUCT_unit_tests.json','PRODUCT_revision06.json','PRODUCT_atomic_scope.json',
    'PRODUCT_revision13.json','PRODUCT_revision12.json','PRODUCT_revision11.json','PRODUCT_revision10.json','PRODUCT_revision09.json','PRODUCT_revision08.json','build_product.py',
    'pg_engine/engine.mjs','pg_engine/transport.py','pg_engine/check_product.py','pg_engine/check_revision06.py','pg_engine/check_atomic_window.py','pg_engine/check_revision08.py','pg_engine/check_revision09.py','pg_engine/check_revision13.py','pg_engine/check_revision12.py','pg_engine/check_revision11.py','pg_engine/check_revision10.py','pg_engine/package.json','pg_engine/package-lock.json','pg_engine/README.md')


def build():
    members={f'anomaly_detection/{name}.py' for name in (*MODULES,'input_subjects')}|{f'tests/{name}.py' for name in (*TESTS,'test_input_subjects')}
    members.update(DOCS);members.update(('DEVELOPER_HANDOFF_FA.md','Run_AD_Input_Update.cmd','Install_Update.py','run_anomaly.py','Start_AnomalyDetection.cmd','Stop_AnomalyDetection.cmd'))
    members.update('validation/'+name for name in (*VALIDATION,'pg_engine/check_input_subjects.py','PRODUCT_input_subjects.json',
        'pg_engine/check_family_audit.py','PRODUCT_family_audit.json','check_install_release.py',
        'PRODUCT_release_startup.json','PRODUCT_winstart.json','recheck_input.py'))
    members.update(path.relative_to(ROOT).as_posix() for path in (ROOT/'fixtures').glob('*.json'))
    members.add('reference/handoff_20261031/reference/viewer_schema_reference.json')
    protected=ROOT/'reference/baseline_readonly/RELEASE_MANIFEST.json'
    if protected.is_file():
        protected_entries=json.loads(protected.read_text())['files_sha256']
        for name,expected in protected_entries.items():
            assert hashlib.sha256((protected.parent/name).read_bytes()).hexdigest()==expected,('protected source changed',name)
    for name in members:
        path=ROOT/name
        assert path.is_file() and path.resolve().is_relative_to(ROOT),name
        assert not any(part in ('data','reports','releases','node_modules','__pycache__') for part in path.relative_to(ROOT).parts)
        assert 'local.' not in name and 'credentials' not in name and 'library_' not in name
    entries={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(members)}
    sha=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    manifest={'build_id':BUILD,'source_sha256':sha,'files_sha256':entries,'storage_backend':'postgresql',
        'production_sqlite_imports':False,'source_modified':False,'source_checkpoint_modified':False,
        'deployment_scope':'AD_WINDOWS_VENV_STARTUP_IDENTITY_AND_PRIOR_DETECTOR_FIXES',
        'verified_input_subject_contract':'verified-inquiry-input-1',
        'historical_target_age_limit':None,'model_context_days':56,'continuous_horizons_minutes':[5,60,1440,10080],
        'content_horizons_minutes':[60,1440,10080,43200],'adaptive_content_horizon':'COMPLETE_CONTIGUOUS_COVERAGE_2_TO_30_DAYS',
        'cross_session_person_resolution':'REQUIRES_VERIFIED_STABLE_PRINCIPAL_NOT_IN_PINNED_SOURCE',
        'case_identity_includes_date_or_window':False,'analysis_entities':['actor_session','service_population','whole_system'],
        'source_cdc_complete':False,
        'native_windows_postgresql':'NOT_RUN','capacity_and_precision_recall':'NOT_EVALUATED'}
    (ROOT/'RELEASE_MANIFEST.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    archive=ROOT/'releases/P24_AD_Release_20261108_WinStart.zip';archive.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as output:
        for name in sorted(members|{'RELEASE_MANIFEST.json'}):
            info=zipfile.ZipInfo('AnomalyDetection/'+name,(2026,11,8,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o644<<16
            output.writestr(info,(ROOT/name).read_bytes(),compresslevel=9)
    report={'build_id':BUILD,'source_sha256':sha,'file':str(archive),'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
        'zip_bytes':archive.stat().st_size,'members':len(members)+1,'production_python_modules':len(MODULES)+1,
        'protected_reference_files_unchanged':len(protected_entries) if protected.is_file() else 'REFERENCE_NOT_PACKAGED',
        'private_data_configs_or_helpers_included':False}
    (ROOT/'validation/PRODUCT_release.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return archive


if __name__=='__main__':build()
