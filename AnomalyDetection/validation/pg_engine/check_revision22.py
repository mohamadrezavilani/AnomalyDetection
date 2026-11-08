"""Catalog-aware initialization, selective upgrades and startup lock diagnostics.

SQLSTATE55P03 is injected by SQL; this is not a two-session native lock test.
The shared PGlite session cannot reproduce a second client's lock lifetime.
"""
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import hashlib,json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.product_worker import run
from anomaly_detection.process_control import write_json,read_json
from anomaly_detection.snapshot import ContractError
from check_revision10 import TARGET as T,SESSION as ACTOR,SERVICES,packet,metadata

ROOT=Path(__file__).resolve().parents[2]


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        assert store.initialization_schema['executed']>0
        checks['fresh_install_creates_missing_owned_tables_indexes_columns_and_markers']='PASS_SQL'
        raw.execute('CREATE TABLE public.source_guard(id INTEGER PRIMARY KEY,body TEXT)')
        raw.execute("INSERT INTO public.source_guard VALUES(1,'source-untouched')")
        store.save_state('startup_cursor_fixture',{'after':123,'keep':True})
        apply_window(store,packet(T,{SERVICES[0]:2}))
        before=[dict(r) for r in raw.execute('SELECT * FROM anomaly_detection.adp_facts ORDER BY request_key').fetchall()]
        execute=raw.execute;queries=[]
        def no_ddl(query,args=()):
            queries.append(query)
            if query.startswith(('ALTER ','CREATE ')):
                return execute("DO $$ BEGIN RAISE EXCEPTION 'startup reader lock fixture' USING ERRCODE='55P03'; END $$")
            return execute(query,args)
        with patch.object(raw,'execute',side_effect=no_ddl):store.initialize()
        assert store.initialization_schema['executed']==0 and store.initialization_schema['skipped_existing']==111
        assert not any(q.startswith(('ALTER ','CREATE ')) for q in queries)
        assert [dict(r) for r in execute('SELECT * FROM anomaly_detection.adp_facts ORDER BY request_key').fetchall()]==before
        assert store.state('startup_cursor_fixture')=={'after':123,'keep':True}
        checks['complete_existing_install_issues_zero_ddl_under_injected_ddl_lock_conflict']='PASS_111_STATEMENTS_SKIPPED_AFTER_CATALOG_CHECK'
        checks['restart_keeps_existing_facts_and_cursor_unchanged']='PASS'
        execute('DROP INDEX anomaly_detection.adp_profile_service');queries.clear()
        def record(query,args=()):queries.append(query);return execute(query,args)
        with patch.object(raw,'execute',side_effect=record):store.initialize()
        ddls=[q for q in queries if q.startswith(('ALTER ','CREATE '))]
        assert len(ddls)==1 and ddls[0].startswith('CREATE INDEX IF NOT EXISTS adp_profile_service'),ddls
        checks['missing_index_upgrade_creates_only_that_index_without_redundant_table_alters']='PASS'
        execute('ALTER TABLE anomaly_detection.adp_jobs DROP COLUMN primary_version');queries.clear()
        with patch.object(raw,'execute',side_effect=record):store.initialize()
        ddls=[q for q in queries if q.startswith(('ALTER ','CREATE '))]
        assert len(ddls)==1 and 'ADD COLUMN IF NOT EXISTS primary_version' in ddls[0],ddls
        assert execute('SELECT primary_version FROM anomaly_detection.adp_jobs').fetchone()['primary_version']==1
        checks['missing_additive_column_is_repaired_with_original_default_without_replaying_other_ddl']='PASS'
        # Real missing work must still report lock failure, then retry cleanly.
        execute('ALTER TABLE anomaly_detection.adp_case_feedback DROP COLUMN reviewed_end_ns')
        original=engine.query;fail=True;failed_sql=[]
        def conflict(role,sql,args):
            nonlocal fail
            if fail and sql.startswith('ALTER TABLE anomaly_detection.adp_case_feedback ADD COLUMN'):
                fail=False;failed_sql.append(sql)
                return original(role,"DO $$ BEGIN RAISE EXCEPTION 'startup lock fixture private text' USING ERRCODE='55P03'; END $$",())
            return original(role,sql,args)
        engine.query=conflict
        class Clock:
            elapsed=0.
            def monotonic(self):return 100+self.elapsed
            def time_ns(self):return T+10*FIVE_NS+int(self.elapsed*1e9)
            def wait(self,n):self.elapsed+=max(10,n)
        class Source:
            page_size=128
            def __init__(self,project):self.project=Path(project);self.last_source=metadata(T);self.last_metrics=[]
            def page(self,after=None):return {'rows':[],'source':self.last_source,'after':None,'has_more':False}
        starts=[];states=[]
        def prepare(_):starts.append(True);return engine.connect()
        def publish(path,value):
            if Path(path).name=='product_status.json':states.append(json.loads(json.dumps(value)))
            write_json(path,value)
        clock=Clock()
        with TemporaryDirectory(dir=ROOT/'validation') as temp,ExitStack() as stack:
            root=Path(temp)/'AnomalyDetection';root.mkdir()
            write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':'startup-fixture22'})
            stack.enter_context(patch('anomaly_detection.product_worker.write_json',side_effect=publish))
            stack.enter_context(patch('anomaly_detection.product_pipeline.read_window_burst',return_value=[{'status':'CAUGHT_UP'}]))
            stack.enter_context(patch.object(ProductStore,'audit_keys',return_value=[]))
            stack.enter_context(patch('anomaly_detection.audit_scope.keys',return_value=[]))
            run(root,'startup-fixture22',prepare_pg=prepare,source_factory=Source,clock=clock,wait=clock.wait,max_cycles=8,web=False)
            status=read_json(root/'reports/product_status.json')
        assert len(starts)==2 and len(failed_sql)==1,len(starts)
        blocked=next(s for s in states if s['state']=='WAITING_FOR_DATABASE_LOCK')
        event=blocked['last_initialization_failure']
        assert event['phase']=='prepare_owned_schema' and event['step']=='inspect_owned_catalog_and_migrate_missing_objects'
        assert any(m['operation']=='ALTER' and m['sqlstate']=='55P03' for m in event['queries'])
        assert 'private text' not in json.dumps(event) and 'ADD COLUMN' not in json.dumps(event)
        assert status.get('storage_ready') and status['source_attempts']>0 and status['evaluated_jobs']>0,status
        checks['startup_lock_has_exact_phase_safe_statement_fingerprint_and_explicit_waiting_state']='PASS_SQL55P03_INJECTED_NOT_NATIVE_CONCURRENT_LOCK'
        checks['required_migration_retries_after_lock_clears_and_worker_evaluates_existing_jobs']='PASS_SYNTHETIC_SOURCE_PACKETS'
        assert execute('SELECT body FROM public.source_guard').fetchone()['body']=='source-untouched'
        assert store.state('startup_cursor_fixture')=={'after':123,'keep':True}
        checks['source_fixture_and_unrelated_owned_cursor_survive_upgrade_and_retry']='PASS'
        engine.query=original
        # A marker or name alone must not bypass an incompatible shape.
        execute('ALTER TABLE anomaly_detection.adp_state ALTER COLUMN body TYPE VARCHAR')
        try:store.initialize()
        except ContractError as exc:assert str(exc)=='PRODUCT_SCHEMA_COLUMN_TYPE_MISMATCH',str(exc)
        else:raise AssertionError('incompatible existing column was accepted')
        checks['existing_object_names_do_not_bypass_column_type_validation']='PASS_FAIL_CLOSED'
        report={'build_id':BUILD_ID,'status':'PASS_CATALOG_AWARE_STARTUP_AND_LOCK_RETRY_SQL','checks':checks,
            'owner_connections':0,'production_source_writes':0,'lock_timeout_increased':False,'old_schema_reset':False,
            'native_windows_postgresql22':'NOT_RUN','native_two_session_lock_test':'NOT_RUN','production_precision_recall_capacity':'NOT_MEASURED'}
        (ROOT/'validation/PRODUCT_revision22.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
