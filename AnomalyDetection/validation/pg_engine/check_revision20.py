"""Real SQL cancellation of the exact native19 failing statistics statement.

Proves rollback/budget restoration, independent sections and worker progress
on one connection. Source pages/profile packets are explicit synthetic fixtures;
this is not native owner acceptance or a production-capacity measurement.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import hashlib,json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.runtime_statistics import collect
from anomaly_detection.product_worker import run
from anomaly_detection.process_control import read_json,write_json
from anomaly_detection.scenario_store import publish_scope
from anomaly_detection.product_web import render
from tests.test_scenarios import point
from check_revision10 import TARGET as T,SESSION as ACTOR,SERVICES,packet,metadata

ROOT=Path(__file__).resolve().parents[2]
NATIVE_STATEMENT='523fc7dc5c10cad5'


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection')
        store=ProductStore(raw);store.initialize();service=SERVICES[0]
        apply_window(store,packet(T,{service:2}),cursor_name='fixture')
        current=raw.execute('SELECT request_key,anchor_key,revision,at_ns FROM anomaly_detection.adp_facts ORDER BY request_key').fetchall()
        expected=[r['request_key'] for r in current]
        publish_scope(store,ACTOR,service,T,expected)
        original=engine.query;cancellations=0;cancel=True
        normal_timeout=raw.execute("SELECT current_setting('statement_timeout') AS value").fetchone()['value']
        def inject(role,sql,args):
            nonlocal cancellations
            if cancel and hashlib.sha256(sql.encode()).hexdigest()[:16]==NATIVE_STATEMENT:
                cancellations+=1
                return original(role,"DO $$ BEGIN RAISE EXCEPTION 'statistics cancellation fixture' USING ERRCODE='57014'; END $$",())
            return original(role,sql,args)
        engine.query=inject
        cold=store.report()
        assert cancellations==1 and cold['statistics_collection']['status']=='PARTIAL'
        assert cold['statistics_collection']['sections']['jobs']['status']=='UNAVAILABLE_TIMEOUT'
        assert cold['jobs']['pending'] is None and cold['registered_behaviors']==2
        assert cold['statistics_collection']['sections']['scenario_analysis']['status']=='CURRENT'
        assert raw.execute("SELECT current_setting('statement_timeout') AS value").fetchone()['value']==normal_timeout
        assert raw.execute('SELECT 1 AS n').fetchone()['n']==1
        checks['exact_native_failing_query_is_cancelled_without_losing_other_sections_or_connection']='PASS_REAL_SQL57014_SAVEPOINT'
        checks['unknown_queue_count_stays_null_and_owned_statement_timeout_is_restored']='PASS'
        cancel=False;warm=store.report();count=warm['jobs'];stamp=warm['statistics_collection']['sections']['jobs']['observed_ns']
        cancel=True;cached=store.report()
        assert cached['jobs']==count and cached['statistics_collection']['sections']['jobs']['status']=='CACHED_AFTER_TIMEOUT'
        assert cached['statistics_collection']['sections']['jobs']['observed_ns']==stamp
        checks['cached_count_keeps_original_timestamp_and_is_not_labelled_current']='PASS'
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            readonly=store.report();assert readonly['statistics_collection']['status']=='PARTIAL'
            html=render(store,{'statistics':readonly},'/',{},'token')
            assert 'مقدار نامعلوم صفر محسوب نمی‌شود' in html and 'dir="rtl"' in html
        checks['partial_statistics_are_read_only_and_the_rtl_dashboard_explains_missing_counts']='PASS_HTML'
        class Deadline:
            at=0.
            def monotonic(self):return self.at
        budget=Deadline();called=[]
        def first():budget.at=2.;return 7
        values,quality=collect(store,[('first',first),('deferred',lambda:called.append(1))],clock=budget.monotonic,seconds=1)
        assert not called and values['deferred'] is None and quality['sections']['deferred']['status']=='DEFERRED_BUDGET'
        checks['statistics_start_budget_defers_remaining_sections_without_running_them']='PASS'
        try:collect(store,[('broken',lambda:raw.execute('SELECT * FROM anomaly_detection.missing_fixture_table'))])
        except Exception as exc:assert exc.sqlstate=='42P01'
        else:raise AssertionError('a non-timeout storage error was swallowed')
        assert raw.execute('SELECT 1 AS n').fetchone()['n']==1
        checks['non_timeout_schema_failures_still_propagate_and_rollback']='PASS'
        class Clock:
            elapsed=0.
            def monotonic(self):return 100+self.elapsed
            def time_ns(self):return T+10*FIVE_NS+int(self.elapsed*1e9)
            def wait(self,n):self.elapsed+=max(10,n)
        clock=Clock();prepared=[];profile_reads=[];errors=[]
        from anomaly_detection.process_control import safe_failure as classify
        def observed_failure(exc):errors.append({'type':type(exc).__name__,'message':str(exc)});return classify(exc)
        class Source:
            def __init__(self,project):self.project=Path(project);self.last_source=metadata(T);self.last_metrics=[]
            def page(self,after=None):return {'rows':[],'source':self.last_source,'after':None,'has_more':False}
            def profile(self,key):
                row=next(r for r in current if r['request_key']==key);profile_reads.append(key)
                p=point(int(key,16),ACTOR,row['at_ns'],topic='same-bill',subject='same-bill')
                p.update(service_path=service,semantic_active=True,semantic_revision=row['revision'],anchor_key=row['anchor_key'])
                return {'source':self.last_source,'request_key':key,'profile':p}
        def prepare(_):prepared.append(True);return raw
        with TemporaryDirectory(dir=ROOT/'validation') as temp:
            root=Path(temp)/'AnomalyDetection';root.mkdir()
            write_json(root/'RELEASE_MANIFEST.json',{'build_id':BUILD_ID,'source_sha256':'statistics-fixture20'})
            with patch('anomaly_detection.product_worker.safe_failure',side_effect=observed_failure), patch('anomaly_detection.product_pipeline.read_window_burst',return_value=[{'status':'CAUGHT_UP'}]), \
                 patch('anomaly_detection.scenario_traffic.read_page',return_value={'source':metadata(T),'status':'CAUGHT_UP'}), \
                 patch('anomaly_detection.service_sampling.read',return_value={'source':metadata(T),'status':'CAUGHT_UP'}), \
                 patch.object(ProductStore,'audit_keys',return_value=[]), \
                 patch('anomaly_detection.audit_scope.keys',return_value=[]):
                run(root,'statistics-fixture20',source_factory=Source,prepare_pg=prepare,clock=clock,wait=clock.wait,max_cycles=8,web=False)
            state=read_json(root/'reports/product_status.json')
        assert len(prepared)==1 and cancellations>=3,(len(prepared),cancellations,errors)
        assert state['source_attempts']>0 and state['evaluated_jobs']>0,state
        assert state['content_reads']==2 and state['scenario_evaluations']>0,state
        assert state.get('last_storage_failure') is None and state.get('last_scenario_failure') is None,state
        assert len(profile_reads)==2 and state['statistics_status']=='PARTIAL'
        checks['persistent_statistics_timeouts_do_not_reconnect_or_block_source_primary_profiles_and_scenario_jobs']='PASS_ONE_WRITER_CONNECTION_SYNTHETIC_SOURCE_PACKETS'
        # The worker deliberately closes only its owned connection on stop;
        # use a fresh handle to inspect the same isolated data.
        verify=engine.connect()
        assert verify.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_profiles').fetchone()['n']==2
        assert verify.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_scenario_jobs WHERE processed_version>0').fetchone()['n']>0
        checks['content_profiles_and_scenario_results_are_persisted_despite_the_statistics_failure']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_OPTIONAL_STATISTICS_FAILURE_ISOLATION_SQL','checks':checks,
            'native19_failure_statement':NATIVE_STATEMENT,'new_source_writes':0,'owner_connections':0,
            'native_windows_postgresql20':'NOT_RUN','production_precision_recall_capacity':'NOT_MEASURED'}
        (ROOT/'validation/PRODUCT_revision20.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
