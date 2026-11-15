"""Queue progress, bounded plans and epoch safety on disposable PostgreSQL."""
import json
import os
import time
import unittest
import uuid
from unittest.mock import patch

from anomaly_detection import FIVE_NS,CATALOG_SHA,SOURCE_SHA
from anomaly_detection import audit_scope,model_queue
from anomaly_detection.product_store import ProductStore
from anomaly_detection.snapshot import canonical

TARGET=100*FIVE_NS
SERVICE='Services.v1/WaterBills'


def nodes(plan):
    yield plan
    for child in plan.get('Plans',[]):yield from nodes(child)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native AD test cluster not configured')
class RuntimeBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.psycopg=psycopg;cls.sql=sql
        cls.params={'host':os.environ['P24_DELTA_PG_HOST'],'port':int(os.environ.get('P24_DELTA_PG_PORT','5432')),
                    'user':os.environ.get('P24_DELTA_PG_USER','postgres'),'connect_timeout':3}
        cls.admin=psycopg.connect(**cls.params,dbname='postgres',autocommit=True)

    @classmethod
    def tearDownClass(cls):cls.admin.close()

    def setUp(self):
        from psycopg.rows import dict_row
        self.name='p24_design_adbounds_'+uuid.uuid4().hex
        self.admin.execute(self.sql.SQL('CREATE DATABASE {}').format(self.sql.Identifier(self.name)))
        self.addCleanup(lambda:self.admin.execute(self.sql.SQL('DROP DATABASE {}').format(self.sql.Identifier(self.name))))
        self.raw=self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row)
        self.addCleanup(self.raw.close)
        self.raw.execute('CREATE SCHEMA anomaly_detection')
        self.store=ProductStore(self.raw);self.store.initialize();self.store._history_floor_ns=0

    def seed(self,count=1,*,legacy=False):
        self.raw.execute("INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,version,primary_version,primary_processed_version,dirty) "
            "SELECT 'actor-'||i,%s,7,4,%s,FALSE FROM generate_series(1,%s) i",(TARGET,None if legacy else 4,count))
        self.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs VALUES(%s,1)',('reference:'+SERVICE,))
        self.raw.execute('INSERT INTO anomaly_detection.adp_peer_dependencies(session_key,target_ns,service_path,begin_ns,epoch) '
            'SELECT session_key,target_ns,%s,%s,1 FROM anomaly_detection.adp_jobs',('reference:'+SERVICE,FIVE_NS))

    def job(self):return dict(self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',('actor-1',)).fetchone())
    def epoch(self):return self.raw.execute('SELECT version FROM anomaly_detection.adp_peer_epochs WHERE service_path=%s',('reference:'+SERVICE,)).fetchone()['version']

    def test_reference_burst_coalesces_but_epoch_rejects_inflight_and_completion_reopens(self):
        self.seed(legacy=True)
        # The first notification must invalidate a legacy signal even when
        # its job is already dirty for a secondary-model change.
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE')
        model_queue.reference_changed(self.store,[(SERVICE,TARGET-FIVE_NS)])
        pending=self.job();self.assertEqual(pending['primary_version'],5)
        self.assertEqual(pending['primary_processed_version'],4)
        previous=self.epoch()
        from psycopg.rows import dict_row
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row) as other:
            other_store=ProductStore(other)
            for _ in range(10):model_queue.reference_changed(other_store,[(SERVICE,TARGET-FIVE_NS)])
        self.assertEqual(self.job()['version'],pending['version'])
        self.assertEqual(self.epoch(),previous+10)
        stale={'source':{'captured_at_ns':TARGET},'peer_inputs':{'reference:'+SERVICE:previous}}
        self.assertEqual(self.store.complete(pending,stale,[],TARGET)['status'],'INPUT_CHANGED_RETRY')
        self.assertTrue(self.job()['dirty'])
        # A valid completion installs the current dependency generation.
        current={'source':{'captured_at_ns':TARGET},'peer_inputs':{'reference:'+SERVICE:self.epoch()}}
        with patch('anomaly_detection.cases.sync_actor'):
            self.assertEqual(self.store.complete(self.job(),current,[],TARGET)['status'],'APPLIED')
        self.assertFalse(self.job()['dirty'])
        self.assertEqual(self.job()['primary_processed_version'],5)
        dependency=self.raw.execute('SELECT * FROM anomaly_detection.adp_peer_dependencies').fetchone()
        self.assertIsNone(dependency['reference_notified_epoch'])
        model_queue.reference_changed(self.store,[(SERVICE,TARGET-FIVE_NS)])
        self.assertTrue(self.job()['dirty']);self.assertEqual(self.job()['primary_version'],6)

    def test_multiple_services_coalesce_same_pending_primary_and_time_boundaries_survive(self):
        self.seed()
        self.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs VALUES(%s,1)',('reference:other',))
        self.raw.execute("INSERT INTO anomaly_detection.adp_peer_dependencies(session_key,target_ns,service_path,begin_ns,epoch) "
            "VALUES('actor-1',%s,'reference:other',%s,1)",(TARGET,FIVE_NS))
        for at in (TARGET,TARGET+1,0):model_queue.reference_changed(self.store,[(SERVICE,at)])
        self.assertFalse(self.job()['dirty']) # at=0 precedes dependency begin
        model_queue.reference_changed(self.store,[(SERVICE,TARGET-1),('other',TARGET-1)])
        self.assertEqual(self.job()['primary_version'],5)
        self.assertEqual(self.job()['version'],8)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_peer_dependencies WHERE reference_notified_epoch IS NOT NULL').fetchone()['n'],2)

    def test_batched_notifications_and_parent_window_roll_back_together(self):
        self.seed(300)
        raw=self.raw
        class Interrupted:
            pages=0
            def __getattr__(self,name):return getattr(raw,name)
            def execute(self,sql,params=()):
                if 'SET reference_notified_epoch=' in sql:
                    self.pages+=1
                    if self.pages==2:raise RuntimeError('interrupt-publication')
                return raw.execute(sql,params)
        self.store.raw=Interrupted()
        with self.assertRaisesRegex(RuntimeError,'interrupt-publication'):
            with self.store.transaction():
                self.store.save_state('publication-test',{'complete':True})
                model_queue.reference_changed(self.store,[(SERVICE,TARGET-1)])
        self.store.raw=raw
        self.assertEqual(self.epoch(),1);self.assertFalse(self.job()['dirty'])
        self.assertEqual(self.store.state('publication-test'),{})
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_peer_dependencies WHERE reference_notified_epoch IS NOT NULL').fetchone()['n'],0)
        model_queue.reference_changed(self.store,[(SERVICE,TARGET-1)])
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs WHERE dirty').fetchone()['n'],300)

    def test_reference_history_avoids_repeated_full_queue_writes_and_keeps_pk_plans(self):
        count=100000;repeats=12
        self.seed(count)
        self.raw.execute('CREATE TABLE anomaly_detection.adp_legacy_jobs (LIKE anomaly_detection.adp_jobs INCLUDING ALL)')
        self.raw.execute('INSERT INTO anomaly_detection.adp_legacy_jobs SELECT * FROM anomaly_detection.adp_jobs')
        self.raw.execute('ANALYZE anomaly_detection.adp_peer_dependencies')
        self.raw.execute('ANALYZE anomaly_detection.adp_jobs');self.raw.execute('ANALYZE anomaly_detection.adp_legacy_jobs')
        plans={};raw=self.raw
        class CapturePlans:
            def __getattr__(self,name):return getattr(raw,name)
            def execute(self,sql,params=()):
                for table in ('adp_jobs','adp_peer_dependencies'):
                    if 'UPDATE anomaly_detection.'+table+' SET ' in sql and 'ctid=ANY' in sql and table not in plans:
                        plans[table]=raw.execute('EXPLAIN (FORMAT JSON) '+sql,params).fetchone()['QUERY PLAN'][0]['Plan']
                return raw.execute(sql,params)
        self.store.raw=CapturePlans()
        plan=self.raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT session_key,target_ns FROM anomaly_detection.adp_peer_dependencies '
            'WHERE service_path=%s AND reference_notified_epoch IS NULL AND target_ns>%s AND begin_ns<=%s '
            'ORDER BY target_ns,session_key LIMIT 128',('reference:'+SERVICE,TARGET-1,TARGET-1)).fetchone()['QUERY PLAN'][0]['Plan']
        self.assertTrue(any(n.get('Index Name')=='adp_peer_reference_scan_v1' for n in nodes(plan)))
        self.assertFalse(any(n['Node Type'] in ('Seq Scan','Sort') for n in nodes(plan)))
        times={'old':[],'bounded':[]};old_writes=0
        for i in range(repeats):
            # Alternate execution order on the same cluster; compare pending
            # rewrites separately from the necessary first invalidation.
            for variant in (('old','bounded') if i%2==0 else ('bounded','old')):
                started=time.perf_counter()
                if variant=='old':
                    old_writes+=self.raw.execute('WITH affected AS (SELECT DISTINCT session_key,target_ns '
                        'FROM anomaly_detection.adp_peer_dependencies WHERE service_path=%s AND begin_ns<=%s AND target_ns>%s) '
                        'UPDATE anomaly_detection.adp_legacy_jobs j SET primary_version=primary_version+1,version=version+1,dirty=TRUE,due_ns=0 '
                        'FROM affected a WHERE j.session_key=a.session_key AND j.target_ns=a.target_ns',
                        ('reference:'+SERVICE,TARGET-1,TARGET-1)).rowcount
                else:model_queue.reference_changed(self.store,[(SERVICE,TARGET-1)])
                times[variant].append(time.perf_counter()-started)
        self.assertEqual(old_writes,count*repeats)
        row=self.raw.execute('SELECT COUNT(*) AS n,MIN(version) AS lo,MAX(version) AS hi,BOOL_AND(dirty) AS pending FROM anomaly_detection.adp_jobs').fetchone()
        self.assertEqual(dict(row),{'n':count,'lo':8,'hi':8,'pending':True})
        self.assertEqual(self.epoch(),repeats+1)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_peer_dependencies').fetchone()['n'],count)
        for table,plan in plans.items():
            self.assertTrue(any(n['Node Type']=='Tid Scan' and n.get('Relation Name')==table for n in nodes(plan)))
            self.assertFalse(any(n['Node Type']=='Seq Scan' and n.get('Relation Name')==table for n in nodes(plan)))
        self.assertEqual(set(plans),{'adp_jobs','adp_peer_dependencies'})
        print('REFERENCE_BOUNDS '+json.dumps({'consumers':count,'reference_changes':repeats,'old_job_rewrites':old_writes,
            'bounded_job_rewrites':count,'old_seconds':round(sum(times['old']),4),
            'bounded_seconds':round(sum(times['bounded']),4),'bounded_repeat_seconds':round(sum(times['bounded'][1:]),4)}))

    def fact(self,request,session,target,*,details=None):
        self.raw.execute('INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,kind,state,revision,eligible,body,content_digest,last_seen_ns,details) '
            "VALUES(%s,%s,%s,%s,%s,'service_execution','active',1,TRUE,'{}','fixture',1,%s)",
            (request,'anchor-'+request,session,target+1,SERVICE,details))

    def test_owned_schema_upgrade_preserves_rows_restores_budget_and_skips_repeat_ddl(self):
        self.seed(2,legacy=True)
        for name in ('adp_peer_reference_scan_v1','adp_signal_candidate_scan_v1','adp_fact_candidate_needed_v1'):
            self.raw.execute('DROP INDEX anomaly_detection.'+name)
        self.raw.execute('ALTER TABLE anomaly_detection.adp_jobs DROP COLUMN primary_processed_version')
        self.raw.execute('ALTER TABLE anomaly_detection.adp_peer_dependencies DROP COLUMN reference_notified_epoch')
        self.raw.execute("SET statement_timeout='3s'")
        self.store.initialize()
        self.assertEqual(self.store.initialization_schema['executed'],5)
        self.assertEqual(self.job()['version'],7);self.assertIsNone(self.job()['primary_processed_version'])
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_peer_dependencies').fetchone()['n'],2)
        self.assertEqual(self.raw.execute('SHOW statement_timeout').fetchone()['statement_timeout'],'3s')
        self.store.initialize();self.assertEqual(self.store.initialization_schema['executed'],0)

    def signal(self,key,session,target,*,review=True,family='rate_5m',body=None,primary=4):
        values=dict(signal_key=key,case_key='case-'+key,scope_key='scope-'+key,job_session=session,target_ns=target,
            job_version=1,source_kind='actor',family=family,state='ACTIVE',qualified=True,review_eligible=review,
            begin_ns=target,end_ns=target+FIVE_NS,score=1,body=canonical(body or {}),content_digest='fixture',updated_ns=1,primary_version=primary)
        self.raw.execute('INSERT INTO anomaly_detection.adp_case_signals('+','.join(values)+') VALUES('+','.join(['%s']*len(values))+')',tuple(values.values()))

    def source_window(self,target):
        # Use the installed store's real packet path for its owned window.
        from tests.test_scenario_invalidation_pg import NativeScenarioInvalidationTests
        packet=NativeScenarioInvalidationTests.window_packet(self)
        packet['target_ns']=target;packet['rows']=[]
        from anomaly_detection.product_pipeline import apply_window
        self.assertEqual(apply_window(self.store,packet)['status'],'COMPLETE')

    def test_candidate_pass_progresses_through_empty_pages_survives_restart_and_new_arrivals(self):
        self.source_window(TARGET)
        self.raw.execute("INSERT INTO anomaly_detection.adp_case_signals(signal_key,case_key,scope_key,job_session,target_ns,job_version,source_kind,family,state,qualified,review_eligible,begin_ns,end_ns,score,body,content_digest,updated_ns) "
            "SELECT 'sig-'||lpad(i::text,6,'0'),'case','scope','actor-'||i,%s,1,'actor','rate_5m','ACTIVE',TRUE,FALSE,%s,%s,1,'{}','fixture',1 FROM generate_series(1,320) i",(TARGET,TARGET,TARGET+FIVE_NS))
        self.signal('wanted','000-old',TARGET)
        self.fact('request-needed','000-old',TARGET)
        self.raw.execute('ANALYZE anomaly_detection.adp_case_signals')
        original=audit_scope.candidate_page;pages=[]
        def record(store,after):
            page=original(store,after);pages.append(len(page));return page
        found=[]
        with patch('anomaly_detection.audit_scope.candidate_page',side_effect=record):
            for i in range(15):
                found=audit_scope.keys(self.store,TARGET)
                if found:break
                # A new top-of-history hint must not restart/starve the pass.
                self.signal('new-'+str(i),'zzz-'+str(i),TARGET+FIVE_NS)
                self.store=ProductStore(self.raw);self.store._history_floor_ns=0
        self.assertEqual(found,['request-needed'])
        self.assertGreater(len(pages),1);self.assertTrue(all(n<=32 for n in pages))
        self.assertEqual(audit_scope.keys(self.store,TARGET),['request-needed'])

    def test_candidate_hints_keep_canonical_legacy_rules_and_exact_due_index(self):
        self.source_window(TARGET);self.seed()
        self.fact('canonical','canonical',TARGET);self.fact('missing-job','missing-job',TARGET)
        self.fact('current-job','actor-1',TARGET)
        self.signal('canonical','canonical',TARGET,review=False,family='peer_service_rate_5m',
            body={'baseline_unit':'canonical_service_executions','service_path':SERVICE},primary=1)
        self.signal('missing','missing-job',TARGET,review=False,family='peer_service_rate_5m',primary=None)
        self.signal('current','actor-1',TARGET,review=False,family='peer_service_rate_5m')
        found=set()
        for _ in range(8):
            found.update(audit_scope.keys(self.store,TARGET))
            self.store.save_state(audit_scope.STATE,{})
        self.assertEqual(found,{'canonical','current-job'})
        self.raw.execute("INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,state,revision,eligible,body,content_digest,last_seen_ns) "
            "SELECT 'old-'||i,'old-anchor-'||i,'actor-1',%s-i*%s,%s,'active',1,TRUE,'{}','fixture',1 FROM generate_series(1,20000) i",(TARGET,FIVE_NS,SERVICE))
        # A dense target where almost every request is already fully audited
        # distinguishes the needed-evidence index from a normal time lookup.
        from anomaly_detection.input_subjects import VERSION
        self.raw.execute("INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,state,revision,eligible,body,content_digest,last_seen_ns,details) "
            "SELECT 'done-'||i,'done-anchor-'||i,'actor-1',%s,%s,'active',1,TRUE,'{}','fixture',1,"
            "jsonb_build_object('source_present',TRUE,'quality',jsonb_build_object('evidence_available',TRUE,'conflicted',FALSE),"
            "'semantic',jsonb_build_object('state','active','revision',1,'anchor_key','done-anchor-'||i),"
            "'input_subject',jsonb_build_object('version',%s::text,'status','VERIFIED'))::text FROM generate_series(1,20000) i",
            (TARGET+1,SERVICE,VERSION))
        self.raw.execute('ANALYZE anomaly_detection.adp_facts')
        sql='SELECT f.request_key FROM anomaly_detection.adp_facts f WHERE '+audit_scope.FACT_SCOPE+audit_scope.needed()+' ORDER BY f.next_audit_ns,f.request_key LIMIT %s'
        plan=self.raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,('actor-1',TARGET,TARGET+FIVE_NS,TARGET,TARGET,1)).fetchone()['QUERY PLAN'][0]['Plan']
        self.assertTrue(any(n.get('Index Name')=='adp_fact_candidate_needed_v1' for n in nodes(plan)),canonical(plan))
        self.assertFalse(any(n['Node Type'] in ('Seq Scan','Sort') for n in nodes(plan)))
        self.assertEqual(audit_scope.due_requests(self.store,{'session_key':'actor-1','target_ns':TARGET},TARGET,1),['current-job'])
        self.store._history_floor_ns=TARGET+FIVE_NS
        self.store.save_state(audit_scope.STATE,{})
        self.assertEqual(audit_scope.keys(self.store,TARGET),[])

    def test_request_scoped_source_read_retains_all_identifiers_without_global_scan(self):
        from anomaly_detection.pg_source import collect_sample
        queries=[]
        class StopRead(Exception):pass
        def capture(sql,params=(),**kw):
            if 'current_database()' in sql:return [{'database':'p24_design_viewer','read_only':'on','isolation':'repeatable read'}]
            if 'viewer_live_state' in sql:return [{'generation':1,'stream_key':'fixture','keys_fingerprint':'fixture','next_ns':TARGET}]
            if 'viewer_semantic_checkpoint' in sql:return [{'generation':1,'state':'ready'}]
            if 'viewer_service_catalog_state' in sql:return [{'fingerprint':CATALOG_SHA}]
            queries.append((sql,params))
            if 'public.viewer_events' in sql:raise StopRead()
            return []
        wanted=['0'*63+'1','0'*63+'2']
        with self.assertRaises(StopRead):collect_sample(capture,runtime_sha256=SOURCE_SHA,request_keys=wanted,sample_limit=2)
        sql,params=next((q,p) for q,p in queries if 'public.viewer_contract_identifiers' in q)
        self.raw.execute('CREATE TABLE public.viewer_contract_identifiers(origin_key TEXT,version_key TEXT,request_key TEXT,issuer TEXT,kind TEXT,scope TEXT,field_path TEXT,identity_key TEXT)')
        self.raw.execute("INSERT INTO public.viewer_contract_identifiers SELECT 'origin-'||i,'version-'||(i%3),lpad((i/4)::text,64,'0'),'issuer','kind','scope','field','identity-'||i FROM generate_series(1,1000000) i")
        self.raw.execute('CREATE INDEX vci_req ON public.viewer_contract_identifiers(request_key)')
        self.raw.execute('ANALYZE public.viewer_contract_identifiers')
        old=self.raw.execute('SELECT * FROM public.viewer_contract_identifiers WHERE request_key=ANY(%s)',(wanted,)).fetchall()
        new=self.raw.execute(sql,params).fetchall()
        self.assertEqual(sorted(map(canonical,new)),sorted(map(canonical,old)))
        self.assertEqual(len(new),8)
        plan=self.raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,params).fetchone()['QUERY PLAN'][0]['Plan']
        self.assertTrue(any(n.get('Index Name')=='vci_req' for n in nodes(plan)))
        self.assertFalse(any(n['Node Type']=='Seq Scan' for n in nodes(plan)))

    def test_one_request_can_finish_after_one_second_while_page_budget_stays_one_second(self):
        from anomaly_detection.pg_source import product_read_budget,BudgetQuery
        with self.assertRaises(self.psycopg.errors.QueryCanceled):
            with self.raw.transaction(),product_read_budget():
                self.raw.execute('SET TRANSACTION READ ONLY')
                BudgetQuery(self.raw)('SELECT pg_sleep(1.1) AS pause',cap=1)
        with self.raw.transaction(),product_read_budget(single_request=True):
            self.raw.execute('SET TRANSACTION READ ONLY')
            query=BudgetQuery(self.raw)
            self.assertEqual(len(query('SELECT pg_sleep(1.1) AS pause',cap=1)),1)
            self.assertEqual(query.statement_ms,2000)
            self.assertEqual(self.raw.execute("SELECT current_setting('transaction_read_only') AS value").fetchone()['value'],'on')
        with product_read_budget():self.assertEqual(BudgetQuery(self.raw).statement_ms,1000)

    def test_origin_probe_keeps_cross_request_versions_and_missing_raw_with_both_key_layouts(self):
        from anomaly_detection.pg_source import origin_events
        import sys
        from pathlib import Path
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
        from p24_foundation import viewer_origin_storage as origin
        self.raw.execute('CREATE TABLE public.viewer_events(origin_key TEXT,version_key TEXT,request_key TEXT,at_ns BIGINT,callpath TEXT,PRIMARY KEY(origin_key,version_key))')
        self.raw.execute("INSERT INTO public.viewer_events SELECT lpad((i/3)::text,64,'0'),lpad((i%3)::text,64,'0'),'request-'||i,i,'Services.v1/Fixture' FROM generate_series(1,500000) i")
        self.raw.execute('CREATE TABLE public.viewer_raw_events(origin_key TEXT,version_key TEXT,PRIMARY KEY(origin_key,version_key))')
        self.raw.execute("INSERT INTO public.viewer_raw_events SELECT origin_key,version_key FROM public.viewer_events WHERE at_ns%5<>0")
        self.raw.execute('CREATE FUNCTION '+origin.FUNCTION+'(key_text text) RETURNS bytea LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $origin$'+origin.BODY+'$origin$')
        for table in ('viewer_events','viewer_raw_events'):
            self.raw.execute('CREATE INDEX '+table+'_binary ON public.'+table+'('+origin.key_sql('origin_key')+','+origin.key_sql('version_key')+')')
            self.raw.execute('ANALYZE public.'+table)
        wanted=[str(i).zfill(64) for i in (1,2,3,20,1000,140000)]
        expected=self.raw.execute('SELECT e.*,EXISTS(SELECT 1 FROM public.viewer_raw_events r WHERE r.origin_key=e.origin_key AND r.version_key=e.version_key) AS raw_available FROM public.viewer_events e WHERE e.origin_key=ANY(%s)',(wanted,)).fetchall()
        raw=self.raw
        for binary in (False,True):
            plans=[]
            def q(sql,params):
                if binary:sql=origin.qualify(sql)
                plans.append(raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,params).fetchone()['QUERY PLAN'][0]['Plan'])
                return raw.execute(sql,params).fetchall()
            q.origin_keys_active=lambda:binary;q._origin_module=origin
            found=origin_events(q,wanted)
            self.assertEqual(sorted(map(canonical,found)),sorted(map(canonical,expected)))
            self.assertEqual(len(found),18)
            self.assertTrue(any(not r['raw_available'] for r in found))
            self.assertGreater(len({r['request_key'] for r in found}),len(wanted))
            self.assertFalse(any(n['Node Type']=='Seq Scan' for n in nodes(plans[0])))


if __name__=='__main__':unittest.main()
