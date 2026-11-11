"""Native PG18 qualification; only creates its own disposable p24_design_delta_* DBs.

Opt in with P24_DELTA_PG_HOST / PORT / USER for a test PostgreSQL cluster.
Never opens the Viewer product database or reads its private config.
"""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import initialize_live, bind_stream, publish_capture, affected_closure
from tests.test_viewer_online import START, FIVE_NS, verified_file, snapshot, iso
from tests.test_viewer_r6_service_journey import log, sql


def crash_publish(config, keys, capture, start, point):
    db=ViewerDB(config=config,keys_path=keys)
    publish_capture(db,capture,start,start+FIVE_NS,fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


def sleeping_viewer_backend(config):
    import psycopg
    with psycopg.connect(**config,autocommit=True) as raw:
        raw.execute('SELECT pg_advisory_lock(240026,1)')
        raw.execute('SELECT pg_sleep(30)')


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 test cluster not configured')
class NativeMinimalPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql as pgsql
        cls.pgsql=pgsql
        cls.parameters={'host':os.environ['P24_DELTA_PG_HOST'],
            'port':int(os.environ.get('P24_DELTA_PG_PORT','5432')),
            'user':os.environ.get('P24_DELTA_PG_USER',os.environ.get('USER','postgres')),
            'connect_timeout':3}
        cls.admin=psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True)
        version=int(cls.admin.execute('SHOW server_version_num').fetchone()[0])
        if version<180000:raise unittest.SkipTest('PG18+ required for this native qualification')

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.keys=self.root/'keys';generate_keys(self.keys)
        self.name='p24_design_delta_'+uuid.uuid4().hex
        self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(self.name)))
        self.addCleanup(lambda:self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(self.name))))
        self.config=dict(self.parameters,dbname=self.name)
        self.db=ViewerDB(config=self.config,keys_path=self.keys);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='native-delta')

    def publish(self,rows,start=START,mode='forward',fault=None):
        path=verified_file(self.root/(uuid.uuid4().hex+'.gz'),rows,start)
        return publish_capture(self.db,path,start,start+FIVE_NS,mode=mode,fault=fault)

    def test_native_scoped_pipeline_late_payment_and_revision_equal_full_rebuild(self):
        first=[log(1,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
            log(2,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
            log(3,'late','ClientAyanCoTopUp.ProductReserve Line:1','Output:[]')]
        self.publish(first);self.publish([],START+FIVE_NS)
        callback=log(4,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))
        callback['@timestamp']=iso(START+2*FIVE_NS+65_000_000_000)
        late=log(5,'late','Services.v1/TopUpProductPurchase Line:1','POST (G00000 | successful)')
        late['@timestamp']=iso(START+2*FIVE_NS+70_000_000_000)
        self.publish([callback,late],START+2*FIVE_NS)
        key=self.db.lookup_request('pay')['request_key']
        self.assertEqual(len(affected_closure(self.db,[key])),2);self.db.conn.rollback()
        changed=dict(first[1],RequestID='new-owner',message=sql('ud_prc_paymentExists',paymentKey='K2'))
        self.publish([first[0],changed,first[2]],mode='recheck')
        before=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(before,snapshot(self.db))
        self.assertEqual(self.db.lookup_request('pay')['conflicted'],1)
        self.assertEqual(self.db.lookup_request('new-owner')['conflicted'],1)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],4)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+3*FIVE_NS)

    def test_native_rollback_after_contract_keeps_evidence_and_cursor_atomic(self):
        self.publish([log(1,'first','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        before=snapshot(self.db);state=self.db.one('SELECT * FROM viewer_live_state');self.db.conn.rollback()
        row=log(2,'second','Services.v1/ElectricBills Line:1','POST (G00000 | successful)')
        row['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        def fault(stage):
            if stage=='after_relations':raise RuntimeError('injected_after_contract')
        with self.assertRaises(RuntimeError):self.publish([row],START+FIVE_NS,fault=fault)
        self.assertEqual(before,snapshot(self.db));self.assertEqual(state,self.db.one('SELECT * FROM viewer_live_state'))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],1)
        self.db.conn.rollback();self.publish([row],START+FIVE_NS)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],2)

    def test_concurrent_read_only_snapshot_and_observer_queries_are_native_compatible(self):
        import importlib.util
        import psycopg
        from psycopg.rows import dict_row
        path=Path(__file__).resolve().parents[1]/'AnomalyDetection/validation/observe_viewer_live.py'
        spec=importlib.util.spec_from_file_location('native_observer',path)
        observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
        web_path=Path(__file__).resolve().parents[1]/'viewer_performance/Run_Viewer_Web.py'
        web_spec=importlib.util.spec_from_file_location('native_existing_web',web_path)
        web=importlib.util.module_from_spec(web_spec);web_spec.loader.exec_module(web)
        self.publish([log(1,'first','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row,
                options='-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=100') as reader:
            reader.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
            count=lambda:reader.execute('SELECT COUNT(*) AS n FROM viewer_requests').fetchone()['n']
            self.assertEqual(count(),1)
            row=log(2,'second','Services.v1/ElectricBills Line:1','POST (G00000 | successful)')
            row['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
            observed=[]
            def during(stage):
                if stage=='after_relations':
                    observed.append(count())
                    web.check_existing({'config':self.config,'keys_path':self.keys})
            self.publish([row],START+FIVE_NS,fault=during)
            self.assertEqual(observed,[1]);self.assertEqual(count(),1)
            reader.execute('ROLLBACK');self.assertEqual(count(),2)
            probe=observer.Reader(reader)
            for statement in (observer.STATE_SQL,observer.RECEIPTS_SQL,observer.RESUMES_SQL,
                    observer.ACTIVITY_SQL,observer.TABLES_SQL,observer.AD_COUNTERS_SQL,observer.INDEXES_SQL,*observer.COUNTERS.values()):
                self.assertEqual(probe.optional(statement)['status'],'READ')
            guard=probe.rows("SELECT current_setting('transaction_read_only') AS read_only")
            self.assertEqual(guard,[{'read_only':'on'}])

    def test_process_crash_rolls_back_then_retry_and_postcommit_crash_remains_committed(self):
        self.publish([log(1,'first','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        row=log(2,'second','Services.v1/ElectricBills Line:1','POST (G00000 | successful)')
        start=START+FIVE_NS;row['@timestamp']=iso(start+1_000_000_000)
        path=verified_file(self.root/'crash.gz',[row],start)
        self.db.conn.rollback()
        for point,expected_receipts in (('after_relations',1),('after_commit',2)):
            child=multiprocessing.get_context('spawn').Process(target=crash_publish,
                args=(self.config,self.keys,path,start,point))
            child.start();child.join(20)
            if child.is_alive():child.terminate();child.join(5);self.fail('own crash-test child exceeded deadline')
            self.assertEqual(child.exitcode,73)
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],expected_receipts)
            self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],
                start if point=='after_relations' else start+FIVE_NS)
            self.db.conn.rollback()
        from p24_foundation.viewer_online import LiveWorker
        # Scheduler reads the committed cursor; it cannot replay the committed
        # window after the child died before acknowledging success.
        requested=[]
        def capture(a,b):requested.append((a,b));return verified_file(self.root/'next.gz',[],a)
        result=LiveWorker(self.db,capture).step(now=start+2*FIVE_NS+60_000_000_000)
        self.assertEqual(requested,[(start+FIVE_NS,start+2*FIVE_NS)])
        self.assertEqual(result['status'],'PUBLISHED')
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],3)

    def test_large_group_no_clique_and_session_head_plan_reads_only_first_active_row(self):
        self.db.many('INSERT INTO viewer_links VALUES(?,?,?,?,?)',
            [('o'+str(n),'v','r'+str(n),'platform_payment','same') for n in range(2000)])
        self.assertEqual(len(affected_closure(self.db,['r0'])),2000)
        self.db.many('''INSERT INTO viewer_semantic_occurrences(request_key,anchor_key,session_key,anchor_ns,
            state,revision,updated_at) VALUES(?,?,?,?,?,?,?)''',
            [(str(n).zfill(64),'anchor'+str(n),'hot' if n<1000 else 'other'+str(n%20),n,'active',1,'fixture')
                for n in range(20000)])
        self.db.sql('ANALYZE viewer_semantic_occurrences')
        self.db._refresh_semantic_session_heads(['hot'])
        self.assertEqual(self.db.one('SELECT anchor_ns FROM viewer_semantic_session_heads')['anchor_ns'],999)
        plan=self.db.one("EXPLAIN (ANALYZE,FORMAT JSON) SELECT request_key,anchor_ns FROM viewer_semantic_occurrences WHERE session_key='hot' AND state='active' ORDER BY anchor_ns DESC,request_key DESC LIMIT 1")
        root=plan['QUERY PLAN'][0]['Plan'];child=root['Plans'][0]
        self.assertEqual(root['Actual Rows'],1)
        self.assertEqual(child['Node Type'],'Index Scan')
        self.assertEqual(child['Index Name'],'vso_session_latest')
        self.assertEqual(child['Actual Rows'],1)

    def test_global_validity_snapshot_sees_other_request_versions_and_caps_probe_at_two(self):
        row=log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        self.publish([row])
        original=self.db.one('SELECT * FROM viewer_events LIMIT 1')
        columns=[d[0] for d in self.db.sql('SELECT * FROM viewer_events LIMIT 0').description]
        for n in range(3):
            changed=dict(original,version_key='outside-version'+str(n),request_key='outside-request'+str(n))
            self.db.sql('INSERT INTO viewer_events VALUES('+','.join('?' for _ in columns)+')',[changed[c] for c in columns])
        self.db.rebuild(request_keys=[original['request_key']],commit=False)
        cache=self.db.one('SELECT version_count FROM viewer_projection_versions WHERE origin_key=?',(original['origin_key'],))
        self.assertEqual(cache['version_count'],2)
        request=self.db.one('SELECT conflicted,root_call FROM viewer_requests WHERE request_key=?',(original['request_key'],))
        self.assertEqual(request,{'conflicted':1,'root_call':None})
        self.db.conn.rollback()

    def test_readonly_control_can_end_only_the_exact_singleton_session(self):
        import importlib.util
        from datetime import timedelta
        import psycopg
        from psycopg.rows import dict_row
        path=Path(__file__).resolve().parents[1]/'viewer_performance/Stop_Viewer_Worker.py'
        spec=importlib.util.spec_from_file_location('native_stop_control',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row) as held, \
             psycopg.connect(**self.config,autocommit=True,row_factory=dict_row,
                options='-c default_transaction_read_only=on') as reader:
            held.execute('SELECT pg_advisory_lock(240026,1)')
            lease=dict(reader.execute(module.LEASE_SQL).fetchone())
            self.assertFalse(module.terminate_lease(reader,dict(lease,backend_start=lease['backend_start']+timedelta(seconds=1))))
            self.assertFalse(module.terminate_lease(reader,dict(lease,client_port=lease['client_port']+1)))
            self.assertFalse(module.terminate_lease(reader,dict(lease,client_addr='192.0.2.1')))
            self.assertEqual(held.execute('SELECT 1 AS n').fetchone()['n'],1)
            self.assertTrue(module.terminate_lease(reader,lease))
            self.assertEqual(reader.execute(module.LEASE_SQL).fetchall(),[])

    def test_dead_client_with_sleeping_server_is_cleaned_by_exact_lease_and_release_is_observed(self):
        import importlib.util
        import time
        import psycopg
        from psycopg.rows import dict_row
        path=Path(__file__).resolve().parents[1]/'viewer_performance/Stop_Viewer_Worker.py'
        spec=importlib.util.spec_from_file_location('orphan_viewer_control',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        child=multiprocessing.get_context('spawn').Process(target=sleeping_viewer_backend,args=(self.config,))
        child.start()
        try:
            with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row) as reader:
                deadline=time.monotonic()+8;value=None
                while time.monotonic()<deadline:
                    rows=reader.execute(module.LEASE_SQL).fetchall()
                    if rows:
                        current=reader.execute('SELECT wait_event FROM pg_stat_activity WHERE pid=%s',(rows[0]['pid'],)).fetchone()
                        if current and current['wait_event']=='PgSleep':value=dict(rows[0]);break
                    time.sleep(.05)
                self.assertIsNotNone(value,'own child did not enter its bounded sleep')
                child.terminate();child.join(5);self.assertFalse(child.is_alive())
                self.assertTrue(module.same_lease(value,dict(reader.execute(module.LEASE_SQL).fetchone())))
                self.assertTrue(module.terminate_lease(reader,value))
                def lease():
                    rows=reader.execute(module.LEASE_SQL).fetchall()
                    return dict(rows[0]) if rows else None
                result=module.observe_release(lease,value,{'process_stopped':True},timeout=3)
                self.assertEqual(result['status'],'VIEWER_WORKER_STOPPED')
                self.assertTrue(result['postgres_lock_released'])
        finally:
            if child.is_alive():child.terminate();child.join(5)

    def bounded_ad_source(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        import psycopg
        from psycopg.rows import dict_row
        queries=[]
        @contextmanager
        def snapshot():
            with psycopg.connect(**self.config,row_factory=dict_row) as raw:
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                def q(statement,params=(),*,cap):
                    self.assertTrue(statement.lstrip().startswith('SELECT '))
                    queries.append((statement,params))
                    rows=raw.execute(statement,params).fetchall()
                    self.assertLessEqual(len(rows),cap)
                    return [dict(row) for row in rows]
                yield q
        source=SimpleNamespace(project=Path(__file__).resolve().parents[1],snapshot=snapshot,
            metadata=lambda q:{'generation':1,'semantic_generation':1,'next_ns':START+FIVE_NS,
                               'analysis_floor_ns':0,'retention_cutoff_ns':0})
        return source,queries

    def test_bounded_technical_census_advances_empty_raw_pages_and_equals_complete_root_query(self):
        from AnomalyDetection.anomaly_detection.scenario_traffic import read_page
        rows=[log(n,'provider-'+str(n),'ClientFixture.Call','Output:[]') for n in range(1,131)]
        for n,row in enumerate(rows,1):row['@timestamp']=iso(START+n*1_000_000_000)
        root=log(201,'root','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        root['@timestamp']=iso(START+201*1_000_000_000)
        rows.append(root)
        self.publish(rows)
        expected=[r['request_key'] for r in self.db.all("SELECT e.request_key FROM viewer_events e JOIN viewer_requests r ON r.request_key=e.request_key WHERE e.kind IN ('client','other') AND trim(split_part(e.callpath,' Line:',1))=trim(split_part(r.root_call,' Line:',1)) ORDER BY e.at_ns,e.origin_key")]
        source,queries=self.bounded_ad_source();cursor={'page_size':64};found=[];scanned=0
        for turn in range(8):
            packet=read_page(source,cursor)
            self.assertLessEqual(packet['scanned_events'],64)
            if turn==0:self.assertEqual(packet['rows'],[]);self.assertTrue(packet['has_more'])
            found.extend(r['request_key'] for r in packet['rows']);scanned+=packet['scanned_events']
            if not packet['has_more']:break
            cursor={'target_ns':packet['target_ns'],'stamp':packet['stamp'],'after':packet['after'],'page_size':64}
        self.assertEqual(scanned,len(rows));self.assertEqual(found,expected)
        self.assertTrue(any('page AS MATERIALIZED' in q[0] for q in queries))

    def test_native_content_reader_uses_one_raw_batch_and_preserves_qualified_profile(self):
        from AnomalyDetection.anomaly_detection.request_profiles import read
        rows=[log(1,'profile','Services.v1/WaterBills Line:1','POST (G00000 | successful)')]
        rows.extend(log(n,'profile','ClientFixture.Call','Input:{"BillID":"001"} Output:{"Result":true}') for n in range(2,5))
        self.publish(rows)
        key=self.db.lookup_request('profile')['request_key']
        source,queries=self.bounded_ad_source();packet=read(source,key)
        self.assertTrue(packet['profile']['qualified'])
        self.assertTrue(packet['profile']['input_complete'])
        batches=[q for q in queries if q[0].startswith('SELECT k.origin_key')]
        self.assertEqual(len(batches),1);self.assertEqual(len(batches[0][1]),8)

    def test_control_normalizes_native_inet_text_and_preserves_local_only_guard(self):
        import importlib.util
        import psycopg
        from psycopg.rows import dict_row
        path=Path(__file__).resolve().parents[1]/'viewer_performance/Stop_Viewer_Worker.py'
        spec=importlib.util.spec_from_file_location('native_control_addresses',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row) as held, \
             psycopg.connect(**self.config,autocommit=True,row_factory=dict_row,
                options='-c default_transaction_read_only=on') as reader:
            rows=reader.execute("""SELECT address::text AS legacy,host(address) AS normalized,expected
                FROM (VALUES ('127.0.0.1'::inet,true),('::1'::inet,true),
                    ('::ffff:127.0.0.1'::inet,true),('192.0.2.1'::inet,false),
                    ('2001:db8::1'::inet,false)) AS endpoints(address,expected)""").fetchall()
            for row in rows:
                with self.assertRaises(ValueError):module.ipaddress.ip_address(row['legacy'])
                self.assertEqual(module.loopback(row['legacy']),row['expected'])
                self.assertEqual(module.loopback(row['normalized']),row['expected'])
            legacy=reader.execute('SELECT inet_server_addr()::text AS address').fetchone()['address']
            self.assertIn('/',legacy)
            with self.assertRaises(ValueError):module.ipaddress.ip_address(legacy)
            guard=reader.execute(module.GUARD_SQL).fetchone()
            self.assertEqual(guard['db'],self.name)
            self.assertNotIn('/',guard['address'])
            server_address=module.ipaddress.ip_interface(legacy).ip
            self.assertEqual(module.ipaddress.ip_address(guard['address']),server_address)
            # Docker port publishing can expose the container's non-loopback
            # address. The product's local-only check must still reject it.
            self.assertEqual(module.loopback(guard['address']),server_address.is_loopback)
            self.assertEqual(module.loopback(legacy),server_address.is_loopback)
            held.execute('SELECT pg_advisory_lock(240026,1)')
            lease=dict(reader.execute(module.LEASE_SQL).fetchone())
            self.assertEqual(lease['pid'],held.info.backend_pid)
            self.assertNotIn('/',lease['client_addr'])
            client=held.execute('SELECT host(inet_client_addr()) AS address').fetchone()['address']
            self.assertEqual(lease['client_addr'],client)
            self.assertEqual(module.loopback(client),module.ipaddress.ip_address(client).is_loopback)


if __name__=='__main__':unittest.main()
