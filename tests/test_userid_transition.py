import gzip
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from account_behavior import storage
from account_behavior.identity import Evidence,observed
from compact_behavior import FIVE
from compact_behavior.extract import instant,iso
from compact_behavior.source import WindowFile
from tools.userid_transition import samples


def source_hit(rid,uid,at,**other):
    return {'_source':dict(RequestID=rid,UserID=uid,Session='****',message='private witness',
                           CallPath='Services.v1/WaterBills',**{'@timestamp':iso(at)},**other)}


class Source:
    def __init__(self,rows):
        self.rows=rows
        self.metadata={}
    def records(self):
        yield from self.rows
        self.metadata=dict(count=len(self.rows),expected_count=len(self.rows),complete=True,method='fixture')


class IdentityTests(unittest.TestCase):
    def test_only_structured_core_account_id_is_authoritative(self):
        for v in (True,'1e3',2.0,2**63,-12,{},[1,2]):
            self.assertIsNone(observed({'UserID':v})[0])
        self.assertEqual(observed({'_source':{'UserID':2**63-1},'fields':{'UserID':[str(2**63-1)]}}),(2**63-1,'VALID'))
        self.assertEqual(observed({'_source':{'UserID':'20'},'fields':{'UserID':[21]}}),(None,'CONFLICT'))
        for v in (None,0,'0','****','N/A',''):
            self.assertIsNone(observed({'UserID':v,'Session':'abc','message':'UserID=77','IP':'192.0.2.5'})[0])
        self.assertEqual(observed({'fields':{'UserID':['0017']}}),(17,'VALID'))
        self.assertIsNone(observed({'message':'{"UserID":17}','Session':'17','userid':17})[0])

    def test_evidence_is_order_independent_and_cutoff_is_exclusive(self):
        hits=[(22,4),(10,2),(12,2),(20,9),(25,8)]
        def resolve(rows):
            result=Evidence()
            for at,uid in rows:result=result.merge(Evidence.from_row({'UserID':uid},at))
            return result
        a=resolve(hits)
        self.assertEqual(a,resolve(list(reversed(hits))))
        self.assertEqual(a.resolve(10),(None,'UNATTRIBUTED'))
        self.assertEqual(a.resolve(20),(2,'VERIFIED'))
        self.assertEqual(a.resolve(21),(None,'CONFLICT'))

    def test_samples_remove_credentials_and_preserve_identity_shapes_across_windows(self):
        t=instant(storage.ORIGIN); aliases=samples.Aliases()
        with TemporaryDirectory() as d:
            for i in range(2):
                src=Source([source_hit('original-request','789321',t+i*FIVE),source_hit('second',0,t+i*FIVE)])
                path=Path(d)/f'{i}.json.gz';states,report=samples.write_window(src,path,aliases,t+i*FIVE)
                if i==0:first=states
                else:self.assertEqual(set(states),set(first))
                data=gzip.decompress(path.read_bytes()).decode()
                for private in ('789321','original-request','private witness','****'):
                    self.assertNotIn(private,data)
                self.assertEqual(report['identity_by_request'],{'VERIFIED':1,'UNATTRIBUTED':1})
                projected,count,_=storage.scan(WindowFile(path),t+i*FIVE)
                self.assertEqual(len(projected),2);self.assertEqual(count,2)


@unittest.skipUnless(os.getenv('P24_DELTA_PG_HOST'),'requires disposable PostgreSQL')
class DatabaseTests(unittest.TestCase):
    def test_fresh_database_replay_corrections_conflict_and_atomicity(self):
        cfg=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
                 user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
        name='p24_accounts_test_'+uuid4().hex[:12];stream='test-source';t=instant(storage.ORIGIN)
        self.assertTrue(storage.prepare(cfg,stream,name)['created'])
        self.assertFalse(storage.prepare(cfg,stream,name)['created'])
        with self.assertRaisesRegex(ValueError,'mismatch'):storage.prepare(cfg,'other',name)
        def write(db,at,records):
            fr,n,_=storage.scan(Source(records),at)
            return storage.publish(db,stream,at,fr,n)
        with storage.connect(cfg,name) as db:
            def state(r):return db.execute('SELECT user_id,status,revision FROM p24_account.requests WHERE request_id=%s',(r,)).fetchone()
            r1=source_hit('one',0,t);r2=source_hit('two',444,t+1)
            write(db,t,[r1,r2]);self.assertEqual(state('one')['status'],'UNATTRIBUTED')
            next_rows=[source_hit('one','444',t+FIVE),source_hit('three',777,t+FIVE)]
            write(db,t+FIVE,next_rows)
            self.assertEqual(state('one')['user_id'],state('two')['user_id'])
            self.assertEqual(db.execute('SELECT count(DISTINCT user_id) AS n FROM p24_account.requests').fetchone()['n'],2)
            self.assertEqual(write(db,t+FIVE,next_rows)['changes'],0)
            write(db,t,[source_hit('one',999,t),r2]);self.assertEqual(state('one')['status'],'CONFLICT')
            write(db,t,[r1,r2]);self.assertEqual(state('one')['user_id'],444)
            with self.assertRaises(RuntimeError):
                with db.transaction():
                    write(db,t+FIVE,[])
                    raise RuntimeError('injected before commit')
            self.assertEqual(state('one')['user_id'],444)
            write(db,t+FIVE,[]);self.assertIsNone(state('three'))
            write(db,t+FIVE,next_rows);self.assertEqual(state('three')['revision'],3)
            with self.assertRaisesRegex(ValueError,'checkpoint'):write(db,t+3*FIVE,[])
        # Only this test's own uniquely named and created database is removed.
        from psycopg import sql
        with storage.connect(cfg) as db:db.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))


    def test_affected_lookup_uses_request_index_on_large_unrelated_history(self):
        from psycopg import sql
        cfg=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
                 user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
        name='p24_accounts_test_'+uuid4().hex[:12]
        storage.prepare(cfg,'sizing',name)
        try:
            with storage.connect(cfg,name) as db, db.transaction():
                db.execute("""INSERT INTO p24_account.window_requests(start_ns,request_id,first_ns,last_ns)
                    SELECT i/200, 'r'||i, i, i FROM generate_series(1,200000) AS i""")
                db.execute('ANALYZE p24_account.window_requests')
                db.execute("CREATE TEMP TABLE affected AS SELECT 'r'||i AS request_id FROM generate_series(1,32) AS i")
                db.execute('ANALYZE affected')
                plan=db.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+storage.AFFECTED_FRAGMENTS).fetchone()['QUERY PLAN'][0]['Plan']
                def nodes(p):
                    yield p
                    for child in p.get('Plans',[]):yield from nodes(child)
                reads=[n for n in nodes(plan) if n.get('Relation Name')=='window_requests' or n.get('Index Name')=='account_fragment_request']
                self.assertEqual(plan['Actual Rows'],32)
                self.assertTrue(any(n.get('Index Name')=='account_fragment_request' for n in reads))
                self.assertFalse(any(n['Node Type']=='Seq Scan' for n in reads))
        finally:
            with storage.connect(cfg) as db:db.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))


class ScheduledRoleTests(unittest.TestCase):
    def test_freeze_matches_deployed_task_and_separate_history_code_directory(self):
        from subprocess import list2cmdline
        from tools.userid_transition.legacy_tasks import installed
        p=r'E:\P24 Example\project'
        py=p+r'\.venv\Scripts\python.exe'
        code=r'E:\P24 Example\releases\r38'
        history=r'E:\P24 Example\releases\r37'
        def action(exe,root,args):
            return dict(actions=[dict(Execute=exe,WorkingDirectory=root,Arguments=list2cmdline(args))])
        tasks={'core':action(py,code,['-X','utf8','-B','-m','compact_product','supervise','--project',p]),
               'history':action('powershell.exe',history,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
                    history+r'\compact_product\History_Compact_Product.ps1','-Action','Worker','-Project',p,'-Python',py])}
        self.assertEqual(installed(p,py,tasks),dict(core=code,history=history))
        tasks['core']['actions'][0]['Arguments'] += ' --other-project'
        with self.assertRaisesRegex(ValueError,'does_not_match'):installed(p,py,tasks)

    def test_guardian_only_starts_web_and_existing_analysis(self):
        from tools.userid_transition.serve_preserved import supervise
        from compact_product import runtime
        from unittest.mock import MagicMock
        db=MagicMock()
        with patch('compact_product.version.verify',return_value={'source_sha256':'demo'}), \
                patch('compact_product.config.load',return_value=(MagicMock(source_schema='p24_compact_testing'),{'DATABASE':{}},'same')), \
                patch('compact_behavior.store.Store',return_value=db), \
                patch.object(runtime,'status',return_value={r:{'running':False} for r in runtime.ROLES}), \
                patch.object(runtime,'start') as start,patch('time.sleep',side_effect=KeyboardInterrupt):
            try:
                with self.assertRaises(KeyboardInterrupt):supervise(Path('/test_project'),Path('/test_release'),'demo')
            finally:
                import sys
                sys.path.remove('/test_release')
            self.assertEqual([call.kwargs['roles'] for call in start.call_args_list],[('web',),('analysis',)])


@unittest.skipUnless(os.getenv('P24_DELTA_PG_HOST'),'requires disposable PostgreSQL')
class PreservedProductTests(unittest.TestCase):
    from tests.test_compact_product_pg import CompactProductPostgresTests as _fixture
    setUp = _fixture.setUp
    tearDown = _fixture.tearDown

    def test_real_compact_ingest_history_and_replay_rejected_while_ad_and_web_serve(self):
        from compact_product.web import create_app
        from tools.userid_transition.presentation import freeze
        from tests.test_compact_audit35 import inquiry_rows
        from tests.test_compact_extract import extract,T
        import psycopg
        db=self.db.conn
        s=self.config.source_schema
        old_rows=inquiry_rows()
        self.db.publish('test',T,T+FIVE,extract(old_rows),len(old_rows))
        # Verify that a backlog already present at freeze time can still produce its original actual case.
        receipt=freeze(db,s,'test')
        self.assertEqual(freeze(db,s,'test'),receipt)
        with self.assertRaises(psycopg.Error) as forward:
            self.db.publish('test',T+FIVE,T+2*FIVE,{},0)
        self.assertEqual(forward.exception.sqlstate,'55000')
        with self.assertRaises(psycopg.Error):
            self.db.publish('test',T-FIVE,T,{},0,allow_history=True)
        with self.assertRaises(psycopg.Error):
            self.db.publish('test',T,T+FIVE,extract(inquiry_rows(same=True)),len(old_rows))
        self.assertEqual(self.db.cursor('test'),T+FIVE)
        for _ in range(30):
            if self.db.step('test')['status']=='ANALYSIS_IDLE':break
        self.assertEqual(db.execute(f'SELECT count(*) AS n FROM {s}.behaviors').fetchone()['n'],10)
        self.assertEqual(freeze(db,s,'test')['epoch'],receipt['epoch'])
        app=create_app(self.config,self.database,'test')
        client=app.test_client()
        for path in ('/','/sessions?q=crawler',receipt['review_path']):
            response=client.get(path)
            self.assertEqual(response.status_code,200)
            self.assertIn(b'WaterBills',response.data)
        self.assertIn(b'/cases/',client.get(receipt['review_path']).data)
        # Other streams are not blocked by this stream-specific rule.
        self.db.publish('other',T,T+FIVE,{},0)
        self.assertEqual(self.db.cursor('other'),T+FIVE)


@unittest.skipUnless(os.getenv('P24_DELTA_PG_HOST'),'requires disposable PostgreSQL')
class PreparationCommandTests(unittest.TestCase):
    def test_complete_four_window_capture_and_shadow_via_cli(self):
        import json
        from zipfile import ZipFile
        from contextlib import redirect_stdout
        from io import StringIO
        from compact_behavior.source import ElasticWindow
        from tools.userid_transition.__main__ import main
        from psycopg import sql
        start=instant(storage.ORIGIN)
        user_id=2**63-4
        def page(source,path,body=None,method='POST'):
            if method=='DELETE':return {}
            if '/_pit?' in path:return {'id':'mock-pit'}
            self.assertEqual(set(body['_source']),{'@timestamp','UserID','Session','RequestID','CallPath'})
            i=(source.start-start)//FIVE
            ids=['boundary' if i in (1,2) else 'window'+str(i)]
            hits=[]
            for n,rid in enumerate(ids):
                hit=source_hit(rid,user_id if i!=1 else 0,source.start)
                hit['_source'].pop('message');hit['sort']=[n+1]
                hits.append(hit)
            return {'timed_out':False,'_shards':{'total':1,'successful':1,'failed':0,'skipped':0},
                    'hits':{'total':{'value':len(hits),'relation':'eq'},'hits':hits}}
        cfg=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
                 user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
        name='p24_accounts_test_'+uuid4().hex[:12]
        with TemporaryDirectory() as d, patch.object(ElasticWindow,'request',page),redirect_stdout(StringIO()):
            root=Path(d)
            (root/'viewer_config.local.py').write_text("DATABASE="+repr(cfg)+"\nELASTICSEARCH={'host':'http://localhost:9001','index_pattern':'core-*'}\n")
            args=['--project',d,'--output',str(root/'reports'),'--new-database',name]
            try:
                self.assertEqual(main(['prepare',*args]),0)
                bundle=next(root.rglob('Core_UserID_Samples*.zip'))
                with ZipFile(bundle) as z:
                    cov=json.loads(z.read('coverage.json'))
                    self.assertEqual((len(cov['windows']),cov['distinct_verified_accounts'],cov['cross_window_requests']),(4,1,1))
                    self.assertEqual(cov['identity_check'],'VERIFIED_IDS_OBSERVED')
                    self.assertEqual(cov['windows'][0]['verified_ids_above_js_safe_integer_lines'],1)
                with storage.connect(cfg,name) as db:
                    self.assertEqual(db.execute('SELECT count(*) AS n FROM p24_account.requests').fetchone()['n'],0)
                self.assertEqual(main(['shadow',*args]),0)
                self.assertEqual(main(['shadow',*args]),0)
                with storage.connect(cfg,name) as db:
                    self.assertEqual(db.execute('SELECT count(*) AS n FROM p24_account.windows').fetchone()['n'],4)
                    self.assertEqual(db.execute('SELECT DISTINCT user_id FROM p24_account.requests').fetchall(),[{'user_id':user_id}])
                    self.assertEqual(db.execute('SELECT next_ns FROM p24_account.contract').fetchone()['next_ns'],start+4*FIVE)
            finally:
                with storage.connect(cfg) as db:db.execute(sql.SQL('DROP DATABASE IF EXISTS {}').format(sql.Identifier(name)))
