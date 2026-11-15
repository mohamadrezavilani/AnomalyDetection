"""Publication-local tokens preserve progress without weakening late evidence."""
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import unittest
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import OnlinePublisherTests,START,FIVE_NS,iso,snapshot,verified_file
from tests.test_viewer_r6_service_journey import log
from p24_foundation.viewer_online import publish_capture


class EpochChecks:
    def publish_rows(self,rows,number=0,*,fault=None):
        start=START+number*FIVE_NS
        for i,row in enumerate(rows):row['@timestamp']=iso(start+(i+1)*1_000_000_000)
        path=verified_file(self.root/('epoch-'+str(number)+'-'+str(len(list(self.root.glob('epoch*'))))+'.gz'),rows,start)
        return publish_capture(self.db,path,start,start+FIVE_NS,fault=fault)

    def epoch(self,start=START):
        row=self.db.one('SELECT revision FROM viewer_window_epochs WHERE start_ns=?',(start,))
        return row['revision'] if row else 0

    def test_unrelated_publication_preserves_old_token_and_late_request_touches_it(self):
        self.publish_rows([log(1,'late','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        first=self.epoch()
        self.publish_rows([log(2,'unrelated','Services.v1/WaterBills Line:1','POST (G00000 | successful)')],1)
        self.assertEqual(self.epoch(),first)
        self.publish_rows([log(3,'late','Services.v1/WaterBills Line:1','POST (G00000 | successful)',session='b'*32)],2)
        self.assertGreater(self.epoch(),first)
        before=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(snapshot(self.db),before)

    def test_failed_publication_rolls_back_window_tokens_and_maintenance_fence(self):
        self.publish_rows([log(1,'r','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        first=self.epoch();maintenance=self.db.one('SELECT maintenance_epoch FROM viewer_window_epoch_state')['maintenance_epoch']
        def fail(stage):
            if stage=='before_commit':raise RuntimeError('controlled_epoch_rollback')
        with self.assertRaises(RuntimeError):
            self.publish_rows([log(2,'r','ClientFixture.Call','Output:[]')],1,fault=fail)
        self.assertEqual(self.epoch(),first)
        self.assertEqual(self.db.one('SELECT maintenance_epoch FROM viewer_window_epoch_state')['maintenance_epoch'],maintenance)
        self.assertEqual(self.epoch(START+FIVE_NS),0)
        self.db.write_lock()
        self.db.sql("UPDATE viewer_requests SET identity_state='unknown'")
        self.db.conn.commit()
        self.assertGreater(self.db.one('SELECT maintenance_epoch FROM viewer_window_epoch_state')['maintenance_epoch'],maintenance)


class WindowEpochTests(EpochChecks,unittest.TestCase):
    setUp=OnlinePublisherTests.setUp


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativeWindowEpochTests(EpochChecks,unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)
    setUp=native.NativeMinimalPublicationTests.setUp

    def source(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'AnomalyDetection'))
        from anomaly_detection.product_source import ProductSource
        import psycopg
        from psycopg.rows import dict_row
        source=object.__new__(ProductSource)
        source.identity={'runtime_sha256':'fixture'};source.config={'user':self.config['user']}
        source.analysis_floor_ns=START;source.page_size=2;source.last_source=None
        @contextmanager
        def read():
            with psycopg.connect(**self.config,row_factory=dict_row) as raw:
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                def q(statement,parameters=(),*,cap):
                    rows=raw.execute(statement,parameters).fetchall()
                    if statement.startswith('SELECT current_database()'):rows[0]['db']='p24_design_viewer'
                    self.assertLessEqual(len(rows),cap)
                    return rows
                yield q
        source.snapshot=read
        return source

    def test_ad_finishes_a_window_despite_a_new_publication_between_every_page(self):
        from psycopg.rows import dict_row
        import psycopg
        source=self.source()
        from anomaly_detection.product_pipeline import read_window,apply_window
        from anomaly_detection.product_store import ProductStore
        self.publish_rows([log(i,'r'+str(i),'Services.v1/WaterBills Line:1','POST (G00000 | successful)') for i in range(1,8)])
        with psycopg.connect(**self.config,autocommit=True,row_factory=dict_row) as owned:
            owned.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(owned);store.initialize()
            store.save_state('fresh_cursor',{'next_ns':START})
            stamps=[];statuses=[]
            for page in range(4):
                packet=read_window(source,store.state('fresh_cursor'));stamps.append(packet['stamp'])
                result=apply_window(store,packet);statuses.append(result['status'])
                if page<3:self.publish_rows([log(100+page,'new'+str(page),'Services.v1/WaterBills Line:1','POST (G00000 | successful)')],page+1)
            self.assertEqual(statuses,['READING','READING','READING','COMPLETE'])
            self.assertEqual(len(set(stamps)),1)
            self.assertEqual(store.state('fresh_cursor'),{'next_ns':START+FIVE_NS})
            self.assertEqual(owned.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_members WHERE start_ns=%s',(START,)).fetchone()['n'],7)

    def test_late_identity_change_restarts_both_semantic_and_technical_censuses(self):
        source=self.source()
        from anomaly_detection.product_pipeline import read_window
        from anomaly_detection.scenario_traffic import read_page
        self.publish_rows([log(i,'late' if i==1 else 'r'+str(i),'Services.v1/WaterBills Line:1','POST (G00000 | successful)') for i in range(1,5)])
        first=read_window(source,{'next_ns':START})
        traffic=read_page(source,{'next_ns':START,'page_size':64})
        cursor={'target_ns':START,'stamp':first['stamp'],'after':first['after']}
        self.publish_rows([log(20,'late','Services.v1/WaterBills Line:1','POST (G00000 | successful)',session='b'*32)],1)
        self.assertTrue(read_window(source,cursor)['restart'])
        self.assertEqual(read_page(source,{'target_ns':START,'stamp':traffic['stamp'],'page_size':64})['status'],'RESTART')
