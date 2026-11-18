"""Physical-copy ownership, full-history oracle and recovery on private PG."""
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from viewer_performance.behavior_resources import CopyOwner,PhaseBudget


def crash_owned_copy(params,source,folder):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(**params,dbname='postgres',autocommit=True,row_factory=dict_row) as admin:
        owner=CopyOwner(admin,source,folder,lambda:None,time.monotonic()+60)
        with owner.clone():os._exit(73)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 required')
class NativeBehaviorBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.rows import dict_row
        cls.psycopg,cls.sql=psycopg,sql
        cls.params=dict(host=os.environ['P24_DELTA_PG_HOST'],port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
                        user=os.environ.get('P24_DELTA_PG_USER','postgres'),connect_timeout=3)
        cls.admin=psycopg.connect(**cls.params,dbname='postgres',autocommit=True,row_factory=dict_row)
    @classmethod
    def tearDownClass(cls):cls.admin.close()
    def setUp(self):
        from p24_foundation.privacy import generate_keys
        from p24_foundation.viewer_data import ViewerDB
        from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture
        from viewer_performance.financial_screen.fixtures import seed,corpus
        from viewer_performance.capacity.fixtures import START,FIVE
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.keys=self.root/'keys';generate_keys(self.keys)
        self.name='p24_design_capacity_template_'+uuid.uuid4().hex[:12]+'_qualification'
        self.admin.execute(self.sql.SQL('CREATE DATABASE {}').format(self.sql.Identifier(self.name)))
        self.addCleanup(lambda:self.admin.execute(self.sql.SQL('DROP DATABASE {}').format(self.sql.Identifier(self.name))))
        self.options=dict(config=dict(self.params,dbname=self.name),keys_path=self.keys)
        with ViewerDB(**self.options) as db:
            db.init();initialize_live(db);bind_stream(db,start_ns=START-FIVE,stream_key='fixed-fixture')
            old=seed(self.root,START,24)[0];publish_capture(db,old['path'],old['start'],old['start']+FIVE)
            db.sql('CREATE SCHEMA anomaly_detection');db.sql('CREATE TABLE anomaly_detection.fixture_feedback(id INTEGER PRIMARY KEY,note TEXT)')
            db.sql("INSERT INTO anomaly_detection.fixture_feedback VALUES(1,'retained human review')");db.conn.commit()
        self.jobs=corpus(self.root,(2,2,2))[:2]
    def test_real_physical_copies_balanced_capacity_and_whole_history_preservation(self):
        from viewer_performance.behavior_benchmark import run
        from p24_foundation.viewer_data import ViewerDB
        from viewer_performance.behavior_oracle import retained,archives
        with ViewerDB(**self.options) as db:before=(retained(db),archives(db));cursor=db.one('SELECT * FROM viewer_live_state')
        result=run(Path(__file__).resolve().parents[1],self.root/'benchmark',lambda:None,lambda value:None,
                   windows=2,max_seconds=180,parameters=self.params,options=self.options,capture_paths=[j['path'] for j in self.jobs],qualification_disk_path=self.root)
        self.assertEqual(result['status'],'LARGE_HISTORY_EQUIVALENCE_AND_CAPACITY_COMPLETE',result.get('failure'))
        self.assertEqual(len(result['lanes']),6);self.assertEqual(result['remaining_owned_databases'],[])
        self.assertEqual([l['scope_mode'] for l in result['lanes'][2:]],['full','behavior','behavior','full'])
        self.assertTrue(all(w['full_output_oracle'] is None for l in result['lanes'][2:] for w in l['windows']))
        self.assertFalse(result['capacity_target_accepted'])
        with ViewerDB(**self.options) as db:self.assertEqual((retained(db),archives(db)),before);self.assertEqual(db.one('SELECT * FROM viewer_live_state'),cursor)
    def test_crash_after_tag_recovers_only_exact_owned_copy(self):
        folder=self.root/'crash';folder.mkdir()
        child=multiprocessing.get_context('spawn').Process(target=crash_owned_copy,args=(self.params,self.name,str(folder)))
        child.start();child.join(30);self.assertEqual(child.exitcode,73)
        receipt=folder/'allocations.json';state=json.loads(receipt.read_text());self.assertEqual(state['allocations'][0]['state'],'OWNED')
        self.assertEqual(CopyOwner.recover(self.admin,receipt),[])
        self.assertEqual(json.loads(receipt.read_text())['allocations'][0]['state'],'DROPPED')
        self.assertTrue(self.admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(self.name,)).fetchone())
    def test_active_template_session_blocks_copy_without_killing_it(self):
        folder=self.root/'active';folder.mkdir();owner=CopyOwner(self.admin,self.name,folder,lambda:None,time.monotonic()+30)
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True) as held:
            with self.assertRaisesRegex(ValueError,'ACTIVE_SESSIONS'):
                with owner.clone():self.fail('must not create while source has sessions')
            self.assertEqual(held.execute('SELECT 1').fetchone()[0],1)
        self.assertEqual(owner.state['allocations'],[])
    def test_forged_recovery_receipt_cannot_drop_template(self):
        receipt=self.root/'forged.json';receipt.write_text(json.dumps(dict(version=1,run_id='a'*32,allocations=[dict(name=self.name,oid=1,state='OWNED')])))
        with self.assertRaisesRegex(ValueError,'NAME_NOT_OWNED'):CopyOwner.recover(self.admin,receipt)
    def test_phase_deadline_cancels_actual_blocking_sql(self):
        with self.assertRaises(TimeoutError):
            with PhaseBudget(lambda:None,time.monotonic()+.1,connection=self.admin,interval=.02):self.admin.execute('SELECT pg_sleep(20)')
        self.assertEqual(self.admin.execute('SELECT 1 AS n').fetchone()['n'],1)


if __name__=='__main__':unittest.main()
