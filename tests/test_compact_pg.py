import concurrent.futures
import multiprocessing
import os
from pathlib import Path
import tempfile
import gzip
import json
import subprocess
import sys
import unittest
import uuid
from compact_behavior import FIVE
from compact_behavior.extract import Limits,LimitExceeded,behavior_id
from compact_behavior.store import Store
from tests.test_compact_extract import row,extract,T


def crash(config,schema,point):
    store=Store(config,schema=schema)
    store.publish('test',T,T+FIVE,extract([row()]),1,
                  fault=lambda where:os._exit(73) if where==point else None)
    os._exit(74)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PostgreSQL required')
class CompactPostgresTests(unittest.TestCase):
    def setUp(self):
        self.config=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
                         user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
        self.schema='p24_compact_test_'+uuid.uuid4().hex[:12]
        self.store=Store(self.config,schema=self.schema);self.store.init()
    def tearDown(self):
        self.store.conn.execute('DROP SCHEMA '+self.schema+' CASCADE');self.store.close()
    def rows(self,name):return self.store.conn.execute('SELECT * FROM '+self.schema+'.'+name).fetchall()
    def publish(self,rows,start=T):return self.store.publish('test',start,start+FIVE,extract(rows),len(rows))
    def test_real_copy_replay_is_noop_including_dirty_versions(self):
        a=self.publish([row()]);before=self.rows('behaviors');dirty=self.rows('dirty_windows')
        b=self.publish([row()]*2)
        self.assertEqual(a['inserted'],1);self.assertEqual(b['inserted'],0);self.assertFalse(b['fresh_publication'])
        self.assertEqual(before,self.rows('behaviors'));self.assertEqual(dirty,self.rows('dirty_windows'))
    def test_boundary_pending_and_late_payload_become_one_behavior(self):
        support=row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"001"}] Output:[]')
        a=self.publish([support]);self.assertEqual(a['pending_requests'],1);self.assertEqual(self.rows('behaviors'),[])
        b=self.publish([row(at='2026-10-20T08:25:01Z')],T+FIVE)
        self.assertEqual(b['inserted'],1);self.assertEqual(b['pending_requests'],0)
        core=self.rows('behaviors')[0];self.assertTrue(core['features']['input_eligible'])
        self.assertEqual(core['features']['input']['targets']['[].WaterBillID'],'001')
    def test_session_correction_invalidates_old_window_without_duplicate(self):
        self.publish([row()])
        self.publish([row(session='session-2',path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[] Output:[]',at='2026-10-20T08:25:01Z')],T+FIVE)
        core=self.rows('behaviors');self.assertEqual(len(core),1);self.assertIsNone(core[0]['session_id'])
        self.assertFalse(core[0]['features']['rate_eligible']);self.assertEqual(self.rows('dirty_windows')[0]['version'],2)
    def test_before_commit_rollback_has_no_checkpoint_or_notification(self):
        def fail(where):raise RuntimeError('artificial_failure')
        with self.assertRaises(RuntimeError):self.store.publish('test',T,T+FIVE,extract([row()]),1,fault=fail)
        self.assertEqual(self.rows('behaviors'),[]);self.assertEqual(self.rows('streams'),[])
        self.assertEqual(self.rows('dirty_windows'),[]);self.publish([row()])
    def test_actual_process_crash_before_and_after_commit(self):
        ctx=multiprocessing.get_context('spawn')
        p=ctx.Process(target=crash,args=(self.config,self.schema,'before_commit'));p.start();p.join(20)
        self.assertEqual(p.exitcode,73);self.assertEqual(self.rows('behaviors'),[]);self.assertIsNone(self.store.cursor('test'))
        p=ctx.Process(target=crash,args=(self.config,self.schema,'after_commit'));p.start();p.join(20)
        self.assertEqual(p.exitcode,73);self.assertEqual(len(self.rows('behaviors')),1);self.assertEqual(self.store.cursor('test'),T+FIVE)
        before=self.rows('behaviors');self.publish([row()]);self.assertEqual(self.rows('behaviors'),before)
    def test_pending_limit_rolls_back_instead_of_expiring_unknown_requests(self):
        self.store.limits=Limits(pending_requests=0)
        with self.assertRaises(LimitExceeded):self.publish([row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[]')])
        self.assertEqual(self.rows('pending_requests'),[]);self.assertIsNone(self.store.cursor('test'))
    def test_gap_and_contract_change_rejected_without_advancing(self):
        self.publish([row()])
        with self.assertRaisesRegex(ValueError,'checkpoint_gap'):self.publish([],T+2*FIVE)
        self.store.conn.execute('UPDATE '+self.schema+".streams SET extractor='different'")
        with self.assertRaisesRegex(ValueError,'contract_changed'):self.publish([],T+FIVE)
        self.assertEqual(self.store.cursor('test'),T+FIVE)
    def test_two_publishers_preserve_both_fragments(self):
        def publish(records):
            db=Store(self.config,schema=self.schema)
            try:return db.publish('test',T,T+FIVE,extract(records),len(records))
            finally:db.close()
        late=row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[{"WaterBillID":"001"}] Output:[]')
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results=list(pool.map(publish,[[row()],[late]]))
        core=self.rows('behaviors');self.assertEqual(len(core),1)
        self.assertTrue(core[0]['features']['input_eligible']);self.assertEqual(self.rows('pending_requests'),[])
        self.assertEqual(len(self.rows('windows')),1)
    def test_same_target_different_requests_remain_distinct(self):
        self.publish([row('r1'),row('r2')]);self.assertEqual(len(self.rows('behaviors')),2)
        self.assertEqual(self.rows('dirty_windows')[0]['version'],1)
    def test_actual_cli_complete_and_incomplete_file_with_postgres_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'config.py';config.write_text('DATABASE = '+repr(self.config),encoding='utf-8')
            path=root/'sample.json.gz';out=root/'result.json'
            packet={'logs':[row()],'count':1,'complete':True,'window_start':'2026-10-20T08:20:00Z','window_end':'2026-10-20T08:25:00Z'}
            with gzip.open(path,'wt') as f:json.dump(packet,f)
            command=[sys.executable,'-B','-m','compact_behavior','--config',str(config),'--stream','cli',
                     '--schema',self.schema,'--files',str(path),'--output',str(out)]
            p=subprocess.run(command,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            result=json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(result['windows'][0]['inserted'],1);self.assertFalse(result['legacy_runtime_used'])
            self.assertTrue(result['package']['source_sha256']);self.assertGreater(result['process_peak_rss_bytes'],0)
            packet['complete']=False
            with gzip.open(path,'wt') as f:json.dump(packet,f)
            command[command.index('cli')]='incomplete'
            p=subprocess.run(command,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,2);self.assertIsNone(self.store.cursor('incomplete'))


if __name__=='__main__':unittest.main()
