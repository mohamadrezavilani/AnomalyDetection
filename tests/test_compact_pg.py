import concurrent.futures
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,HTTPServer
import multiprocessing
import os
from pathlib import Path
import tempfile
import gzip
import json
import subprocess
import sys
import threading
import unittest
import uuid
from compact_behavior import FIVE
from compact_behavior.extract import Limits,LimitExceeded,behavior_id,iso
from compact_behavior.store import Store
from tests.test_compact_extract import row,extract,T,FlakyWindow,ScriptedScroll,es_document,scroll_packet


@contextmanager
def scroll_http_server(packets):
    state={'packets':list(packets),'calls':[],'deleted':[]}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self,status,value):
            data=json.dumps(value).encode();self.send_response(status)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def do_POST(self):
            length=int(self.headers.get('Content-Length',0));body=json.loads(self.rfile.read(length) or b'null')
            state['calls'].append((self.path,body))
            if '/_pit?' in self.path:self.respond(400,{'error':{'type':'illegal_argument_exception'}})
            elif state['packets']:self.respond(200,state['packets'].pop(0))
            else:self.respond(500,{'error':{'type':'unexpected_extra_scroll_request'}})
        def do_DELETE(self):
            body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
            state['deleted'].extend(body['scroll_id']);self.respond(200,{'succeeded':True})
    server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield 'http://127.0.0.1:'+str(server.server_port),state
    finally:server.shutdown();server.server_close();thread.join(5)


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
    def test_context_only_update_does_not_rewrite_behavior_or_requeue_ad(self):
        self.publish([row()])
        before=self.rows('behaviors'); dirty=self.rows('dirty_windows'); windows=self.rows('windows'); streams=self.rows('streams')
        r=self.publish([dict(row(),IP='192.0.2.1',UserAgent='Browser')])
        self.assertEqual(r['context_records_updated'],1)
        self.assertEqual(self.rows('behaviors'),before)
        self.assertEqual(self.rows('dirty_windows'),dirty)
        self.assertEqual(self.rows('windows'),windows)
        self.assertEqual(self.rows('streams'),streams)
        context=self.rows('request_context')[0]['context']
        self.assertEqual(context['values']['ip'][0]['value'],'192.0.2.1')
        self.assertEqual(self.publish([dict(row(),IP='',UserAgent='')])['context_records_updated'],0)
        self.assertEqual(self.rows('request_context')[0]['context'],context)

    def test_pending_context_survives_restart_completion_and_replay(self):
        support=dict(row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[]'),IP='192.0.2.1',UserAgent='Browser')
        self.publish([support]);self.store.close()
        self.store=Store(self.config,schema=self.schema);self.store.init()
        self.publish([row(at='2026-10-20T08:25:01Z')],T+300000000000)
        self.assertEqual(len(self.rows('behaviors')),1)
        context=self.rows('request_context')[0]['context']
        self.assertEqual(context['values']['user_agent'][0]['value'],'Browser')
        self.assertEqual(context['values']['ip'][0]['value'],'192.0.2.1')
        self.assertEqual(self.rows('pending_requests'),[])
        self.assertEqual(self.publish([row(at='2026-10-20T08:25:01Z')],T+300000000000)['context_records_updated'],0)

    def test_context_rollback_and_expired_pending_cleanup(self):
        def failure(where): raise RuntimeError('rollback')
        with self.assertRaises(RuntimeError):
            self.store.publish('test',T,T+300000000000,extract([dict(row(),IP='192.0.2.1')]),1,fault=failure)
        self.assertEqual(self.rows('request_context'),[])
        self.publish([dict(row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[]'),IP='192.0.2.1')])
        self.store.conn.execute(f"UPDATE {self.schema}.pending_requests SET status='EXPIRED',updated_at_ns=0")
        self.store.conn.execute(f"UPDATE {self.schema}.queue_counts SET active_pending=0,expired_pending=1")
        self.publish([],T+300000000000)
        self.assertEqual(self.rows('request_context'),[])

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
        self.assertEqual(core['features']['input']['targets']['[].WaterBillID'],[{'type':'string','value':'001'}])
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
    def test_pending_high_water_does_not_deadlock_or_expire_early(self):
        self.store.limits=Limits(pending_requests=2)
        def partial(key,at):
            return dict(row(key,path='ClientAyanCoInquiry.WaterBillInquiry',
                message='Input:[{"WaterBillID":"001"}]',at=iso(at)),IP='192.0.2.1')
        self.publish([partial('a',T+10**9),partial('b',T+10**9)])
        before={r['behavior_id']:r for r in self.rows('pending_requests')}
        result=self.publish([partial('c',T+FIVE+10**9)],T+FIVE)
        self.assertTrue(result['pending_high_water_warning'])
        self.assertEqual(result['pending_requests'],3)
        self.assertEqual(result['pending_expired_this_window'],0)
        self.assertEqual(self.store.cursor('test'),T+2*FIVE)
        self.assertEqual(self.rows('behaviors'),[])
        for r in self.rows('pending_requests'):
            self.assertEqual(r['status'],'WAITING')
            if r['behavior_id'] in before:self.assertEqual(r,before[r['behavior_id']])
        # Replay cannot extend deadlines or duplicate queue counts.
        self.publish([partial('c',T+FIVE+10**9)],T+FIVE)
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],3)
        for i in range(2,7):self.publish([],T+i*FIVE)
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],1)
        self.assertEqual(self.rows('queue_counts')[0]['expired_pending'],2)
        # Expiry is not evidence deletion: completion still merges old input/IP.
        self.publish([row('a',at=iso(T+7*FIVE+10**9))],T+7*FIVE)
        b=self.rows('behaviors')[0]
        self.assertEqual(b['features']['input']['targets']['[].WaterBillID'][0]['value'],'001')
        c=next(c for c in self.rows('request_context') if c['behavior_id']==b['behavior_id'])
        self.assertEqual(c['context']['values']['ip'][0]['value'],'192.0.2.1')
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],0)
        self.assertEqual(self.rows('queue_counts')[0]['expired_pending'],2)

    def test_server_pending_distribution_advances_and_drains_beyond_old_5k_batch(self):
        # Exact counts from the owner's read-only report, synthetic payloads.
        counts=[754,848,25797,1048,10582,380]
        def wave(i,n):
            return [row('wave-%d-%d'%(i,k),path='ClientAyanCoInquiry.WaterBillInquiry',
                        message='Input:[]',at=iso(T+i*FIVE+10**9)) for k in range(n)]
        for i,n in enumerate(counts):self.publish(wave(i,n),T+i*FIVE)
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],39409)
        # New window admits 2k and expires only the actually due 754: >40k.
        result=self.publish(wave(6,2000),T+6*FIVE)
        self.assertEqual(result['pending_requests'],40655)
        self.assertEqual(result['pending_expired_this_window'],754)
        self.assertTrue(result['pending_high_water_warning'])
        self.assertEqual(self.store.cursor('test'),T+7*FIVE)
        self.publish([],T+7*FIVE)
        result=self.publish([],T+8*FIVE)
        self.assertEqual(result['pending_expired_this_window'],25797)
        self.assertEqual(result['pending_requests'],14010)
        for i in range(9,13):self.publish([],T+i*FIVE)
        queue=self.rows('queue_counts')[0]
        self.assertEqual((queue['active_pending'],queue['expired_pending']),(0,41409))
        self.assertEqual(self.rows('behaviors'),[])
        self.assertEqual(self.store.conn.execute(f'SELECT count(*) AS n FROM {self.schema}.pending_requests').fetchone()['n'],41409)

    def test_above_warning_publication_and_expiry_remain_atomic(self):
        self.store.limits=Limits(pending_requests=0)
        records=extract([row(path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:[]')])
        def fail(where):raise RuntimeError('injected rollback')
        with self.assertRaises(RuntimeError):self.store.publish('test',T,T+FIVE,records,1,fault=fail)
        self.assertEqual(self.rows('pending_requests'),[]);self.assertIsNone(self.store.cursor('test'))
        self.store.publish('test',T,T+FIVE,records,1)
        for i in range(1,6):self.publish([],T+i*FIVE)
        with self.assertRaises(RuntimeError):self.store.publish('test',T+6*FIVE,T+7*FIVE,{},0,fault=fail)
        self.assertEqual(self.rows('pending_requests')[0]['status'],'WAITING')
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],1)
        self.assertEqual(self.store.cursor('test'),T+6*FIVE)
        self.publish([],T+6*FIVE)
        self.assertEqual(self.rows('queue_counts')[0]['active_pending'],0)
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
    def test_retry_publishes_only_complete_snapshot_into_real_postgres(self):
        from compact_behavior.__main__ import measure_window
        result=measure_window(self.store,'test',FlakyWindow())
        self.assertEqual({r['request_id'] for r in self.rows('behaviors')},{'r1','r2'})
        self.assertEqual(result['source_records'],2);self.assertEqual(len(self.rows('windows')),1)
        self.assertEqual(self.store.cursor('test'),T+FIVE)
    def test_retry_exhaustion_keeps_database_and_checkpoint_unchanged(self):
        from compact_behavior.__main__ import measure_window
        from compact_behavior.source import ElasticPageError
        source=FlakyWindow(always_fail=True)
        with self.assertRaises(ElasticPageError):measure_window(self.store,'test',source)
        self.assertEqual(source.attempts,3);self.assertEqual(self.rows('behaviors'),[])
        self.assertEqual(self.rows('dirty_windows'),[]);self.assertIsNone(self.store.cursor('test'))
    def test_owner_scroll_protocol_over_http_through_real_postgres_commit(self):
        from compact_behavior.__main__ import measure_window
        from compact_behavior.source import ElasticWindow
        packets=[scroll_packet('p1',[es_document(i) for i in range(500)],1002,initial=True),
            scroll_packet('p2',[es_document(i) for i in range(500,1000)],1002,early=True),
            scroll_packet('p3',[es_document(i) for i in range(1000,1002)],1002,early=True),scroll_packet('p4',[],1002)]
        with scroll_http_server(packets) as (url,server):
            source=ElasticWindow({'host':url,'index_pattern':'logs-*'},T,T+FIVE)
            result=measure_window(self.store,'test',source)
            self.assertFalse(server['packets']);self.assertEqual(server['deleted'],['p4'])
            self.assertEqual(len(server['calls']),5) # unsupported PIT, then four scroll pages
        self.assertEqual({r['request_id'] for r in self.rows('behaviors')},{str(i) for i in range(1002)})
        self.assertEqual(result['source_records'],1002);self.assertEqual(result['inserted'],1002)
        self.assertEqual(result['source_completeness']['unique_documents'],1002)
        self.assertEqual(result['source_completeness']['scroll_early_terminated_pages'],2)
        self.assertTrue(result['source_completeness']['terminal_empty_page'])
        self.assertEqual(len(result['source_attempts']),1);self.assertEqual(self.store.cursor('test'),T+FIVE)
    def test_unproven_scroll_never_writes_behavior_or_checkpoint(self):
        from compact_behavior.__main__ import measure_window
        for mode in ['short','duplicate','surplus']:
            with self.subTest(mode=mode):
                total=1 if mode=='surplus' else 2
                final=scroll_packet('p2',[],total,early=True) if mode=='short' else scroll_packet('p2',[es_document(1 if mode=='duplicate' else 2)],total,early=True)
                source=ScriptedScroll([scroll_packet('p1',[es_document(1)],total,initial=True),final])
                with self.assertRaises(ValueError):measure_window(self.store,mode,source)
                self.assertEqual(self.rows('behaviors'),[]);self.assertEqual(self.rows('pending_requests'),[])
                self.assertEqual(self.rows('dirty_windows'),[]);self.assertEqual(self.rows('windows'),[])
                self.assertIsNone(self.store.cursor(mode));self.assertEqual(source.deleted,['p2'])
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
