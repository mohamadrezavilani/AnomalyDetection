"""Final D/E/F/G guards: real publisher path, synthetic ES transport only."""
from __future__ import annotations
import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation import viewer_online
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token
from p24_foundation.viewer_elastic import ElasticCapture
from p24_foundation.viewer_online import (FIVE_NS,initialize_live,bind_stream,publish_capture,
    live_status,LiveWorker,single_worker,validate_capture,utc_ns,iso)
from tests.test_viewer_r6_service_journey import log,sql

START=utc_ns('2026-10-24T04:15:00Z')


def verified_file(path,rows,start=START):
    proof=dict(expected_total=len(rows),total_relation='eq',returned_records=len(rows),
        unique_origins=len(rows),counts_match=True,query_snapshot_complete=True,reached_empty_page=True)
    with gzip.open(path,'wt',encoding='utf-8') as f:
        json.dump(dict(window_start=iso(start),window_end=iso(start+FIVE_NS),count=len(rows),
                       complete=True,logs=rows,verification=proof),f)
    return path


def snapshot(db):
    columns={
      'viewer_requests':'*','viewer_actions':'*','viewer_action_history':'*',
      'viewer_contract_identifiers':'*','viewer_contract_edges':'*','viewer_contract_observations':'*',
      'viewer_semantic_occurrences':'request_key,anchor_key,session_key,anchor_ns,kind,occurrence_key,root_call,root_code,category,initiation,state',
      'viewer_semantic_session_heads':'*',
    }
    return {table:sorted((json.dumps(r,sort_keys=True,ensure_ascii=True) for r in db.all('SELECT '+cols+' FROM '+table)))
            for table,cols in columns.items()}


class OnlinePublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.keys=self.root/'keys.json';generate_keys(self.keys)
        self.opts=dict(sqlite_path=self.root/'viewer.db',keys_path=self.keys)
        self.db=ViewerDB(**self.opts);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db)
        bind_stream(self.db,start_ns=START,stream_key='synthetic')

    def publish(self,rows,*,start=START,mode='forward',fault=None):
        path=verified_file(self.root/('capture'+str(len(list(self.root.glob('*.gz'))))+'.json.gz'),rows,start)
        return publish_capture(self.db,path,start,start+FIVE_NS,mode=mode,fault=fault)

    def test_incremental_late_root_repeat_ip_and_batch_parity(self):
        first=[log(1,'late','ClientAyanCoTopUp.ProductReserve Line:1','Output:[]'),
               log(2,'peer','Services.v1/WaterBills Line:2','POST (G00000 | successful)',session='b'*32)]
        self.publish(first)
        key=token(self.db.keys,'request','late')
        before=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
        late=log(3,'late','Services.v1/TopUpProductPurchase Line:7','POST (G00000 | successful)')
        late['@timestamp']=iso(START+FIVE_NS+1_000_000_000);late['IP']='192.0.2.99'
        repeat=log(4,'again','Services.v1/WaterBills Line:2','POST (G00000 | successful)')
        repeat['@timestamp']=iso(START+FIVE_NS+2_000_000_000)
        calls=[];original=self.db.rebuild
        def bounded(**kw):calls.append(kw);return original(**kw)
        self.db.rebuild=bounded
        info=self.publish([late,repeat],start=START+FIVE_NS)
        self.assertFalse(info['bootstrap']);self.assertEqual(info['impacted_requests'],2)
        self.assertEqual(len(calls),1);self.assertIsNotNone(calls[0]['request_keys'])
        after=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
        self.assertEqual(before['anchor_key'],after['anchor_key']);self.assertNotEqual(before['kind'],after['kind'])
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],3)
        incremental=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(incremental,snapshot(self.db))

    def test_conflict_retracts_old_and_new_request_with_payment_dependency(self):
        rows=[log(1,'p','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
              log(2,'p','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
              log(3,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')]
        self.publish(rows)
        changed=copy.deepcopy(rows[2]);changed['RequestID']='b';changed['message']='POST (GD2016 | fail)'
        self.publish([*rows[:2],changed],mode='recheck')
        for rid in ('a','b'):
            self.assertEqual(self.db.lookup_request(rid)['conflicted'],1)
        inc=snapshot(self.db);self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(inc,snapshot(self.db))
        self.assertGreater(self.db.one('SELECT COUNT(*) AS n FROM viewer_event_captures')['n'],3)

    def test_duplicate_capture_keeps_counts_roles_keys_and_restart_cursor(self):
        row=log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        self.publish([row]);self.db.update_service_role('Services.v1/WaterBills','support','unknown','retain')
        fingerprint=self.db.keys.fingerprint
        self.publish([row],mode='recheck')
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],1)
        self.assertEqual(self.db.semantic_sessions()['total'],0)
        with ViewerDB(**self.opts) as other:
            bind_stream(other,start_ns=START,stream_key='synthetic')
            self.assertEqual(other.keys.fingerprint,fingerprint)
            self.assertEqual(other.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)
            self.assertEqual(other.one('SELECT note FROM viewer_service_roles')['note'],'retain')

    def test_faults_before_commit_leave_whole_previous_generation(self):
        self.publish([log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        before=snapshot(self.db);state=self.db.one('SELECT * FROM viewer_live_state')
        late=log(2,'b','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        late['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        for point in ('after_ingest','after_requests','after_relations','after_semantics','before_commit'):
            def crash(stage):
                if stage==point:raise RuntimeError('controlled_crash')
            with self.assertRaisesRegex(RuntimeError,'controlled_crash'):
                self.publish([late],start=START+FIVE_NS,fault=crash)
            self.assertEqual(snapshot(self.db),before)
            self.assertEqual(self.db.one('SELECT * FROM viewer_live_state'),state)
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],1)
        self.publish([late],start=START+FIVE_NS)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],2)

    def test_post_commit_disconnect_is_reconciled_from_durable_checkpoint(self):
        def crash(stage):
            if stage=='after_commit':raise RuntimeError('connection_lost_after_commit')
        with self.assertRaises(RuntimeError):
            self.publish([log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')],fault=crash)
        with ViewerDB(**self.opts) as other:
            self.assertEqual(other.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)
            self.assertEqual(other.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],1)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],1)

    def test_reader_during_publication_keeps_old_snapshot_then_new(self):
        self.publish([log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        row=log(2,'b','Services.v1/GasBills Line:1','POST (G00000 | successful)');row['@timestamp']=iso(START+FIVE_NS)
        with ViewerDB(**self.opts) as reader:
            reader.sql('BEGIN')
            old=reader.semantic_sessions()['generation']
            def observe(stage):
                if stage=='after_requests':
                    self.assertEqual(reader.semantic_sessions()['generation'],old)
                    self.assertEqual(reader.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],1)
                    self.assertEqual(reader.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],1)
            self.publish([row],start=START+FIVE_NS,fault=observe)
            self.assertEqual(reader.semantic_sessions()['generation'],old)
            reader.conn.rollback()
            self.assertGreater(reader.semantic_sessions()['generation'],old)
            self.assertEqual(reader.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],2)

    def test_empty_window_advances_but_forward_gap_and_stream_change_rejected(self):
        self.publish([])
        with self.assertRaisesRegex(ValueError,'noncontiguous'):
            self.publish([],start=START+2*FIVE_NS)
        with self.assertRaisesRegex(ValueError,'stream_or_keys'):
            bind_stream(self.db,start_ns=START+FIVE_NS,stream_key='synthetic')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)

    def test_real_recheck_scheduler_and_failure_does_not_advance(self):
        paths={START:verified_file(self.root/'empty.gz',[])};calls=[]
        def capture(a,b):calls.append(a);return paths[a]
        worker=LiveWorker(self.db,capture)
        now=START+FIVE_NS+60_000_000_000
        self.assertEqual(worker.step(now=now)['mode'],'forward')
        self.assertEqual(worker.step(now=now)['mode'],'recheck')
        self.assertEqual(worker.step(now=now)['status'],'WAITING')
        self.assertEqual(calls,[START,START])
        with self.assertRaises(RuntimeError):worker.step(now=now+FIVE_NS)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)
        self.assertEqual(live_status(self.db,now=now+FIVE_NS)['status'],'ERROR')

    def test_singleton_os_lock(self):
        with single_worker(self.db,self.root/'worker.lock'):
            with self.assertRaisesRegex(ValueError,'already_running'):
                with single_worker(self.db,self.root/'worker.lock'):pass
        with single_worker(self.db,self.root/'worker.lock'):pass

    def test_reverse_late_rechecks_match_chronological_batch(self):
        a=[log(1,'query','Services.v1/WaterBills Line:1','POST (G00000 | successful)'),
           log(2,'query','DBPath.x.ud_prc_invoiceInfo',sql('ud_prc_invoiceInfo',invoiceUniqueID='I'))]
        b=[log(3,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
           log(4,'pay','DBPath.x.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',paymentKey='K')),
           log(5,'pay','DBPath.x.ud_prc_paymentRequestForInvoiceSettlement',sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='I',paymentKey='K'))]
        for r in b:r['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        # Valid empty captures establish the forward cursor; then old windows
        # receive their evidence in reverse knowledge/arrival order.
        self.publish([]);self.publish([],start=START+FIVE_NS)
        self.publish(b,start=START+FIVE_NS,mode='recheck');self.publish(a,mode='recheck')
        inc=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(inc,snapshot(self.db))
        self.assertEqual(self.db.semantic_sessions()['total'],1)
        self.assertEqual(len(self.db.request(token(self.db.keys,'request','query'))['service_journey']['steps']),2)

    def test_changed_payment_origin_invalidates_old_group_and_session_head(self):
        rows=[log(1,'p','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
              log(2,'p','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
              log(3,'peer','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
              log(4,'peer','Core.v1/WalletPayment Line:1','POST (G00000 | successful)')]
        self.publish(rows)
        changed=dict(rows[0]);changed['message']=sql('ud_prc_paymentExists',paymentKey='OTHER')
        info=self.publish([changed],mode='recheck')
        self.assertEqual(info['impacted_requests'],2)
        inc=snapshot(self.db);self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(inc,snapshot(self.db))
        self.assertEqual(self.db.lookup_request('p')['conflicted'],1)

    def test_wrong_keys_are_rejected_before_m1_database_adoption(self):
        self.publish([log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
        # Simulate an M1 DB without online binding; raw source identity stays.
        self.db.sql('DELETE FROM viewer_live_state');self.db.conn.commit()
        other_keys=self.root/'different_keys.json';generate_keys(other_keys)
        with ViewerDB(sqlite_path=self.opts['sqlite_path'],keys_path=other_keys) as wrong:
            with self.assertRaisesRegex(ValueError,'keys_or_raw_identity_mismatch'):
                bind_stream(wrong,start_ns=START,stream_key='synthetic')

    def test_capture_proof_and_corruption_rejected_without_database_changes(self):
        path=verified_file(self.root/'bad.gz',[])
        data=json.load(gzip.open(path,'rt'));data['verification']['counts_match']=False
        with gzip.open(path,'wt') as f:json.dump(data,f)
        with self.assertRaisesRegex(ValueError,'proof_incomplete'):
            publish_capture(self.db,path,START,START+FIVE_NS)
        path.write_bytes(b'not gzip')
        with self.assertRaises(Exception):publish_capture(self.db,path,START,START+FIVE_NS)
        self.assertEqual(self.db.one('SELECT generation FROM viewer_live_state')['generation'],0)

    def test_live_capture_decoded_once(self):
        path=verified_file(self.root/'once.gz',[log(1,'once','Services.v1/WaterBills Line:1','POST (G00000)')])
        with patch.object(viewer_online.gzip,'open',wraps=gzip.open) as decoded:
            result=publish_capture(self.db,path,START,START+FIVE_NS)
        self.assertEqual(result['status'],'PUBLISHED')
        self.assertEqual(decoded.call_count,1)

    def test_capture_replaced_during_publication_rolls_back(self):
        first=log(1,'original','Services.v1/WaterBills Line:1','POST (G00000)')
        path=verified_file(self.root/'original.gz',[first])
        replacement=dict(first,**{'@timestamp':iso(START+FIVE_NS)})
        other=verified_file(self.root/'replacement.gz',[replacement])
        original_hash=viewer_online.hash_file

        def replace_before_hash(filename):
            other.replace(filename)
            return original_hash(filename)

        with patch.object(viewer_online,'hash_file',side_effect=replace_before_hash):
            with self.assertRaisesRegex(ValueError,'capture_changed_during_publication'):
                publish_capture(self.db,path,START,START+FIVE_NS)
        state=self.db.one('SELECT generation,next_ns FROM viewer_live_state')
        self.assertEqual(dict(state),{'generation':0,'next_ns':START})
        for table in ('viewer_events','viewer_raw_events','viewer_live_receipts','viewer_live_windows'):
            self.assertEqual(self.db.one(f'SELECT COUNT(*) AS n FROM {table}')['n'],0)


class FakeElastic:
    def __init__(self,responses):self.responses=iter(responses);self.cleared=[];self.queries=[]
    def search(self,body,timeout):self.queries.append(body);return next(self.responses)
    def scroll(self,sid,timeout):
        item=next(self.responses)
        if isinstance(item,Exception):raise item
        return item
    def clear(self,sid):self.cleared.append(sid)


def es_page(hits,total=1,**kwargs):
    result=dict(_scroll_id='cursor',timed_out=False,_shards=dict(total=1,successful=1,failed=0),
                hits=dict(total=dict(value=total,relation='eq'),hits=hits))
    result.update(kwargs);return result


class OnlineCaptureTests(unittest.TestCase):
    def test_verified_streamed_capture_and_empty_window(self):
        source=log(1,'q','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        hit=dict(_index='synthetic-index',_id='1',_source=source)
        with tempfile.TemporaryDirectory() as t:
            fake=FakeElastic([es_page([hit]),es_page([])])
            path=ElasticCapture(fake,t)(START,START+FIVE_NS)
            self.assertEqual(validate_capture(path,START,START+FIVE_NS)['records'],1)
            self.assertEqual(fake.cleared,['cursor'])
            self.assertNotIn('Session',json.dumps(fake.queries))
            fake=FakeElastic([es_page([],total=0)])
            empty=ElasticCapture(fake,t)(START,START+FIVE_NS)
            self.assertEqual(validate_capture(empty,START,START+FIVE_NS)['records'],0)

    def test_incomplete_and_duplicate_search_never_publish_partial_file(self):
        source=log(1,'q','Services.v1/WaterBills Line:1','POST (G00000 | successful)')
        hit=dict(_index='synthetic-index',_id='1',_source=source)
        cases=[
          [es_page([],timed_out=True)], [es_page([],terminated_early=True)],
          [es_page([],_shards=dict(total=2,successful=1,failed=1))],
          [es_page([])], [es_page([hit]),es_page([hit])],
          [es_page([hit]),TimeoutError('expired cursor')],
          [es_page([hit],_scroll_id=None)],
          [es_page([dict(hit,_id=None)])],
        ]
        for responses in cases:
            with self.subTest(case=cases.index(responses)),tempfile.TemporaryDirectory() as t:
                fake=FakeElastic(responses)
                with self.assertRaises(Exception):ElasticCapture(fake,t)(START,START+FIVE_NS)
                self.assertFalse(list(Path(t).glob('*.json.gz')))
                self.assertFalse(list(Path(t).glob('*.partial')))

if __name__=='__main__':unittest.main()
