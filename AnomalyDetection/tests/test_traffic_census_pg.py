"""Native regression tests for complete, restartable request-root censuses.

The source metadata is a declared fixture. All paging, staging, publication,
rescan and rollback SQL runs against a disposable native PostgreSQL database.
"""
from contextlib import contextmanager
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection.history_reset import tehran_boundary
from anomaly_detection.product_store import ProductStore
from anomaly_detection.scenario_traffic import apply,read_page
from tests import test_scenario_invalidation_pg as native

TARGET=tehran_boundary('2026-10-23')[1]
LANE='scenario_traffic_cursor'
SERVICE='Services.v1/Fixture'


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native AD cluster not configured')
class NativeTrafficCensusTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeScenarioInvalidationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeScenarioInvalidationTests.tearDownClass.__func__)
    setUp=native.NativeScenarioInvalidationTests.setUp

    def meta(self,generation=1):
        return dict(namespace='viewer:fixture',stream_key='fixture',keys_fingerprint='fixture',
            generation=generation,semantic_generation=generation,captured_at_ns=TARGET+FIVE_NS,
            next_ns=TARGET+FIVE_NS,retention_cutoff_ns=0,analysis_floor_ns=0,
            source_finality='not_established',catalog_fingerprint='fixture')

    def event(self,n,*,origin=None,version=None,at=None):
        return dict(origin_key=origin or f'{n:064x}',version_key=version or f'{n+1000:064x}',
            request_key=f'{n+2000:064x}',session_key='b'*64,owner_session='b'*64,
            at_ns=at or TARGET+1,ip_key='c'*64,callpath=SERVICE,root_call=SERVICE,
            kind='client',identity_state='assigned',conflicted=False,root_count=1,
            semantic_service=None,semantic_state=None,root_match=True,raw_available=True,variants=1)

    def packet(self,rows,*,more=False,generation=1):
        return dict(source=self.meta(generation),target_ns=TARGET,stamp='fixture-'+str(generation),
            status='PAGE',rows=rows,has_more=more,page_size=64,
            after=[rows[-1]['at_ns'],rows[-1]['origin_key'],rows[-1]['version_key']] if more else None)

    def count(self):
        row=self.raw.execute('SELECT body FROM anomaly_detection.adp_traffic_counts WHERE service_path=%s AND start_ns=%s',
            (SERVICE,TARGET)).fetchone()
        return json.loads(row['body']) if row else None

    def source(self,events):
        self.raw.execute('CREATE TABLE public.viewer_live_windows(start_ns BIGINT PRIMARY KEY,end_ns BIGINT,generation BIGINT,last_publish_ns BIGINT)')
        self.raw.execute('INSERT INTO public.viewer_live_windows VALUES(%s,%s,1,1)',(TARGET,TARGET+FIVE_NS))
        self.raw.execute('CREATE TABLE public.viewer_events(origin_key TEXT,version_key TEXT,at_ns BIGINT,request_key TEXT,session_key TEXT,ip_key TEXT,callpath TEXT,kind TEXT,PRIMARY KEY(origin_key,version_key))')
        self.raw.execute('CREATE INDEX event_time ON public.viewer_events(at_ns)')
        self.raw.execute('CREATE TABLE public.viewer_requests(request_key TEXT PRIMARY KEY,root_call TEXT,root_count INTEGER,identity_state TEXT,conflicted BOOLEAN,session_key TEXT)')
        self.raw.execute('CREATE TABLE public.viewer_raw_events(origin_key TEXT,version_key TEXT,PRIMARY KEY(origin_key,version_key))')
        self.raw.execute('CREATE TABLE public.viewer_semantic_occurrences(request_key TEXT PRIMARY KEY,root_call TEXT,state TEXT)')
        for row in events:
            self.raw.execute('INSERT INTO public.viewer_events VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                tuple(row[k] for k in ('origin_key','version_key','at_ns','request_key','session_key','ip_key','callpath','kind')))
            self.raw.execute('INSERT INTO public.viewer_requests VALUES(%s,%s,1,\'assigned\',FALSE,%s) ON CONFLICT DO NOTHING',
                (row['request_key'],SERVICE,row['session_key']))
            self.raw.execute('INSERT INTO public.viewer_raw_events VALUES(%s,%s)',(row['origin_key'],row['version_key']))
        queries=[]
        @contextmanager
        def snapshot():
            from psycopg.rows import dict_row
            with self.psycopg.connect(**self.params,dbname=self.name,row_factory=dict_row) as raw:
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                def q(statement,params=(),*,cap):
                    self.assertTrue(statement.startswith('SELECT '));queries.append(statement)
                    rows=raw.execute(statement,params).fetchall()
                    self.assertLessEqual(len(rows),cap)
                    return [dict(r) for r in rows]
                yield q
        return SimpleNamespace(snapshot=snapshot,metadata=lambda q:self.meta()),queries

    def test_equal_time_origin_versions_crossing_page_boundary_are_all_examined(self):
        events=[self.event(i) for i in range(1,64)]
        events += [self.event(64,origin='f'*64,version=f'{v:064x}',at=TARGET+2) for v in (1,2)]
        events += [self.event(65,at=TARGET+3)]
        source,_=self.source(events);cursor={'page_size':64};scanned=0;seen=[]
        for turn in range(5):
            packet=read_page(source,cursor);scanned+=packet['scanned_events']
            seen.extend((r['origin_key'],r['version_key']) for r in packet['rows'])
            self.assertLessEqual(packet['scanned_events'],64)
            self.assertIn(apply(self.store,packet),('PAGE','COMPLETE'))
            if not packet['has_more']:break
            cursor=self.store.state(LANE)
        self.assertEqual(scanned,len(events))
        self.assertCountEqual(seen,[(r['origin_key'],r['version_key']) for r in events])
        # A conflicting origin never becomes two logical executions.
        self.assertEqual(self.count()['requests'],64)
        self.assertFalse(self.count()['complete'])

    def test_history_rescan_discards_previous_partial_pass_before_publishing_new_input(self):
        from anomaly_detection.history_rescan import prepare
        old=self.event(1);new=self.event(2)
        self.assertEqual(apply(self.store,self.packet([old],more=True)),'PAGE')
        self.assertIsNone(self.count())
        prepare(self.store,'2026-10-23','d'*32)
        restarted=ProductStore(self.raw)
        self.assertEqual(apply(restarted,self.packet([new],generation=2)),'COMPLETE')
        self.assertEqual(self.count()['request_keys'],[new['request_key']])
        self.assertEqual(self.count()['requests'],1)
        members=self.raw.execute('SELECT request_key FROM anomaly_detection.adp_traffic_members').fetchall()
        self.assertEqual([r['request_key'] for r in members],[new['request_key']])

    def test_continuation_with_a_different_stamp_is_rejected_without_changing_staging(self):
        apply(self.store,self.packet([self.event(1)],more=True))
        before=self.store.state(LANE)
        with self.assertRaisesRegex(ValueError,'TRAFFIC_STAGE_STAMP_MISMATCH'):
            apply(self.store,self.packet([self.event(2)],generation=2))
        self.assertEqual(self.store.state(LANE),before)
        self.assertIsNone(self.count())
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_traffic_staging').fetchone()['n'],1)

    def test_legacy_two_part_cursor_restarts_target_without_withdrawing_published_counts(self):
        row=self.event(1);source,_=self.source([row])
        apply(self.store,self.packet([row]))
        partial=self.packet([self.event(2)],more=True)
        apply(self.store,partial)
        cursor=self.store.state(LANE);cursor['after']=cursor['after'][:2]
        # Use the real source stamp, so the restart must be a cursor upgrade.
        cursor['stamp']=read_page(source,{'page_size':64})['stamp']
        self.store.save_state(LANE,cursor)
        packet=read_page(source,cursor)
        self.assertEqual(packet['status'],'RESTART')
        self.assertEqual(apply(self.store,packet),'RESTART')
        self.assertEqual(self.count()['request_keys'],[row['request_key']])
        self.assertEqual(self.store.state(LANE),{'target_ns':TARGET})
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_traffic_staging').fetchone()['n'],0)

    def test_failed_final_commit_keeps_published_data_and_partial_cursor_for_restart(self):
        old=self.event(1);first=self.event(2);last=self.event(3)
        apply(self.store,self.packet([old]))
        apply(self.store,self.packet([first],more=True,generation=2))
        tables=('adp_state','adp_traffic_counts','adp_traffic_members','adp_traffic_staging',
                'adp_profile_scopes','adp_scenario_jobs','adp_profile_tasks')
        def saved():
            return {t:sorted(json.dumps(dict(r),sort_keys=True) for r in self.raw.execute(
                self.sql.SQL('SELECT * FROM anomaly_detection.{}').format(self.sql.Identifier(t))).fetchall()) for t in tables}
        before=saved();save=self.store.save_state
        def fail_final(name,value):
            if name==LANE and value=={'next_ns':TARGET+FIVE_NS}:raise RuntimeError('controlled_final_commit_failure')
            return save(name,value)
        with patch.object(self.store,'save_state',side_effect=fail_final):
            with self.assertRaisesRegex(RuntimeError,'controlled_final_commit_failure'):
                apply(self.store,self.packet([last],generation=2))
        self.assertEqual(saved(),before)
        self.assertEqual(self.count()['request_keys'],[old['request_key']])
        restarted=ProductStore(self.raw)
        self.assertEqual(apply(restarted,self.packet([last],generation=2)),'COMPLETE')
        self.assertEqual(self.count()['request_keys'],sorted([first['request_key'],last['request_key']]))

    def test_first_page_cleanup_is_limited_to_its_lane_and_window(self):
        other_lane='scenario_old_traffic_cursor'
        apply(self.store,self.packet([self.event(1)]))
        apply(self.store,self.packet([self.event(3)],more=True))
        apply(self.store,self.packet([self.event(2)],more=True),cursor_name=other_lane)
        self.store.save_state(LANE,{'next_ns':TARGET})
        self.assertEqual(apply(self.store,self.packet([])),'COMPLETE')
        self.assertEqual(self.count()['requests'],0)
        self.assertTrue(self.count()['complete'])
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_traffic_members').fetchone()['n'],0)
        remaining=self.raw.execute('SELECT lane,body FROM anomaly_detection.adp_traffic_staging').fetchall()
        self.assertEqual([r['lane'] for r in remaining],[other_lane])
        self.assertEqual(json.loads(remaining[0]['body'])['request_key'],self.event(2)['request_key'])

    def test_replayed_partial_page_and_empty_filtered_page_preserve_exact_request_membership(self):
        first=self.event(1);last=self.event(2)
        partial=self.packet([first],more=True)
        self.assertEqual(apply(self.store,partial),'PAGE')
        self.assertEqual(apply(self.store,partial),'PAGE')
        empty=self.packet([]);empty['has_more']=True
        empty['after']=[TARGET+2,'e'*64,'d'*64]
        self.assertEqual(apply(self.store,empty),'PAGE')
        self.assertEqual(apply(ProductStore(self.raw),self.packet([last])),'COMPLETE')
        self.assertEqual(self.count()['requests'],2)
        self.assertCountEqual(self.count()['request_keys'],[first['request_key'],last['request_key']])


if __name__=='__main__':unittest.main()
