"""Native regression tests for complete, restartable request-root censuses.

The source metadata is a declared fixture. All paging, staging, publication,
rescan and rollback SQL runs against a disposable native PostgreSQL database.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
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

    def killed_final_page(self,phase):
        old,first,last=(self.event(i) for i in (1,2,3))
        apply(self.store,self.packet([old]))
        apply(self.store,self.packet([first],more=True,generation=2))
        tables=('adp_state','adp_traffic_counts','adp_traffic_members','adp_traffic_staging',
                'adp_profile_scopes','adp_scenario_jobs','adp_profile_tasks')
        def saved():
            return {t:sorted(json.dumps(dict(r),sort_keys=True) for r in self.raw.execute(
                self.sql.SQL('SELECT * FROM anomaly_detection.{}').format(self.sql.Identifier(t))).fetchall()) for t in tables}
        before=saved()
        code='''import json,re,sys
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from anomaly_detection.product_store import ProductStore
from anomaly_detection.scenario_traffic import apply
cfg=json.loads(sys.stdin.readline())
assert re.fullmatch(r'p24_design_adperf_[0-9a-f]{32}',cfg['database'])
with psycopg.connect(**cfg['params'],dbname=cfg['database'],autocommit=True,row_factory=dict_row) as raw:
    assert raw.execute('SELECT current_database() AS db').fetchone()['db']==cfg['database']
    store=ProductStore(raw);store._history_floor_ns=0
    original=store.save_state
    def pause():
        Path(cfg['marker']).write_text(cfg['phase'],encoding='utf-8')
        sys.stdin.readline()
    def checkpoint(name,value):
        if cfg['phase']=='before_commit' and name==cfg['lane'] and 'next_ns' in value:pause()
        return original(name,value)
    store.save_state=checkpoint
    assert apply(store,cfg['packet'],cursor_name=cfg['lane'])=='COMPLETE'
    if cfg['phase']=='after_commit':pause()
'''
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'paused'
            child=subprocess.Popen([sys.executable,'-B','-c',code],cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                child.stdin.write(json.dumps(dict(params=self.params,database=self.name,marker=str(marker),
                    phase=phase,lane=LANE,packet=self.packet([last],generation=2)))+'\n');child.stdin.flush()
                deadline=time.monotonic()+15
                while not marker.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.02)
                if not marker.exists():
                    child.kill();out,err=child.communicate(timeout=5)
                    self.fail('Child did not reach transaction boundary: '+out+err)
                self.assertEqual(self.count()['requests'],1 if phase=='before_commit' else 2)
                child.kill();child.wait(timeout=5)
                self.assertNotEqual(child.returncode,0)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
                for stream in (child.stdin,child.stdout,child.stderr):stream.close()
        if phase=='before_commit':
            self.assertEqual(saved(),before)
            self.assertEqual(apply(ProductStore(self.raw),self.packet([last],generation=2)),'COMPLETE')
        self.assertEqual(self.count()['request_keys'],sorted([first['request_key'],last['request_key']]))
        self.assertEqual(self.store.state(LANE),{'next_ns':TARGET+FIVE_NS})
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_traffic_staging').fetchone()['n'],0)

    def test_process_kill_before_final_commit_keeps_prior_output_and_recovers_partial_pass(self):
        self.killed_final_page('before_commit')

    def test_process_kill_after_final_commit_keeps_counts_and_cursor_together(self):
        self.killed_final_page('after_commit')

    def test_ready_recheck_ready_changes_counts_without_erasing_cases_or_human_feedback(self):
        from anomaly_detection.cases import replace_scope,identity
        from anomaly_detection.case_summary import statistics,case_status
        actor='b'*64
        self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,version,primary_version,dirty) VALUES(%s,%s,1,1,FALSE)',(actor,TARGET))
        self.raw.execute("INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns,dirty,processed_version) VALUES('feature','traffic',%s,%s,%s,FALSE,1)",(SERVICE,SERVICE,TARGET))
        items={kind:dict(signal_key='signal-'+kind,family=family,entity_type=kind,
            entity_key=actor if kind=='actor' else SERVICE,service_path=SERVICE,target_ns=TARGET,
            status='CANDIDATE',observed=10,upper=2,evidence_verified=True,single_signal_review_eligible=True)
            for kind,family in (('actor','peer_service_rate_5m'),('service','service_volume'))}
        def publish(version):
            for kind in items:
                job={'target_ns':TARGET,'version':version,'primary_version':version}
                if kind=='actor':job['session_key']=actor
                with self.store.transaction():
                    replace_scope(self.store,kind,[items[kind]],TARGET+version,
                        source_kind='actor' if kind=='actor' else 'feature',job=job)
        # Feature input lookup uses its actual scope key.
        publish(1)
        self.raw.execute("UPDATE anomaly_detection.adp_case_signals SET scope_key='feature' WHERE source_kind='feature'")
        keys={k:identity(k,actor if k=='actor' else SERVICE,'activity' if k=='actor' else 'service_volume',SERVICE) for k in items}
        self.assertEqual(statistics(self.store)['READY'],{'bucket':'READY','cases':2,'services':1,'actors':1})
        revision=self.raw.execute('SELECT revision FROM anomaly_detection.adp_cases WHERE case_key=%s',(keys['actor'],)).fetchone()['revision']
        self.raw.execute('INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision) VALUES(%s,%s,%s,%s,%s)',
            (keys['actor'],'confirmed_suspicious','retained operator review',TARGET,revision))
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=2,primary_version=2,dirty=TRUE')
        self.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET version=2,dirty=TRUE')
        self.assertEqual(statistics(self.store)['RECHECK']['cases'],2)
        self.assertEqual(statistics(self.store).get('READY',{}).get('services',0),0)
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE')
        self.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        # Keep the same feature scope while publishing its new receipt.
        with self.store.transaction():
            replace_scope(self.store,'feature',[items['service']],TARGET+2,source_kind='feature',job={'target_ns':TARGET,'version':2})
            replace_scope(self.store,'actor',[items['actor']],TARGET+2,job={'session_key':actor,'target_ns':TARGET,'version':2,'primary_version':2})
        self.assertEqual(case_status(self.store,keys['service'])['bucket'],'READY')
        self.assertEqual(case_status(self.store,keys['actor'])['bucket'],'REVIEWED')
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases').fetchone()['n'],2)
        self.assertEqual(self.raw.execute('SELECT note FROM anomaly_detection.adp_case_feedback').fetchone()['note'],'retained operator review')


if __name__=='__main__':unittest.main()
