"""Synthetic multi-day fixtures. No production identities or raw inputs."""
import copy
import multiprocessing
import os
import time
import unittest
import uuid
from unittest.mock import patch

from compact_ad import longitudinal as long, long_store
from compact_behavior import FIVE
from compact_behavior.extract import digest

SERVICE='Services.v1/WaterBills'
DAY=long.day_start(1800000000000000000)


def daily(day, peers=110):
    result={}
    for i in range(peers+1):
        name='crawler' if i==peers else 'peer-'+str(i)
        tokens=[digest(['bill',day,j]) for j in range(10)] if name=='crawler' else [digest(['bill',i])]
        result[name]=dict(count=10,days=1,invalid=False,evidence=[digest([name,day,j]) for j in range(6)],
                          fields={'$.BillID':dict(tokens=tokens,covered=10,overflow=False)})
    return result


class LongitudinalTests(unittest.TestCase):
    def evaluate(self,actors,span=3):
        return long.evaluate(actors,service=SERVICE,end=DAY+span*long.DAY,span=span,signature='synthetic')

    def test_low_daily_volume_distinct_crawler_is_single_method_case(self):
        from compact_product.cases import select_cases
        actors=long.merge((daily(d) for d in range(3)),active_days=True)
        results=self.evaluate(actors)
        self.assertEqual([r['session_id'] for r in results],['crawler'])
        result=results[0]
        self.assertEqual((result['observed'],result['active_days'],result['requests']), (30,3,30))
        row=dict(result,finding_id='synthetic',start_ns=result['window_start_ns'],result=result)
        self.assertEqual(select_cases([row])[0]['reasons'],['QUALIFIED_SINGLE_METHOD'])

    def test_two_reviewed_axes_can_both_qualify_for_one_session(self):
        actors=long.merge((daily(d,peers=160) for d in range(3)),active_days=True)
        for a in actors.values():
            a['fields']['NationalCode']=copy.deepcopy(a['fields']['$.BillID'])
        results=self.evaluate(actors)
        self.assertEqual({r['numeric_path'] for r in results},{'$.BillID','NationalCode'})
        self.assertEqual([r['observed'] for r in results],[30,30])

    def test_same_target_across_days_not_summed_and_typed_fields_not_mixed(self):
        chunks=[daily(d) for d in range(3)]
        for row in chunks:
            row['crawler']['fields']['$.BillID']['tokens']=['same']
        self.assertFalse(self.evaluate(long.merge(chunks,active_days=True)))
        chunks=[daily(d) for d in range(3)]
        for row in chunks:
            value=row['crawler']['fields'].pop('$.BillID')
            row['crawler']['fields']['$.PhoneNumber']=value
        self.assertFalse(self.evaluate(long.merge(chunks,active_days=True)))

    def test_unknown_inputs_thin_peers_and_short_activity_do_not_become_normal_evidence(self):
        for change in ('invalid','coverage','days','peers'):
            actors=long.merge((daily(d,peers=99 if change=='peers' else 110) for d in range(3)),active_days=True)
            if change=='invalid':actors['crawler']['invalid']=True
            if change=='coverage':actors['crawler']['fields']['$.BillID']['covered']-=1
            if change=='days':actors['crawler']['days']=1
            self.assertFalse(self.evaluate(actors),change)

    def test_rare_activity_uses_explicit_exposure_scaled_population_and_excludes_self(self):
        actors=long.merge((daily(d) for d in range(3)),active_days=True)
        for name,a in actors.items():
            if name!='crawler':a['count']=1;a['days']=1;a['fields']['$.BillID']['covered']=1
        result=self.evaluate(actors)[0]
        self.assertEqual(result['peer_basis'],'SERVICE_POPULATION_ACTIVE_DAY_SCALED')
        self.assertEqual(result['baseline'],3)
        self.assertEqual(result['peer_count'],110)
        self.assertEqual(result['session_id'],'crawler')
        actors=long.merge((daily(d) for d in range(3)),active_days=True)
        actors['crawler']['fields']['$.BillID']['tokens']=list(actors['peer-0']['fields']['$.BillID']['tokens'])
        self.assertFalse(self.evaluate(actors))

    def test_cap_is_lower_bound_and_censored_peers_cannot_make_false_outlier(self):
        chunks=[daily(d) for d in range(30)]
        actors=long.merge(chunks,active_days=True)
        result=self.evaluate(actors,30)[0]
        self.assertTrue(result['observed_is_lower_bound'])
        self.assertEqual(result['observed'],long.TARGET_CAP+1)
        actors['peer-0']['fields']['$.BillID']['overflow']=True
        self.assertFalse(self.evaluate(actors,30))

    def test_replay_order_determinism_and_budget_fail_closed(self):
        chunks=[daily(d) for d in range(3)]
        first=long.merge(chunks,active_days=True)
        second=long.merge(reversed(chunks),active_days=True)
        # Witness order is chronological; counts and union are order independent.
        for name in first:self.assertEqual(first[name]['fields'],second[name]['fields'])
        self.assertEqual(long.unpack(long.pack(first)),first)
        with patch.object(long,'ENTRY_CAP',10),self.assertRaises(long.CapacityExceeded):
            long.merge(chunks)
        with patch.object(long,'BYTE_CAP',10),self.assertRaises(long.CapacityExceeded):
            long.unpack(long.pack({})+b'garbage')

    def test_projection_reuses_features_without_identity_linking_or_raw_values(self):
        from compact_ad.engine import summarize
        from tests.test_compact_ad import behavior
        from tests.test_compact_extract import T
        rows=[behavior(str(i),'session-'+str(i%2),target='private-target',start=T) for i in range(4)]
        base=summarize(rows,cutoff_ns=T+FIVE)
        extended=summarize(rows,cutoff_ns=T+FIVE,collect_longitudinal=True)
        self.assertEqual(base[0],extended[0])
        profile=long.projection(extended[0],extended[2])[SERVICE]
        self.assertEqual(set(profile),{'session-0','session-1'})
        self.assertNotIn('private-target',str(profile))
        self.assertEqual([p['count'] for p in profile.values()],[2,2])

    def test_single_forest_needs_held_out_calibration_and_weak_signals_stay_separate(self):
        from compact_product.cases import select_cases, service_groups
        result=dict(reference_windows=36,evidence=['a','b','c'],single_signal_review_eligible=True,
                    calibration_rows=100,calibration_tail_rank=.009)
        row=dict(finding_id='forest',method='isolation_forest',service='*',session_id='s',start_ns=0,result=result)
        self.assertFalse(select_cases([row]))
        row['verdict'] = 'CONFIRMED'
        self.assertEqual(len(select_cases([row])),1)
        self.assertFalse(service_groups(select_cases([row])))
        del row['verdict']
        result['calibration_tail_rank']=.02
        self.assertFalse(select_cases([row]))


def crash_long(database,s,a,point):
    from compact_ad.store import AnalysisStore
    db=AnalysisStore(database,schema=s,ad_schema=a)
    long_store.run_period(db,'test',fault=lambda where: os._exit(73) if where==point else None)
    os._exit(74)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PostgreSQL required')
class LongitudinalPostgresTests(unittest.TestCase):
    def setUp(self):
        from compact_ad.store import AnalysisStore
        from compact_product.config import Config
        self.database=dict(host=os.environ['P24_DELTA_PG_HOST'],port=os.environ['P24_DELTA_PG_PORT'],
                           user=os.environ['P24_DELTA_PG_USER'],dbname='postgres')
        key=uuid.uuid4().hex[:10]
        self.cfg=Config(source_schema='p24_compact_long_'+key,ad_schema='p24_compact_ad_long_'+key)
        self.db=AnalysisStore(self.database,schema=self.cfg.source_schema,ad_schema=self.cfg.ad_schema)
        self.db.init();self.s=self.db.schema;self.a=self.db.ad_schema

    def tearDown(self):
        self.db.conn.execute('DROP SCHEMA '+self.a+' CASCADE')
        self.db.conn.execute('DROP SCHEMA '+self.s+' CASCADE');self.db.close()

    def seed(self):
        self.db.publish('test',DAY,DAY+FIVE,{},0)
        self.db.conn.execute(f'DELETE FROM {self.s}.dirty_windows')
        self.db.conn.execute(f'UPDATE {self.s}.queue_counts SET dirty_keys=0')
        with self.db.conn.transaction():
            self.db.conn.execute(f'''INSERT INTO {self.s}.windows(stream_id,start_ns,end_ns,source_records,extracted_requests,content_hash,published_at_ns)
                SELECT 'test',v,v+%s,0,0,'synthetic',1 FROM generate_series(%s::bigint,%s::bigint,%s::bigint) v
                ON CONFLICT(stream_id,start_ns) DO UPDATE SET published_at_ns=1''',(FIVE,DAY,DAY+3*long.DAY-FIVE,FIVE))
            self.db.conn.execute(f'''INSERT INTO {self.a}.long_manifest SELECT stream_id,start_ns,published_at_ns,%s,0
                FROM {self.s}.windows''',(long.VERSION,))
            for day in range(3):
                profile=daily(day)
                long_store.save(self.db.conn,self.a,'test',DAY+day*long.DAY,1,{SERVICE:(digest(profile),long.pack(profile))})
        for _ in range(3):self.assertEqual(long_store.build_day(self.db,'test')['state'],'READY')
        self.db.conn.execute(f'DELETE FROM {self.a}.long_runs WHERE end_ns<>%s OR span<>3',(DAY+3*long.DAY,))

    def ready(self):
        result=long_store.run_period(self.db,'test')
        self.assertEqual(result['state'],'READY')
        return self.db.conn.execute(f'SELECT * FROM {self.a}.findings').fetchone()

    def test_old_limit_eight_thousand_actors_is_retried_by_indexed_evaluator(self):
        self.seed()
        for day in range(3):
            profile={str(i):dict(count=7,days=1,invalid=False,evidence=['a','b','c'],
                fields={'WaterBillID':dict(tokens=[digest([i,j]) for j in range(day*7,day*7+7)],covered=7,overflow=False)}) for i in range(8000)}
            self.db.conn.execute(f'''UPDATE {self.a}.long_days SET payload=%s,signature=%s
                WHERE stream_id='test' AND day_ns=%s''',(long.pack(profile),digest(profile),DAY+day*long.DAY))
        self.db.conn.execute(f"UPDATE {self.a}.long_runs SET state='LIMIT',retry_ns=0,details='{{}}'::jsonb")
        self.db.conn.execute(f'''INSERT INTO {self.a}.long_runs(stream_id,service,end_ns,span,state)
            VALUES ('test','synthetic-waiting',%s,3,'WAITING')''',(DAY+long.DAY,))
        result=long_store.run_period(self.db,'test')
        self.assertEqual(result['state'],'READY')
        self.assertEqual(result['actors'],8000)

    def test_comparison_cursor_is_fenced_and_publishes_only_after_completion(self):
        from unittest.mock import patch
        self.seed()
        original=long.evaluate
        def pause(actors,**kwargs):
            values=original(actors,**kwargs)
            raise long.ComparisonPending(len(actors),values,kwargs['diagnostics'])
        with patch.object(long,'evaluate',side_effect=pause):
            self.assertEqual(long_store.run_period(self.db,'test')['state'],'WAITING')
        self.assertEqual(self.db.conn.execute(f'SELECT count(*) AS n FROM {self.a}.findings').fetchone()['n'],0)
        self.db.conn.execute(f'UPDATE {self.a}.long_runs SET retry_ns=0')
        self.assertEqual(long_store.run_period(self.db,'test')['state'],'READY')
        self.assertEqual(self.db.conn.execute(f'SELECT count(*) AS n FROM {self.a}.findings').fetchone()['n'],1)

    def test_day_folding_source_fences_idempotency_feedback_and_web(self):
        from compact_product.web import create_app
        self.seed();finding=self.ready();self.assertIsNotNone(finding)
        client=create_app(self.cfg,self.database,'test',secret='synthetic').test_client()
        from datetime import datetime
        from zoneinfo import ZoneInfo
        date=datetime.fromtimestamp((DAY+3*long.DAY-FIVE)/1e9,ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d')
        page=client.get('/incidents?tab=cases&date='+date+'&days=3')
        self.assertEqual(page.status_code,200);self.assertIn('crawler',page.get_data(as_text=True))
        import re
        cid=re.search(r'/cases/([a-f0-9]+)',page.get_data(as_text=True)).group(1)
        detail=client.get('/cases/'+cid+'?date='+date+'&days=3')
        self.assertEqual(detail.status_code,200)
        self.assertIn('110',detail.get_data(as_text=True))
        multi = client.get('/incidents?period=multi&tab=cases&date='+date+'&days=3')
        self.assertEqual(multi.status_code,200)
        self.assertIn('crawler',multi.get_data(as_text=True))
        self.assertIn('864',multi.get_data(as_text=True))
        self.assertEqual(client.get('/incidents?date='+date+'&tab=services').status_code,200)
        # A later five-minute reanalysis must not retire an independent method.
        from compact_ad.engine import evaluate
        work=self.db.snapshot('test',DAY+3*long.DAY-FIVE)
        self.db.commit_analysis(work,evaluate(work['start'],work['summary'],work['services'],work['actors'],work['references']),.01)
        self.assertEqual(self.db.conn.execute(f'SELECT status FROM {self.a}.findings WHERE method=%s',(long.METHOD,)).fetchone()['status'],'ANOMALY')
        self.db.conn.execute(f"UPDATE {self.a}.long_runs SET state='PENDING',retry_ns=0")
        self.ready()
        self.assertEqual(self.db.conn.execute(f'SELECT revision FROM {self.a}.findings').fetchone()['revision'],1)
        self.db.conn.execute(f"INSERT INTO {self.a}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,1,'FALSE_POSITIVE','synthetic',1)",(finding['finding_id'],))
        self.assertNotIn('crawler',client.get('/incidents?tab=cases&date='+date).get_data(as_text=True))
        self.db.conn.execute(f'DELETE FROM {self.a}.feedback')
        self.db.conn.execute(f'UPDATE {self.s}.windows SET published_at_ns=2 WHERE start_ns=%s',(DAY,))
        self.assertNotIn('crawler',client.get('/incidents?tab=cases&date='+date).get_data(as_text=True))
        self.db.conn.execute(f"UPDATE {self.a}.long_runs SET state='PENDING',retry_ns=0")
        self.assertEqual(long_store.run_period(self.db,'test')['state'],'WAITING')
        preserved=self.db.conn.execute(f'SELECT revision,status FROM {self.a}.findings WHERE method=%s',(long.METHOD,)).fetchone()
        self.assertEqual(preserved,dict(revision=1,status='ANOMALY'))

    def test_actual_crash_before_after_atomic_publish_and_replay(self):
        self.seed()
        for point in ('before_commit','after_commit'):
            p=multiprocessing.get_context('spawn').Process(target=crash_long,args=(self.database,self.s,self.a,point))
            p.start();p.join(20)
            self.assertEqual(p.exitcode,73)
            self.assertEqual(self.db.conn.execute(f'SELECT count(*) AS n FROM {self.a}.findings').fetchone()['n'],int(point=='after_commit'))
        self.db.conn.execute(f"UPDATE {self.a}.long_runs SET state='PENDING',retry_ns=0")
        self.ready()
        self.assertEqual(self.db.conn.execute(f'SELECT count(*) AS n FROM {self.a}.finding_history').fetchone()['n'],1)

    def test_older_strong_case_is_not_hidden_by_a_full_weak_signal_page(self):
        from compact_product.web import create_app
        from datetime import datetime
        from zoneinfo import ZoneInfo
        self.seed();self.ready()
        self.db.conn.execute(f'''INSERT INTO {self.a}.findings
            SELECT 'weak-'||n,'test',%s,'actor_rate',%s,'noisy','ANOMALY','{{}}'::jsonb,'synthetic',1,1,1
            FROM generate_series(1,10001) n''',(DAY+4*long.DAY-FIVE,SERVICE))
        date=datetime.fromtimestamp((DAY+4*long.DAY-FIVE)/1e9,ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d')
        client=create_app(self.cfg,self.database,'test',secret='synthetic').test_client()
        page=client.get('/incidents?tab=cases&date='+date)
        self.assertEqual(page.status_code,200)
        self.assertIn('crawler',page.get_data(as_text=True))
        self.assertIn('کامل نیستند',page.get_data(as_text=True))

    def test_concurrent_source_change_rejects_computation(self):
        from compact_ad.store import AnalysisStore
        self.seed()
        other=AnalysisStore(self.database,schema=self.s,ad_schema=self.a)
        original=long.evaluate
        def changed(*args,**kwargs):
            other.conn.execute(f'UPDATE {self.s}.windows SET published_at_ns=published_at_ns+1 WHERE start_ns=%s',(DAY,))
            return original(*args,**kwargs)
        try:
            with patch.object(long,'evaluate',side_effect=changed):
                self.assertEqual(long_store.run_period(self.db,'test')['status'],'LONGITUDINAL_RETRY')
        finally:other.close()
        self.assertEqual(self.db.conn.execute(f'SELECT count(*) AS n FROM {self.a}.findings').fetchone()['n'],0)

    def test_existing_compact_backfill_preserves_base_results_cursor_and_empty_windows(self):
        from tests.test_compact_extract import T,row,extract
        self.db.publish('test',T,T+FIVE,extract([row('synthetic')]),1)
        self.db.step('test')
        cursor=self.db.cursor('test')
        before=self.db.conn.execute(f'SELECT * FROM {self.a}.window_results').fetchall()
        self.db.conn.execute(f'DELETE FROM {self.a}.long_manifest')
        self.assertEqual(long_store.backfill(self.db,'test')['status'],'LONGITUDINAL_WINDOW_PREPARED')
        self.assertEqual(before,self.db.conn.execute(f'SELECT * FROM {self.a}.window_results').fetchall())
        self.assertEqual(cursor,self.db.cursor('test'))
        self.assertIsNone(long_store.backfill(self.db,'test'))
        self.assertIsNone(long_store.build_day(self.db,'test'))

    def test_late_evidence_reprojects_old_window_even_when_publication_time_is_unchanged(self):
        from tests.test_compact_extract import T,row,extract
        from compact_behavior.extract import iso
        from compact_ad.engine import evaluate
        self.db.publish('test',T,T+FIVE,extract([row('late',path=SERVICE,at=iso(T+10**9))]),1)
        self.db.step('test')
        publication=self.db.conn.execute(f'SELECT published_at_ns FROM {self.s}.windows WHERE start_ns=%s',(T,)).fetchone()
        old=self.db.conn.execute(f'SELECT signature FROM {self.a}.long_windows WHERE start_ns=%s',(T,)).fetchone()
        late=row('late',path=SERVICE,at=iso(T+2*10**9),message='Input:{"Identifier":"synthetic-new"} Output:{"Amount":1}')
        self.db.publish('test',T+FIVE,T+2*FIVE,extract([late]),1)
        self.assertEqual(publication,self.db.conn.execute(f'SELECT published_at_ns FROM {self.s}.windows WHERE start_ns=%s',(T,)).fetchone())
        work=self.db.snapshot('test',T);self.assertTrue(work['long_needed'])
        self.db.commit_analysis(work,evaluate(T,work['summary'],work['services'],work['actors'],work['references']),.01)
        new=self.db.conn.execute(f'SELECT signature FROM {self.a}.long_windows WHERE start_ns=%s',(T,)).fetchone()
        self.assertNotEqual(old,new)
        # Emulate an older deployed AD acknowledging work without updating this
        # extension, then pruning its processed dirty notice. Revision detects it.
        self.db.conn.execute(f'UPDATE {self.a}.window_results SET revision=revision+1 WHERE start_ns=%s',(T,))
        self.db.conn.execute(f'DELETE FROM {self.s}.dirty_windows WHERE start_ns=%s',(T,))
        self.assertTrue(self.db.snapshot('test',T)['long_needed'])
        self.assertEqual(long_store.backfill(self.db,'test')['start_ns'],T)
