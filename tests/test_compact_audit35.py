"""Owner acceptance scenarios; all identities and targets are synthetic."""
from copy import deepcopy
import os
import random
import statistics
import time
import unittest
from unittest.mock import patch
from compact_behavior import FIVE, inquiry
from compact_behavior.extract import materialize, iso
from compact_ad.engine import summarize, evaluate, upper
from compact_ad import longitudinal as long
from compact_product import case_selection, provider_contracts
from tests.test_compact_extract import T, row, extract
from tests import test_compact_product_pg as product_tests


def inquiry_rows(n=10, *, outcome='success', crossed=False, unknown_last=False, same=False, prefix='r',session='crawler'):
    rows=[]
    for i in range(n+int(unknown_last)):
        offset=int(i*11.84*10**9/max(1,n-1))
        at=T+FIVE-5_920_000_000+offset if crossed else T+10**9+offset
        code='G00000' if outcome=='success' or outcome=='mixed' and i%2==0 else 'GR0010'
        message='POST https://example.test/water HTTP/1.1'+('' if outcome=='unknown' else f' ({code} | result)')
        key=f'{prefix}-{i}'
        base=row(key,session,path='Services.v1/WaterBills',message=message,at=iso(at))
        value='{}' if unknown_last and i==n else '{"Identifier":"bill-'+str(0 if same else i)+'"}'
        rows.extend([base,dict(base,message='Input:'+value)])
    return rows


def long_actor(count=21,width=21,days=3,overflow=False):
    return dict(count=count,days=days,invalid=False,evidence=['a','b','c'],
                fields={'WaterBillID':dict(tokens=list(range(width)),covered=count,overflow=overflow)})


class AuditContracts(unittest.TestCase):
    def test_provider_only_energy_inputs_follow_exact_core_fields(self):
        for api,path,field,axis in [('Services.v1/ElectricBills','ClientAyanCoInquiry.ElectricityBillInquiry','ElectricityBillID','ElectricityBillID'),
                ('Services.v2/GasBills','ClientAyanCoInquiry.GasBillInquiry','ParticipateCode','ParticipateCode')]:
            records=[row(path=api),row(path=path,message='Input:{"'+field+'":"fixture","TraceNumber":"tracking-is-not-target"}')]
            b=materialize('test',extract(records)['req-1'])
            self.assertEqual(b['features'][inquiry.POLICY],{axis:inquiry.token('fixture')})

    def test_consistent_sql_does_not_hide_independent_provider_contract(self):
        records=[row(path=inquiry.CELL_SERVICE),
            row(path=provider_contracts.MCI,message='Input:{"MobileNumber":"fixture"} Output:[{"Status":{"Code":"GD2048"},"Parameters":null}]')]
        for with_sql in (False,True):
            sample=records+([row(path='DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',
                message='(SQL Parameters: @queryParameters={"LineNumber":"fixture"} @queryResult={"Result":null})')] if with_sql else [])
            state=extract(sample)['req-1'];b=materialize('test',state)
            self.assertTrue(provider_contracts.observed_no_bill(b,state))
        sample=records+[row(path=provider_contracts.MCI,message='Output:[{"Status":{"Code":"GD2046"},"Parameters":null}]')]
        state=extract(sample)['req-1']
        self.assertIsNone(provider_contracts.observed_contract(materialize('test',state),state))

    def test_known_refusals_do_not_taint_another_sessions_mix(self):
        from tests.test_compact_ad import behavior
        good=[behavior(f'g-{i}','good',target=str(i)) for i in range(20)]
        baseline=summarize(good)[0]
        refs=[dict(start_ns=T-i*FIVE,summary=baseline) for i in range(24,0,-1)]
        def decision(rows):
            s,services,actors=summarize(rows)
            return next(r for r in evaluate(T,s,services,actors,refs) if r['method']=='service_mix' and r['session_id']=='good')
        expected=decision(good)
        self.assertEqual(expected['status'],'NORMAL')
        for code,symbol in [('G00010','UserAccessObjectsDoesNotContainAccessObject'),('G00002','SessionIsNotValid'),('G00003','NullCheckError')]:
            records=[row('refusal','other',path='Services.v1/InvoiceRegister',message=f'POST https://example.test/api HTTP/1.1 ({code} | {symbol})')]
            if code=='G00010':records.append(row('refusal','other',path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/WaterBills)'))
            refusal=materialize('test',extract(records)['refusal'])
            self.assertEqual(decision(good+[refusal]),expected)

    def test_long_peer_distribution_matches_expanded_reference(self):
        rng=random.Random(91)
        for scenario in range(6):
            actors={str(i):long_actor(count=rng.choice([21,30,70,200]),width=rng.choice([1,4,8,21]),days=rng.choice([2,3,4,7])) for i in range(180)}
            actors['outlier']=long_actor(count=100,width=120,days=3,overflow=scenario==1)
            if scenario==2:actors['0']['fields']['WaterBillID']['overflow']=True
            actual=long.evaluate(actors,service='Services.v1/WaterBills',end=T,span=3,signature='reference')
            expected={}
            for session,a in actors.items():
                if a['days']<3:continue
                f=a['fields']['WaterBillID'];observed=len(f['tokens'])+int(f['overflow'])
                if observed<=20:continue
                peers=[(len(p['fields']['WaterBillID']['tokens']),p['fields']['WaterBillID']['overflow']) for key,p in actors.items()
                       if key!=session and abs(p['days']-a['days'])<=1 and a['count']/2<=p['count']<=a['count']*2]
                basis='VOLUME_AND_ACTIVITY_MATCHED'
                if len(peers)<100:
                    peers=[(len(p['fields']['WaterBillID']['tokens'])*a['days']/p['days'],p['fields']['WaterBillID']['overflow']) for key,p in actors.items() if key!=session]
                    basis='SERVICE_POPULATION_ACTIVE_DAY_SCALED'
                if len(peers)<100 or any(c for _,c in peers):continue
                values=[v for v,_ in peers];limit=max(20,upper(values),max(values)+1)
                rank=min(1,3*(1+sum(v>=observed for v in values))/(1+len(values)))
                if observed>limit and rank<=.05:expected[session]=(statistics.median(values),limit,len(values),rank,basis)
            observed={r['session_id']:(r['baseline'],r['threshold'],r['peer_count'],r['adjusted_tail_rank'],r['peer_basis']) for r in actual}
            self.assertEqual(observed,expected)

    def test_eight_thousand_peers_finish_and_deadline_can_resume(self):
        actors={str(i):long_actor() for i in range(8000)}
        began=time.perf_counter()
        self.assertEqual(long.evaluate(actors,service='water',end=T,span=3,signature='fixture'),[])
        self.assertLess(time.perf_counter()-began,5)
        cursor=0
        while cursor<300:
            try:
                long.evaluate(dict(list(actors.items())[:300]),service='water',end=T,span=3,signature='fixture',resume_index=cursor,budget_seconds=0)
                break
            except long.ComparisonPending as pending:
                self.assertGreater(pending.resume_index,cursor)
                cursor=pending.resume_index


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PostgreSQL required')
class AuditPostgres(unittest.TestCase):
    setUp=product_tests.CompactProductPostgresTests.setUp
    tearDown=product_tests.CompactProductPostgresTests.tearDown

    def publish(self,records,stream='test'):
        from compact_behavior.extract import instant
        windows={}
        for r in records:
            at=instant(r['@timestamp']);windows.setdefault(at//FIVE*FIVE,[]).append(r)
        for start,values in sorted(windows.items()):self.db.publish(stream,start,start+FIVE,extract(values),len(values))

    def drain(self,stream='test'):
        for _ in range(30):
            result=self.db.step(stream)
            s,a=self.config.source_schema,self.config.ad_schema
            pending=self.db.conn.execute(f'''SELECT EXISTS(SELECT 1 FROM {s}.dirty_windows WHERE stream_id=%s AND processed_version<version)
                OR EXISTS(SELECT 1 FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version) AS pending''',(stream,stream)).fetchone()['pending']
            if not pending:return
        self.fail('base analysis did not drain')

    def cases(self,stream='test'):
        return case_selection.select(self.db.conn,self.config,stream,T,T+2*FIVE)[0]

    def test_owner_ten_targets_success_failure_unknown_and_window_boundary(self):
        for crossed in (False,True):
            for outcome in ('success','failure','mixed','unknown'):
                stream=f'{crossed}-{outcome}'
                records=inquiry_rows(outcome=outcome,crossed=crossed)
                self.publish(records,stream);self.drain(stream)
                cases=self.cases(stream)
                self.assertEqual(len(cases),1,(crossed,outcome))
                finding=next(f for f in cases[0]['findings'] if f['method']=='target_diversity')
                self.assertEqual(finding['result']['distinct_targets'],10)
                self.assertAlmostEqual(finding['result']['span_seconds'],11.84,places=6)
                self.assertEqual(len(set(finding['result']['evidence'])),10)
                before=finding['revision']
                self.publish(records,stream);self.drain(stream)
                replay=next(f for f in self.cases(stream)[0]['findings'] if f['method']=='target_diversity')
                self.assertEqual(replay['revision'],before)

    def test_unknown_target_is_a_lower_bound_and_heavy_retry_peers_do_not_veto(self):
        records=inquiry_rows(12,unknown_last=True)
        for n in range(21):records.extend(inquiry_rows(16,same=True,prefix=f'p-{n}',session=f'peer-{n}'))
        self.publish(records);self.drain()
        case=self.cases()[0]
        self.assertEqual(case['session_id'],'crawler')
        r=next(f['result'] for f in case['findings'] if f['method']=='target_diversity')
        self.assertEqual((r['distinct_targets'],r['requests'],r['covered_requests']),(12,13,12))
        self.assertTrue(r['observed_is_lower_bound'])

    def test_one_target_or_duplicate_internal_logs_does_not_become_ten_targets(self):
        for n,records in enumerate([inquiry_rows(same=True),inquiry_rows(1)*12]):
            stream='negative-'+str(n)
            self.publish(records,stream);self.drain(stream)
            self.assertFalse(self.cases(stream))

    def test_previous_window_correction_removes_stale_crossing_case(self):
        records=inquiry_rows(crossed=True)
        self.publish(records);self.drain();self.assertEqual(len(self.cases()),1)
        extra=dict(records[1],message='Input:{"Identifier":"conflicting-late-value"}')
        self.publish(records+[extra])
        self.assertFalse(self.cases())
        self.drain();self.assertFalse(self.cases())

    def test_boundary_signature_requeues_next_window_when_aggregate_counts_do_not_change(self):
        from psycopg.types.json import Jsonb
        from compact_behavior.extract import behavior_id
        records=inquiry_rows(crossed=True)
        self.publish(records);self.drain();self.assertEqual(len(self.cases()),1)
        s,a=self.config.source_schema,self.config.ad_schema
        before=self.db.conn.execute(f"SELECT summary->'security'->>'base_summary_hash' AS hash FROM {a}.window_results WHERE start_ns=%s",(T,)).fetchone()['hash']
        # Simulate a versioned projection correction: five distinct previous
        # targets remain five, but one is now also a current-window target.
        with self.db.conn.transaction():
            self.db.conn.execute(f"UPDATE {s}.behaviors SET features=jsonb_set(features,%s,%s),revision=revision+1 WHERE behavior_id=%s",
                ([inquiry.POLICY,'WaterBillID'],Jsonb(inquiry.token('bill-9')),behavior_id('test','r-0')))
            self.db.conn.execute(f'UPDATE {s}.streams SET change_epoch=change_epoch+1')
            self.db.conn.execute(f"UPDATE {s}.dirty_windows SET version=version+1 WHERE stream_id='test' AND start_ns=%s AND session_id='@all'",(T,))
            self.db.conn.execute(f"UPDATE {s}.queue_counts SET dirty_keys=dirty_keys+1 WHERE stream_id='test'")
        self.db.step('test')
        after=self.db.conn.execute(f"SELECT summary->'security'->>'base_summary_hash' AS hash FROM {a}.window_results WHERE start_ns=%s",(T,)).fetchone()['hash']
        self.assertEqual(before,after)
        self.assertTrue(self.db.conn.execute(f'SELECT processed_version<version AS pending FROM {a}.reanalysis WHERE start_ns=%s',(T+FIVE,)).fetchone()['pending'])
        self.drain();self.assertFalse(self.cases())

    def test_refresh_stale_timing_queues_once_and_reaches_same_operator_selector(self):
        import sys
        from tools import Refresh_Compact_Inquiry_Case as refresh
        records=inquiry_rows()
        self.publish(records);self.drain()
        case=self.cases()[0];fid=case['findings'][0]['finding_id'];witness=case['findings'][0]['result']['evidence'][0]
        a=self.config.ad_schema
        self.db.conn.execute(f'UPDATE {a}.window_results SET timing_confirmed_revision=0')
        argv=['refresh','--project','fixture','--witness',witness,'--service','Services.v1/WaterBills','--axis','WaterBillID','--apply']
        database=self.database
        config=self.config
        make=lambda *args,**kw:product_tests.AnalysisStore(database,schema=config.source_schema,ad_schema=config.ad_schema)
        with patch.object(sys,'argv',argv),patch.object(refresh,'load',return_value=(config,{'DATABASE':database},'test')),patch.object(refresh,'Store',side_effect=make),patch.object(refresh,'writers'),patch.object(refresh,'verify',return_value={'source_sha256':'fixture'}):
            self.assertEqual(refresh.main(),0)
            first=self.db.conn.execute(f'SELECT version FROM {a}.reanalysis WHERE stream_id=%s AND start_ns=%s',('test',T)).fetchone()
            self.assertEqual(refresh.main(),0)
            self.assertEqual(self.db.conn.execute(f'SELECT version FROM {a}.reanalysis WHERE stream_id=%s AND start_ns=%s',('test',T)).fetchone(),first)
        self.drain()
        self.assertEqual(len(self.cases()),1)
        finding=self.cases()[0]['findings'][0]
        self.db.conn.execute(f"INSERT INTO {a}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,'FALSE_POSITIVE','fixture',1)",(fid,finding['revision']))
        self.db.conn.execute(f'UPDATE {a}.window_results SET timing_confirmed_revision=0')
        with patch.object(sys,'argv',argv),patch.object(refresh,'load',return_value=(config,{'DATABASE':database},'test')),patch.object(refresh,'Store',side_effect=make),patch.object(refresh,'writers'),patch.object(refresh,'verify',return_value={'source_sha256':'fixture'}):
            self.assertEqual(refresh.main(),0)
        pending=self.db.conn.execute(f'SELECT version,processed_version FROM {a}.reanalysis WHERE stream_id=%s AND start_ns=%s',('test',T)).fetchone()
        self.assertEqual(pending['version'],pending['processed_version'])

    def test_packet_statistics_reuse_preserves_late_fragment_meaning(self):
        from compact_behavior.statistics import PacketStatistics
        records=inquiry_rows()
        states=extract(records)
        reference=PacketStatistics()
        for state in states.values():reference.observe(materialize('test',state))
        with patch('compact_behavior.store.materialize',wraps=materialize) as measured:
            result=self.db.publish('test',T,T+FIVE,states,len(records))
            self.assertEqual(measured.call_count,10)
        self.assertEqual(result['packet_statistics'],reference.result())
        late=[row('r-0','crawler',path='ClientAyanCoInquiry.WaterBillInquiry',message='Output:{"Amount":10}',at=iso(T+FIVE+10**9))]
        result=self.db.publish('test',T+FIVE,T+2*FIVE,extract(late),1)
        self.assertEqual(result['packet_statistics']['observed_public_api_requests'],0)
        self.assertEqual(result['updated'],1)

    def test_release_observer_is_readonly_and_omits_session_and_payload(self):
        from tools.Review_Compact_Release import snapshot
        import json
        self.publish(inquiry_rows());self.drain()
        before=self.db.conn.execute(f'SELECT content_hash,revision FROM {self.config.source_schema}.behaviors ORDER BY behavior_id').fetchall()
        value=snapshot(self.db,self.config,'test')
        self.assertEqual(value['operator_cases'],1)
        self.assertNotIn('crawler',json.dumps(value))
        self.assertNotIn('bill-',json.dumps(value))
        after=self.db.conn.execute(f'SELECT content_hash,revision FROM {self.config.source_schema}.behaviors ORDER BY behavior_id').fetchall()
        self.assertEqual(before,after)


if __name__=='__main__':unittest.main()
