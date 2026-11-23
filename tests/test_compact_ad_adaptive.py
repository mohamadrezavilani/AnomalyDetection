from copy import deepcopy
import math
import unittest
from compact_behavior import FIVE
from compact_behavior.extract import materialize,instant
from compact_ad.engine import summarize,evaluate
from compact_ad.patterns import patterns
from compact_ad.seasonality import fit,phase,adjust_rates
from compact_ad.forest import SmallIsolationForest
from tests.test_compact_extract import row,extract,T
from tests.test_compact_ad import behavior


class AdaptiveTests(unittest.TestCase):
    def test_rate_limit_attempts_are_counted_per_session_and_evaluated_without_input(self):
        from copy import deepcopy
        def attempt(key,session='same'):
            source=[row(key,session,path='Services.v1/InvoiceRegister',message='POST https://example.test/api HTTP/1.1 (GR0004 | limited)'),
                row(key,session,path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/PostPackagesStatus)')]
            return materialize('t',extract(source)[key])
        rows=[attempt('r'+str(i)) for i in range(8)]+[attempt('other','another')]
        summary,services,actors=summarize(rows)
        service=services['Services.v1/PostPackagesStatus']
        self.assertEqual(service['rejected_count'],9)
        self.assertEqual(service['rejected_actors'],{'same':8,'another':1})
        self.assertEqual(service['count'],0);self.assertFalse(actors)
        reference=deepcopy(summary)
        reference['services']['Services.v1/PostPackagesStatus']['rejected_actor_p95']=0
        refs=[dict(start_ns=T-(i+1)*FIVE,summary=reference) for i in range(24)]
        results=evaluate(T,summary,services,actors,refs)
        selected={r['session_id']:r for r in results if r['method']=='rate_limit_rejections'}
        self.assertEqual(selected['same']['observed'],8)
        self.assertEqual(selected['same']['status'],'ANOMALY')
        self.assertEqual(selected['another']['status'],'NORMAL')
        self.assertFalse(any(r['method']=='target_diversity' and r['session_id']=='same' for r in results))
    def test_rate_limited_dispatch_is_a_separate_attempt_not_a_completed_service(self):
        source=[row(path='Services.v1/InvoiceRegister',message='POST https://example.test/api HTTP/1.1 (GR0004 | limited)'),
            row(path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/LandLinePhoneBills)')]
        body=materialize('t',extract(source)['req-1'])
        self.assertIsNone(body['service_key'])
        self.assertFalse(body['features']['service_rate_eligible'])
        self.assertEqual(body['features']['rejected_attempt']['service'],'Services.v1/LandLinePhoneBills')
        summary,_,_=summarize([body])
        self.assertEqual(summary['services']['Services.v1/LandLinePhoneBills']['count'],0)
        self.assertEqual(summary['services']['Services.v1/LandLinePhoneBills']['rejected_count'],1)
        source.append(row(path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/WaterBills)'))
        self.assertNotIn('rejected_attempt',materialize('t',extract(source)['req-1'])['features'])

    def test_owner_confirmed_duration_and_invalid_values(self):
        for raw,expected in [('123.5',123.5),('',None),('NaN',None),(-1,None),(True,None)]:
            body=materialize('t',extract([dict(row(),ExecutionTime=raw)])['req-1'])
            self.assertEqual(body['reported_duration'],expected)
            self.assertEqual(body['duration_unit'],'MILLISECONDS_OWNER_CONFIRMED_20261122')
        body=materialize('t',extract([dict(row(path='ClientAyanCoInquiry.WaterBillInquiry'),ExecutionTime=9000),
                                     dict(row(),ExecutionTime=20)])['req-1'])
        self.assertEqual(body['reported_duration'],20)

    def test_phone_target_and_final_provider_binding_do_not_accept_otp(self):
        for service,provider in [('SfaraCoupon','SfaraCouponInquiry'),('LivelihoodInformation','SfaraCouponInquiry'),
                                 ('LandLinePhoneBills','FixedLineBillInquiry')]:
            base=row(path='Services.v1/'+service)
            otp=row(path='ClientAyanCoInquiry.SfaraCouponRequestOtp',message='Output:{"Code":"G00000"}')
            target=row(path='ClientAyanCoInquiry.'+provider,message='Input:{"LineNumber":"09120000000"} Output:{"Amount":10}')
            bad=materialize('t',extract([base,otp])['req-1'])
            self.assertFalse(bad['features']['output_eligible'])
            good=materialize('t',extract([base,otp,target])['req-1'])
            self.assertTrue(good['features']['output_eligible'])
            self.assertIn('LineNumber',good['features']['input']['targets'])

    def test_origin_keeps_only_origin_and_no_credentials(self):
        from compact_behavior.context import empty,observe
        c=empty();observe(c,'origin','https://example.test/path?token=SECRET','sql.create')
        self.assertEqual(c['values']['origin'][0]['value'],'https://example.test')
        c=empty();observe(c,'origin','https://user:SECRET@example.test','sql.create')
        self.assertFalse(c['values'])

    def test_latency_detects_service_degradation_and_excludes_missing_times(self):
        target=T+20*FIVE
        refs=[]
        for j in range(12):
            rows=[behavior(str(i),'s'+str(i),start=target-(12-j)*FIVE) for i in range(20)]
            for r in rows:r['reported_duration']=100
            summary,_,_=summarize(rows)
            refs.append(dict(start_ns=target-(12-j)*FIVE,summary=summary))
        rows=[behavior(str(i),'s'+str(i),start=target) for i in range(20)]
        for r in rows:r['reported_duration']=1000
        args=summarize(rows)
        result=next(r for r in evaluate(target,*args,refs) if r['method']=='service_latency')
        self.assertEqual(result['status'],'ANOMALY');self.assertEqual(result['measurement_unit'],'milliseconds')
        for r in rows:r['reported_duration']=None
        result=next(r for r in evaluate(target,*summarize(rows),refs) if r['method']=='service_latency')
        self.assertEqual(result['status'],'INVALID_INPUT')

    def test_daily_weekly_selection_and_gap_warmup(self):
        target=instant('2026-11-22T00:00:00+03:30')
        times=[target-i*12*FIVE for i in range(28*24,0,-1)]
        daily=tuple((at,100 if 8<=phase(at,'daily')<20 else 5) for at in times)
        self.assertEqual(fit(daily)['family'],'daily')
        weekly=tuple((at,100 if phase(at,'weekly')//24<5 else 5) for at in times)
        self.assertEqual(fit(weekly)['family'],'weekly')
        self.assertEqual(fit(daily[::2])['status'],'INSUFFICIENT_COVERAGE')

    def test_seasonal_night_spike_and_no_future_leakage(self):
        start=instant('2026-11-22T00:00:00+03:30');service='Services.v1/WaterBills'
        refs=[]
        for i in range(28*24,0,-1):
            at=start-i*12*FIVE;n=100 if 8<=phase(at,'daily')<20 else 5
            refs.append(dict(start_ns=at,rates={service:[n,n,True]},complete=True,summary_hash=str(at)))
        original=dict(method='service_rate',service=service,status='NORMAL',observed=50)
        results=[deepcopy(original)];adjust_rates(start,results,refs,None)
        self.assertEqual(results[0]['baseline_family'],'daily');self.assertEqual(results[0]['status'],'ANOMALY')
        again=[deepcopy(original)];adjust_rates(start,again,refs+[dict(start_ns=start,rates={},complete=True,summary_hash='future')],None)
        self.assertEqual(results,again)
        original['observed']=5;results=[original];adjust_rates(start,results,refs,None)
        self.assertEqual(results[0]['status'],'NORMAL')

    def test_forest_is_deterministic_and_extreme_point_scores_higher(self):
        rows=[[math.log1p(i%20+10),float(i%3)] for i in range(160)]
        a=SmallIsolationForest().fit(rows);b=SmallIsolationForest().fit(rows)
        self.assertEqual(a.trees,b.trees)
        self.assertGreater(a.score([100,100]),a.score(rows[50]))

    def test_cross_window_sequence_boundary_and_ties(self):
        actors={('s','B'):dict(events=[(T+10,'B','b1'),(T+20,'B','b2')])}
        summary,current=patterns(actors,{'s':[(T-10,'A','a1')]},T)
        from compact_behavior.extract import digest
        self.assertEqual(summary['transitions'][digest(['A','B'])],1)
        self.assertTrue(current['s']['continuity'])
        _,gap=patterns(actors,None,T);self.assertFalse(gap['s']['continuity'])
        tied={('s','A'):dict(events=[(T,'A','a'),(T,'B','b')])}
        summary,current=patterns(tied,{},T)
        self.assertTrue(current['s']['tied']);self.assertFalse(summary['transitions'])

    def test_pattern_limit_and_training_vectors_have_no_identity(self):
        actors={('PRIVATE_SESSION','A'):dict(events=[(T+i,'A','private-request-'+str(i)) for i in range(20)])}
        summary,_=patterns(actors,{},T)
        import json
        self.assertNotIn('PRIVATE_SESSION',json.dumps(summary));self.assertNotIn('private-request',json.dumps(summary))
        actors[('PRIVATE_SESSION','A')]['events']*=30
        _,result=patterns(actors,{},T);self.assertTrue(result['PRIVATE_SESSION']['limited'])

    def test_sequence_and_timing_positives_require_continuity_and_past_calibration(self):
        from compact_ad.patterns import evaluate_patterns
        from compact_behavior.extract import digest
        refs=[dict(start_ns=T-(48-i)*FIVE,summary={'patterns':{
            'complete':True,'transitions':{digest(['A','A']):100},'peer_vectors':[],
            'timing_n':5,'timing_p05':.5,'timing_gap_median':20}}) for i in range(48)]
        actors={('s','A'):dict(events=[(T+i*3*10**9,'A' if i%2==0 else 'B',str(i)) for i in range(30)])}
        def run(previous):
            results=[]
            def add(method,service,session,status,*args,**kwargs):
                r=dict(method=method,status=status);results.append(r);return r
            evaluate_patterns(T,{}, {},actors,refs,add,previous)
            return {r['method']:r for r in results}
        positive=run({'s':[]})
        self.assertEqual(positive['service_sequence']['status'],'ANOMALY')
        self.assertEqual(positive['service_sequence']['rare_cross_services'],['A','B'])
        self.assertEqual(positive['timing_regularization']['timing_services'],[])
        missing=run(None)
        self.assertEqual(missing['service_sequence']['status'],'INSUFFICIENT_DATA')
        self.assertEqual(missing['timing_regularization']['status'],'INSUFFICIENT_DATA')
        actors[('s','A')]['events'] = [(at,'B',bid) for at,_,bid in actors[('s','A')]['events']]
        single=run({'s':[]})
        self.assertEqual(single['service_sequence']['rare_cross_services'],[])
        self.assertEqual(single['timing_regularization']['timing_services'],['B'])

    def test_forest_readiness_does_not_substitute_for_sequence_calibration(self):
        from compact_ad.patterns import evaluate_patterns
        from compact_behavior.extract import digest
        refs=[dict(start_ns=T-(60-i)*FIVE,summary={'patterns':{
            'complete':i<6,'transitions':{digest(['A','A']):100} if i<6 else {},
            'peer_vectors':[[math.log1p(10+j),0.,1.,0.] for j in range(4)]}}) for i in range(60)]
        actors={('s','A'):dict(events=[(T+i*3*10**9,'A' if i%2==0 else 'B',str(i)) for i in range(30)])}
        results=[]
        def add(method,service,session,status,*args,**kwargs):
            r=dict(method=method,status=status);results.append(r);return r
        evaluate_patterns(T,{}, {},actors,refs,add,{'s':[]})
        forest=next(r for r in results if r['method']=='isolation_forest')
        sequence=next(r for r in results if r['method']=='service_sequence')
        self.assertIn(forest['status'],('NORMAL','ANOMALY'))
        self.assertEqual(sequence['status'],'INSUFFICIENT_DATA')
        self.assertEqual(sequence['calibration_windows'],2)


if __name__=='__main__':unittest.main()
