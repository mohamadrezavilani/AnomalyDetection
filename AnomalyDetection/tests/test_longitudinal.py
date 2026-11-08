"""Cumulative content changes have ordinary, missing-data and identity controls."""
from copy import deepcopy
import unittest
from anomaly_detection import FIVE_NS
from anomaly_detection.longitudinal import DAY,aggregate,evaluate,spans,day
from anomaly_detection.snapshot import digest

T=1800000000000000000//FIVE_NS*FIVE_NS
SERVICE='Fixture.v1/Inquiry'


def request(actor,at,subject,ip='client-a',i=0):
    return {'request_key':digest([actor,at,subject,i]),'session_key':actor,'at_ns':at,'qualified':True,'reference_qualified':True,
        'subjects':[{'channel':SERVICE,'field':'$.BillID','key':digest(subject)}],'ip_keys':[digest(ip)]}


def cohort():
    rows=[]
    for k in range(1024):
        for d in range(7):
            for i in range(5):rows.append(request('ref'+str(k),T-(6-d)*DAY-FIVE_NS+1+i,'bill'+str(i)))
    return rows


class LongitudinalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs=cohort();cls.covered=list(range(T-7*DAY,T+FIVE_NS,FIVE_NS))
        cls.crawler=[request('a',T-(6-d)*DAY+1+i,'bill'+str(d*5+i),'client'+str(d)) for d in range(7) for i in range(5)]
        cls.items=evaluate('a',SERVICE,T,cls.refs+cls.crawler,cls.covered)
    def d(self,items,family='long_subject_enumeration',duration=7*DAY):
        return next(d for d in items if d['family']==family and d['duration_ns']==duration)
    def test_normal_daily_count_and_content_but_cumulative_new_bills_are_detected(self):
        self.assertEqual(self.d(self.items,duration=DAY)['status'],'NO_DEVIATION_OBSERVED')
        long=self.d(self.items)
        self.assertEqual(long['observed'],35);self.assertEqual(long['expected'],5)
        self.assertEqual(long['observed_requests'],35);self.assertEqual(long['reference_actors'],1024)
        self.assertTrue(long['single_signal_review_eligible']);self.assertLess(long['begin_ns'],T-DAY)
    def test_same_daily_bills_and_volume_remain_ordinary(self):
        now=[request('a',T-(6-d)*DAY+1+i,'bill'+str(i)) for d in range(7) for i in range(5)]
        items=evaluate('a',SERVICE,T,self.refs+now,self.covered)
        self.assertFalse(any(d.get('single_signal_review_eligible') for d in items))
    def test_cumulative_ip_change_retains_one_authoritative_session(self):
        d=self.d(self.items,'long_client_ip_rotation')
        self.assertEqual(d['observed'],7);self.assertTrue(d['single_signal_review_eligible'])
        self.assertEqual(d['entity_key'],'a');self.assertIn('NO_IP',d['identity_basis'])
    def test_mobile_ip_change_without_content_evidence_is_watch_not_fraud(self):
        now=[request('a',T-(6-d)*DAY+1+i,'bill'+str(i),'client'+str(d)) for d in range(7) for i in range(5)]
        d=self.d(evaluate('a',SERVICE,T,self.refs+now,self.covered),'long_client_ip_rotation')
        self.assertEqual(d['status'],'CANDIDATE');self.assertFalse(d['single_signal_review_eligible'])
    def test_sessions_are_not_joined_by_ip_or_the_same_bill(self):
        split=[dict(r,session_key='other-session') for r in self.crawler]
        d=self.d(evaluate('a',SERVICE,T,self.refs+split,self.covered))
        self.assertIsNone(d['observed']);self.assertFalse(d['evidence_verified'])
    def test_missing_current_profile_does_not_become_a_normal_or_complete_count(self):
        now=deepcopy(self.crawler);now[0]['qualified']=False
        d=self.d(evaluate('a',SERVICE,T,self.refs+now,self.covered))
        self.assertEqual(d['status'],'INSUFFICIENT_DATA');self.assertFalse(d['evidence_verified'])
    def test_missing_partition_disables_the_entire_long_horizon(self):
        covered=[t for t in self.covered if t!=T-3*DAY]
        items=evaluate('a',SERVICE,T,self.refs+self.crawler,covered)
        self.assertEqual(self.d(items)['status'],'INSUFFICIENT_DATA')
        self.assertTrue(any(2*DAY<=d['duration_ns']<3*DAY for d in items))
    def test_references_with_missing_or_future_completion_are_excluded_whole(self):
        refs=deepcopy(self.refs)
        for r in refs[::35]:r['reference_qualified']=False
        d=self.d(evaluate('a',SERVICE,T,refs+self.crawler,self.covered))
        self.assertEqual(d['reference_actors'],0);self.assertEqual(d['status'],'INSUFFICIENT_DATA')
    def test_confirmed_or_unreviewed_eligible_findings_never_train_the_reference(self):
        refs=deepcopy(self.refs)
        for r in refs[::35]:r['training_quarantined']=True
        d=self.d(evaluate('a',SERVICE,T,refs+self.crawler,self.covered))
        self.assertEqual(d['reference_actors'],0)
    def test_duplicate_request_never_counts_twice_across_horizons(self):
        a=aggregate(self.crawler+self.crawler)
        self.assertEqual(a['requests'],35);self.assertEqual(a['groups'][(SERVICE,'$.BillID')]['distinct'],35)
    def test_nanosecond_before_tehran_midnight_never_rounds_into_the_next_day(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        ns=int(datetime(2026,11,6,tzinfo=ZoneInfo('Asia/Tehran')).timestamp())*1_000_000_000
        self.assertEqual(day(ns-1),'2026-11-05');self.assertEqual(day(ns),'2026-11-06')
    def test_work_bound_exceeded_is_unknown(self):
        items=evaluate('a',SERVICE,T,self.refs+self.crawler,self.covered,bounded=False)
        self.assertTrue(all(d['status']=='INSUFFICIENT_DATA' for d in items))
    def test_full_month_is_supported_without_a_100_request_cap(self):
        rows=[request('a',T-i*DAY+j,'x'+str(i*8+j)) for i in range(30) for j in range(8)]
        covered=list(range(T-30*DAY,T+FIVE_NS,FIVE_NS))
        d=self.d(evaluate('a',SERVICE,T,rows,covered),duration=30*DAY)
        self.assertEqual(d['observed_requests'],240);self.assertEqual(d['observed'],240)
        self.assertEqual(d['status'],'INSUFFICIENT_DATA') # no fabricated reference
    def test_same_maximum_statistic_is_compared_across_all_complete_typed_fields(self):
        refs=deepcopy(self.refs);now=deepcopy(self.crawler)
        for r in refs+now:r['subjects']+= [dict(r['subjects'][0],channel='provider-copy')]
        d=self.d(evaluate('a',SERVICE,T,refs+now,self.covered))
        self.assertEqual(d['observed'],35);self.assertEqual(d['comparison_count'],10)
        self.assertTrue(d['single_signal_review_eligible'])


if __name__=='__main__':unittest.main()
