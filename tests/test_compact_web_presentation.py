import unittest
from unittest.mock import patch, MagicMock
from compact_product.web import create_app
from compact_product.config import Config
from compact_ad import MODEL
from compact_behavior import FEATURES


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.store = patch('compact_product.web.Store').start()
        self.addCleanup(patch.stopall)
        self.db = self.store.return_value.conn
        self.app = create_app(Config(), {}, 'stream', secret='test')
        self.client = self.app.test_client()

    def test_group_list_labels_threshold_and_keeps_identity_inside_details(self):
        self.db.execute.return_value.fetchall.return_value = [dict(
            group_id='a'*32, methods=['actor_rate'], service='Core.v1/LoginByOTP',
            session_id='private-long-session',session_count=2,has_service_scope=True,first_ns=0,last_ns=300000000000,
            signal_count=3,finding_id='f',result=dict(observed=51,baseline=3,
            threshold=18.8,reference_windows=24))]
        response=self.client.get('/signals')
        self.assertEqual(response.status_code,200)
        body=response.get_data(as_text=True)
        self.assertIn('آستانهٔ تشخیص',body)
        self.assertIn('3 هشدار مرتبط',body)
        self.assertIn('/incident-groups/'+'a'*32,body)
        self.assertNotIn('>private-long-session<',body)
        sql,args=self.db.execute.call_args.args
        self.assertIn('GROUP BY',sql)
        self.assertIn('timing_confirmed_revision=r.revision',sql)
        self.assertIn('source_published_ns=w.published_at_ns',sql)
        self.assertIn('processed_version<d.version',sql)
        self.assertIn('processed_version<j.version',sql)
        self.assertIn('finding_revision=f.revision',sql)
        self.assertEqual(args[:5],['stream',MODEL,FEATURES,MODEL,FEATURES])

    def test_bad_group_and_cursor_are_rejected(self):
        self.assertEqual(self.client.get('/incident-groups/nope').status_code,404)
        self.assertEqual(self.client.get('/signals?before=nope&id=a').status_code,400)

    def test_empty_group_does_not_claim_no_anomaly(self):
        self.db.execute.return_value.fetchall.return_value=[]
        r=self.client.get('/incident-groups/'+'a'*32)
        self.assertEqual(r.status_code,200)
        self.assertIn('بازتحلیل',r.get_data(as_text=True))


class SearchContractTests(unittest.TestCase):
    def test_exact_ids_and_tehran_bounds_are_parameterized(self):
        from compact_product.search import filters
        from compact_behavior.extract import behavior_id,instant
        raw='AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
        values,sql,args=filters({'request_id':raw,'session_id':raw,'ip':'::ffff:192.0.2.10',
            'from':'2026-11-22T11:00','to':'2026-11-22T12:00'},'test')
        self.assertEqual(args[:2],[behavior_id('test',raw),'aaaaaaaabbbbccccddddeeeeeeeeeeee'])
        self.assertNotIn(raw,sql);self.assertNotIn('192.0.2.10',sql)
        self.assertEqual(values['ip'],'192.0.2.10')
        self.assertEqual(args[-2:],[instant('2026-11-22T07:30:00Z'),instant('2026-11-22T08:30:00Z')])

    def test_filter_validation_and_source_spelling_are_not_guessed(self):
        from compact_product.search import filters,decorate
        for args in ({'ip':'not-an-ip'},{'from':'2026-13-01T00:00'},
            {'from':'2026-11-22T12:00','to':'2026-11-22T11:00'},{'request_id':'x'*513}):
            with self.assertRaises(ValueError):filters(args,'t')
        row={'request_id':'aaaaaaaabbbbccccddddeeeeeeeeeeee','session_id':None}
        decorate(row,{'raw_request_ids':['AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE','another-request']})
        self.assertEqual(row['original_request_ids'],['AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'])
        decorate(row,{})
        self.assertEqual(row['original_request_ids'],[])


class CasePolicyTests(unittest.TestCase):
    def signal(self,method='actor_rate',session='s',service='Services.v1/WaterBills',at=0):
        result = dict(reference_windows=24,evidence=['a','b','c'])
        if method == 'target_diversity':
            from compact_behavior import inquiry
            result.update(subject_policy=inquiry.POLICY, numeric_path='WaterBillID', observed=8, threshold=6)
        return dict(finding_id=str((method,session,service,at)),method=method,session_id=session,
                    service=service,start_ns=at,result=result)

    def test_correlated_volume_and_target_methods_do_not_self_confirm(self):
        from compact_product.cases import select_cases
        self.assertFalse(select_cases([self.signal(m) for m in ('actor_rate','isolation_forest','rate_limit_rejections')]))
        self.assertFalse(select_cases([self.signal(m) for m in ('repeated_target','target_diversity')]))
        self.assertEqual(len(select_cases([self.signal(),self.signal('target_diversity')])),1)

    def test_manual_retries_are_not_independent_corroboration_of_volume(self):
        from compact_product.cases import select_cases
        rows=[self.signal(m) for m in ('actor_rate','repeated_target','isolation_forest','rate_limit_rejections')]
        for row in rows:row['result'].update(observed=60,threshold=35)
        self.assertFalse(select_cases(rows))
        # The rule is about evidence dependence, not an arbitrary count cutoff.
        for row in rows:row['result']['observed']=10000
        self.assertFalse(select_cases(rows))
        # Keep repetition as context once other dimensions qualify the case.
        rows.append(self.signal('target_diversity'))
        selected=select_cases(rows)
        self.assertEqual(len(selected),1)
        self.assertIn('repeated_target',selected[0]['methods'])
        repeated=self.signal('repeated_target');repeated['verdict']='CONFIRMED'
        self.assertEqual(select_cases([repeated])[0]['reasons'],['HUMAN_CONFIRMED'])

    def test_repetition_alone_cannot_corroborate_timing_or_diversity(self):
        from compact_product.cases import select_cases
        for method in ('timing_regularization','service_sequence','target_diversity'):
            self.assertFalse(select_cases([self.signal('repeated_target'),self.signal(method)]))
            other = self.signal(method)
            if method in ('timing_regularization', 'service_sequence'):
                self.assertFalse(select_cases([self.signal(), other]))
                key = 'timing_services' if method=='timing_regularization' else 'rare_cross_services'
                other['result'][key] = ['Services.v1/WaterBills']
            self.assertEqual(len(select_cases([self.signal(), other])),1)

    def test_standalone_verified_short_diversity_and_bulk_exception(self):
        from compact_product.cases import select_cases, BULK_DELETE
        finding = self.signal('target_diversity')
        finding['result']['observed'] = 12
        self.assertEqual(select_cases([finding])[0]['reasons'], ['DISTINCT_REVIEWED_TARGETS'])
        finding['result']['numeric_path'] = 'TraceNumber'
        self.assertFalse(select_cases([finding, self.signal()]))
        timing = self.signal('timing_regularization', service='*')
        timing['result']['timing_services'] = [BULK_DELETE]
        self.assertFalse(select_cases([self.signal(service=BULK_DELETE), timing]))
        timing['verdict'] = 'CONFIRMED'
        self.assertEqual(select_cases([timing])[0]['reasons'], ['HUMAN_CONFIRMED'])

    def test_different_sessions_windows_services_and_thin_evidence_do_not_confirm(self):
        from compact_product.cases import select_cases
        for other in (self.signal('target_diversity',session='other'),self.signal('target_diversity',at=1),
                      self.signal('target_diversity',service='Other.v1/Operation')):
            self.assertFalse(select_cases([self.signal(),other]))
        for field,value in [('reference_windows',12),('evidence',['a','a','b'])]:
            other=self.signal('target_diversity');other['result'][field]=value
            self.assertFalse(select_cases([self.signal(),other]))

    def test_health_requires_three_consecutive_windows_and_is_not_user_misuse(self):
        from compact_product.cases import select_cases
        from compact_behavior import FIVE
        rows=[self.signal('service_latency',session=None,at=i*FIVE) for i in (0,1,3)]
        self.assertFalse(select_cases(rows))
        rows.append(self.signal('service_latency',session=None,at=2*FIVE))
        self.assertFalse(select_cases(rows))  # Persistence does not validate a pooled reference.
        for row in rows:row['result'].update(baseline_family='daily',validation_samples=24,duration_valid=10)
        self.assertFalse(select_cases(rows))  # Ten-sample p95 can be a single maximum.
        for row in rows:row['result']['duration_valid']=40
        cases=select_cases(rows);self.assertEqual(len(cases),1)
        self.assertEqual(cases[0]['domain'],'service_health')
        row=self.signal();row['verdict']='CONFIRMED';row['result']['reference_windows']=0
        self.assertEqual(select_cases([row])[0]['reasons'],['HUMAN_CONFIRMED'])

    def test_attempt_report_separates_result_present_from_never_analyzed(self):
        from compact_product.attempt_review import review_status
        row=dict(this_request_counted_in_stored_attempts=True,analysis_current=False,
                 analysis_window=None,needs_feature_repair=False)
        self.assertEqual(review_status(row),'COMPACT_ATTEMPT_WAITING_FOR_AD')
        row['analysis_window']={'revision':36}
        self.assertEqual(review_status(row),'COMPACT_ATTEMPT_RESULT_PRESENT_RECHECK_PENDING')
        row['analysis_current']=True
        self.assertEqual(review_status(row),'COMPACT_ATTEMPT_CURRENT')
