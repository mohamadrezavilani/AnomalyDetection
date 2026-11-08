"""Abstention and pending work must remain visible without inventing an alert."""
from copy import deepcopy
import json
import unittest
from anomaly_detection.product_evaluations import evaluation_state,parse_session
from anomaly_detection.product_web import render

SESSION='a'*64;TARGET=1_800_000_000_000_000_000//300_000_000_000*300_000_000_000


class EvaluationTests(unittest.TestCase):
    def test_coverage_and_unclassified_work_are_not_reported_as_evaluated_normal(self):
        self.assertEqual(evaluation_state({'target_scope':'COVERAGE_ONLY','dirty':True}),'COVERAGE_ONLY')
        self.assertEqual(evaluation_state({'target_scope':None,'dirty':True}),'SCOPE_PENDING')

    def job(self,**values):
        return dict(session_key=SESSION,target_ns=TARGET,version=2,processed_version=2,dirty=False,
                    last_evaluated_ns=TARGET+400_000_000_000,evaluation=json.dumps({'decisions':[
                        {'family':'rate_5m','service_path':'Public.v1/ExchangeCrypto','status':'INSUFFICIENT_DATA',
                         'reason':'insufficient_complete_series_history','observed':50,'history_windows':0}]}),**values)
    def test_insufficient_and_mixed_results_are_not_normal(self):
        job=self.job();value=json.loads(job['evaluation'])
        value['decisions'].append({'family':'service_mix','status':'NO_DEVIATION_OBSERVED'})
        job['evaluation']=json.dumps(value)
        self.assertEqual(evaluation_state(job),'INSUFFICIENT_DATA')
    def test_existing_current_result_is_visible_while_scope_migration_is_pending(self):
        job=self.job();job['target_scope']=None
        job['evaluation']='{"decisions":[{"status":"CANDIDATE"}]}'
        self.assertEqual(evaluation_state(job),'CANDIDATE')
    def test_current_input_change_makes_previous_candidate_stale(self):
        job=self.job();job.update(dirty=True,version=3)
        job['evaluation']=json.dumps({'decisions':[{'status':'CANDIDATE'}]})
        self.assertEqual(evaluation_state(job),'RECHECK_REQUIRED')
    def test_never_evaluated_is_pending_even_when_context_is_available(self):
        job=self.job();job.update(dirty=True,processed_version=0,last_evaluated_ns=None,evaluation=None)
        self.assertEqual(evaluation_state(job),'PENDING')
    def test_empty_decisions_are_not_normal(self):
        job=self.job();job['evaluation']='{"decisions":[]}'
        self.assertEqual(evaluation_state(job),'NOT_EVALUATED')
    def test_viewer_url_and_canonical_key_resolve_same_session(self):
        self.assertEqual(parse_session('http://127.0.0.1:5021/session/'+SESSION+'/behavior?generation=2590'),SESSION)
        self.assertEqual(parse_session(SESSION),SESSION)
        with self.assertRaises(ValueError):parse_session('7225AFBEA9F94B299A920EA6A94DBE03')
    def store(self,job):
        calls=[]
        class Rows:
            def __init__(self,value):self.value=value
            def fetchone(self):return deepcopy(self.value)
            def fetchall(self):return deepcopy(self.value)
        class Raw:
            def execute(self,sql,params=()):
                if not sql.startswith('SELECT '):raise AssertionError('render attempted a write')
                calls.append(sql)
                if 'SELECT * FROM anomaly_detection.adp_jobs' in sql:return Rows(job)
                if 'SELECT j.*' in sql:return Rows([job|{'summary':json.dumps({'counts':{'Public.v1/ExchangeCrypto':50}})}])
                if 'adp_windows' in sql:return Rows({'body':json.dumps({'counts':{'Public.v1/ExchangeCrypto':50},'witnesses':{'Public.v1/ExchangeCrypto':'1'*64}})})
                if 'adp_source_windows' in sql:return Rows({'complete':True})
                if 'adp_incidents' in sql:return Rows(None)
                raise AssertionError(sql)
        class Store:raw=Raw()
        return Store(),calls
    def test_cold_real_count_and_reason_are_visible_without_incident(self):
        store,calls=self.store(self.job())
        page=render(store,{},'/evaluation/'+SESSION+'/'+str(TARGET),{},'csrf')
        self.assertIn('دادهٔ ناکافی',page);self.assertIn('50',page)
        self.assertIn('سابقهٔ معتبر برای ساخت مدل زمانی کافی نیست.',page)
        self.assertIn('http://127.0.0.1:5021/request/'+'1'*64,page)
        self.assertTrue(calls)
    def test_pending_same_session_page_does_not_claim_evaluation(self):
        job=self.job();job.update(dirty=True,last_evaluated_ns=None,processed_version=0,evaluation=None)
        store,_=self.store(job)
        page=render(store,{},'/evaluations',{'session_key':[SESSION]},'csrf')
        self.assertIn('در صف ارزیابی',page)
        self.assertIn('/evaluation/'+SESSION,page)
    def test_service_names_are_escaped_and_invalid_targets_rejected(self):
        job=self.job();value=json.loads(job['evaluation']);value['decisions'][0]['service_path']='<script>unsafe</script>'
        job['evaluation']=json.dumps(value);store,_=self.store(job)
        page=render(store,{},'/evaluation/'+SESSION+'/'+str(TARGET),{},'csrf')
        self.assertNotIn('<script>unsafe',page);self.assertIn('&lt;script&gt;',page)
        with self.assertRaises(ValueError):render(store,{},'/evaluation/'+SESSION+'/9999999999999999999',{},'csrf')


if __name__=='__main__':unittest.main()
