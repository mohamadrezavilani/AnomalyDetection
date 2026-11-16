"""Reference identity and full-session aggregation, without production data."""
from copy import deepcopy
import json
import os
import unittest
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection import service_reference as ref
from tests import test_scenario_invalidation_pg as native

TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SERVICE='Services.v1/ReferenceFixture'


def points():
    return [dict(session_key='peer-'+str(i),start_ns=TARGET-FIVE_NS,value=1) for i in range(120)]


def model(values):
    return ref.reference(values,'actor',TARGET,SERVICE,unit='canonical_service_executions',reference_id='fixture')


class ReferenceIdentityTests(unittest.TestCase):
    def test_late_coverage_changes_identity_even_when_session_maxima_are_unchanged(self):
        short=points();long=short+[dict(p,start_ns=TARGET-2*288*FIVE_NS) for p in short]
        old,new=model(short),model(long)
        self.assertEqual(old['reference_values'],new['reference_values'])
        self.assertEqual(old['status'],'INSUFFICIENT_DATA')
        self.assertEqual(new['status'],'READY_BASELINE')
        self.assertNotEqual(old['model_id'],new['model_id'])

    def test_new_middle_point_changes_pinned_count_without_replacing_old_model(self):
        short=points();values=short+[dict(p,start_ns=TARGET-2*288*FIVE_NS) for p in short]
        old=model(values);new=model(values+[dict(values[0],start_ns=TARGET-2*FIVE_NS)])
        self.assertEqual(old['reference_values'],new['reference_values'])
        self.assertEqual(old['observed_span_ns'],new['observed_span_ns'])
        self.assertEqual(new['active_session_windows'],old['active_session_windows']+1)
        self.assertNotEqual(old['model_id'],new['model_id'])

    def test_equivalent_input_order_and_excluded_points_keep_the_same_pin(self):
        values=points()+[dict(p,start_ns=TARGET-2*288*FIVE_NS) for p in points()]
        extra=[dict(session_key='actor',start_ns=TARGET-FIVE_NS,value=999),
               dict(session_key='future',start_ns=TARGET,value=999),
               dict(session_key='bad',start_ns=TARGET-FIVE_NS,value=999,qualified=False)]
        self.assertEqual(model(values),model(list(reversed(deepcopy(values)))+extra))


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native AD cluster not configured')
class NativeReferenceContractTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeScenarioInvalidationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeScenarioInvalidationTests.tearDownClass.__func__)
    setUp=native.NativeScenarioInvalidationTests.setUp

    def seed(self,sessions=201,windows=100,*,stride_ns=3*FIVE_NS):
        self.raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points "
            "SELECT %s,'service_execution','peer-'||s,%s-w*%s,1,TRUE "
            "FROM generate_series(1,%s) s CROSS JOIN generate_series(1,%s) w",
            (SERVICE,TARGET,stride_ns,sessions,windows))

    def read(self):return ref.model(self.store,SERVICE,'actor',TARGET,'service_execution')

    def test_over_twenty_thousand_points_still_form_a_complete_small_session_reference(self):
        self.seed()
        result,_=self.read()
        self.assertEqual(result['status'],'READY_BASELINE')
        self.assertEqual(result['other_session_epochs'],201)
        self.assertEqual(result['active_session_windows'],20100)
        self.assertEqual(result['reference_values'],[1]*201)
        self.assertTrue(ref.rank_screen(result,10,1)['high'])

    def test_dense_reference_matches_full_raw_oracle_and_rejects_self_future_and_invalid_session(self):
        self.seed()
        self.raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points VALUES"
            "(%s,'service_execution','actor',%s,999,TRUE),"
            "(%s,'service_execution','future',%s,999,TRUE),"
            "(%s,'service_execution','peer-1',%s,999,FALSE)",
            (SERVICE,TARGET-FIVE_NS,SERVICE,TARGET,SERVICE,TARGET-FIVE_NS))
        rows=self.raw.execute('SELECT session_key,start_ns,value,qualified FROM anomaly_detection.adp_service_reference_points').fetchall()
        # SQL disqualifies a whole session if any point inside its horizon is invalid.
        bad={r['session_key'] for r in rows if TARGET-ref.HORIZON<=r['start_ns']<TARGET and not r['qualified']}
        expected=ref.reference([dict(r) for r in rows if r['session_key'] not in bad],
            'actor',TARGET,SERVICE,unit='canonical_service_executions',reference_id='owned-complete-windows')
        actual,_=self.read()
        for field in expected:self.assertEqual(actual[field],expected[field],field)
        self.assertEqual(actual['other_session_epochs'],200)
        self.assertEqual(actual['upper'],1)

    def test_over_session_budget_is_explicit_and_never_a_truncated_valid_reference(self):
        self.seed(sessions=20001,windows=2,stride_ns=288*FIVE_NS)
        actual,_=self.read()
        self.assertEqual(actual['status'],'INSUFFICIENT_DATA')
        self.assertEqual(actual['reference_values'],[])
        self.assertEqual(actual['reason'],'CANONICAL_SESSION_REFERENCE_BUDGET_EXCEEDED')
        self.assertTrue(actual['canonical_session_limit_exceeded'])
        # Exactly the full aggregate budget is valid, with no actor sampled.
        self.raw.execute('DELETE FROM anomaly_detection.adp_service_reference_points WHERE session_key=%s',('peer-20001',))
        from anomaly_detection.model_queue import reference_changed
        reference_changed(self.store,[(SERVICE,TARGET-288*FIVE_NS)])
        boundary,_=self.read()
        self.assertEqual(boundary['status'],'READY_BASELINE')
        self.assertEqual(boundary['other_session_epochs'],20000)
        self.assertEqual(len(boundary['reference_values']),20000)
        self.assertFalse(boundary.get('canonical_session_limit_exceeded',False))

    def test_actual_result_commit_keeps_old_and_new_reference_bodies_under_distinct_ids(self):
        self.seed(sessions=120,windows=1)
        self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',('actor',TARGET))
        old,epochs=self.read()
        def commit(value,inputs):
            job=self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',('actor',TARGET)).fetchone()
            decision=dict(finding_key='pf1:reference-fixture',family='peer_service_rate_5m',dimension='activity',
                status='CANDIDATE' if value['status']=='READY_BASELINE' else 'INSUFFICIENT_DATA',model=value,
                observed=10,expected=value['expected'],upper=value['upper'],service_path=SERVICE)
            with patch('anomaly_detection.cases.sync_actor'):
                out=self.store.complete(job,{'source':{'captured_at_ns':TARGET+FIVE_NS},'peer_inputs':inputs},[decision],TARGET+FIVE_NS)
            self.assertEqual(out['status'],'APPLIED')
        commit(old,epochs)
        self.raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points "
            "SELECT %s,'service_execution','peer-'||s,%s,1,TRUE FROM generate_series(1,120) s",
            (SERVICE,TARGET-2*288*FIVE_NS))
        from anomaly_detection.model_queue import reference_changed
        reference_changed(self.store,[(SERVICE,TARGET-2*288*FIVE_NS)])
        new,epochs=self.read();commit(new,epochs)
        self.assertEqual(new['status'],'READY_BASELINE')
        saved=self.raw.execute('SELECT model_id,body FROM anomaly_detection.adp_models ORDER BY created_ns,model_id').fetchall()
        self.assertEqual(len(saved),2)
        by_id={r['model_id']:json.loads(r['body']) for r in saved}
        self.assertEqual(by_id[old['model_id']],old)
        self.assertEqual(by_id[new['model_id']],new)


if __name__=='__main__':unittest.main()
