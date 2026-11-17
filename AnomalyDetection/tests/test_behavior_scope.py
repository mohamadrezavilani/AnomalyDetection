import json
import unittest
import os
from anomaly_detection.behavior_scope import BEHAVIOR,FULL,DISABLED,decisions,fact,source_scope
from anomaly_detection.context_models import evaluate
from tests.test_context_models import record,TARGET as T,SERVICE


class BehaviorAdapterTests(unittest.TestCase):
    def test_financial_absence_is_explicit_and_cannot_be_a_negative(self):
        result=decisions([dict(family=family,status='CANDIDATE',model={'model_id':'old'},score=8)
                          for family in DISABLED],{'input_contract':BEHAVIOR})
        self.assertTrue(all(r['status']=='OUT_OF_SCOPE' and 'model' not in r and not r['evidence_verified'] for r in result))

    def test_legacy_financial_fact_is_projected_without_mutating_history(self):
        original=dict(relations=[{'payment':True}],identifiers=[{}],observations=[{'axis':'service_dispatch.otp_validation'},{'axis':'financial'}],
                      outcomes={'financial':{},'service_dispatch.inquiry_result':{}},viewer_journey={'payment':{}})
        converted=fact(original,{'input_contract':BEHAVIOR})
        self.assertEqual(converted['relations'],[]);self.assertEqual(len(converted['observations']),1)
        self.assertEqual(converted['viewer_journey']['status'],'OUT_OF_SCOPE');self.assertTrue(original['relations'])

    def test_retained_context_decisions_equal_full_inputs_and_disabled_families_not_cold(self):
        rows=[record(i,otp='G00000') for i in range(120)]+[record(900+i,current=True,otp='GB999') for i in range(12)]
        context=dict(session_key='a'*64,target_ns=T,evidence_verified=True)
        baseline=evaluate(context,rows)
        changed=evaluate(dict(context,source={'input_contract':BEHAVIOR}),rows)
        for family in ('otp_result_change','request_latency'):
            a=[r for r in baseline if r['family']==family];b=[{k:v for k,v in r.items() if k not in ('input_contract','behavioral_features')} for r in changed if r['family']==family]
            self.assertEqual(a,b)
        self.assertTrue(all(r['status']=='OUT_OF_SCOPE' for r in changed if r['family'] in DISABLED))

    def test_model_receipts_have_distinct_stable_contract_identity(self):
        value={'family':'rate_5m','model':{'model_id':'am2:old'},'model_id':'am2:old'}
        converted=decisions([value],{'input_contract':BEHAVIOR})[0]
        self.assertNotEqual(converted['model_id'],value['model_id'])
        self.assertEqual(decisions([converted],{'input_contract':BEHAVIOR})[0]['model_id'],converted['model_id'])
        self.assertEqual(converted['model']['compatible_history_contracts'],[FULL,BEHAVIOR])


if __name__=='__main__':unittest.main()


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 required')
class NativeBehaviorScopeTests(unittest.TestCase):
    from tests.test_runtime_bounds_pg import RuntimeBoundsTests as Fixture
    setUpClass=classmethod(Fixture.setUpClass.__func__)
    tearDownClass=classmethod(Fixture.tearDownClass.__func__)
    setUp=Fixture.setUp

    def test_scope_migration_archives_finance_and_keeps_feedback_models_and_cursor(self):
        from anomaly_detection.cases import replace_scope
        from anomaly_detection.snapshot import canonical
        from anomaly_detection.case_summary import case_status
        actor='a'*64;target=300_000_000_000
        source=dict(namespace='viewer:test',stream_key='test',keys_fingerprint='same',generation=1,semantic_generation=1,
                    input_contract=FULL,scope_epoch=0,behavioral_features='observed-behavior-features-1',financial_relations='COMPLETE')
        with self.store.transaction():
            self.store.bind(source)
            item=dict(signal_key='scope-signal',family='payment_result_change',entity_type='actor',entity_key=actor,
                      service_path='Services.v1/WaterBills',status='CANDIDATE',reason='old-financial',
                      begin_ns=target,end_ns=target+300_000_000_000,target_ns=target,score=3,evidence_verified=True)
            replace_scope(self.store,'scope-old',[item],target,source_kind='actor',job=dict(session_key=actor,target_ns=target,version=1))
            case=self.raw.execute('SELECT case_key FROM anomaly_detection.adp_cases').fetchone()['case_key']
            self.raw.execute('INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision) VALUES(%s,%s,%s,%s,%s)',
                             (case,'confirmed_suspicious','keep this review',target,1))
            self.raw.execute('INSERT INTO anomaly_detection.adp_models VALUES(%s,%s,%s,%s)',('finance-model','payment_result_change','{}',target))
            self.store.save_state('fresh_cursor',{'next_ns':target})
            body=dict(item,finding_key='pf1:finance',dimension='context')
            self.raw.execute('INSERT INTO anomaly_detection.adp_findings VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                             ('pf1:finance',actor,target,'payment_result_change','context','ACTIVE',1,3,'old',canonical(body),target))
        changed=dict(source,input_contract=BEHAVIOR,scope_epoch=1,financial_relations='OUT_OF_SCOPE')
        with self.store.transaction():self.store.bind(changed)
        self.assertEqual(self.raw.execute('SELECT state FROM anomaly_detection.adp_findings').fetchone()['state'],'OUT_OF_SCOPE')
        self.assertEqual(case_status(self.store,case)['bucket'],'OUT_OF_SCOPE')
        self.assertEqual(self.store.state('fresh_cursor'),{'next_ns':target})
        self.assertEqual(self.raw.execute('SELECT note FROM anomaly_detection.adp_case_feedback').fetchone()['note'],'keep this review')
        self.assertEqual(self.raw.execute('SELECT model_id FROM anomaly_detection.adp_models').fetchone()['model_id'],'finance-model')
        self.assertTrue(self.raw.execute('SELECT 1 FROM anomaly_detection.adp_finding_versions').fetchone())
        self.assertTrue(self.raw.execute('SELECT 1 FROM anomaly_detection.adp_case_versions WHERE revision>1').fetchone())
