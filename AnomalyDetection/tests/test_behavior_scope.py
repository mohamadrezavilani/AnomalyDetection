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

    def test_parent_child_receipt_references_share_the_same_namespace(self):
        source={'input_contract':BEHAVIOR}
        parent=dict(family='peer_service_rate_5m',model={'model_id':'am2:parent'},model_id='am2:parent')
        child=dict(family='input_subject_burst',model={'model_id':'am2:child','reference_model_id':'am2:parent'},
                   model_id='am2:child',reference_model_id='am2:parent')
        a,b=decisions([parent,child],source)
        self.assertEqual(a['model_id'],b['reference_model_id'])
        self.assertEqual(a['model_id'],b['model']['reference_model_id'])
        self.assertEqual(decisions([a,b],source),[a,b])
        self.assertEqual(child['reference_model_id'],'am2:parent')

    def test_export_projects_finance_without_destroying_the_original_receipt(self):
        from anomaly_detection.case_export import compact
        value={'relations':[{'kind':'finance'}],'identifiers':[{'kind':'invoice'}],
               'observations':[{'axis':'finance'},{'axis':'service_dispatch.access'}],
               'versions':{'input_contract':FULL},'input_subject':{'field':'WaterBillID'}}
        row=compact('case_facts',{'details':json.dumps(value)},{'input_contract':BEHAVIOR})
        shown=json.loads(row['details'])
        self.assertEqual(shown['financial_relations'],'OUT_OF_SCOPE')
        self.assertEqual(shown['relations'],[]);self.assertEqual(shown['identifiers'],[])
        self.assertEqual(shown['input_subject'],value['input_subject']);self.assertEqual(len(value['relations']),1)

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

    def test_persisted_parent_child_models_resolve_to_the_actual_behavior_receipts(self):
        from anomaly_detection.snapshot import canonical,digest
        actor='a'*64;target=300_000_000_000
        source=dict(namespace='viewer:test',stream_key='test',keys_fingerprint='same',generation=1,semantic_generation=1,
                    input_contract=BEHAVIOR,scope_epoch=1,behavioral_features='observed-behavior-features-1',financial_relations='OUT_OF_SCOPE',captured_at_ns=target)
        with self.store.transaction():
            self.store.bind(source)
            self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',(actor,target))
        job=dict(self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs').fetchone())
        context=dict(source=source,windows=[],target_complete=False)
        values=[]
        for family,name in (('peer_service_rate_5m','parent'),('input_subject_burst','child')):
            model=dict(model_id='am2:'+name)
            if name=='child':model['reference_model_id']='am2:parent'
            values.append(dict(family=family,dimension='activity',finding_key='pf1:'+digest(name),status='NO_DEVIATION_OBSERVED',model=model))
        self.store.complete(job,context,values,target)
        models=[json.loads(r['body']) for r in self.raw.execute('SELECT body FROM anomaly_detection.adp_models').fetchall()]
        child=next(v for v in models if v.get('reference_model_id'))
        self.assertIn(child['reference_model_id'],{v['model_id'] for v in models})
        self.assertTrue(all(v['input_contract']==BEHAVIOR for v in models))

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
        from anomaly_detection.behavior_scope import advance_migration,MIGRATION
        self.assertFalse(self.store.state(MIGRATION)['complete'])
        for _ in range(10):
            if advance_migration(self.store,limit=1)['complete']:break
        self.assertEqual(self.raw.execute('SELECT state FROM anomaly_detection.adp_findings').fetchone()['state'],'OUT_OF_SCOPE')
        self.assertEqual(case_status(self.store,case)['bucket'],'OUT_OF_SCOPE')
        self.assertEqual(self.store.state('fresh_cursor'),{'next_ns':target})
        self.assertEqual(self.raw.execute('SELECT note FROM anomaly_detection.adp_case_feedback').fetchone()['note'],'keep this review')
        self.assertEqual(self.raw.execute('SELECT model_id FROM anomaly_detection.adp_models').fetchone()['model_id'],'finance-model')
        self.assertTrue(self.raw.execute('SELECT 1 FROM anomaly_detection.adp_finding_versions').fetchone())
        self.assertTrue(self.raw.execute('SELECT 1 FROM anomaly_detection.adp_case_versions WHERE revision>1').fetchone())
        from anomaly_detection.behavior_scope import advance_requalification
        with self.store.transaction():
            self.raw.execute("INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,dirty,version,processed_version,evaluation) VALUES(%s,%s,FALSE,1,1,%s)",
                             (actor,target,canonical({'input_contract':BEHAVIOR,'scope_epoch':1})))
            self.store.bind(dict(source,scope_epoch=3))
            advance_requalification(self.store,limit=1)
        job=self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs').fetchone()
        self.assertTrue(job['dirty']);self.assertEqual(job['version'],2)
        self.assertNotEqual(case_status(self.store,case)['bucket'],'READY')
        self.assertEqual(self.raw.execute('SELECT note FROM anomaly_detection.adp_case_feedback').fetchone()['note'],'keep this review')
        self.assertEqual(self.store.state('fresh_cursor'),{'next_ns':target})
        with self.store.transaction():advance_requalification(self.store,limit=1)
        self.assertEqual(self.raw.execute('SELECT version FROM anomaly_detection.adp_jobs').fetchone()['version'],2)
        self.assertTrue(self.store.state('finance_requalification')['jobs_done'])
        with self.assertRaisesRegex(Exception,'WITHOUT_NEW_EPOCH'):
            with self.store.transaction():self.store.bind(dict(source,input_contract=BEHAVIOR,scope_epoch=3))
