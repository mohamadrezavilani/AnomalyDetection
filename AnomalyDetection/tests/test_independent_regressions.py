"""Independent behavioural regressions discovered at commit 8739ecfedade.

No native database, source startup, live state or external configuration is used.
"""
import unittest
from audit.run_independent_audit import ACTOR, S, OTHER, T, detail, behavior_context, exact_greater
from anomaly_detection.context_models import evaluate
from anomaly_detection.product_models import evaluate as behavior


class IndependentRegressions(unittest.TestCase):
    def test_previously_seen_rare_otp_failure_becomes_dominant(self):
        self._frequency_shift('otp_result_change','otp','G00000','GD2076')

    def test_previously_seen_rare_payment_failure_becomes_dominant(self):
        self._frequency_shift('payment_result_change','payment',('bill_payments','Success'),('bill_payments','Failed'))

    def test_previously_seen_rare_journey_becomes_dominant(self):
        self._frequency_shift('journey_profile_change','roles',('service_operation',),('other_role',))

    def test_previously_seen_rare_business_failure_becomes_dominant(self):
        self._frequency_shift('business_result_change','inquiry','G00000','GD2076')

    def _frequency_shift(self,family,field,usual,rare):
        self.assertLess(exact_greater(20,0,1,119),1e-20)
        context,_=behavior_context(current=20)
        rows=[detail(i,**{field:usual if i<119 else rare}) for i in range(120)]
        rows += [detail(900+i,current=True,**{field:rare}) for i in range(20)]
        decisions=behavior(context,[],rows) if family=='business_result_change' else evaluate(context,rows)
        d=next(d for d in decisions if d['family']==family)
        self.assertEqual(d['status'],'CANDIDATE')
        self.assertFalse(d['operator_alert'])

    def test_business_result_does_not_use_unavailable_evidence(self):
        context,_=behavior_context(current=20)
        rows=[detail(i,inquiry='G00000',available=False) for i in range(120)]
        rows += [detail(900+i,current=True,inquiry='GD2076',available=False) for i in range(20)]
        d=next(d for d in behavior(context,[],rows) if d['family']=='business_result_change')
        self.assertEqual(d['status'],'INSUFFICIENT_DATA')

    def test_one_ready_service_does_not_hide_another_services_missing_reference(self):
        context,_=behavior_context(current=20)
        rows=[detail(i,otp='OK') for i in range(120)]+[detail(900+i,current=True,otp='BAD') for i in range(20)]
        rows += [detail(2000+i,current=True,otp='BAD',service=OTHER) for i in range(20)]
        ds=evaluate(context,rows)
        self.assertTrue(any(d['family']=='otp_result_change' and d['service_path']==OTHER
                            and d['status']=='INSUFFICIENT_DATA' for d in ds))

    def test_different_semantic_kinds_cannot_overwrite_each_others_finding(self):
        context,_=behavior_context(current=20)
        rows=[detail(i,otp='OK') for i in range(120)]+[detail(900+i,current=True,otp='BAD') for i in range(20)]
        rows += [detail(2000+i,otp='OK',kind='wallet_funding_execution') for i in range(120)]
        rows += [detail(3000+i,current=True,otp='OK',kind='wallet_funding_execution') for i in range(20)]
        ds=[d for d in evaluate(context,rows) if d['family']=='otp_result_change' and d['service_path']==S]
        self.assertEqual(len(ds),2)
        self.assertEqual(len({d['finding_key'] for d in ds}),2)

    def test_unavailable_second_service_remains_explicitly_unknown(self):
        context,_=behavior_context(current=20)
        rows=[detail(i,otp='OK') for i in range(120)]+[detail(900+i,current=True,otp='BAD') for i in range(20)]
        rows += [detail(2000+i,current=True,otp='BAD',service=OTHER,available=False) for i in range(20)]
        self.assertTrue(any(d['family']=='otp_result_change' and d['service_path']==OTHER
                            and d['status']=='INSUFFICIENT_DATA' for d in evaluate(context,rows)))

    def test_same_distribution_and_duplicate_evidence_do_not_create_a_shift(self):
        context,_=behavior_context(current=20)
        rows=[detail(i,otp='OK' if i%2 else 'BAD') for i in range(120)]
        rows += [detail(900+i,current=True,otp='OK' if i%2 else 'BAD') for i in range(20)]
        ds=evaluate(context,rows+rows)
        d=next(d for d in ds if d['family']=='otp_result_change')
        self.assertEqual(d['status'],'NO_DEVIATION_OBSERVED')

    def test_mature_service_reference_does_not_disable_five_sample_evaluators(self):
        from audit.run_independent_audit import RESULTS,service_checks
        start=len(RESULTS)
        service_checks()
        controls=[r for r in RESULTS[start:] if r['test']=='1025_frames_positive_blocked']
        self.assertEqual(len(controls),5)
        self.assertEqual({r['family']:r['status'] for r in controls},{r['family']:'PASS' for r in controls})


if __name__=='__main__':unittest.main()
