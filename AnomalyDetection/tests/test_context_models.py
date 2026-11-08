import unittest
from copy import deepcopy
from anomaly_detection import FIVE_NS
from anomaly_detection.context_models import evaluate

TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SERVICE='Services.v1/WaterBills'

def record(n,*,current=False,latency=1,otp=None,payment=None,roles=('service_operation',),truncated=False,service=SERVICE):
    at=TARGET+1 if current else TARGET-(n+1)*FIVE_NS+1
    key=f'{n:064x}';origin='a'*64
    observations=[] if otp is None else [{'qualified':True,'axis':'service_dispatch.otp_validation','value':otp,'at_ns':at+2}]
    invoice={'sources':[{'request_key':key}],'inquiry_payments':[],'bill_payments':[]}
    if payment:invoice[payment[0]]=[{'statuses':[{'value':payment[1],'evidence':{'at_ns':at+2}}]}]
    fact={'source_present':True,'quality':{'evidence_available':True,'conflicted':False},
        'semantic':{'kind':'service_execution'},'observations':observations,
        'transport':{'started_ns':at,'ended_ns':at+int(latency*1e9)},
        'identifiers':[{'issuer':'p24','kind':'invoice','scope':'','identity_key':key,'origin_key':origin,'evidence_quality':{'qualified':True}}],
        'evidence':[{'origin_key':origin,'at_ns':at}],
        'viewer_journey':{'journey':{'identity_status':'resolved','truncated':truncated,'coverage_caveats':[],
            'steps':[{'role':role,'ended_ns':at+10} for role in roles]},'payment':{'invoices':[invoice],'truncated':truncated}}}
    return {'request_key':key,'at_ns':at,'service_path':service,'details':fact}

def run(rows):return evaluate({'session_key':'f'*64,'target_ns':TARGET,'evidence_verified':True},rows)
def family(rows,name):return next(x for x in run(rows) if x['family']==name)

class ContextModelsTests(unittest.TestCase):
    def test_latency_positive_and_usual_negative(self):
        history=[record(i) for i in range(120)]
        self.assertEqual(family(history+[record(900,current=True,latency=100)],'request_latency')['status'],'CANDIDATE')
        self.assertEqual(family(history+[record(901,current=True)],'request_latency')['status'],'NO_DEVIATION_OBSERVED')
    def test_observation_span_is_not_misreported_as_proven_http_duration(self):
        result=family([record(i) for i in range(120)]+[record(900,current=True,latency=100)],'request_latency')
        self.assertEqual(result['measurement'],'first_to_last_observed_event_span')
        self.assertFalse(result['is_http_duration_proof'])
    def test_future_completion_cannot_train_latency(self):
        rows=[record(i) for i in range(120)]
        for row in rows:row['details']['transport']['ended_ns']=TARGET+1
        self.assertEqual(family(rows+[record(900,current=True,latency=100)],'request_latency')['status'],'INSUFFICIENT_DATA')
    def test_optional_otp_and_payment_are_not_failures(self):
        rows=[record(i) for i in range(120)]+[record(900+i,current=True) for i in range(12)]
        self.assertEqual(family(rows,'otp_result_change')['status'],'INSUFFICIENT_DATA')
        self.assertEqual(family(rows,'payment_result_change')['status'],'INSUFFICIENT_DATA')
    def test_qualified_otp_change_is_context_only(self):
        rows=[record(i,otp='G00000') for i in range(120)]+[record(900+i,current=True,otp='GD2076') for i in range(12)]
        decision=family(rows,'otp_result_change')
        self.assertEqual(decision['status'],'CANDIDATE');self.assertEqual(decision['dimension'],'context');self.assertFalse(decision['operator_alert'])
    def test_future_otp_observation_is_not_past_training(self):
        past=[record(i,otp='G00000') for i in range(120)]
        for r in past:r['details']['observations'][0]['at_ns']=TARGET+1
        self.assertEqual(family(past+[record(900+i,current=True,otp='GD') for i in range(12)],'otp_result_change')['status'],'INSUFFICIENT_DATA')
    def test_financial_status_profile_is_not_settlement(self):
        past=[record(i,payment=('bill_payments','Success')) for i in range(120)]
        now=[record(900+i,current=True,payment=('bill_payments','Failed')) for i in range(12)]
        d=family(past+now,'payment_result_change');self.assertEqual(d['status'],'CANDIDATE');self.assertEqual(d['dimension'],'context')
        self.assertNotIn('settled',d)
    def test_fee_and_bill_results_are_separate_profiles(self):
        past=[record(i,payment=('inquiry_payments','Success')) for i in range(120)]
        now=[record(900+i,current=True,payment=('bill_payments','Success')) for i in range(12)]
        self.assertEqual(family(past+now,'payment_result_change')['status'],'CANDIDATE')
    def test_service_and_kind_cannot_borrow_incompatible_context(self):
        past=[record(i,otp='OK',service='Core.v1/Another') for i in range(120)]
        now=[record(900+i,current=True,otp='FAIL') for i in range(12)]
        self.assertEqual(family(past+now,'otp_result_change')['status'],'INSUFFICIENT_DATA')
        for r in past:r['service_path']=SERVICE;r['details']['semantic']['kind']='wallet_funding_execution'
        self.assertEqual(family(past+now,'otp_result_change')['status'],'INSUFFICIENT_DATA')
    def test_truncated_journey_cannot_prove_novel_profile(self):
        past=[record(i) for i in range(120)]
        now=[record(900+i,current=True,roles=('new_role',),truncated=True) for i in range(12)]
        self.assertEqual(family(past+now,'journey_profile_change')['status'],'INSUFFICIENT_DATA')
    def test_journey_positive_preserves_statistical_context_meaning(self):
        rows=[record(i) for i in range(120)]+[record(900+i,current=True,roles=('new_role',)) for i in range(12)]
        d=family(rows,'journey_profile_change');self.assertEqual(d['status'],'CANDIDATE');self.assertEqual(d['dimension'],'context')
    def test_unavailable_evidence_is_not_normal(self):
        rows=[record(i) for i in range(120)]+[record(900,current=True)]
        for r in rows:r['details']['quality']['evidence_available']=False
        self.assertEqual({d['status'] for d in run(rows)},{'INSUFFICIENT_DATA'})
    def test_high_typed_identifier_diversity_is_explainable_context(self):
        past=[record(i) for i in range(120)]
        now=[record(900+i,current=True) for i in range(12)]
        d=family(past+now,'typed_target_diversity');self.assertEqual(d['status'],'CANDIDATE');self.assertEqual(d['dimension'],'context')

if __name__=='__main__':unittest.main()
