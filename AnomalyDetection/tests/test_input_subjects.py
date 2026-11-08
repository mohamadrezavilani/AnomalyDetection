import json
from types import SimpleNamespace
import unittest

from anomaly_detection import FIVE_NS
from anomaly_detection.input_subjects import CONTRACTS, VERSION, collect, decisions, input_value
from anomaly_detection.review_policy import corroborated_scopes


TARGET = 1_800_000_000_000_000_000
SESSION = "a"*64
WATER = "Services.v1/WaterBills"


def parse_section(message, marker):
    try:
        return json.JSONDecoder().raw_decode(message.split(marker,1)[1].lstrip())[0], "complete"
    except (IndexError, ValueError):
        return None, "unlogged"


def evidence_for(request, at, service, subject):
    field, methods = CONTRACTS[service]
    event = {"request_key":request,"anchor_key":"anchor-"+request,"revision":1,
             "kind":"service_execution","state":"active","session_key":SESSION,
             "root_call":service,"anchor_ns":at}
    origin = "origin-"+request
    locator = {"request_key":request,"origin_key":origin,"version_key":"v",
               "at_ns":at,"raw_available":True,"callpath":"ClientAyanCoInquiry."+methods[0]}
    msg = ("Input:"+json.dumps([{field:subject,"TraceNumber":"ignored"}])+
           "\nOutput:"+json.dumps({"BillUniqueID":"new-"+request}))
    sample = SimpleNamespace(occurrences={request:event},
        requests={request:{"identity_state":"assigned","session_key":SESSION,"conflicted":False}},
        tables={"viewer_events":[locator]},origins={origin:{"v":locator}})
    reader = SimpleNamespace(get_raw=lambda *_:{"message":msg})
    detail = {"source_present":True,"semantic":event,"quality":{"evidence_available":True,"conflicted":False},
              "evidence":[locator|{"qualified":True}]}
    subject_receipt = collect(sample,reader,parse_section,lambda raw,k:(raw[k],"present"),b"k"*32)
    return event, {"request_key":request,"details":detail|{"input_subject":subject_receipt[request]}}


def peer_rate(service=WATER):
    values = [1]*8184+[10]*31+[38]
    return {"family":"peer_service_rate_5m","status":"CANDIDATE","observed":10,"comparison_count":1,
            "service_path":service,"model":{"status":"READY_BASELINE","unit":"canonical_service_executions",
                "model_id":"test-peer","cutoff_ns":TARGET,"other_session_epochs":len(values),
                "expected":1,"upper":38,"reference_values":values}}


class InputSubjectTests(unittest.TestCase):
    def evaluate(self, rows, service=WATER, **kwargs):
        events,details=zip(*rows)
        context=dict(events=list(events),target_complete=True,target_events_complete=True)
        context.update(kwargs)
        return next(decisions({"session_key":SESSION,"target_ns":TARGET},context,details,[peer_rate(service)]))

    def rows(self, same=False, service=WATER):
        field=CONTRACTS[service][0]
        prefix="0912" if field=="MobileNumber" else "021" if field=="FixedLineNumber" else "000"
        width=7 if field=="MobileNumber" else 8
        return [evidence_for(str(i),TARGET+1+i*1_300_000_000,service,prefix+str(1 if same else i+1).zfill(width))
                for i in range(10)]

    def test_verified_distinct_inputs_are_ready_within_historical_max_for_all_contracts(self):
        for service in CONTRACTS:
            with self.subTest(service=service):
                rows=self.rows(service=service)
                decision=self.evaluate(rows+rows,service)
                self.assertEqual(decision["status"],"CANDIDATE")
                self.assertEqual(decision["observed"],10)
                self.assertEqual(decision["verified_input_requests"],10)
                self.assertEqual(decision["observed_span_ns"],11_700_000_000)
                self.assertAlmostEqual(decision["upper_bound_tail_rank"],33/8217)
                self.assertTrue(decision["single_signal_review_eligible"])
                self.assertNotIn("subject_key",json.dumps(decision))

    def test_one_input_and_ten_generated_output_items_stay_one_input(self):
        decision=self.evaluate(self.rows(same=True))
        self.assertEqual(decision["observed"],1)
        self.assertEqual(decision["reason"],"ONE_VERIFIED_INPUT_SUBJECT")
        self.assertFalse(decision["single_signal_review_eligible"])

    def test_missing_or_changed_witness_cannot_qualify_diversity(self):
        rows=self.rows()
        rows[-1][1]["details"]["evidence"][0]["version_key"]="late-revision"
        decision=self.evaluate(rows)
        self.assertEqual(decision["status"],"INSUFFICIENT_DATA")
        self.assertEqual(decision["verified_input_requests"],9)
        self.assertNotIn("observed",decision)

    def test_late_provider_witness_requires_a_new_receipt(self):
        rows=self.rows()
        evidence=rows[-1][1]["details"]["evidence"]
        evidence.append(evidence[0]|{"origin_key":"late-provider-witness"})
        decision=self.evaluate(rows)
        self.assertEqual(decision["reason"],"VERIFIED_INPUT_EVIDENCE_INCOMPLETE")
        self.assertEqual(decision["verified_input_requests"],9)

    def test_partial_window_is_never_a_verified_subject_case(self):
        self.assertEqual(self.evaluate(self.rows(),target_events_complete=False)["status"],"INSUFFICIENT_DATA")

    def test_output_only_and_conflicting_input_aliases_are_not_subjects(self):
        for msg in ('Output:{"WaterBillID":"12345","text":"Input:"}',
                    'Input:{"WaterBillID":"12345","Parameters":{"WaterBillID":"99999"}}',
                    'Input:[{"WaterBillID":12345}]','Input:[{"WaterBillID":"00000"}]'):
            self.assertIsNone(input_value(msg,"WaterBillID",parse_section))
        self.assertEqual(input_value('Input:[{"WaterBillID":"00123"}]',"WaterBillID",parse_section),"00123")

    def test_mobile_canonical_form_does_not_inflate_distinct_targets(self):
        a=input_value('Input:[{"MobileNumber":"+989120000001"}]',"MobileNumber",parse_section)
        b=input_value('Input:[{"MobileNumber":"09120000001"}]',"MobileNumber",parse_section)
        self.assertEqual(a,b)
        self.assertEqual(b,"09120000001")

    def test_compatible_scope_cannot_be_created_by_other_services_or_input_rate_pair(self):
        activity={"family":"peer_service_rate_5m","dimension":"activity","service_path":WATER}
        content={"family":"input_subject_burst","dimension":"input_subject","service_path":WATER}
        timing={"family":"timing_regularization","dimension":"timing","service_path":"Other.v1/Api"}
        self.assertEqual(corroborated_scopes([activity,content,timing]),set())
        self.assertEqual(corroborated_scopes([activity,timing|{"service_path":WATER}]),{WATER})
