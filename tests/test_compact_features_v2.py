import unittest
import json
import hashlib
from pathlib import Path
from compact_behavior.extract import features, materialize, facts, merge, behavior_id
from compact_behavior.feature_contract import extract_features
from tests.test_compact_extract import row, extract, T


class PayloadAndScopeTests(unittest.TestCase):
    def test_large_payload_keeps_exact_features_without_retaining_the_large_value(self):
        value = {"WaterBillID": "001", "Amount": 42, "Description": "x" * 400000}
        records = [row(), row(message="Input:" + json.dumps(value))]
        state = extract(records)["req-1"]
        self.assertLess(len(json.dumps(state)), 10000)
        self.assertEqual(state["inputs"][0]["representation"], "FEATURES_ONLY_V1")
        body = materialize("s", state)
        self.assertEqual(body["features"]["input"], features(value))
        self.assertTrue(body["features"]["input_eligible"])
        self.assertTrue(body["features"]["rate_eligible"])
        self.assertEqual(extract(records), extract(list(reversed(records)) * 2))

    def test_omitted_text_change_is_still_a_conflict_even_with_identical_features(self):
        a = {"BillID": "A", "Description": "x" * 400000}
        b = dict(a, Description="y" * 400000)
        state = extract([row(), row(message="Output:" + json.dumps(a)), row(message="Output:" + json.dumps(b))])["req-1"]
        body = materialize("s", state)
        self.assertIn("output_conflict", body["quality"])
        self.assertFalse(body["features"]["output_eligible"])
        self.assertTrue(body["features"]["rate_eligible"])

    def test_excessive_payload_depth_invalidates_its_direction_without_blocking_rate(self):
        value = {"BillID":"W"}
        for _ in range(25):
            value = {"nested":value}
        state = extract([row(), row(message="Input:" + json.dumps(value) + ' Output:{"Amount":42}')])["req-1"]
        body = materialize("s", state)
        self.assertIn("inputs_content_limit", body["quality"])
        self.assertFalse(body["features"]["input_eligible"])
        self.assertTrue(body["features"]["output_eligible"])
        self.assertTrue(body["features"]["rate_eligible"])

    def test_feature_storage_limit_is_per_component_and_does_not_stop_rate(self):
        value = [{"BillID": str(i) + "x" * 512, "Amount": i} for i in range(512)]
        body = materialize("s", extract([row(), row(message="Input:" + json.dumps(value))])["req-1"])
        feature = body["features"]["input"]
        self.assertFalse(body["features"]["input_feature_eligibility"]["targets"])
        self.assertIn("FEATURE_STORAGE_LIMIT", feature["completeness"]["targets"]["reasons"])
        self.assertTrue(body["features"]["input_feature_eligibility"]["numeric"])
        self.assertTrue(body["features"]["rate_eligible"])

    def test_existing_unpacked_state_is_compacted_without_changing_request_identity(self):
        from compact_behavior.extract import empty
        value = {"BillID": "A", "Description": "x" * 400000}
        old = extract([row()])["req-1"]
        old["inputs"] = [dict(value=value, basis="public_api", path="Services.v1/WaterBills", observed_at_ns=T)]
        new = merge(old, empty("req-1"))
        self.assertEqual(materialize("s", old)["behavior_id"], materialize("s", new)["behavior_id"])
        self.assertEqual(materialize("s", old)["features"]["input"], materialize("s", new)["features"]["input"])
        self.assertLess(len(json.dumps(new)), 10000)

    def test_source_role_catalog_is_preserved_with_explicit_owner_additions(self):
        from compact_behavior.services import operation_catalog
        source = Path(__file__).resolve().parents[1] / "catalogs/viewer_service_roles.json"
        registered = json.loads(source.read_text(encoding="utf-8"))["routes"]
        catalog = operation_catalog()
        self.assertEqual(catalog["source_catalog_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        added=catalog['owner_additions']['roles']
        self.assertFalse(set(added)&set(registered))
        self.assertEqual({k:v["role"] for k,v in catalog["routes"].items()},
            {**{k:v["role"] for k,v in registered.items()},**added})
        from compact_behavior.services import routes
        self.assertFalse(set(routes())-set(catalog['routes']))

    def test_confirmed_topup_role_does_not_invent_provider_output_binding(self):
        records=[row(path='Services.v1/InvoiceRegister'),
            row(path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/TopUpProductReserve)'),
            row(path='DBPath.pishkhan24.application.ud_prc_invoiceRequest',message='(SQL Parameters: @serviceID=1202)'),
            row(path='DBPath.pishkhan24.application.ud_prc_invoiceRegister',message='(SQL Parameters: @queryParameters={"LineNumber":"example","Amount":100})'),
            row(path='ClientAyanCoTopUp.TopUpChargeCustom',message='Output:{"Amount":100}')]
        body=materialize('s',extract(records)['req-1'])
        self.assertEqual(body['operation_role'],'business')
        self.assertTrue(body['features']['service_rate_eligible'])
        self.assertTrue(body['features']['input_eligible'])
        self.assertFalse(body['features']['output_eligible'])
        self.assertIn('output_binding_unconfirmed',body['quality'])
        partial=materialize('s',extract(records[:2])['req-1'])
        self.assertEqual(partial['operation_role'],'unknown')
        self.assertIn('unresolved_dispatch',partial['quality'])

    def test_auxiliary_calls_do_not_become_meaningful_actions_or_retain_large_content(self):
        from compact_ad.engine import summarize
        from compact_behavior.services import meaningful
        for api in ("Core.v1/ConfigBasic", "Core.v1/UserServiceQueries", "Services.v1/AddUserData"):
            with self.subTest(api=api):
                state = extract([row(path=api), row(path=api, message='Output:{"Description":"' + 'x' * 400000 + '"}')])["req-1"]
                body = materialize("s", state)
                self.assertFalse(meaningful(api))
                self.assertFalse(body["features"]["service_rate_eligible"])
                self.assertEqual(state["outputs"], [])
                body["kind"] = "observed_api_operation"  # An already persisted old row.
                self.assertEqual(summarize([body])[0]["services"], {})

    def test_many_internal_rows_still_produce_one_water_inquiry(self):
        from compact_ad.engine import summarize
        records = [row(), row(path="ClientAyanCoInquiry.WaterBillInquiry", message='Input:{"WaterBillID":"W"}')]
        records += [row(path="DBPath.Some.InternalRead", message="SELECT internal") for _ in range(30)]
        body = materialize("s", extract(records)["req-1"])
        self.assertEqual(body["label_fa"], "استعلام قبض آب")
        self.assertEqual(summarize([body])[0]["services"]["Services.v1/WaterBills"]["count"], 1)

    def test_unknown_operation_is_not_assumed_meaningful_or_normal(self):
        from compact_ad.engine import summarize
        body = materialize("s", extract([row(path="Services.v99/Unregistered")])["req-1"])
        self.assertEqual(body["operation_role"], "unknown")
        self.assertFalse(body["features"]["service_rate_eligible"])
        self.assertEqual(summarize([body])[0]["services"]["<unresolved>"]["count"], 0)

    def test_dispatcher_preserves_public_input_and_requires_exact_service_binding(self):
        records = [row(path="Services.v1/InvoiceRegister"), row(path="Services.v1/InvoiceRegister", message='Input:{"WaterBillID":"W"}')]
        unresolved = materialize("s", extract(records)["req-1"])
        self.assertEqual(unresolved["operation_role"], "unknown")
        self.assertFalse(unresolved["features"]["service_rate_eligible"])
        records += [row(path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess", message="(SQL Parameters: @action=v1/WaterBills)"), row(path="DBPath.pishkhan24.application.ud_prc_invoiceRequest", message="(SQL Parameters: @serviceID=7)")]
        body = materialize("s", extract(records)["req-1"])
        self.assertEqual(body["operation_role"], "business")
        self.assertTrue(body["features"]["service_rate_eligible"])
        self.assertTrue(body["features"]["input_eligible"])
        self.assertEqual(body["features"]["input"]["targets"]["WaterBillID"][0]["value"], "W")


class FeatureContractTests(unittest.TestCase):
    def test_array_multiset_preserves_first_and_duplicate_typed_targets(self):
        a = features([{"BillID": "A"}, {"BillID": "B"}, {"BillID": "B"}, {"BillID": 1}])
        b = features([{"BillID": "X"}, {"BillID": "B"}, {"BillID": "B"}, {"BillID": 1}])
        self.assertNotEqual(a["targets"], b["targets"])
        self.assertEqual(len(a["targets"]["[].BillID"]), 4)
        self.assertEqual(
            a,
            features(
                [{"BillID": 1}, {"BillID": "B"}, {"BillID": "A"}, {"BillID": "B"}]
            ),
        )

    def test_numeric_array_has_order_independent_multiplicity(self):
        a = features({"amounts": [2, 2, 8]})["numeric"]["amounts[]"]
        self.assertEqual(
            (a["count"], a["min"], a["max"], a["sum"], a["mean"]), (3, 2, 8, 12, 4)
        )
        self.assertEqual(a, features({"amounts": [8, 2, 2]})["numeric"]["amounts[]"])
        self.assertNotEqual(
            a["values_hash"],
            features({"amounts": [2, 8]})["numeric"]["amounts[]"]["values_hash"],
        )

    def test_33rd_item_is_seen_and_real_limit_is_explicit(self):
        a = [{"BillID": str(i)} for i in range(33)]
        b = a[:-1] + [{"BillID": "changed"}]
        self.assertNotEqual(features(a)["targets"], features(b)["targets"])
        limited = extract_features(a, max_array_items=32)
        for component in ("targets", "numeric", "shape"):
            self.assertFalse(limited["completeness"][component]["complete"])
            self.assertIn("ARRAY_LIMIT", limited["completeness"][component]["reasons"])

    def test_component_limits_do_not_suppress_independent_features(self):
        f = extract_features({"BillID": "1", "a": 1, "b": 2}, max_shapes=1)
        self.assertTrue(f["completeness"]["targets"]["complete"])
        self.assertTrue(f["completeness"]["numeric"]["complete"])
        self.assertFalse(f["completeness"]["shape"]["complete"])

    def test_huge_integer_does_not_crash_or_claim_numeric_eligibility(self):
        f = features({"value": 10**400})
        self.assertFalse(f["completeness"]["numeric"]["complete"])

    def test_same_selected_path_parse_error_invalidates_output_only(self):
        state = extract(
            [row(), row(message='Output:{"Amount":1}'), row(message="Output:[broken")]
        )["req-1"]
        b = materialize("s", state)
        self.assertFalse(b["features"]["output_eligible"])
        self.assertTrue(b["features"]["rate_eligible"])
        self.assertFalse(any(b["features"]["output_feature_eligibility"].values()))

    def test_unrelated_provider_error_does_not_poison_selected_business_output(self):
        state = extract(
            [
                row(),
                row(
                    path="DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2",
                    message='(SQL Parameters: @queryResult={"Amount":1})',
                ),
                row(path="ClientAyanCoUnrelated.Output", message="Output:[broken"),
            ]
        )["req-1"]
        self.assertTrue(materialize("s", state)["features"]["output_eligible"])

    def test_malformed_higher_priority_does_not_fall_back_to_good_provider(self):
        state = extract(
            [
                row(),
                row(
                    path="DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2",
                    message="(SQL Parameters: @queryResult=[broken)",
                ),
                row(path="ClientAyanCoInquiry.WaterBillInquiry", message="Output:[1]"),
            ]
        )["req-1"]
        b = materialize("s", state)
        self.assertEqual(b["features"]["output_basis"], "business_parameters")
        self.assertFalse(b["features"]["output_eligible"])

    def test_duplicate_json_object_keys_are_rejected(self):
        state = extract([row(), row(message='Output:{"Amount":1,"Amount":2}')])["req-1"]
        self.assertFalse(materialize("s", state)["features"]["output_eligible"])

    def test_json_encoded_duplicate_keys_never_overwrite_a_target_silently(self):
        import json
        payload = {"Parameters": '{"WaterBillID":"A","WaterBillID":"B"}'}
        state = extract([row(), row(message="Input:" + json.dumps(payload))])["req-1"]
        body = materialize("s", state)
        self.assertFalse(body["features"]["input_eligible"])
        self.assertFalse(any(body["features"]["input_feature_eligibility"].values()))
        self.assertTrue(body["features"]["rate_eligible"])
        self.assertIn("ENCODED_JSON_PARSE_ERROR", body["features"]["input"]["completeness"]["targets"]["reasons"])

    def test_empty_object_paths_are_part_of_the_response_shape(self):
        signatures = {features(value)["shape_hash"] for value in ({}, {"a": {}}, {"b": {}}, {"a": []})}
        self.assertEqual(len(signatures), 4)
        self.assertEqual(features({"a": {}, "b": 1}), features({"b": 1, "a": {}}))

    def test_exact_same_request_dispatch_and_no_name_guess(self):
        records = [
            row(path="Services.v1/InvoiceRegister"),
            row(
                path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess",
                message="(SQL Parameters: @action=v1/WaterBills)",
            ),
            row(
                path="DBPath.pishkhan24.application.ud_prc_invoiceRequest",
                message="(SQL Parameters: @serviceID=7)",
            ),
        ]
        body = materialize("s", extract(records)["req-1"])
        self.assertEqual(body["service_key"], "Services.v1/WaterBills")
        unconfirmed = materialize(
            "s",
            extract(
                [
                    records[0],
                    row(
                        path="ClientAyanCoInquiry.WaterBillInquiry", message="Output:[]"
                    ),
                ]
            )["req-1"],
        )
        self.assertIsNone(unconfirmed["service_key"])
        records.append(
            row(
                path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess",
                message="(SQL Parameters: @action=v1/GasBills)",
            )
        )
        self.assertIsNone(materialize("s", extract(records)["req-1"])["service_key"])

    def test_missing_session_does_not_invalidate_known_service_rate(self):
        b = materialize("s", extract([row(session="N/A")])["req-1"])
        self.assertTrue(b["features"]["service_rate_eligible"])
        self.assertFalse(b["features"]["session_eligible"])
        self.assertFalse(b["features"]["rate_eligible"])

    def test_observed_services_automatic_endpoints_are_excluded_from_business_rates(self):
        for path in ("Services.v1/AddUserData", "Services.v1/GetUserData", "Core.v1/AddUserData", "Core.v1/GetUserData"):
            with self.subTest(path=path):
                body = materialize("s", extract([row(path=path)])["req-1"])
                self.assertEqual(body["kind"], "automatic_support")
                self.assertFalse(body["features"]["rate_eligible"])
                self.assertFalse(body["features"]["service_rate_eligible"])
                self.assertFalse(body["features"]["result_eligible"])

    def test_nested_malformed_json_and_omitted_binary_are_incomplete(self):
        self.assertFalse(features({"Parameters": "[broken"})["complete"])
        self.assertFalse(
            features({"image": {"binary_content_omitted": True, "characters": 100}})[
                "complete"
            ]
        )

    def test_resolved_dispatch_uses_only_exact_reviewed_provider_pair(self):
        records = [
            row(path="Services.v1/InvoiceRegister"),
            row(
                path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess",
                message="(SQL Parameters: @action=v1/WaterBills)",
            ),
            row(
                path="DBPath.pishkhan24.application.ud_prc_invoiceRequest",
                message="(SQL Parameters: @serviceID=7)",
            ),
            row(
                path="ClientAyanCoInquiry.WaterBillInquiry",
                message='Input:{"BillID":"one"} Output:{"Amount":10}',
            ),
        ]
        body = materialize("s", extract(records)["req-1"])
        self.assertTrue(body["features"]["output_eligible"])
        self.assertEqual(
            body["features"]["output_basis"], "reviewed_same_request_provider"
        )
        records.append(
            row(path="ClientAyanCoInquiry.WaterBillInquiry", message="Output:[broken")
        )
        self.assertFalse(
            materialize("s", extract(records)["req-1"])["features"]["output_eligible"]
        )

    def test_later_identical_payload_keeps_first_known_time_and_one_variant(self):
        from compact_behavior.extract import iso
        from compact_behavior import FIVE

        records = [row()] + [
            row(
                path="ClientAyanCoInquiry.WaterBillInquiry",
                message='Input:{"BillID":"same"} Output:[]',
                at=iso(T + 20 * 10**9 + i),
            )
            for i in range(70)
        ]
        state = extract(records)["req-1"]
        self.assertEqual(len(state["inputs"]), 1)
        late = extract(
            [
                row(
                    path="ClientAyanCoInquiry.WaterBillInquiry",
                    message='Input:{"BillID":"same"} Output:[]',
                    at=iso(T + FIVE + 10**9),
                )
            ]
        )["req-1"]
        body = materialize("s", merge(state, late))
        self.assertTrue(body["features"]["input_eligible"])
        self.assertEqual(body["features"]["input_asof_ns"], T + 20 * 10**9)

    def test_revision_contract_does_not_rekey_behavior(self):
        a = materialize("s", extract([row()])["req-1"])
        self.assertEqual(a["behavior_id"], behavior_id("s", "req-1"))
        self.assertEqual(a["features"]["version"], "compact-features-2")
        self.assertEqual(a["features"]["financial_chain"], "OUT_OF_SCOPE")




class InquirySubjectTests(unittest.TestCase):
    def body(self, api, value, *, path=None):
        import json
        from tests.test_compact_extract import row, extract
        from compact_behavior.extract import materialize
        return materialize('test', extract([row(path=api), row(path=path or api,
            message='Input:' + json.dumps(value))])['req-1'])

    def test_source_aliases_do_not_count_incidental_ids(self):
        from compact_behavior.inquiry import POLICY, token
        water = self.body('Services.v1/WaterBills', {'Identifier':'001', 'MobileNumber':'x'})
        provider = self.body('Services.v1/WaterBills', {'Parameters':{'WaterBillID':'001'}},
                             path='ClientAyanCoInquiry.WaterBillInquiry')
        self.assertEqual(water['features'][POLICY], {'WaterBillID':token('001')})
        self.assertEqual(provider['features'][POLICY], water['features'][POLICY])
        self.assertEqual(self.body('Services.v1/PostTrackingExtended',
            {'TrackingCode':'P', 'MobileNumber':'x'})['features'][POLICY], {'TrackingCode':token('P')})
        self.assertNotEqual(token('01'),token('1'))
        self.assertEqual(self.body('Services.v1/WaterBills', {'Identifier':'A',
            'Parameters':{'Identifier':'B'}})['features'][POLICY], {})
        self.assertNotIn(POLICY,self.body('Services.v1/WaterBills', {'Identifier':'x'},
            path='ClientAyanCoUnreviewed.Method')['features'])
        self.assertEqual(self.body('Services.v1/WaterBills', {'Nested':{'Identifier':'x'},
            'Identifier':' '})['features'][POLICY], {})

    def test_unreviewed_operation_cannot_qualify_from_an_incidental_generic_id(self):
        from compact_ad.engine import summarize, evaluate
        from tests.test_compact_extract import T
        body=self.body('Public.v1/ExchangeGold', {'NationalCode':'unrelated'})
        summary, services, actors=summarize([body])
        rows=[r for r in evaluate(T,summary,services,actors,[]) if r['method']=='target_diversity']
        self.assertEqual([r['reason'] for r in rows],['INQUIRY_SUBJECT_NOT_REVIEWED'])

    def test_oversized_input_snapshot_and_old_duplicate_share_one_timed_variant(self):
        import copy
        from compact_behavior.extract import timed_union
        from compact_behavior.inquiry import POLICY, token
        from compact_behavior.payload import packed
        data={'Identifier':'001','Description':'x'*20000}
        self.assertEqual(self.body('Services.v1/WaterBills',data)['features'][POLICY],{'WaterBillID':token('001')})
        new = dict(packed(data,inquiry_input=True),observed_at_ns=20)
        old = copy.deepcopy(new); old.pop('inquiry_candidates'); old['observed_at_ns']=10
        expected=dict(new,observed_at_ns=10)
        for a,b in ((old,new),(new,old)):
            self.assertEqual(timed_union([a],[b],1,'input'),[expected])

    def test_contract_and_person_have_independent_counts_references_and_readiness(self):
        from compact_behavior import FIVE
        from compact_ad.engine import summarize, evaluate
        from tests.test_compact_extract import T
        for version in ('v1','v2'):
            api=f'Services.{version}/RealEstateContract'
            rows=[self.body(api, {'TrackingCode':str(i),'NationalCode':'same'}) for i in range(40)]
            for i,row in enumerate(rows):
                row['behavior_id']=str(i)
            baseline=[self.body(api, {'TrackingCode':'one','NationalCode':'one'}) for _ in range(3)]
            reference=summarize(baseline)[0]
            refs=[dict(start_ns=T+i*FIVE,summary=reference) for i in range(12)]
            summary,services,actors=summarize(rows,collect_longitudinal=True)
            out=evaluate(T+12*FIVE,summary,services,actors,refs)
            counts={r['numeric_path']:(r['observed'],r['status']) for r in out if r['method']=='target_diversity'}
            self.assertEqual(counts,{'TrackingCode':(40,'ANOMALY'),'NationalCode':(1,'NORMAL')})
            rows.append(self.body(api,{'TrackingCode':'last'}))
            out=evaluate(T+12*FIVE,*summarize(rows),refs)
            self.assertEqual({r['numeric_path']:r['status'] for r in out if r['method']=='target_diversity'},
                             {'TrackingCode':'ANOMALY','NationalCode':'INVALID_INPUT'})


if __name__ == "__main__":
    unittest.main()
