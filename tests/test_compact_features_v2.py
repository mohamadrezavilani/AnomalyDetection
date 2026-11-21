import unittest
from compact_behavior.extract import features, materialize, facts, merge, behavior_id
from compact_behavior.feature_contract import extract_features
from tests.test_compact_extract import row, extract, T


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


if __name__ == "__main__":
    unittest.main()
