import json
import unittest
from pathlib import Path

from p24_foundation.request_chains import build_request_chain_candidates
from tests.helpers import TEST_KEYS

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalogs/error_code_catalog.json"


def build(name):
    path = ROOT / "fixtures" / name
    return build_request_chain_candidates(path.read_bytes(), locator=path.name, keys=TEST_KEYS,
        namespace="request_chain_test:" + name, catalog_path=CATALOG)


class RequestChainCandidateTests(unittest.TestCase):
    def test_boundary_capture_keeps_client_sql_and_provider_outcomes_separate(self):
        result = build("boundary.sanitized.json")
        self.assertEqual(result["source_record_count"], 14)
        self.assertEqual(result["request_projection_count"], 1)
        chain = result["chains"][0]
        self.assertEqual(chain["client_http_request_count"], 1)
        self.assertEqual(chain["client_http_endpoint"], "Services.v3/ElectricBillsExport")
        self.assertEqual(chain["client_http_recorded_outcome"], "failure")
        self.assertEqual(chain["role_observation_counts"]["sql"], 12)
        self.assertEqual(chain["role_observation_counts"]["provider"], 1)
        sql = [o for o in chain["observations"] if o["operation_role"] == "sql"]
        self.assertTrue(any(x["recorded_operation_outcome"] == "success" and
                            any(y["evidence_layer"] == "sql_result" and y["recorded_outcome"] == "success"
                                for y in x["outcome_observations"]) for x in sql))
        self.assertEqual(result["capture_finality"], "not_established")
        self.assertFalse(chain["execution_or_workflow_finality_proven"])

    def test_registration_versions_remain_distinct_and_unlinked_to_session(self):
        result = build("registration.sanitized.json")
        by_endpoint = {row["client_http_endpoint"]: row for row in result["chains"]}
        self.assertEqual(set(by_endpoint), {"Core.v1/DeviceRegister", "Core.v2/DeviceRegister"})
        self.assertTrue(all(row["client_http_request_count"] == 1 for row in by_endpoint.values()))
        self.assertTrue(all(row["observed_access_check_actions"][0]["binding_state"] ==
                            "unverified_caller_context" for row in by_endpoint.values()))
        self.assertTrue(all(not any("session" in key.casefold() for key in row) for row in result["chains"]))

    def test_fixture_chain_export_never_contains_raw_identity_or_payload_values(self):
        from p24_foundation.intake import read_batch
        names = ["boundary.sanitized.json", "ip_activity.sanitized.json",
                 "registration.sanitized.json", "session_activity.sanitized.json",
                 "taxonomy/provider_ping.sanitized.json"]
        serialized_outputs = []
        for name in names:
            result = build(name)
            serialized = json.dumps(result, ensure_ascii=False)
            serialized_outputs.append(serialized)
            batch = read_batch(ROOT / "fixtures" / name)
            for record in batch.records:
                for container in (record.get("_source", {}), record.get("fields", {})):
                    for field in ("RequestID", "IP", "Session"):
                        value = container.get(field)
                        value = value[0] if isinstance(value, list) and len(value) == 1 else value
                        if isinstance(value, str) and value and value.upper() != "N/A":
                            self.assertNotIn(value, serialized, (name, field))
        for serialized in serialized_outputs:
            self.assertNotIn("SQL Parameters", serialized)
            self.assertNotIn("userAgent", serialized)
            self.assertNotIn("rsaKey", serialized)
        self.assertFalse(result["raw_request_ids_ip_session_sql_values_or_payloads_exported"])

    def test_export_is_deterministic_and_captures_source_limits(self):
        first = build("ip_activity.sanitized.json")
        second = build("ip_activity.sanitized.json")
        self.assertEqual(first, second)
        self.assertFalse(first["coverage"]["source_query_complete"])
        self.assertFalse(first["coverage"]["source_window_complete"])
        self.assertEqual(first["source_capture_scope"],
                         "input_capture_only_not_a_complete_source_window_claim")
        self.assertEqual(first["cross_source_request_union"],
                         "not_computed; captures may overlap")

    def test_tied_timestamps_are_marked_without_asserting_order(self):
        result = build("registration.sanitized.json")
        observations = [o for chain in result["chains"] for o in chain["observations"]]
        self.assertTrue(any(o["same_timestamp_tie"] for o in observations))
        self.assertTrue(all(o["request_link_basis"] == "same_request_id_co_observation_candidate"
                            for o in observations))


if __name__ == "__main__":
    unittest.main()
