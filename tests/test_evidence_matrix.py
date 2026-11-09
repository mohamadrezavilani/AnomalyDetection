import json
import unittest
from pathlib import Path

from p24_foundation.evidence_matrix import build_evidence_matrix

ROOT = Path(__file__).resolve().parents[1]


def catalog(name):
    return json.loads((ROOT / "catalogs" / name).read_text(encoding="utf-8"))


class EvidenceMatrixTests(unittest.TestCase):
    def test_exact_source_and_context_aligns_layers_without_merging_outcomes(self):
        result = build_evidence_matrix(catalog("request_chain_candidates.json"),
            catalog("action_api_reconciliation_candidates.json"),
            catalog("error_operation_candidates.json"))
        source = next(row for row in result["sources"] if row["source"] == "boundary.sanitized.json")
        pair = next(row for row in source["route_outcome_pairs"]
                    if row["client_http_endpoint"] == "Services.v3/ElectricBillsExport")
        self.assertEqual(pair["access_check_action"], "v3/ElectricBillsExport")
        self.assertEqual(pair["observed_chain_request_count"], 1)
        self.assertEqual(pair["chain_crosswalk_count_relation"], "equal_in_this_capture")
        layers = {(row["operation_role"], row["evidence_layer"], row["code"], row["recorded_outcome"])
                  for row in pair["outcome_observations"]}
        self.assertIn(("client_http", "platform_log", "GD2016", "failure"), layers)
        self.assertIn(("provider", "platform_log", "G00000", "success"), layers)
        self.assertIn(("provider", "provider_body", "GD2016", "failure"), layers)
        self.assertIn(("sql", "workflow_body", "GD2016", "unknown"), layers)
        self.assertFalse(pair["execution_or_causality_proven"])
        self.assertFalse(result["response_semantics_authoritative"])

    def test_device_register_versions_stay_distinct_and_api_conflict_survives(self):
        result = build_evidence_matrix(catalog("request_chain_candidates.json"),
            catalog("action_api_reconciliation_candidates.json"),
            catalog("error_operation_candidates.json"))
        source = next(row for row in result["sources"] if row["source"] == "registration.sanitized.json")
        pairs = {(row["client_http_endpoint"], row["access_check_action"]): row
                 for row in source["route_outcome_pairs"]}
        self.assertIn(("Core.v1/DeviceRegister", "v1/DeviceRegister"), pairs)
        self.assertIn(("Core.v2/DeviceRegister", "v2/DeviceRegister"), pairs)
        self.assertNotEqual(pairs[("Core.v1/DeviceRegister", "v1/DeviceRegister")]["client_http_endpoint"],
                            pairs[("Core.v2/DeviceRegister", "v2/DeviceRegister")]["client_http_endpoint"])
        self.assertEqual(pairs[("Core.v2/DeviceRegister", "v2/DeviceRegister")]["api_candidate_state"],
                         "request_name_match_version_or_path_unresolved")
        self.assertIn("/core.svc/v1/DeviceRegister", json.dumps(
            pairs[("Core.v2/DeviceRegister", "v2/DeviceRegister")]["api_route_candidates"]))

    def test_provider_only_ping_outcome_is_retained_without_client_link(self):
        result = build_evidence_matrix(catalog("request_chain_candidates.json"),
            catalog("action_api_reconciliation_candidates.json"),
            catalog("error_operation_candidates.json"))
        source = next(row for row in result["sources"] if row["source"] == "provider_ping.sanitized.json")
        ping = next(row for row in source["unpaired_outcome_observations"] if row["code"] == "GR0010")
        self.assertEqual(ping["operation_callpath"], "EwanoApi.Ping")
        self.assertEqual(ping["recorded_outcome"], "unknown")
        self.assertEqual(ping["link_state"], "no_client_endpoint_action_context_observed")
        self.assertEqual(ping["semantic_authority"], "unverified_candidate")

    def test_ambiguous_multi_endpoint_context_is_not_cross_product_joined(self):
        chains = {"sources": [{"locator": "x", "source_sha256": "h", "chains": [],
                               "request_projection_count": 0, "coverage": {}, "capture_finality": "unknown"}]}
        api = {"sources": [{"source": "x", "source_sha256": "h", "pairs": []}]}
        errors = {"sources": [{"locator": "x", "source_sha256": "h", "groups": [{
            "operation_role": "provider", "operation_callpath": "P", "code": "E1",
            "same_request_contexts": [{"client_http_endpoints": ["A", "B"],
                "access_check_actions": ["a", "b"], "distinct_request_count": 1}]
        }]}]}
        result = build_evidence_matrix(chains, api, errors)
        source = result["sources"][0]
        self.assertEqual(source["route_outcome_pairs"], [])
        self.assertEqual(source["ambiguous_outcome_context_count"], 1)

    def test_unmatched_source_hashes_do_not_join(self):
        chains = {"sources": [{"locator": "x", "source_sha256": "chain", "chains": [],
                               "request_projection_count": 0, "coverage": {}, "capture_finality": "unknown"}]}
        api = {"sources": [{"source": "x", "source_sha256": "other", "pairs": [{
            "client_http_endpoint": "A", "access_check_action": "a"}]}]}
        result = build_evidence_matrix(chains, api, {"sources": []})
        self.assertEqual(len(result["sources"]), 2)
        self.assertFalse(any(row["api_reconciliation_catalog_present"] is False for row in result["sources"]
                             if row["source_sha256"] == "other"))


if __name__ == "__main__":
    unittest.main()
