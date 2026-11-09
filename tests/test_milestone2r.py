"""Causal, identity, counting and privacy oracles for the combined 2R milestone."""
import copy
import json
import unittest
import uuid
from dataclasses import replace

from p24_foundation.errors import FoundationError
from p24_foundation.investigation import request_card, scoped_outcome
from p24_foundation.outcomes import OutcomeRule, ScopedOutcomeResolver
from p24_foundation.reconstruction import reconstruct, select_events
from p24_foundation.time import parse_time
from p24_foundation.workflows import (DeliveryObservation, ExternalEvent, SelectedEvidence,
    StateContract, WorkflowState, reconcile_workflows)
from tests.helpers import TEST_KEYS, document, fixture, normalized


def token(kind, value):
    return TEST_KEYS.token("milestone2r", kind, value)


def ref(value):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "milestone2r:" + value))


def evidence(value, event=10, received=20, **kwargs):
    return SelectedEvidence(ref(value), "milestone2r", token("origin", value), event, received, **kwargs)


def event(value, identity="logical-A", **kwargs):
    base = ExternalEvent(ref(value), "issuer-A", "topic-A", "event-id", token("external_event", identity),
        "test_v1", "a" * 64, "schema.1", "verified", "verified", ref("assert:" + value), ref("fact:" + value))
    return replace(base, **kwargs)


def contract(**kwargs):
    base = StateContract("synthetic.1", (("received", "pending"), ("settled", "success"), ("failed", "failure")),
        (("received", "settled"), ("received", "failed")), ("settled", "failed"),
        ("provider",), "issuer-sequence", "synthetic:test-contract", "reviewed")
    return replace(base, **kwargs)


def state(value, key="settled", **kwargs):
    base = WorkflowState(ref(value), token("workflow", "A"), "synthetic.1", key, "provider",
        "accepted", "verified", "complete", issuer_sequence=1, sequence_domain="issuer-sequence",
        link_assertion_ref=ref("link:" + value), state_fact_ref=ref("state:" + value))
    return replace(base, **kwargs)


def reconcile(sources, events=(), deliveries=(), states=(), **kwargs):
    params = dict(namespace="milestone2r", event_cutoff_ns=100, knowledge_at_ns=1000, contracts=(contract(),))
    params.update(kwargs)
    return reconcile_workflows(sources, events, deliveries, states, **params)


class ScopedOutcomeContractTests(unittest.TestCase):
    def setUp(self):
        self.a = dict(code="GD1111", entry_id="A:1", source_sha256="a"*64, code_system="A",
            source_file="a.xlsx", definition_state="complete_definition", user_message_fa="تعریف الف")
        self.b = dict(self.a, entry_id="B:1", source_sha256="b"*64, code_system="B", user_message_fa="تعریف ب")
        self.rule = OutcomeRule("test", "1", "Provider.Operation", "provider", "provider_body", "Output.Status.Code",
            "GD1111", "failure", "synthetic:review", "A:1", "a"*64)
        self.scope = dict(endpoint="Provider.Operation", role="provider", layer="provider_body", path="Output.Status.Code")

    def test_duplicate_code_definitions_never_select_last_row(self):
        for records in ([self.a, self.b], [self.b, self.a]):
            resolved = ScopedOutcomeResolver(dict(records=records), rules=()).resolve("GD1111", **self.scope)
            self.assertIsNone(resolved["meaning_fa"])
            self.assertEqual(resolved["outcome"], "unknown")
            self.assertEqual(len(resolved["meaning_candidates"]), 2)

    def test_reviewed_exact_binding_selects_source_without_promoting_other_candidates(self):
        resolver = ScopedOutcomeResolver(dict(records=[self.a, self.b]), rules=(self.rule,))
        result = resolver.resolve("GD1111", **self.scope)
        self.assertEqual((result["outcome"], result["meaning_fa"]), ("failure", "تعریف الف"))
        for field, changed in (("endpoint", "Provider.Other"), ("role", "sql"), ("layer", "workflow_body"), ("path", "Input.Status.Code")):
            with self.subTest(field=field):
                self.assertEqual(resolver.resolve("GD1111", **dict(self.scope, **{field:changed}))["outcome"], "unknown")

    def test_rule_revision_boundaries_and_overlap_are_explicit(self):
        first = replace(self.rule, effective_from_ns=10, effective_until_ns=20)
        second = replace(self.rule, revision="2", outcome="success", effective_from_ns=20)
        resolver = ScopedOutcomeResolver(dict(records=[self.a]), rules=(first,second))
        self.assertEqual(resolver.resolve("GD1111", at_ns=19, **self.scope)["outcome"], "failure")
        self.assertEqual(resolver.resolve("GD1111", at_ns=20, **self.scope)["outcome"], "success")
        self.assertEqual(resolver.resolve("GD1111", **self.scope)["outcome"], "unknown")
        overlapping = ScopedOutcomeResolver(dict(records=[self.a]), rules=(self.rule,second))
        self.assertEqual(overlapping.resolve("GD1111", at_ns=20, **self.scope)["interpretation_state"], "conflicting_rules")

    def test_missing_binding_source_abstains_and_policy_digest_changes(self):
        good = ScopedOutcomeResolver(dict(records=[self.a]), rules=(self.rule,))
        changed = ScopedOutcomeResolver(dict(records=[self.b]), rules=(self.rule,))
        self.assertNotEqual(good.digest, changed.digest)
        self.assertEqual(changed.resolve("GD1111", **self.scope)["interpretation_state"], "binding_source_unavailable")
        self.assertEqual(changed.resolve("GD1111", **self.scope)["outcome"], "unknown")

    def test_real_provider_and_sql_layers_stay_distinct(self):
        rows=normalized(fixture("boundary.sanitized.json").records)
        provider=next(e["descriptor"] for e in rows if e["descriptor"]["role"]=="provider")
        body=next(o for o in provider["outcomes"] if o["layer"]=="provider_body")
        self.assertEqual(body["interpretation_state"],"reviewed_sample_binding")
        self.assertEqual(provider["operation_outcome"],"failure")
        workflow=[o for e in rows for o in e["descriptor"]["outcomes"] if o["layer"]=="workflow_body" and o["code"]=="GD2016"][0]
        self.assertEqual(workflow["outcome"],"unknown");self.assertIsNone(workflow["meaning_fa"])

    def test_read_view_filters_extra_candidate_and_rule_fields(self):
        row=dict(code="GD1111",meaning_candidates=[dict(entry_id="A:1",raw="SECRET")],
                 applied_rule=dict(id="test",revision="1",raw="SECRET"))
        self.assertNotIn("SECRET",json.dumps(scoped_outcome(row)))


class LifecycleLedgerTests(unittest.TestCase):
    def summarize(self, rows, cutoff="2026-10-20T07:45:00Z"):
        return reconstruct(select_events(normalized(rows),parse_time(cutoff).epoch_ns))

    def verification_rows(self):
        rows=[document(rid="verify",oid="http",path="Core.v1/LoginByOTP")]
        for name in ("oneTimePasswordValidate","oneTimePasswordConsume","userSessionVerify"):
            proc="ud_prc_"+name
            rows.append(document(rid="verify",oid=proc,path="DBPath.app."+proc,
                message="(Command Text: "+proc+")(Code: 1)(Result: Ok)(SQL Parameters: @session=SESSION_A @otpCode=SECRET @identifier=PRIVATE_PHONE)"))
        return rows

    def test_markers_have_source_references_ties_and_no_credential_values(self):
        summary=self.summarize(self.verification_rows())[0]
        life=request_card(summary)["lifecycle"]
        self.assertEqual(len(life["markers"]),3)
        self.assertTrue(all(m["source_event_version_id"] and m["timestamp_tied"] for m in life["markers"]))
        self.assertEqual(life["flow_evidence_state"],"verification_sql_chain_observed")
        self.assertEqual(life["authentication_state"],"not_established")
        self.assertNotIn("SECRET",json.dumps(life));self.assertNotIn("PRIVATE_PHONE",json.dumps(life))

    def test_same_session_across_ip_changes_does_not_merge_request_flows(self):
        rows=self.verification_rows()
        rows[-1]["_source"]["RequestID"]="different-request"
        rows[-1]["_source"]["IP"]="203.0.113.1"
        results=self.summarize(rows)
        self.assertEqual(len({r["session_key"] for r in results}),1)
        self.assertFalse(any(request_card(r)["lifecycle"]["sql_otp_verification_chain_observed"] for r in results))

    def test_registration_missing_session_stays_unassigned(self):
        results=self.summarize(fixture("registration.sanitized.json").records)
        for row in results:
            life=request_card(row)["lifecycle"]
            self.assertEqual(life["flow_evidence_state"],"session_creation_procedure_observed")
            self.assertIsNone(life["assigned_session_key"])
            self.assertEqual(life["account_binding"],"not_available")

    def test_late_marker_does_not_change_earlier_cutoff_and_failed_client_is_separate(self):
        rows=self.verification_rows();rows[-1]["_source"]["@timestamp"]="2026-10-20T07:30:01Z"
        rows[0]["_source"]["message"]="POST https://fixture.invalid/login HTTP/1.1 (G00002 | Unknown)"
        early=request_card(self.summarize(rows,"2026-10-20T07:30:00Z")[0])["lifecycle"]
        later=request_card(self.summarize(rows)[0])["lifecycle"]
        self.assertFalse(early["sql_otp_verification_chain_observed"])
        self.assertTrue(later["sql_otp_verification_chain_observed"])
        self.assertEqual(later["observed_client_result"],"unknown")
        self.assertEqual(later["authentication_state"],"not_established")

    def test_repeated_operations_do_not_multiply_lifecycle_markers(self):
        summary=self.summarize(self.verification_rows())[0]
        before=request_card(summary)["lifecycle"]
        summary["operations"]*=2
        self.assertEqual(request_card(summary)["lifecycle"],before)


class WorkflowReconciliationTests(unittest.TestCase):
    def test_contradictory_delivery_assertions_do_not_multiply_source_observations(self):
        delivery=DeliveryObservation(ref("a"),"http_accepted",token("attempt","same"),token("request","same"),True,"issuer-A","callback")
        result=reconcile([evidence("a")],deliveries=[delivery,replace(delivery,acknowledgement="http_rejected")])
        self.assertEqual(result["delivery_observation_count"],1)
        self.assertEqual(result["verified_delivery_attempt_count"],1)
        self.assertEqual(result["delivery_observations"][0]["acknowledgement"],"conflicting")
        self.assertEqual(result["verified_delivery_attempts"][0]["acknowledgement"],"conflicting")

    def test_conflicting_attempt_ids_in_one_source_remain_ambiguous(self):
        delivery=DeliveryObservation(ref("a"),"http_accepted",token("attempt","one"),None,True,"issuer-A","callback")
        result=reconcile([evidence("a")],deliveries=[delivery,replace(delivery,attempt_token=token("attempt","two"))])
        self.assertEqual(result["delivery_observation_count"],1)
        self.assertEqual(result["verified_delivery_attempt_count"],0)
        self.assertEqual(result["delivery_observations"][0]["attempt_identity_state"],"ambiguous")

    def test_multiple_deliveries_one_logical_event_keep_separate_units(self):
        sources=[evidence("a"),evidence("b")]
        deliveries=[DeliveryObservation(ref(v),"http_accepted",token("attempt",v),token("request",v),True,"issuer-A","callback") for v in ("a","b")]
        result=reconcile(sources,[event("a"),event("b")],deliveries)
        self.assertEqual((result["logical_event_count"],result["delivery_observation_count"],result["verified_delivery_attempt_count"],result["distinct_transport_request_count"]),(1,2,2,2))
        self.assertEqual(result["state_publications"],[])
        self.assertFalse(result["acknowledgement_establishes_business_success"])

    def test_same_content_different_verified_ids_is_two_events(self):
        result=reconcile([evidence("a"),evidence("b")],[event("a","first"),event("b","second")])
        self.assertEqual(result["logical_event_count"],2)

    def test_issuer_domain_and_key_version_prevent_identity_collisions(self):
        sources=[evidence(str(i)) for i in range(4)]
        events=[event("0"),event("1",issuer="issuer-B"),event("2",identifier_domain="other"),event("3",token_key_version="v2")]
        self.assertEqual(reconcile(sources,events)["logical_event_count"],4)

    def test_unverified_external_evidence_is_not_promoted_by_transport_success(self):
        result=reconcile([evidence("a")],[event("a",authenticity_state="unverified")],[DeliveryObservation(ref("a"),"http_accepted")])
        self.assertEqual(result["logical_event_count"],0)
        self.assertEqual(result["unverified_event_observations"],1)
        self.assertEqual(result["verified_delivery_attempt_count"],0)
        self.assertEqual(result["delivery_observations"][0]["logical_event_link_state"],"unresolved")

    def test_conflicting_payload_revisions_do_not_last_arrival_win(self):
        result=reconcile([evidence("a"),evidence("b")],[event("a"),event("b",content_sha256="b"*64)])
        self.assertEqual(result["logical_event_count"],1)
        self.assertEqual(result["logical_events"][0]["state"],"conflicting_revisions")
        self.assertEqual(result["logical_events"][0]["revision_count"],2)

    def test_accepted_delivery_and_failed_business_state_coexist(self):
        result=reconcile([evidence("a")],[event("a")],[DeliveryObservation(ref("a"),"http_accepted")],[state("a","failed")])
        self.assertEqual(result["delivery_observations"][0]["acknowledgement"],"http_accepted")
        self.assertEqual(result["state_publications"][0]["published_state"],"failure")

    def test_subject_results_do_not_become_workflow_success(self):
        states=[state("a",subject_domain="bill",subject_token=token("subject","1")),
                state("b","failed",subject_domain="bill",subject_token=token("subject","2"))]
        result=reconcile([evidence("a"),evidence("b")],states=states)
        self.assertEqual({r["published_state"] for r in result["state_publications"]},{"success","failure"})
        self.assertTrue(all(r["state_scope"]=="subject" for r in result["state_publications"]))

    def test_event_cutoff_exclusive_receipt_cutoff_inclusive_and_late_receipts(self):
        sources=[evidence("early",event=99,received=1000),evidence("edge",event=100),evidence("late",received=1001)]
        result=reconcile(sources,[event("early"),event("edge"),event("late")])
        self.assertEqual(result["logical_event_count"],1)
        self.assertEqual(result["excluded_evidence_counts"]["at_or_after_event_cutoff"],1)
        self.assertEqual(result["excluded_evidence_counts"]["not_yet_known"],1)
        newer=reconcile(sources,[event("early"),event("edge"),event("late")],knowledge_at_ns=1001)
        self.assertEqual(newer["logical_event_count"],1)
        self.assertEqual(newer["logical_events"][0]["source_observation_count"],2)

    def test_conflicting_selected_origin_versions_are_excluded(self):
        a=evidence("a");b=replace(evidence("b"),origin_key=a.origin_key)
        result=reconcile([a,b],[event("a"),event("b")])
        self.assertEqual(result["logical_event_count"],0)
        self.assertEqual(result["excluded_evidence_counts"]["conflicting_origin_versions"],2)

    def test_verified_sequence_orders_states_while_timestamps_alone_do_not(self):
        sources=[evidence("a",event=80),evidence("b",event=10)]
        states=[state("a","received",issuer_sequence=1),state("b","settled",issuer_sequence=2)]
        result=reconcile(sources,states=states)["state_publications"][0]
        self.assertEqual((result["published_state"],result["resolution_basis"]),("success","verified_issuer_sequence"))
        unordered=[replace(s,issuer_sequence=None) for s in states]
        result=reconcile(sources,states=unordered)["state_publications"][0]
        self.assertEqual(result["published_state"],"conflicting")

    def test_same_sequence_disagreement_and_terminal_reversal_conflict(self):
        sources=[evidence("a"),evidence("b")]
        for states in ([state("a","received"),state("b","settled")],
                       [state("a","settled",issuer_sequence=1),state("b","received",issuer_sequence=2)]):
            self.assertEqual(reconcile(sources,states=states)["state_publications"][0]["published_state"],"conflicting")

    def test_unknown_contract_partial_state_or_missing_fact_cannot_publish(self):
        sources=[evidence("a")]
        for row in (state("a",contract_version="unknown"),state("a",completeness="partial"),state("a",state_fact_ref=None)):
            result=reconcile(sources,states=[row])
            self.assertEqual(result["state_publications"],[])
            self.assertEqual(result["unresolved_state_observations"],1)
        result=reconcile(sources,states=[state("a")],contracts=(replace(contract(),review_state="unreviewed"),))
        self.assertEqual(result["state_publications"],[])

    def test_input_shuffle_duplicate_replay_and_existing_projection_are_stable(self):
        sources=[evidence("a"),evidence("b")];events=[event("a"),event("b")]
        first=reconcile(sources,events)
        self.assertEqual(first,reconcile(list(reversed(sources))*2,list(reversed(events))*2))
        original=copy.deepcopy(first)
        reconcile(sources+[evidence("c")],events+[event("c",content_sha256="b"*64)])
        self.assertEqual(first,original)

    def test_cross_namespace_and_conflicting_source_metadata_are_rejected(self):
        with self.assertRaises(FoundationError):reconcile([replace(evidence("a"),namespace="OTHER")])
        with self.assertRaises(FoundationError):reconcile([evidence("a"),replace(evidence("a"),received_at_ns=2000)])

    def test_one_source_with_conflicting_logical_identities_is_not_two_events(self):
        result=reconcile([evidence("a")],[event("a","first"),event("a","second")])
        self.assertEqual(result["logical_event_count"],0)
        self.assertEqual(result["conflicting_external_identity_sources"],[ref("a")])


if __name__ == "__main__":
    unittest.main()
