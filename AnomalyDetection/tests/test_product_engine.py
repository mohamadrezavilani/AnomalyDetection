"""Only completeness of the actual target can qualify its current evidence."""
from unittest.mock import patch
import unittest

from anomaly_detection.product_engine import evaluate_job
from anomaly_detection import FIVE_NS
from tests.test_product_models import example,SERVICE


class EvidenceTests(unittest.TestCase):
    def setup_target(self, *, qualified=True,revision=1,expected_count=1):
        context,_=example(current=expected_count);target=context['target_ns'];request='1'*64;anchor='ba1:'+'2'*64
        event={'request_key':request,'anchor_key':anchor,'anchor_ns':target+1,'revision':1,'root_call':SERVICE}
        context['events']=[event]
        rows=[{'request_key':request,'at_ns':target+1,'service_path':SERVICE,'details':{'source_present':True,
            'quality':{'evidence_available':qualified},'semantic':{'state':'active','revision':revision,'anchor_key':anchor}}}]
        class Store:
            def history(self,_):return []
            def excluded_windows(self,_):return set()
            def details(self,_):return rows,False # Past detail page is truncated.
            def complete(self,job,ctx,decisions,now):return ctx
        with patch('anomaly_detection.product_engine.evaluate',return_value=[]):
            return evaluate_job(Store(),{'session_key':context['session_key'],'target_ns':target},context,0)
    def test_busy_past_does_not_hide_complete_target_evidence(self):
        result=self.setup_target();self.assertTrue(result['evidence_verified']);self.assertTrue(result['details_history_truncated'])
    def test_unqualified_origin_does_not_verify_target(self):
        self.assertFalse(self.setup_target(qualified=False)['evidence_verified'])
    def test_stale_revision_does_not_verify_newer_input(self):
        self.assertFalse(self.setup_target(revision=2)['evidence_verified'])
    def test_incomplete_event_set_cannot_verify_a_larger_semantic_count(self):
        self.assertFalse(self.setup_target(expected_count=2)['evidence_verified'])


if __name__=='__main__':unittest.main()
