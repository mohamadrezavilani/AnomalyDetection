"""Candidate freshness checks independent of PostgreSQL or detector usefulness."""
import copy
import unittest
import uuid
import io
import json
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from p24_foundation.behavior_binding import binding_reason, heads_digest, window_key, VERSION
from p24_foundation.behavior_store import persist_candidates
from p24_foundation.errors import FoundationError


class BehaviorBindingTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = str(uuid.uuid4())
        self.evaluation = str(uuid.uuid4())
        self.heads = {'request-a': uuid.uuid4(), 'request-b': uuid.uuid4()}
        self.digest = heads_digest(list(self.heads), self.heads)
        self.binding = dict(version=VERSION,evaluation_id=self.evaluation,start_ns='0',end_ns='300000000000',
            reference_snapshots=[self.snapshot],target_heads_sha256=self.digest)
        self.selections = {window_key('0','300000000000'):self.evaluation}

    def test_unchanged_evidence_stays_active(self):
        self.assertIsNone(binding_reason(self.binding,self.selections,[self.snapshot],self.digest))
        self.assertEqual(self.digest,heads_digest(list(reversed(self.heads)),self.heads))

    def test_added_or_corrected_request_invalidates_whole_partitioned_evaluation(self):
        changed=copy.copy(self.heads);changed['request-c']=uuid.uuid4()
        for digest in (heads_digest(list(changed),changed),heads_digest(['request-a'],self.heads),None):
            self.assertEqual(binding_reason(self.binding,self.selections,[self.snapshot],digest),'behavior_target_group_changed')

    def test_baseline_replacement_and_explicit_selection_invalidate_old_candidates(self):
        self.assertEqual(binding_reason(self.binding,self.selections,[str(uuid.uuid4())],self.digest),'behavior_reference_selection_changed')
        self.assertEqual(binding_reason(self.binding,{},[self.snapshot],self.digest),'behavior_evaluation_superseded')

    def test_malformed_binding_does_not_become_supported(self):
        self.assertEqual(binding_reason({},self.selections,[self.snapshot],self.digest),'behavior_binding_invalid')
        self.assertEqual(binding_reason(dict(self.binding,version='unreviewed'),self.selections,[self.snapshot],self.digest),'behavior_binding_invalid')

    def test_missing_request_support_is_not_silently_dropped(self):
        with self.assertRaisesRegex(FoundationError,'behavior_target_support_unavailable'):
            heads_digest(['request-missing'],self.heads)

    def test_publication_fence_rejects_before_any_findings_are_written(self):
        from contextlib import nullcontext
        store=Mock();store._lock=Mock();store.c.transaction.return_value=nullcontext()
        current=str(uuid.uuid4())
        with patch('p24_foundation.behavior_store.ObservationPublisher') as publisher:
            publisher.return_value._current.return_value=(uuid.UUID(current),7)
            with self.assertRaisesRegex(FoundationError,'stale_behavior_publication'):
                persist_candidates(store,target_spec={'publication_id':current},reference_specs=[{}],rank_cutoff='1/20',expected_generation=6)
        store.c.execute.assert_not_called()

    def test_persistence_requires_explicit_generation(self):
        with self.assertRaisesRegex(FoundationError,'invalid_behavior_publication_generation'):
            persist_candidates(Mock(),target_spec={},reference_specs=[{}],rank_cutoff='1/20',expected_generation=True)

    def test_demo_cannot_implicitly_write_candidates(self):
        from tools.detect_behavior import main
        output=io.StringIO()
        with redirect_stdout(output):
            result=main(['--demo','--persist-candidates','--expected-generation','1','--output','unused-private-report.json'])
        self.assertEqual(result,2)
        self.assertEqual(json.loads(output.getvalue())['error'],'behavior_persistence_arguments_required')
