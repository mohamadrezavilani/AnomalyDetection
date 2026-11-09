"""Revision-aware deterministic identity contracts for proof groups."""
import unittest

from p24_foundation.investigation_links import _investigation_id, _proof_revision_state


class InvestigationLinkIdentityTests(unittest.TestCase):
    def test_exact_publication_and_revision_pair_is_stable_and_order_independent(self):
        pins=[dict(incident_id='incident-b',revision_id='revision-b'),
              dict(incident_id='incident-a',revision_id='revision-a')]
        identifier=_investigation_id('namespace-a','publication-a',pins)
        self.assertEqual(identifier,_investigation_id('namespace-a','publication-a',list(reversed(pins))))
        self.assertNotEqual(identifier,_investigation_id('namespace-a','publication-b',pins))
        self.assertNotEqual(identifier,_investigation_id('namespace-a','publication-a',[
            dict(incident_id='incident-a',revision_id='revision-a2'),pins[0]]))

    def test_proof_is_current_only_when_both_incident_pins_are_current(self):
        self.assertEqual(_proof_revision_state('a','ra','b','rb',{'a':'ra','b':'rb'}),'current')
        self.assertEqual(_proof_revision_state('a','ra','b','rb',{'a':'ra2','b':'rb'}),'historical')
        self.assertEqual(_proof_revision_state('a','ra','b','rb',{'a':'ra','b':'rb2'}),'historical')
        self.assertEqual(_proof_revision_state('a','ra','b','rb',{'a':'ra'}),'historical')
