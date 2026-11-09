"""Finite native tests for evidence-backed incident links and priority."""
import tempfile
import unittest
import uuid
from pathlib import Path

from p24_foundation.errors import FoundationError
from p24_foundation.incidents import IncidentRegistry
from p24_foundation.investigation_links import InvestigationRegistry
from p24_foundation.publication import ObservationPublisher
from p24_foundation.store import FoundationStore,initialize,jsonb
from tests.helpers import TEST_KEYS,batch,document,issue_test_access_token,test_access_policy


class InvestigationLinksPostgresTests(unittest.TestCase):
    connection=None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest('disposable PostgreSQL configuration required')
        initialize(cls.connection)

    def setUp(self):
        self.c=self.connection;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.namespace='links_'+uuid.uuid4().hex
        self.token=issue_test_access_token(self.namespace,roles=('investigator','incident_reviewer'))
        self.store=FoundationStore(self.c,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
        self.pub=ObservationPublisher(self.store);self.incidents=IncidentRegistry(self.store);self.registry=InvestigationRegistry(self.store)
        source=self.store.ingest(batch([document(rid='A',oid='A'),document(rid='B',oid='B',at='2026-10-20T07:31:00Z')]),
            source_key='fixture',interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:35:00Z',
            observed_at='2026-10-20T07:40:00Z',receive_time_basis='synthetic_fixture')
        draft=self.pub.prepare([source['snapshot_id']],event_cutoff='2026-10-20T07:35:00Z',knowledge_at='2026-10-20T07:40:00Z',
            mode='design_fixture',expected_generation=self.pub._current()[1])
        self.publication=self.pub.publish(draft['publication_id'])['publication_id']
        self.heads=self.pub._heads(self.publication)
        self.session=TEST_KEYS.token(self.namespace,'session','SESSION_A')

    def _finding(self,request,pattern):
        run=self.heads[self.store.request_key(request)];detector=uuid.uuid4();fid=uuid.uuid4()
        self.c.execute("""INSERT INTO p24_next.detector_run(namespace_id,detector_run_id,run_id,detector_key,detector_version,
            target_start,target_end,status,applicable_units,evaluated_units,unsupported_units)
            VALUES(%s,%s,%s,'fixture','fixture.1','2026-10-20T07:00Z','2026-10-20T08:00Z','complete',1,1,0)""",
            (self.store.namespace_id,detector,run))
        self.c.execute("""INSERT INTO p24_next.finding(namespace_id,finding_id,detector_run_id,finding_key,scope_kind,subject_key,
            score_numeric,score_unit,evidence_manifest_sha256,measurements,assessment_state)
            VALUES(%s,%s,%s,%s,'session',%s,12,'fixture-z',%s,%s,'supported_deviation')""",
            (self.store.namespace_id,fid,detector,pattern,self.session,'b'*64,jsonb({})))
        self.c.execute('INSERT INTO p24_next.finding_request VALUES(%s,%s,%s,%s,%s,%s)',
            (self.store.namespace_id,fid,run,self.store.request_key(request),'support',jsonb({'fixture':True})))
        return fid

    def _incident(self,request,pattern):
        return self.incidents.refresh(self.publication,scope_kind='session',subject_key=self.session,
            pattern_key=pattern,finding_ids=[self._finding(request,pattern)])

    def test_shared_request_creates_symmetric_revision_pinned_proof(self):
        left=self._incident('A','request-volume');right=self._incident('A','session-purpose')
        result=self.registry.link_shared_requests(self.publication,left['incident_id'],right['incident_id'],access_token=self.token)
        self.assertEqual(result['basis'],'shared_request');self.assertEqual(result['shared_request_count'],1)
        saved=self.registry.read(result['investigation_id'],access_token=self.token)
        self.assertEqual(len(saved['links']),2)
        self.assertTrue(all(x['shared_request_count']==1 and x['basis']=='shared_request' for x in saved['links']))
        self.assertIn('no common identity or root cause inferred',saved['claim'])
        attached=self.registry.for_incident(left['incident_id'],access_token=self.token)
        self.assertEqual(attached['total'],1);self.assertEqual(attached['items'][0]['shared_request_count'],1)
        queue=self.registry.list_for_publication(self.publication,access_token=self.token)
        self.assertEqual(queue['total'],1);self.assertEqual(len(queue['items'][0]['links']),2)
        reused=self.registry.link_shared_requests(self.publication,left['incident_id'],right['incident_id'],access_token=self.token)
        self.assertEqual(result['proof_sha256'],reused['proof_sha256'])

    def test_new_incident_revision_creates_a_distinct_proof_without_rewriting_history(self):
        left=self._incident('A','request-volume');right=self._incident('A','session-purpose')
        first=self.registry.link_shared_requests(self.publication,left['incident_id'],right['incident_id'],access_token=self.token)
        old_group=self.registry.read(first['investigation_id'],access_token=self.token)
        next_finding=self._finding('A','request-volume')
        revised=self.incidents.refresh(self.publication,scope_kind='session',subject_key=self.session,
            pattern_key='request-volume',finding_ids=[next_finding],expected_generation=1)
        self.assertEqual(revised['incident_id'],left['incident_id'])
        self.assertNotEqual(revised['revision_id'],left['revision_id'])
        second=self.registry.link_shared_requests(self.publication,revised['incident_id'],right['incident_id'],access_token=self.token)
        self.assertNotEqual(first['investigation_id'],second['investigation_id'])
        refreshed_old_group=self.registry.read(first['investigation_id'],access_token=self.token)
        expected_old={left['incident_id']:left['revision_id'],right['incident_id']:right['revision_id']}
        self.assertEqual({item['incident_id']:item['incident_revision_id'] for item in old_group['links']},expected_old)
        # Proof order follows UUIDs; compare both identities and every pinned field.
        pinned=lambda group:{item['incident_id']:{k:v for k,v in item.items() if k!='revision_state'}
                             for item in group['links']}
        self.assertEqual(pinned(refreshed_old_group),pinned(old_group))
        self.assertTrue(all(item['revision_state']=='historical' for item in refreshed_old_group['links']))
        new_group=self.registry.read(second['investigation_id'],access_token=self.token)
        self.assertEqual({item['incident_id']:item['incident_revision_id'] for item in new_group['links']},
                         {left['incident_id']:revised['revision_id'],right['incident_id']:right['revision_id']})
        self.assertTrue(all(item['revision_state']=='current' for item in new_group['links']))
        self.assertEqual(self.registry.list_for_publication(self.publication,access_token=self.token)['total'],2)
        repeated=self.registry.link_shared_requests(self.publication,revised['incident_id'],right['incident_id'],access_token=self.token)
        self.assertEqual(second['investigation_id'],repeated['investigation_id'])
        self.assertEqual(second['proof_sha256'],repeated['proof_sha256'])

    def test_common_ip_session_or_time_without_request_overlap_is_not_link_proof(self):
        left=self._incident('A','request-volume');right=self._incident('B','session-purpose')
        with self.assertRaisesRegex(FoundationError,'investigation_shared_request_proof_missing'):
            self.registry.link_shared_requests(self.publication,left['incident_id'],right['incident_id'],access_token=self.token)

    def test_priority_is_explicit_pinned_and_invalidated_by_new_incident_revision(self):
        incident=self._incident('A','request-volume')
        saved=self.registry.decide_priority(incident['incident_id'],priority='medium',impact='single_request',
            urgency='routine',confidence='high',reason_key='operator_assessment',expected_generation=0,access_token=self.token)
        self.assertEqual(saved['priority'],'medium');self.assertFalse(saved['impact_factors']['detector_score_used'])
        current=self.registry.priority(incident['incident_id'],access_token=self.token)
        self.assertEqual(current['priority'],'medium');self.assertFalse(current['stale'])
        with self.assertRaisesRegex(FoundationError,'stale_priority_generation'):
            self.registry.decide_priority(incident['incident_id'],priority='high',impact='service_wide',urgency='active',
                confidence='high',reason_key='service_impact',expected_generation=0,access_token=self.token)
        self.incidents.refresh(self.publication,scope_kind='session',subject_key=self.session,pattern_key='request-volume',
            finding_ids=[self._finding('B','request-volume')],expected_generation=1)
        outdated=self.registry.priority(incident['incident_id'],access_token=self.token)
        self.assertTrue(outdated['stale']);self.assertEqual(outdated['priority'],'unrated')
        history=self.registry.priority_history(incident['incident_id'],access_token=self.token)
        self.assertEqual(history['total'],1);self.assertEqual(history['items'][0]['state'],'stale')
        old_status=self.incidents.revision_status(incident['incident_id'],incident['revision_id'],access_token=self.token)
        current_incident=self.incidents.read(self.publication,incident['incident_id'],access_token=self.token)
        current_status=self.incidents.revision_status(incident['incident_id'],current_incident['revision_id'],access_token=self.token)
        self.assertFalse(old_status['is_latest']);self.assertTrue(current_status['is_latest'])
        with self.assertRaisesRegex(FoundationError,'stale_priority_evidence'):
            self.registry.decide_priority(incident['incident_id'],priority='high',impact='single_request',
                urgency='routine',confidence='high',reason_key='correction',expected_generation=1,
                expected_revision_id=saved['evidence_revision_id'],expected_evidence_sha256=saved['evidence_sha256'],
                access_token=self.token)
        new_preview=self.registry.preview_priority(incident['incident_id'],priority='medium',impact='single_request',
            urgency='routine',confidence='high',reason_key='correction',access_token=self.token)
        self.registry.decide_priority(incident['incident_id'],priority='medium',impact='single_request',urgency='routine',
            confidence='high',reason_key='correction',expected_generation=new_preview['decision_generation'],
            expected_revision_id=new_preview['evidence_revision_id'],expected_evidence_sha256=new_preview['evidence_sha256'],
            access_token=self.token)
        first=self.registry.priority_history(incident['incident_id'],limit=1,access_token=self.token)
        self.assertEqual(first['total'],2);self.assertEqual(first['items'][0]['state'],'current');self.assertIsNotNone(first['next_cursor'])
        second=self.registry.priority_history(incident['incident_id'],limit=1,cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(second['items'][0]['state'],'superseded')
        with self.assertRaisesRegex(FoundationError,'invalid_page_cursor'):
            self.registry.priority_history(incident['incident_id'],limit=1,cursor=first['next_cursor']+'x',access_token=self.token)
        with self.assertRaisesRegex(FoundationError,'invalid_priority_decision'):
            self.registry.decide_priority(incident['incident_id'],priority='critical',impact='known',urgency='routine',
                confidence='high',reason_key='operator_assessment',expected_generation=1,access_token=self.token)
