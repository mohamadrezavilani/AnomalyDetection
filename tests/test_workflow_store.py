"""Native PostgreSQL probes using synthetic, explicitly trusted source facts."""
import copy
import hashlib
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import psycopg

from p24_foundation.errors import FoundationError
from p24_foundation.publication import ObservationPublisher
from p24_foundation.store import FoundationStore, initialize, jsonb
from p24_foundation.workflow_store import WorkflowStore, EventClaim, DeliveryClaim, StateClaim
from p24_foundation.workflows import StateContract
from tests.helpers import TEST_KEYS, batch, document, issue_test_access_token, test_access_policy


class WorkflowPostgresTests(unittest.TestCase):
    connection = None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:
            raise unittest.SkipTest('disposable PostgreSQL configuration required')
        initialize(cls.connection)

    def setUp(self):
        self.c = self.connection
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.namespace = 'workflow_' + uuid.uuid4().hex
        self.token = issue_test_access_token(self.namespace)
        self.store = FoundationStore(self.c, TEST_KEYS, self.namespace, Path(self.tmp.name)/'vault',
                                     access_policy=test_access_policy(self.namespace))
        self.w = WorkflowStore(self.store); self.pub = ObservationPublisher(self.store)
        self.contract = StateContract('synthetic-contract.1',
            (('pending','pending'),('success','success'),('failure','failure')),
            (('pending','success'),('pending','failure')),('success','failure'),('provider',),
            'synthetic-sequence','synthetic:reviewed-test','reviewed')
        self.rows = [document(rid='transport-'+str(i),oid='source-'+str(i),session='N/A',ip='N/A',
            path='EwanoApi.Ping Line:262',at='2026-10-20T07:30:0'+str(i)+'Z',
            message='https://fixture.invalid/ping (G00000 | successful)') for i in range(2)]

    def ingest(self, rows=None, source='synthetic-source', at='2026-10-20T07:40:00Z'):
        return self.store.ingest(batch(self.rows if rows is None else rows),source_key=source,
            interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z',
            observed_at=at,receive_time_basis='synthetic_fixture')

    def base(self, sources, known='2026-10-20T07:50:00Z', mode='design_fixture'):
        return self.store.project([s['snapshot_id'] for s in sources],event_cutoff='2026-10-20T07:40:00Z',
                                  knowledge_at=known,mode=mode)['run_id']

    def fact(self, version, kind, value, domain=None):
        key = uuid.uuid4()
        self.c.execute('''INSERT INTO p24_next.source_event_fact(namespace_id,fact_id,event_version_id,
            fact_key,field_path,direction,sensitivity,public_value,equality_token,token_key_version,
            extraction_version,completeness) VALUES(%s,%s,%s,%s,%s,'metadata',%s,%s,%s,%s,'synthetic-trusted-test.1','complete')''',
            (self.store.namespace_id,key,uuid.UUID(version),kind,'synthetic.'+kind,
             'personal' if domain else 'operational',None if domain else jsonb(value),
             TEST_KEYS.token(self.namespace,domain,value) if domain else None,TEST_KEYS.version if domain else None))
        return str(key)

    def plan(self, base, *, digest=None, subjects=('A','B'), states=('success','failure'), sequence=False):
        versions = [str(r[0]) for r in self.c.execute('''SELECT e.event_version_id FROM p24_next.projection_event p
            JOIN p24_next.event_version e USING(namespace_id,event_version_id) WHERE p.namespace_id=%s AND p.run_id=%s
            AND p.selection_state='selected' ORDER BY e.source_time_epoch_ns''',(self.store.namespace_id,uuid.UUID(base))).fetchall()]
        events=[];deliveries=[];observations=[]
        for i,v in enumerate(versions):
            identity=self.fact(v,'external_event_identity','same-logical-event','external_event')
            content=self.fact(v,'logical_event_content_digest',(digest or ['a'*64]*len(versions))[i])
            events.append(EventClaim(v,identity,content,'synthetic-provider','notice','synthetic-event-id','schema.1','verified','verified'))
            ack=self.fact(v,'delivery_acknowledgement','http_accepted')
            attempt=self.fact(v,'delivery_attempt_identity','attempt-'+str(i),'delivery')
            deliveries.append(DeliveryClaim(v,ack,attempt,'synthetic-provider','synthetic-attempt',True))
            workflow=self.fact(v,'workflow_identifier','same-workflow','workflow')
            state=self.fact(v,'workflow_state',states[i])
            subject=self.fact(v,'workflow_subject',subjects[i],'subject') if subjects[i] else None
            seq=self.fact(v,'issuer_sequence',i) if sequence else None
            observations.append(StateClaim(v,workflow,state,self.contract.version,'accepted','verified',
                                          'synthetic-subject' if subject else None,subject,seq))
        return dict(events=events,deliveries=deliveries,states=observations,contracts=(self.contract,))

    def prepare(self, sources, run=None, known='2026-10-20T07:50:00Z'):
        return self.pub.prepare([s['snapshot_id'] for s in sources],event_cutoff='2026-10-20T07:40:00Z',
            knowledge_at=known,mode='design_fixture',expected_generation=self.pub._current()[1],workflow_run_id=run)

    def test_native_roundtrip_deduplicates_event_but_preserves_subject_and_delivery_units(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base)
        saved=self.w.project(base,**plan);r=saved['result']
        self.assertEqual((r['logical_event_count'],r['delivery_observation_count'],r['verified_delivery_attempt_count'],r['distinct_transport_request_count']),(1,2,2,2))
        self.assertEqual({s['published_state'] for s in r['state_publications']},{'success','failure'})
        self.assertEqual(self.w.project(base,**plan),saved)
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.foundation_workflow_run WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(1,))
        published=self.pub.publish(self.prepare([source],saved['run_id'])['publication_id'])['publication_id']
        page=WorkflowStore(self.store).for_publication(published,access_token=self.token)
        self.assertEqual(page['result']['state_publication_count'],2)
        self.assertEqual(page['result_sha256'],saved['result_sha256'])
        state=page['result']['state_publications'][0]
        detail=self.w.state_evidence(published,state['state_publication_id'],access_token=self.token)
        self.assertEqual(detail['total_observations'],1)
        self.assertIn(detail['items'][0]['state_fact_id'],{s.state_fact_id for s in plan['states']})
        self.assertEqual(detail['items'][0]['source_role'],'provider')
        with psycopg.connect(self.c.info.dsn,password=self.c.info.password,autocommit=True) as connection:
            reopened=FoundationStore(connection,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
            self.assertEqual(WorkflowStore(reopened).for_publication(published,access_token=self.token)['result_sha256'],saved['result_sha256'])

    def test_provider_evidence_without_requestid_remains_visible_without_fabricated_transport(self):
        rows=copy.deepcopy(self.rows)
        for row in rows:row['_source']['RequestID']='N/A'
        source=self.ingest(rows);base=self.base([source]);saved=self.w.project(base,**self.plan(base))
        self.assertEqual(saved['result']['logical_event_count'],1)
        self.assertEqual(saved['result']['delivery_observation_count'],2)
        self.assertEqual(saved['result']['distinct_transport_request_count'],0)
        p=self.pub.publish(self.prepare([source],saved['run_id'])['publication_id'])['publication_id']
        state=self.w.for_publication(p,access_token=self.token)['result']['state_publications'][0]
        self.assertIsNone(self.w.state_evidence(p,state['state_publication_id'],access_token=self.token)['items'][0]['request_key'])

    def test_unknown_state_is_retained_but_not_added_to_known_publication_support(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base,subjects=(None,None),states=('success','not_in_contract'))
        r=self.w.project(base,**plan)['result']
        self.assertEqual(r['unresolved_state_observations'],1)
        self.assertEqual(r['state_publications'][0]['observation_count'],1)
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.workflow_state_observation WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(2,))

    def test_failure_after_state_writes_rolls_back_and_retry_is_complete(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base)
        from p24_foundation.workflows import reconcile_workflows
        validation=reconcile_workflows((),namespace=self.namespace,event_cutoff_ns=0,knowledge_at_ns=0,contracts=(self.contract,))
        with patch('p24_foundation.workflow_store.reconcile_workflows',side_effect=[validation,RuntimeError('synthetic-interruption')]):
            with self.assertRaisesRegex(RuntimeError,'synthetic-interruption'):self.w.project(base,**plan)
        for table in ('foundation_workflow_run','workflow_state_observation','business_workflow','foundation_workflow_contract'):
            self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.'+table+' WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(0,))
        self.assertEqual(self.w.project(base,**plan)['result']['logical_event_count'],1)

    def test_conflicting_payload_revisions_are_retained_without_last_write_wins(self):
        source=self.ingest();base=self.base([source]);r=self.w.project(base,**self.plan(base,digest=['a'*64,'b'*64]))['result']
        self.assertEqual(r['logical_events'][0]['state'],'conflicting_revisions')
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.external_event_revision WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(2,))

    def test_invalid_source_fact_rolls_back_contract_and_entire_projection(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base)
        plan['events'][0]=replace(plan['events'][0],identity_fact_id=plan['events'][1].identity_fact_id)
        with self.assertRaisesRegex(FoundationError,'workflow_fact_source_or_kind_mismatch'):
            self.w.project(base,**plan)
        for table in ('foundation_workflow_run','foundation_workflow_contract','workflow_state_observation','external_event_revision'):
            self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.'+table+' WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(0,))

    def test_unverified_claims_cannot_publish_business_success(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base)
        plan['events']=[replace(x,authenticity_state='unverified') for x in plan['events']]
        plan['states']=[replace(x,authenticity_state='unverified') for x in plan['states']]
        r=self.w.project(base,**plan)['result']
        self.assertEqual(r['logical_event_count'],0);self.assertEqual(r['state_publications'],[])
        self.assertEqual(r['unverified_event_observations'],2)
        self.assertEqual(r['unresolved_state_observations'],2)

    def test_verified_event_identity_does_not_invent_verified_delivery_attempt_identity(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base)
        plan['deliveries']=[replace(d,attempt_fact_id=None,attempt_verified=False) for d in plan['deliveries']]
        r=self.w.project(base,**plan)['result']
        self.assertEqual(r['logical_event_count'],1)
        self.assertEqual(r['verified_delivery_attempt_count'],0)
        self.assertEqual(self.c.execute('SELECT DISTINCT identity_state,external_revision_id FROM p24_next.delivery_attempt WHERE namespace_id=%s',
                                       (self.store.namespace_id,)).fetchall(),[('source_observation_only',None)])

    def test_conflicting_terminal_states_do_not_use_latest_timestamp(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base,subjects=(None,None))
        r=self.w.project(base,**plan)['result']
        self.assertEqual(len(r['state_publications']),1)
        self.assertEqual(r['state_publications'][0]['published_state'],'conflicting')

    def test_reviewed_issuer_sequence_allows_pending_to_success(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base,subjects=(None,None),states=('pending','success'),sequence=True)
        r=self.w.project(base,**plan)['result']
        self.assertEqual(r['state_publications'][0]['published_state'],'success')

    def test_source_replacement_keeps_same_logical_content_and_old_publication(self):
        a=self.ingest();base=self.base([a]);first=self.w.project(base,**self.plan(base))
        p1=self.pub.publish(self.prepare([a],first['run_id'])['publication_id'])['publication_id']
        rows=copy.deepcopy(self.rows)
        for row in rows:row['_source']['ExecutionTime']='2.5'
        b=self.ingest(rows);self.store.replace_source_snapshot(a['snapshot_id'],b['snapshot_id'],expected_prior_revision=1,
            reason_key='corrected_export',declared_by='synthetic-reviewer')
        base2=self.base([b]);second=self.w.project(base2,**self.plan(base2))
        p2=self.pub.publish(self.prepare([b],second['run_id'])['publication_id'])['publication_id']
        self.assertNotEqual(p1,p2)
        self.assertEqual(second['result']['logical_event_count'],1)
        self.assertEqual(self.w.for_publication(p1,access_token=self.token)['result_sha256'],first['result_sha256'])
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.external_event_revision WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(4,))

    def test_signed_cursors_bind_publication_and_state_and_counts_stay_full_scope(self):
        source=self.ingest();base=self.base([source]);saved=self.w.project(base,**self.plan(base))
        p=self.pub.publish(self.prepare([source],saved['run_id'])['publication_id'])['publication_id']
        first=self.w.for_publication(p,limit=1,access_token=self.token)
        second=self.w.for_publication(p,limit=1,cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(first['result']['logical_event_count'],second['result']['logical_event_count'])
        self.assertNotEqual(first['result']['state_publications'],second['result']['state_publications'])
        with self.assertRaisesRegex(FoundationError,'invalid_page_cursor'):
            self.w.state_evidence(p,first['result']['state_publications'][0]['state_publication_id'],cursor=first['next_cursor'],access_token=self.token)
        without=self.pub.publish(self.prepare([source])['publication_id'])['publication_id']
        self.assertEqual(self.w.for_publication(without,access_token=self.token)['status'],'not_provided')
        with self.assertRaises(FoundationError):self.w.for_publication(without,cursor=first['next_cursor'],access_token=self.token)

    def test_permissions_are_required_even_for_missing_publications(self):
        for token in (None,issue_test_access_token(self.namespace,roles=('audit_reviewer',)),issue_test_access_token('other-namespace')):
            with self.subTest(token=bool(token)),self.assertRaises(FoundationError):
                self.w.for_publication(str(uuid.uuid4()),access_token=token)

    def test_policy_redefinition_and_later_policy_knowledge_are_rejected(self):
        source=self.ingest();base=self.base([source]);plan=self.plan(base);self.w.project(base,**plan)
        with self.assertRaisesRegex(FoundationError,'workflow_contract_version_conflict'):
            self.w.project(base,**(plan|dict(contracts=(replace(self.contract,authority_ref='changed'),))))
        historic=self.base([source],mode='historical_revised')
        with self.assertRaisesRegex(FoundationError,'workflow_contract_not_known_at_snapshot'):
            self.w.project(historic,contracts=(replace(self.contract,version='new-policy'),))

    def test_pins_require_exact_source_vector_and_time_and_are_immutable(self):
        source=self.ingest();base=self.base([source]);saved=self.w.project(base,**self.plan(base))
        with self.assertRaisesRegex(FoundationError,'workflow_publication_input_mismatch'):
            self.prepare([source],saved['run_id'],known='2026-10-20T07:51:00Z')
        p=self.pub.publish(self.prepare([source],saved['run_id'])['publication_id'])['publication_id']
        for table,condition in (('foundation_workflow_run','run_id'),('foundation_observation_workflow','publication_id')):
            with self.c.transaction(),self.assertRaises(psycopg.Error):
                with self.c.transaction():
                    self.c.execute('DELETE FROM p24_next.'+table+' WHERE namespace_id=%s AND '+condition+'=%s',
                        (self.store.namespace_id,uuid.UUID(saved['run_id'] if condition=='run_id' else p)))

