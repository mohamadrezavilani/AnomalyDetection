"""Finite native recurrence/review probes; detector findings are synthetic."""
import copy
import tempfile
import unittest
import uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch

import psycopg

from p24_foundation.errors import FoundationError
from p24_foundation.incidents import IncidentRegistry
from p24_foundation.publication import ObservationPublisher
from p24_foundation.store import FoundationStore,initialize,jsonb
from tests.helpers import TEST_KEYS,batch,document,issue_test_access_token,test_access_policy


class IncidentPostgresTests(unittest.TestCase):
    connection=None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest('disposable PostgreSQL configuration required')
        initialize(cls.connection)

    def setUp(self):
        self.c=self.connection;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.namespace='incident_'+uuid.uuid4().hex
        self.token=issue_test_access_token(self.namespace,roles=('investigator','incident_reviewer'))
        self.store=FoundationStore(self.c,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
        self.pub=ObservationPublisher(self.store)
        self.now=datetime(2026,10,21,10,tzinfo=timezone.utc)
        self.registry=IncidentRegistry(self.store,clock=lambda:self.now)
        self.subject=TEST_KEYS.token(self.namespace,'session','SESSION_A')
        self.rows=[document(rid='A',oid='A',at='2026-10-20T07:30:00Z'),
                   document(rid='B',oid='B',at='2026-10-21T07:30:00Z')]
        self.source=self.ingest(self.rows)
        self.p=self.publish([self.source])
        self.heads=self.pub._heads(self.p)

    def ingest(self,rows):
        return self.store.ingest(batch(rows),source_key='test-source',interval_start='2026-10-20T07:25:00Z',
            interval_end='2026-10-21T07:45:00Z',observed_at='2026-10-21T08:00:00Z',receive_time_basis='synthetic_fixture')

    def publish(self,sources):
        draft=self.pub.prepare([s['snapshot_id'] for s in sources],event_cutoff='2026-10-21T07:40:00Z',
            knowledge_at='2026-10-21T08:05:00Z',mode='design_fixture',expected_generation=self.pub._current()[1])
        return self.pub.publish(draft['publication_id'])['publication_id']

    def finding(self,requests=('A',),pattern='repeat',score=10,subject=None,kind='session',family=None,supersedes=None):
        run=self.heads[self.store.request_key(requests[0])];detector=uuid.uuid4();finding=uuid.uuid4()
        self.c.execute('''INSERT INTO p24_next.detector_run(namespace_id,detector_run_id,run_id,detector_key,detector_version,
            target_start,target_end,status,applicable_units,evaluated_units,unsupported_units)
            VALUES(%s,%s,%s,'synthetic','synthetic.1','2026-10-20T07:00:00Z','2026-10-21T07:40:00Z','complete',1,1,0)''',
            (self.store.namespace_id,detector,run))
        self.c.execute('''INSERT INTO p24_next.finding(namespace_id,finding_id,detector_run_id,finding_key,scope_kind,
            subject_key,score_numeric,score_unit,evidence_manifest_sha256,measurements,supersedes_finding_id,assessment_state)
            VALUES(%s,%s,%s,%s,%s,%s,%s,'synthetic-z',%s,%s,%s,'supported_deviation')''',
            (self.store.namespace_id,finding,detector,pattern,kind,subject or self.subject,score,'a'*64,jsonb(dict(failure_family=family)),supersedes))
        for request in requests:
            self.c.execute('INSERT INTO p24_next.finding_request VALUES(%s,%s,%s,%s,%s,%s)',
                (self.store.namespace_id,finding,run,self.store.request_key(request),'support',jsonb(dict(synthetic=True))))
        return finding

    def refresh(self,findings,**changes):
        return self.registry.refresh(self.p,scope_kind='session',subject_key=self.subject,pattern_key='repeat',finding_ids=findings,**changes)

    def read(self,record,**kwargs):
        return self.registry.read(self.p,record['incident_id'],access_token=self.token,**kwargs)

    def decide(self,record,verdict,scope='pattern',**kwargs):
        preview=self.registry.preview(record['incident_id'],scope=scope,access_token=self.token)
        options=dict(scope=scope,verdict=verdict,reason_key='operator_review',preview_sha256=preview['preview_sha256'],command_id=str(uuid.uuid4()),access_token=self.token)
        options.update(kwargs)
        return self.registry.decide(record['incident_id'],**options)

    def test_recurrence_updates_one_record_and_deduplicates_shared_requests(self):
        first=self.finding();record=self.refresh([first]);old=self.read(record)
        second=self.finding(('A','B'),score=20)
        updated=self.refresh([second],expected_generation=1)
        self.assertEqual(record['incident_id'],updated['incident_id'])
        new=self.read(updated)
        self.assertEqual(new['result']['distinct_client_http_requests'],2)
        self.assertEqual(new['result']['occurrence_count'],2) # two separate request clusters; a broad finding cannot bridge their gap
        self.assertEqual(len(new['result']['active_findings']),2)
        self.assertEqual({r['score'] for r in new['result']['active_findings']},{'10','20'})
        self.assertEqual(self.read(record,revision_id=record['revision_id'])['result'],old['result'])
        self.assertTrue(self.refresh([second],expected_generation=1)['reused'])

    def test_separated_request_evidence_forms_two_occurrences_across_days(self):
        record=self.refresh([self.finding(('A',)),self.finding(('B',))])
        r=self.read(record)['result']
        self.assertEqual((r['occurrence_count'],r['distinct_client_http_requests']),(2,2))
        self.assertEqual(r['priority'],'unrated')

    def test_incompatible_subject_and_failure_family_are_not_merged(self):
        foreign=self.finding(subject=TEST_KEYS.token(self.namespace,'session','other'))
        with self.assertRaisesRegex(FoundationError,'incident_scope_mismatch'):self.refresh([foreign])
        with self.assertRaisesRegex(FoundationError,'incident_scope_mismatch'):self.refresh([self.finding(family='availability')])

    def test_session_finding_cannot_blame_a_subject_absent_from_request_evidence(self):
        subject=TEST_KEYS.token(self.namespace,'session','not-in-source')
        finding=self.finding(subject=subject)
        with self.assertRaisesRegex(FoundationError,'finding_subject_not_supported_by_request'):
            self.registry.refresh(self.p,scope_kind='session',subject_key=subject,pattern_key='repeat',finding_ids=[finding])

    def test_correction_retires_stale_support_and_keeps_original_revision(self):
        record=self.refresh([self.finding()]);old=self.read(record)['result']
        rows=copy.deepcopy(self.rows);rows[0]['_source']['ExecutionTime']='9.5'
        replacement=self.ingest(rows)
        self.store.replace_source_snapshot(self.source['snapshot_id'],replacement['snapshot_id'],expected_prior_revision=1,
            reason_key='corrected_export',declared_by='synthetic-reviewer')
        self.p=self.publish([replacement]);new=self.refresh([],expected_generation=1)
        r=self.read(new)['result']
        self.assertEqual(r['distinct_client_http_requests'],0)
        self.assertEqual(r['excluded_findings'][0]['reason'],'evidence_revision_not_current_in_publication')
        self.assertEqual(old['distinct_client_http_requests'],1)

    def test_failed_head_update_rolls_back_and_retry_does_not_duplicate(self):
        finding=self.finding()
        with patch('p24_foundation.incidents.execute_many',side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):self.refresh([finding])
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.incident WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(0,))
        self.assertEqual(self.refresh([finding])['generation'],1)

    def test_superseded_finding_is_audit_only_and_stale_generation_fails(self):
        first=self.finding();record=self.refresh([first]);new=self.finding(score=9,supersedes=first)
        with self.assertRaisesRegex(FoundationError,'stale_incident_generation'):self.refresh([new],expected_generation=0)
        updated=self.refresh([new],expected_generation=1);r=self.read(updated)['result']
        self.assertEqual(len(r['active_findings']),1)
        self.assertEqual(r['excluded_findings'][0]['reason'],'superseded')
        with self.c.transaction(),self.assertRaises(psycopg.Error):
            with self.c.transaction():self.c.execute('DELETE FROM p24_next.foundation_incident_revision WHERE namespace_id=%s',(self.store.namespace_id,))

    def test_review_visibility_changes_immediately_without_score_or_priority_change(self):
        record=self.refresh([self.finding()]);before=self.read(record)['result']
        self.decide(record,'benign');reviewed=self.read(record)
        self.assertEqual(reviewed['review']['visibility'],'reviewed')
        self.assertEqual(reviewed['result'],before)
        self.decide(record,'undo');self.assertEqual(self.read(record)['review']['visibility'],'active')
        self.decide(record,'confirmed');after=self.read(record)
        self.assertEqual(after['result']['priority'],'unrated')
        self.assertFalse(after['review']['priority_changed'])

    def test_broad_scope_narrow_override_and_undo_precedence(self):
        a=self.refresh([self.finding()])
        b=self.registry.refresh(self.p,scope_kind='session',subject_key=self.subject,pattern_key='volume',finding_ids=[self.finding(pattern='volume')])
        preview=self.registry.preview(a['incident_id'],scope='subject',access_token=self.token)
        self.assertEqual(preview['affected_records'],2)
        self.decide(a,'benign',scope='subject')
        self.assertEqual(self.read(b)['review']['visibility'],'reviewed')
        self.decide(a,'confirmed')
        self.assertEqual(self.read(a)['review']['visibility'],'active')
        self.decide(a,'undo')
        self.assertEqual(self.read(a)['review']['visibility'],'reviewed')
        self.decide(a,'undo',scope='subject')
        self.assertEqual(self.read(b)['review']['visibility'],'active')

    def test_expiry_uses_server_clock_and_undo_never_restores_old_narrow_verdict(self):
        record=self.refresh([self.finding()])
        self.decide(record,'benign',expires_at=(self.now+timedelta(minutes=1)).isoformat())
        self.now+=timedelta(minutes=2)
        self.assertEqual(self.read(record)['review']['verdict'],'unmarked')
        self.decide(record,'false_positive');self.decide(record,'undo')
        self.assertEqual(self.read(record)['review']['verdict'],'unmarked')

    def test_stale_preview_rejected_after_new_membership_or_broader_decision(self):
        record=self.refresh([self.finding()]);preview=self.registry.preview(record['incident_id'],access_token=self.token)
        self.refresh([self.finding(('B',))],expected_generation=1)
        with self.assertRaisesRegex(FoundationError,'stale_review_preview'):
            self.registry.decide(record['incident_id'],scope='pattern',verdict='benign',reason_key='operator_review',
                preview_sha256=preview['preview_sha256'],command_id=str(uuid.uuid4()),access_token=self.token)
        preview=self.registry.preview(record['incident_id'],access_token=self.token)
        self.decide(record,'false_positive',scope='subject')
        with self.assertRaisesRegex(FoundationError,'stale_review_preview'):
            self.registry.decide(record['incident_id'],scope='pattern',verdict='confirmed',reason_key='operator_review',
                preview_sha256=preview['preview_sha256'],command_id=str(uuid.uuid4()),access_token=self.token)

    def test_review_command_retry_is_idempotent_and_payload_reuse_is_rejected(self):
        record=self.refresh([self.finding()]);preview=self.registry.preview(record['incident_id'],access_token=self.token)
        args=dict(scope='pattern',verdict='benign',reason_key='operator_review',preview_sha256=preview['preview_sha256'],command_id=str(uuid.uuid4()),access_token=self.token)
        one=self.registry.decide(record['incident_id'],**args);two=self.registry.decide(record['incident_id'],**args)
        self.assertEqual(one['decision_id'],two['decision_id']);self.assertTrue(two['reused'])
        with self.assertRaisesRegex(FoundationError,'review_command_conflict'):
            self.registry.decide(record['incident_id'],**(args|dict(verdict='confirmed')))

    def test_read_role_cannot_review_and_cross_namespace_is_denied_before_lookup(self):
        record=self.refresh([self.finding()])
        for token in (None,issue_test_access_token('other')):
            with self.assertRaisesRegex(FoundationError,'access_denied'):
                self.registry.read(self.p,str(uuid.uuid4()),access_token=token)
        with self.assertRaisesRegex(FoundationError,'access_denied'):
            self.registry.preview(record['incident_id'],access_token=issue_test_access_token(self.namespace))
        self.assertGreater(self.c.execute("SELECT count(*) FROM p24_next.foundation_access_decision WHERE namespace_id=%s AND decision='denied'",(self.store.namespace_id,)).fetchone()[0],0)

    def test_list_cursors_bind_publication_and_freeze_incident_revisions(self):
        a=self.refresh([self.finding()]);b=self.registry.refresh(self.p,scope_kind='session',subject_key=self.subject,
            pattern_key='volume',finding_ids=[self.finding(pattern='volume')])
        first=self.registry.list(self.p,limit=1,access_token=self.token)
        remaining=next(x for x in (a,b) if x['incident_id']!=first['items'][0]['incident_id'])
        pattern='repeat' if remaining==a else 'volume'
        new=self.finding(pattern=pattern,score=30)
        self.registry.refresh(self.p,scope_kind='session',subject_key=self.subject,pattern_key=pattern,finding_ids=[new],expected_generation=1)
        second=self.registry.list(self.p,limit=1,cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(second['items'][0]['generation'],1)
        with self.assertRaisesRegex(FoundationError,'invalid_page_cursor'):
            self.registry.list(self.p,limit=1,cursor=first['next_cursor']+'x',access_token=self.token)

    def test_service_scope_accumulates_across_callers_but_not_failure_families(self):
        service=TEST_KEYS.token(self.namespace,'provider_operation','synthetic-provider.operation')
        a=self.finding(('A',),subject=service,kind='service',pattern='provider-availability',family='availability')
        b=self.finding(('B',),subject=service,kind='service',pattern='provider-availability',family='availability')
        record=self.registry.refresh(self.p,scope_kind='service',subject_key=service,pattern_key='provider-availability',
            failure_family='availability',finding_ids=[a,b])
        result=self.read(record)['result']
        self.assertEqual(result['distinct_client_http_requests'],2)
        self.assertEqual(result['scope_kind'],'service')
        self.assertEqual(result['root_cause'],'not_established')
        with self.assertRaisesRegex(FoundationError,'incident_scope_mismatch'):
            self.registry.refresh(self.p,scope_kind='service',subject_key=service,pattern_key='provider-availability',
                failure_family='validation',finding_ids=[a])

    def test_request_evidence_pages_deduplicate_and_reject_changed_revision_cursor(self):
        record=self.refresh([self.finding(('A','B'))])
        first=self.registry.evidence(self.p,record['incident_id'],limit=1,access_token=self.token)
        second=self.registry.evidence(self.p,record['incident_id'],limit=1,cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(first['total'],2);self.assertNotEqual(first['items'],second['items'])
        self.refresh([self.finding(score=42)],expected_generation=1)
        with self.assertRaisesRegex(FoundationError,'invalid_page_cursor'):
            self.registry.evidence(self.p,record['incident_id'],limit=1,cursor=first['next_cursor'],access_token=self.token)
        pinned=self.registry.evidence(self.p,record['incident_id'],revision_id=record['revision_id'],limit=1,
            cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(pinned['items'],second['items'])

    def test_concurrent_operator_submissions_fence_the_stale_preview(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        record=self.refresh([self.finding()]);preview=self.registry.preview(record['incident_id'],access_token=self.token)
        barrier=threading.Barrier(2)
        def submit(verdict):
            with psycopg.connect(self.c.info.dsn,password=self.c.info.password,autocommit=True) as c:
                store=FoundationStore(c,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
                registry=IncidentRegistry(store,clock=lambda:self.now)
                barrier.wait(timeout=10)
                try:
                    registry.decide(record['incident_id'],scope='pattern',verdict=verdict,reason_key='operator_review',
                        preview_sha256=preview['preview_sha256'],command_id=str(uuid.uuid4()),access_token=self.token)
                    return 'saved'
                except FoundationError as error:return error.code
        with ThreadPoolExecutor(max_workers=2) as executor:
            one=executor.submit(submit,'benign');two=executor.submit(submit,'confirmed')
            self.assertEqual(sorted((one.result(timeout=20),two.result(timeout=20))),['saved','stale_review_preview'])
