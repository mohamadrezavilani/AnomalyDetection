import copy
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psycopg

from p24_foundation.errors import FoundationError
from p24_foundation.publication import ObservationPublisher, head_digest, checked_limit, checked_reference
from p24_foundation.store import FoundationStore, initialize
from tests.helpers import ROOT, TEST_KEYS, MANIFEST, fixture, document, batch,issue_test_access_token,test_access_policy,TEST_ACCESS_PRIVATE_KEY


class PublicationContractTests(unittest.TestCase):
    def publisher(self, **kwargs):
        return ObservationPublisher(SimpleNamespace(c=None,namespace_id=uuid.uuid4(),namespace='contract',keys=TEST_KEYS),**kwargs)

    def test_head_manifest_digest_is_order_independent_and_distinguishes_runs(self):
        a,b=uuid.uuid4(),uuid.uuid4()
        self.assertEqual(head_digest({'a':a,'b':b}),head_digest({'b':b,'a':a}))
        self.assertNotEqual(head_digest({'a':a}),head_digest({'a':b}))
        self.assertEqual(head_digest({}),hashlib.sha256(b'').hexdigest())

    def test_checkpoint_and_page_bounds_reject_boolean_or_unbounded_values(self):
        for value in (0,65,True,'2'):
            with self.subTest(value=value),self.assertRaises(FoundationError):self.publisher(checkpoint_every=value)
        for value in (0,101,True,None):
            with self.subTest(value=value),self.assertRaises(FoundationError):checked_limit(value)
        for value in (None,'not-a-reference',{}):
            with self.subTest(value=value),self.assertRaises(FoundationError):checked_reference(value)

    def test_invalid_prepare_inputs_fail_before_database_access(self):
        base=dict(event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:50:00Z',expected_generation=0)
        for change in (dict(expected_generation=True),dict(expected_generation=-1),dict(mode=[]),dict(association_horizon_seconds=3601)):
            with self.subTest(change=change),self.assertRaises(FoundationError):self.publisher().prepare([],**(base|change))
        with self.assertRaises(FoundationError):self.publisher().prepare(['invalid'],**base)

    def test_signed_cursor_binds_publication_kind_and_scope(self):
        p=self.publisher();pub=uuid.uuid4();cursor=p._cursor(pub,'session','session-key',['1','request-key'])
        self.assertEqual(p._read_cursor(cursor,pub,'session','session-key'),['1','request-key'])
        for target,kind,scope in ((uuid.uuid4(),'session','session-key'),(pub,'requests','session-key'),(pub,'session','another')):
            with self.assertRaises(FoundationError):p._read_cursor(cursor,target,kind,scope)
        for invalid in ('broken',cursor+'x',True,'x'*5000):
            with self.assertRaises(FoundationError):p._read_cursor(invalid,pub,'session','session-key')


class PublicationPostgresTests(unittest.TestCase):
    connection=None
    database_config=None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest('disposable PostgreSQL configuration required')
        initialize(cls.connection)

    def setUp(self):
        self.c=self.connection;self.tmp=tempfile.TemporaryDirectory()
        self.namespace='publication_'+uuid.uuid4().hex
        self.access_token=issue_test_access_token(self.namespace)
        self.store=FoundationStore(self.c,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
        self.pub=ObservationPublisher(self.store)

    def tearDown(self):self.tmp.cleanup()

    def info(self, publication_id=None, *, publisher=None, token=None):
        return (publisher or self.pub).info(publication_id, access_token=token or self.access_token)

    def ingest(self,rows,source='source-A',at='2026-10-20T07:40:00Z'):
        return self.store.ingest(batch(rows),source_key=source,interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z',
                                 observed_at=at,receive_time_basis='synthetic_fixture')

    def prepare(self,sources,*,cutoff='2026-10-20T07:40:00Z',known='2026-10-20T07:50:00Z',expected=None,mode='design_fixture',publisher=None):
        p=publisher or self.pub
        if expected is None:expected=p._current()[1]
        return p.prepare([s['snapshot_id'] for s in sources],event_cutoff=cutoff,knowledge_at=known,expected_generation=expected,mode=mode)

    def publish(self,sources,**kwargs):
        p=kwargs.get('publisher') or self.pub
        return p.publish(self.prepare(sources,**kwargs)['publication_id'])

    def summaries(self,publication_id):
        cursor=None;result={}
        while True:
            page=self.pub.requests(publication_id,limit=100,cursor=cursor,access_token=self.access_token)
            result.update((r['summary']['request_key'],r['summary']) for r in page['items'])
            cursor=page['next_cursor']
            if not cursor:return result

    def assert_full(self,pub,sources,*,cutoff='2026-10-20T07:40:00Z',known='2026-10-20T07:50:00Z',mode='design_fixture'):
        if not sources:
            self.assertEqual(self.summaries(pub['publication_id']),{});return
        run=self.store.project([s['snapshot_id'] for s in sources],event_cutoff=cutoff,knowledge_at=known,mode=mode)
        expected=dict(self.c.execute('SELECT request_key,summary FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s',
                                     (self.store.namespace_id,uuid.UUID(run['run_id']))).fetchall())
        self.assertEqual(self.summaries(pub['publication_id']),expected)
        self.assertEqual(pub['distinct_client_requests'],run['distinct_client_requests'])
        self.assertEqual(pub['selected_request_events'],run['selected_request_events'])
        self.assertEqual(pub['known_sessions'],run['known_sessions'])
        return run

    def test_incremental_retention_exceeds_one_projection_budget_without_losing_history(self):
        # Small limits exercise the real SQL path without a huge synthetic dataset.
        first_rows=[document(rid='A'+str(n),oid='A'+str(n)) for n in range(6)]
        second_rows=[document(rid='B'+str(n),oid='B'+str(n),at='2026-10-20T07:31:00Z') for n in range(6)]
        second_rows.append(document(rid='A0',oid='late-A0',at='2026-10-20T07:31:00Z',
            path='DBPath.ud_prc_invoiceInfo',message='(Command Text: ud_prc_invoiceInfo) (Code: G00000)'))
        first_source=self.ingest(first_rows,source='first')
        with patch('p24_foundation.publication.MAX_PROJECTION_EVENTS',10),patch('p24_foundation.store.MAX_PROJECTION_EVENTS',10):
            first=self.publish([first_source],cutoff='2026-10-20T07:30:00Z')
            before=self.summaries(first['publication_id'])
            second_source=self.ingest(second_rows,source='second')
            second=self.publish([first_source,second_source],cutoff='2026-10-20T07:35:00Z')
            after=self.summaries(second['publication_id'])
            self.assertEqual((len(before),len(after)),(6,12))
            self.assertEqual((second['selected_request_events'],second['distinct_client_requests']),(13,12))
            request=self.store.request_key('A0')
            self.assertEqual(before[request]['selected_event_count'],1)
            self.assertEqual(after[request]['selected_event_count'],2)
            self.assertEqual(after[request]['distinct_client_request_count'],1)
            self.assertEqual(self.summaries(first['publication_id']),before)
            selected=self.pub._header(second['publication_id'])['input_manifest']['effective_sources']
            self.assertEqual(set(selected),{first_source['snapshot_id'],second_source['snapshot_id']})
            # Changing policy forces a full rebuild, whose bound must still hold.
            with self.assertRaisesRegex(FoundationError,'publication_event_limit'):
                self.pub.prepare(selected,event_cutoff='2026-10-20T07:35:00Z',knowledge_at='2026-10-20T07:50:00Z',
                    expected_generation=2,mode='design_fixture',association_horizon_seconds=301)
            oversized=self.ingest([document(rid='large',oid='large'+str(n),at='2026-10-20T07:32:00Z') for n in range(11)],source='large')
            with self.assertRaisesRegex(FoundationError,'projection_event_limit'):
                self.prepare([first_source,second_source,oversized],cutoff='2026-10-20T07:35:00Z')
            self.assertEqual(self.pub._current()[1],2)
            self.assertEqual(self.summaries(first['publication_id']),before)

    def test_prepare_does_not_publish_and_initial_counts_match_real_session_oracle(self):
        a=self.ingest(fixture('session_activity.sanitized.json').records)
        draft=self.prepare([a]);self.assertEqual(self.info()['generation'],0)
        self.assertEqual((draft['status'],draft['request_count'],draft['distinct_client_requests']),('prepared',10,10))
        again=self.prepare([a]);self.assertEqual(again['publication_id'],draft['publication_id'])
        first=self.pub.publish(draft['publication_id']);self.assertEqual(first['generation'],1)
        self.assert_full(first,[a])
        self.assertFalse(first['coverage']['source_window_complete'])
        self.assertFalse(first['coverage']['authoritative_source_heads_published'])
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.source_head WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone(),(0,))

    def test_publication_pins_receipts_as_known_and_later_receipt_creates_new_snapshot(self):
        a=self.ingest([document()],at='2026-10-20T07:40:00Z')
        first=self.publish([a],known='2026-10-20T07:50:00Z')
        first_manifest=self.pub._header(first['publication_id'])['input_manifest']
        first_source=first_manifest['requested_sources'][0]
        self.assertEqual(first_source['receipt_count_known'],1)
        self.assertEqual(first_source['first_receipt_at'],'2026-10-20T07:40:00+00:00')
        duplicate=self.ingest([document()],at='2026-10-20T08:00:00Z')
        self.assertTrue(duplicate['reused'])
        second=self.publish([a],known='2026-10-20T08:10:00Z')
        later_source=self.pub._header(second['publication_id'])['input_manifest']['requested_sources'][0]
        self.assertEqual(later_source['receipt_count_known'],2)
        self.assertEqual(first_source['receipt_count_known'],1)
        self.assertEqual(self.info(first['publication_id'])['distinct_client_requests'],1)
        self.assert_full(second,[a],known='2026-10-20T08:10:00Z')

    def test_publication_manifest_keeps_full_multistep_correction_lineage(self):
        original_row=document(rid='lineage-A',oid='lineage-origin')
        a=self.ingest([original_row],source='lineage-source')
        first=self.publish([a])
        corrected_row=copy.deepcopy(original_row);corrected_row['_source']['ExecutionTime']='2.5'
        b=self.ingest([corrected_row],source='lineage-source')
        self.store.replace_source_snapshot(a['snapshot_id'],b['snapshot_id'],expected_prior_revision=1,
            reason_key='corrected_export',declared_by='reviewer-one')
        final_row=copy.deepcopy(corrected_row);final_row['_source']['ExecutionTime']='3.5'
        c=self.ingest([final_row],source='lineage-source')
        self.store.replace_source_snapshot(b['snapshot_id'],c['snapshot_id'],expected_prior_revision=2,
            reason_key='producer_reissued',declared_by='reviewer-two')
        second=self.publish([a,c])
        item=self.pub._header(second['publication_id'])['input_manifest']['superseded'][0]
        self.assertEqual((item['prior_snapshot_id'],item['replacement_snapshot_id']),(a['snapshot_id'],c['snapshot_id']))
        self.assertEqual([edge['reason_key'] for edge in item['revision_chain']],['corrected_export','producer_reissued'])
        self.assertEqual([edge['declared_by'] for edge in item['revision_chain']],['reviewer-one','reviewer-two'])
        self.assertEqual(self.info(first['publication_id'])['distinct_client_requests'],1)
        self.assert_full(second,[a,c])

    def test_publication_manifest_stops_at_selected_correction(self):
        sources=[]
        for i in range(4):
            row=document(rid='bounded-lineage',oid='bounded-origin')
            row['_source']['ExecutionTime']=str(i+1)
            sources.append(self.ingest([row],source='bounded-chain'))
        for i in range(3):
            self.store.replace_source_snapshot(sources[i]['snapshot_id'],sources[i+1]['snapshot_id'],
                expected_prior_revision=i+1,reason_key='corrected_export',declared_by='reviewer')
        result=self.publish([sources[0],sources[2]])
        chain=result['input_manifest']['superseded'][0]['revision_chain']
        self.assertEqual([(e['prior_snapshot_id'],e['replacement_snapshot_id']) for e in chain],
            [(sources[0]['snapshot_id'],sources[1]['snapshot_id']),(sources[1]['snapshot_id'],sources[2]['snapshot_id'])])
        self.assert_full(result,[sources[0],sources[2]])

    def test_receipt_and_revision_manifest_is_stable_across_database_timezones(self):
        row=document(rid='timezone-stable',oid='timezone-origin');a=self.ingest([row])
        revised=copy.deepcopy(row);revised['_source']['ExecutionTime']='7.5';b=self.ingest([revised])
        self.store.replace_source_snapshot(a['snapshot_id'],b['snapshot_id'],expected_prior_revision=1,
            reason_key='corrected_export',declared_by='reviewer')
        with self.c.transaction():
            self.c.execute("SET LOCAL TIME ZONE 'Asia/Tehran'")
            tehran=self.prepare([a,b])
        with self.c.transaction():
            self.c.execute("SET LOCAL TIME ZONE 'UTC'")
            utc=self.prepare([a,b])
        self.assertEqual(tehran['publication_id'],utc['publication_id'])
        self.assertEqual(tehran['input_manifest_sha256'],utc['input_manifest_sha256'])
        for source in tehran['input_manifest']['requested_sources']:
            self.assertEqual(source['first_receipt_at'],'2026-10-20T07:40:00+00:00')
        self.assertTrue(tehran['input_manifest']['superseded'][0]['revision_chain'][0]['declared_at'].endswith('+00:00'))

    def test_unrelated_append_reuses_old_request_and_reconstructs_only_the_new_one(self):
        a=self.ingest([document()]);first=self.publish([a])
        old=self.pub.request(first['publication_id'],'request-A',access_token=self.access_token)
        b=self.ingest([document(rid='request-B',oid='origin-B')],source='B')
        second=self.publish([a,b]);new=self.pub.request(second['publication_id'],'request-A',access_token=self.access_token)
        self.assertEqual(old['projection_run_id'],new['projection_run_id'])
        self.assertEqual(second['statistics']['reused_requests'],1)
        self.assertEqual(second['statistics']['recomputed_requests'],1)
        self.assertEqual(second['statistics']['reconstructed_request_events'],1)
        self.assertEqual(second['statistics']['stored_entries'],1)
        self.assertEqual(self.info(first['publication_id'])['distinct_client_requests'],1)
        self.assert_full(second,[a,b])

    def test_cross_window_late_provider_chain_reconciles_the_entire_request(self):
        docs=list(fixture('boundary.sanitized.json').records)
        early=[d for d in docs if d['fields']['@timestamp'][0]<'2026-10-20T07:30:00Z']
        late=[d for d in docs if d not in early]
        a=self.ingest(early,at='2026-10-20T07:31:00Z')
        first=self.publish([a],cutoff='2026-10-20T07:30:00Z',known='2026-10-20T07:32:00Z',mode='online_original')
        rid=MANIFEST['anchors']['boundary_request_id']
        self.assertEqual(self.pub.request(first['publication_id'],rid,access_token=self.access_token)['summary']['final_outcome'],'unknown')
        b=self.ingest(late,source='next-window',at='2026-10-20T07:40:00Z')
        second=self.publish([a,b],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:45:00Z',mode='online_original')
        s=self.pub.request(second['publication_id'],rid,access_token=self.access_token)['summary']
        self.assertEqual((s['selected_event_count'],s['sql_observation_count'],s['provider_observation_count'],s['outcome_code']),(14,12,1,'GD2016'))
        self.assertEqual(self.pub.request(first['publication_id'],rid,access_token=self.access_token)['summary']['selected_event_count'],11)
        self.assert_full(second,[a,b],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:45:00Z',mode='online_original')

    def test_duplicate_support_is_counted_once_then_removed_without_resurrection(self):
        d=document();a=self.ingest([d]);b=self.ingest([d],source='overlap')
        first=self.publish([a]);second=self.publish([a,b]);self.assertEqual(second['distinct_client_requests'],1)
        evidence=self.pub.request_evidence(second['publication_id'],'request-A',access_token=self.access_token)
        self.assertEqual(len(evidence['items'][0]['provenance']),2)
        third=self.publish([b]);self.assertEqual(third['distinct_client_requests'],1)
        fourth=self.publish([]);self.assertEqual((fourth['request_count'],fourth['statistics']['removed_requests']),(0,1))
        self.assertEqual(self.info(second['publication_id'])['distinct_client_requests'],1)
        self.assert_full(third,[b]);self.assert_full(fourth,[])

    def test_explicit_empty_correction_preserves_independent_support_and_old_history(self):
        d=document();a=self.ingest([d]);support=self.ingest([d],source='independent')
        first=self.publish([a,support]);empty=self.ingest([],source='source-A')
        self.store.replace_source_snapshot(a['snapshot_id'],empty['snapshot_id'],expected_prior_revision=1,reason_key='corrected_export',declared_by='reviewer')
        revised=self.publish([a,empty,support]);self.assertEqual(revised['distinct_client_requests'],1)
        final=self.publish([a,empty]);self.assertEqual(final['distinct_client_requests'],0)
        self.assertEqual(self.info(first['publication_id'])['distinct_client_requests'],1)
        self.assert_full(revised,[a,empty,support]);self.assert_full(final,[a,empty])

    def test_ambiguity_reads_cannot_gain_variants_from_a_later_unselected_source(self):
        d=document();bad=copy.deepcopy(d);bad['_source']['message']='POST https://fixture.invalid/config HTTP/1.1 (G00002 | Unknown)'
        a=self.ingest([d,bad]);first=self.publish([a])
        before=self.pub.request_evidence(first['publication_id'],'request-A',limit=1,access_token=self.access_token)
        self.assertEqual(before['total_event_versions'],2)
        new=copy.deepcopy(d);new['_source']['ExecutionTime']='123.456'
        self.ingest([new],source='unselected-later-source')
        after=self.pub.request_evidence(first['publication_id'],'request-A',limit=1,access_token=self.access_token)
        self.assertEqual(after['items'],before['items']);self.assertEqual(after['total_event_versions'],2)
        page2=self.pub.request_evidence(first['publication_id'],'request-A',limit=1,cursor=before['next_cursor'],access_token=self.access_token)
        self.assertIsNone(page2['next_cursor']);self.assertEqual(len(page2['items']),1)
        self.assertTrue(page2['items'][0]['provenance'])

    def test_unknown_time_evidence_read_is_frozen_to_its_original_sources(self):
        d=document();del d['_source']['@timestamp']
        a=self.ingest([d]);run=self.store.project([a['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:50:00Z')
        self.assertEqual(self.store.request_evidence(run['run_id'],'request-A',access_token=self.access_token)['total_event_versions'],1)
        later=copy.deepcopy(d);later['_source']['ExecutionTime']='9'
        self.ingest([later],source='unselected-later')
        self.assertEqual(self.store.request_evidence(run['run_id'],'request-A',access_token=self.access_token)['total_event_versions'],1)

    def test_changed_request_id_variants_close_the_whole_origin_request_graph(self):
        a1=document(rid='A',oid='origin-one');b1=document(rid='B',oid='origin-two')
        a=self.ingest([a1,b1]);first=self.publish([a]);self.assertEqual(first['distinct_client_requests'],2)
        b2=copy.deepcopy(a1);b2['_source']['RequestID']='B'
        c2=copy.deepcopy(b1);c2['_source']['RequestID']='C'
        b=self.ingest([b2,c2],source='conflicting-request-identities')
        second=self.publish([a,b]);self.assertEqual((second['request_count'],second['distinct_client_requests']),(3,0))
        self.assertEqual(second['statistics']['impacted_requests'],3)
        self.assertTrue(all(s['ambiguous_event_count']>0 for s in self.summaries(second['publication_id']).values()))
        self.assert_full(second,[a,b])

    def test_requestless_conflicting_version_invalidates_the_previous_head(self):
        d=document();a=self.ingest([d]);self.publish([a])
        changed=copy.deepcopy(d);changed['_source']['RequestID']='N/A'
        b=self.ingest([changed],source='requestless-variant')
        second=self.publish([a,b]);self.assertEqual(second['distinct_client_requests'],0)
        self.assertEqual(self.pub.request(second['publication_id'],'request-A',access_token=self.access_token)['summary']['ambiguous_event_count'],1)
        self.assert_full(second,[a,b])

    def test_time_advance_without_new_sources_only_reconciles_crossing_origins(self):
        rows=[document(rid='A',oid='A'),document(rid='B',oid='B',at='2026-10-20T07:30:00.0000001Z')]
        a=self.ingest(rows);first=self.publish([a],cutoff='2026-10-20T07:30:00Z')
        self.assertEqual(first['distinct_client_requests'],1)
        second=self.publish([a],cutoff='2026-10-20T07:30:00.000001Z')
        self.assertEqual((second['distinct_client_requests'],second['statistics']['reused_requests'],second['statistics']['recomputed_requests']),(2,1,1))
        self.assert_full(second,[a],cutoff='2026-10-20T07:30:00.000001Z')

    def test_policy_change_rebuilds_instead_of_reusing_an_incompatible_result(self):
        a=self.ingest([document()]);self.publish([a])
        second=self.publish([a],mode='historical_revised')
        self.assertEqual(second['statistics']['reconciliation'],'full_policy_rebuild')
        self.assertEqual(second['statistics']['reused_requests'],0)
        self.assert_full(second,[a],mode='historical_revised')

    def test_later_source_cannot_backdate_knowledge_and_publication_cannot_regress(self):
        a=self.ingest([document()],at='2026-10-20T07:40:00Z')
        with self.assertRaises(FoundationError):self.prepare([a],known='2026-10-20T07:39:00Z',mode='online_original')
        first=self.publish([a])
        for changes in (dict(cutoff='2026-10-20T07:39:00Z'),dict(known='2026-10-20T07:49:00Z')):
            with self.assertRaises(FoundationError) as caught:self.prepare([a],**changes)
            self.assertEqual(caught.exception.code,'publication_time_regression')
        self.assertEqual(self.info()['publication_id'],first['publication_id'])

    def test_knowledge_advance_reconciles_newly_eligible_versions_without_new_sources(self):
        d=document()
        self.ingest([d],source='first-intake',at='2026-10-20T07:40:00Z')
        # Synthetic earlier-source claim does not backdate the already stored
        # event receipt. This probes the existing two-bound projection rule.
        earlier=self.ingest([d],source='earlier-source-claim',at='2026-10-20T07:30:00Z')
        first=self.publish([earlier],known='2026-10-20T07:35:00Z',mode='historical_revised')
        self.assertEqual(first['distinct_client_requests'],0)
        second=self.publish([earlier],known='2026-10-20T07:45:00Z',mode='historical_revised')
        self.assertEqual(second['distinct_client_requests'],1)
        self.assert_full(second,[earlier],known='2026-10-20T07:45:00Z',mode='historical_revised')

    def test_stale_preparations_are_fenced_and_repeated_publish_never_rolls_back_current(self):
        a=self.ingest([document()]);first=self.publish([a])
        b=self.ingest([document(rid='B',oid='B')],source='B');c=self.ingest([document(rid='C',oid='C')],source='C')
        one=self.prepare([a,b]);two=self.prepare([a,c])
        second=self.pub.publish(one['publication_id'])
        with self.assertRaises(FoundationError) as caught:self.pub.publish(two['publication_id'])
        self.assertEqual(caught.exception.code,'stale_publication_generation')
        self.assertEqual(self.pub.publish(first['publication_id'])['generation'],1)
        self.assertEqual(self.pub.publish(second['publication_id'])['generation'],2)
        self.assertEqual(self.info()['publication_id'],second['publication_id'])
        with self.assertRaises(FoundationError):self.prepare([a,b],expected=1)

    def test_publication_failure_rolls_back_commit_and_leaves_the_old_view_current(self):
        a=self.ingest([document()]);first=self.publish([a]);b=self.ingest([document(rid='B',oid='B')],source='B')
        prepared=self.prepare([a,b])
        with patch.object(self.pub,'_advance_current',side_effect=RuntimeError('synthetic publication interruption')):
            with self.assertRaises(RuntimeError):self.pub.publish(prepared['publication_id'])
        self.assertEqual(self.info()['publication_id'],first['publication_id'])
        self.assertEqual(self.info(prepared['publication_id'])['status'],'prepared')
        self.assertEqual(self.pub.publish(prepared['publication_id'])['generation'],2)

    def test_reader_sees_old_generation_until_commit_and_can_keep_its_pin(self):
        a=self.ingest([document()]);first=self.publish([a]);b=self.ingest([document(rid='B',oid='B')],source='B')
        prepared=self.prepare([a,b])
        with psycopg.connect(**self.database_config,autocommit=True) as other:
            other.execute("SET statement_timeout='2s'")
            with self.c.transaction():
                self.pub.publish(prepared['publication_id'])
                reader=ObservationPublisher(FoundationStore(other,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace)))
                self.assertEqual(self.info(publisher=reader)['publication_id'],first['publication_id'])
                self.assertEqual(reader.requests(first['publication_id'],access_token=self.access_token)['total_requests'],1)
            self.assertEqual(self.info(publisher=reader)['publication_id'],prepared['publication_id'])
            self.assertEqual(reader.requests(first['publication_id'],access_token=self.access_token)['total_requests'],1)
            self.assertEqual(reader.requests(prepared['publication_id'],access_token=self.access_token)['total_requests'],2)

    def test_two_publishers_cannot_commit_different_results_at_the_same_generation(self):
        a=self.ingest([document()]);self.publish([a])
        b=self.ingest([document(rid='B',oid='B')],source='B');c=self.ingest([document(rid='C',oid='C')],source='C')
        choices=[self.prepare([a,b]),self.prepare([a,c])];barrier=threading.Barrier(2);results=[];lock=threading.Lock()
        def work(choice):
            try:
                with psycopg.connect(**self.database_config,autocommit=True) as connection:
                    publisher=ObservationPublisher(FoundationStore(connection,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace)))
                    barrier.wait(timeout=10)
                    try:outcome=('ok',publisher.publish(choice['publication_id'])['publication_id'])
                    except FoundationError as error:outcome=('rejected',error.code)
            except Exception as error:outcome=('unexpected',type(error).__name__)
            with lock:results.append(outcome)
        threads=[threading.Thread(target=work,args=(choice,)) for choice in choices]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(sorted(r[0] for r in results),['ok','rejected'])
        self.assertIn(('rejected','stale_publication_generation'),results)
        current=self.info();self.assertEqual((current['generation'],current['request_count']),(2,2))
        self.assert_full(current,[a,b] if current['publication_id']==choices[0]['publication_id'] else [a,c])

    def test_automatic_checkpoints_compact_deltas_without_reconstructing_reused_requests(self):
        p=ObservationPublisher(self.store,checkpoint_every=2)
        a=self.ingest([document(rid='A',oid='A')]);b=self.ingest([document(rid='B',oid='B')],source='B')
        first=self.publish([a,b],publisher=p)
        second=self.publish([a],publisher=p);self.assertFalse(second['is_checkpoint'])
        third=self.publish([a],publisher=p);self.assertTrue(third['is_checkpoint'])
        self.assertEqual((third['statistics']['reused_requests'],third['statistics']['recomputed_requests'],third['statistics']['stored_entries']),(1,0,1))
        fourth=self.publish([a],publisher=p)
        self.assertEqual((fourth['request_count'],fourth['statistics']['stored_entries']),(1,0))
        self.assertEqual(self.info(first['publication_id'])['request_count'],2)
        self.assert_full(third,[a]);self.assert_full(fourth,[a])

    def test_a_large_replacement_delta_uses_a_checkpoint_with_no_lost_tombstone(self):
        a=self.ingest([document(rid='A',oid='A')]);b=self.ingest([document(rid='B',oid='B')],source='B')
        with patch('p24_foundation.publication.MAX_HEADS',1):
            first=self.publish([a]);second=self.publish([b])
        self.assertTrue(second['is_checkpoint'])
        self.assertEqual(second['statistics']['checkpoint_reason'],'delta_capacity')
        self.assertEqual((second['request_count'],second['statistics']['stored_entries']),(1,1))
        self.assertEqual(self.info(first['publication_id'])['request_count'],1)
        with self.assertRaises(FoundationError):self.pub.request(second['publication_id'],'A',access_token=self.access_token)
        self.assert_full(second,[b])

    def test_registration_candidates_use_the_whole_publication_not_only_recomputed_requests(self):
        reg=document(rid='register',oid='reg',at='2026-10-20T07:28:00Z',session='N/A',path='Core.v2/DeviceRegister Line:42')
        a=self.ingest([reg]);first=self.publish([a]);self.assertEqual(self.pub.candidates(first['publication_id'],access_token=self.access_token)['total_candidates'],0)
        b=self.ingest([document(rid='later-session',oid='session',at='2026-10-20T07:28:01Z')],source='session')
        second=self.publish([a,b]);candidates=self.pub.candidates(second['publication_id'],access_token=self.access_token)
        self.assertEqual(candidates['total_candidates'],1)
        self.assertEqual(second['statistics']['reused_requests'],1)
        full=self.assert_full(second,[a,b])
        self.assertEqual(candidates['items'],self.store.candidates(full['run_id'],access_token=self.access_token)['items'])
        self.assertEqual(candidates['association_authority'],'context_candidate_only')

    def test_session_pagination_stays_pinned_beyond_500_requests_during_an_update(self):
        a=self.ingest([document(rid=f'R-{i}',oid=f'O-{i}') for i in range(601)])
        first=self.publish([a]);page=self.pub.session_activity(first['publication_id'],'SESSION_A',limit=100,access_token=self.access_token)
        b=self.ingest([document(rid='R-601',oid='O-601')],source='new-request');second=self.publish([a,b])
        seen={x['summary']['request_key'] for x in page['items']};cursor=page['next_cursor']
        while cursor:
            page=self.pub.session_activity(first['publication_id'],'SESSION_A',limit=100,cursor=cursor,access_token=self.access_token)
            seen.update(x['summary']['request_key'] for x in page['items']);cursor=page['next_cursor']
        self.assertEqual(len(seen),601)
        self.assertEqual(self.pub.session_activity(second['publication_id'],'SESSION_A',access_token=self.access_token)['total_requests'],602)
        self.assertEqual(second['statistics']['recomputed_requests'],1)
        self.assert_full(second,[a,b])

    def test_scoped_selector_deduplicates_601_versions_within_statement_budget(self):
        docs=[document(rid=f'bounded-R-{i}',oid=f'bounded-O-{i}') for i in range(601)]
        a=self.ingest(docs,source='selector-A');b=self.ingest(docs,source='selector-B')
        scope=[self.store.request_key(f'bounded-R-{i}') for i in range(601)]
        with self.c.transaction():
            self.c.execute("SET LOCAL statement_timeout='5s'")
            rows=self.store._projection_event_rows([uuid.UUID(a['snapshot_id']),uuid.UUID(b['snapshot_id'])],scope)
        self.assertEqual(len(rows),601)
        self.assertEqual(len({row[1] for row in rows}),601)

    def test_ambiguous_requests_with_no_activity_time_remain_pageable(self):
        docs=[]
        for i in range(3):
            a=document(rid=f'R{i}',oid=f'O{i}');b=copy.deepcopy(a);b['_source']['ExecutionTime']='99';docs.extend([a,b])
        source=self.ingest(docs);pub=self.publish([source]);cursor=None;keys=set()
        while True:
            page=self.pub.requests(pub['publication_id'],limit=1,cursor=cursor,access_token=self.access_token)
            keys.update(r['summary']['request_key'] for r in page['items']);cursor=page['next_cursor']
            if not cursor:break
        self.assertEqual(len(keys),3);self.assert_full(pub,[source])

    def test_cursors_cannot_move_between_publications_sessions_or_evidence_pages(self):
        rows=[document(rid='A',oid='A'),document(rid='A',oid='SQL',path='DBPath.pishkhan24.application.ud_prc_configBadgeServices',message='(Command Text: ud_prc_configBadgeServices)(Code: 1)(Result: Ok)(SQL Parameters: @session=SESSION_A)'),document(rid='B',oid='B')]
        a=self.ingest(rows);first=self.publish([a]);page=self.pub.session_activity(first['publication_id'],'SESSION_A',limit=1,access_token=self.access_token)
        evidence=self.pub.request_evidence(first['publication_id'],'A',limit=1,access_token=self.access_token)
        b=self.ingest([document(rid='C',oid='C')],source='unrelated');second=self.publish([a,b])
        with self.assertRaises(FoundationError):self.pub.session_activity(second['publication_id'],'SESSION_A',cursor=page['next_cursor'],access_token=self.access_token)
        with self.assertRaises(FoundationError):self.pub.session_activity(first['publication_id'],'SESSION_B',cursor=page['next_cursor'],access_token=self.access_token)
        with self.assertRaises(FoundationError):self.pub.request_evidence(second['publication_id'],'A',cursor=evidence['next_cursor'],access_token=self.access_token)
        with self.assertRaises(FoundationError):self.pub.requests(first['publication_id'],cursor=page['next_cursor'],access_token=self.access_token)
        self.assertTrue(self.pub.request_evidence(first['publication_id'],'A',cursor=evidence['next_cursor'],access_token=self.access_token)['items'])

    def test_scoped_run_cannot_satisfy_a_full_projection_work_item(self):
        a=self.ingest([document()])
        work=self.store.enqueue_projection([a['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:50:00Z',mode='online_original',dedupe_key='full')
        claim=self.store.claim_work('worker')[0]
        partial=self.store.project([a['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:50:00Z',mode='online_original',request_keys=[self.store.request_key('request-A')])
        self.assertEqual(partial['projection_scope'],'request_subset')
        with self.assertRaises(FoundationError):self.store.complete_work(work['work_id'],'worker',claim['lease_generation'],partial['run_id'])
        with self.assertRaises(psycopg.Error),self.c.transaction():
            self.c.execute("""UPDATE p24_next.foundation_work_item SET state='completed',result_run_id=%s,lease_owner=NULL,lease_until=NULL
                WHERE namespace_id=%s AND work_id=%s""",(uuid.UUID(partial['run_id']),self.store.namespace_id,uuid.UUID(work['work_id'])))
        with self.assertRaises(FoundationError):self.store.candidates(partial['run_id'],access_token=self.access_token)

    def test_scoped_projection_refuses_to_hide_a_conflicting_request_variant(self):
        a=document(rid='A');b=copy.deepcopy(a);b['_source']['RequestID']='B';source=self.ingest([a,b])
        with self.assertRaises(FoundationError) as caught:
            self.store.project([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:50:00Z',request_keys=[self.store.request_key('A')])
        self.assertEqual(caught.exception.code,'request_scope_not_closed')

    def test_database_guards_entries_headers_commits_pointers_and_access_history(self):
        a=self.ingest([document()]);first=self.publish([a]);p=uuid.UUID(first['publication_id']);n=self.store.namespace_id
        self.pub.requests(p,access_token=self.access_token)
        commands=[('UPDATE p24_next.foundation_observation_publication SET state=\'draft\' WHERE namespace_id=%s',(n,)),
                  ('DELETE FROM p24_next.foundation_observation_entry WHERE namespace_id=%s',(n,)),
                  ('DELETE FROM p24_next.foundation_observation_commit WHERE namespace_id=%s',(n,)),
                  ('DELETE FROM p24_next.foundation_observation_current WHERE namespace_id=%s',(n,)),
                  ('DELETE FROM p24_next.foundation_observation_access WHERE namespace_id=%s',(n,))]
        for sql,args in commands:
            with self.subTest(command=sql),self.assertRaises(psycopg.Error),self.c.transaction():self.c.execute(sql,args)
        later=self.prepare([a])
        with self.assertRaises(psycopg.Error),self.c.transaction():
            self.c.execute('INSERT INTO p24_next.foundation_observation_commit(namespace_id,publication_id,generation) VALUES(%s,%s,2)',(n,uuid.UUID(later['publication_id'])))
        self.assertEqual(self.info()['generation'],1)
        self.assertEqual(self.pub.publish(later['publication_id'])['generation'],2)
        with self.assertRaises(psycopg.Error),self.c.transaction():
            self.c.execute('UPDATE p24_next.foundation_observation_current SET publication_id=%s,generation=1 WHERE namespace_id=%s',(p,n))

    def test_publication_metadata_requires_signed_access_and_logs_read(self):
        a=self.ingest([document()]);published=self.publish([a])
        with self.assertRaises(FoundationError) as denied:
            self.pub.info(published['publication_id'])
        self.assertEqual(denied.exception.code,'access_denied')
        result=self.info(published['publication_id'])
        self.assertEqual(result['publication_id'],published['publication_id'])
        row=self.c.execute("SELECT object_kind,object_token,authentication_state FROM p24_next.foundation_observation_access WHERE namespace_id=%s ORDER BY accessed_at DESC LIMIT 1",(self.store.namespace_id,)).fetchone()
        self.assertEqual((row[0],row[2]),('publication','verified_signed_credential'))
        self.assertNotIn(published['publication_id'],row[1])

    def test_synthetic_limits_fail_explicitly_without_partial_publication(self):
        a=self.ingest([document(),document(rid='B',oid='B')])
        with patch('p24_foundation.publication.MAX_HEADS',1),self.assertRaises(FoundationError):self.prepare([a])
        self.assertEqual(self.info()['generation'],0)
        with patch('p24_foundation.publication.MAX_CLOSURE_STEPS',0),self.assertRaises(FoundationError):self.prepare([a])
        self.assertEqual(self.info()['generation'],0)

    def test_other_namespace_cannot_read_or_publish_a_prepared_view(self):
        a=self.ingest([document()]);first=self.publish([a])
        other_namespace='other_'+uuid.uuid4().hex
        other=ObservationPublisher(FoundationStore(self.c,TEST_KEYS,other_namespace,Path(self.tmp.name)/'other',access_policy=test_access_policy(other_namespace)))
        with self.assertRaises(FoundationError):other.info(first['publication_id'],access_token=issue_test_access_token(other_namespace))
        with self.assertRaises(FoundationError):other.publish(first['publication_id'])
        with self.assertRaises(FoundationError):other.request(first['publication_id'],'request-A')

    def test_repeated_source_set_changes_match_full_reconstruction_across_checkpoints(self):
        generator=random.Random(2402);sources=[]
        for i in range(8):
            docs=[document(rid=f'R{j}',oid=f'origin-{j}') for j in generator.sample(range(10),4)]
            if i%3==0:
                docs[0]['_source']['message']='POST https://fixture.invalid/config HTTP/1.1 (G00002 | Unknown)'
            sources.append(self.ingest(docs,source=f'set-{i}'))
        publisher=ObservationPublisher(self.store,checkpoint_every=3)
        for _ in range(18):
            selected=generator.sample(sources,generator.randrange(9))
            result=self.publish(selected,publisher=publisher)
            self.assert_full(result,selected)
        self.assertEqual(self.info(publisher=publisher)['generation'],18)

    def test_cli_prepares_publishes_and_reads_a_pinned_session_without_printing_its_token(self):
        a=self.ingest([document()]);root=Path(self.tmp.name)
        keyfile=root/'fixture.keys.json';keyfile.write_text(json.dumps(dict(equality=TEST_KEYS.equality.hex(),encryption=TEST_KEYS.encryption.hex(),version=TEST_KEYS.version)))
        from cryptography.hazmat.primitives import serialization
        access_public=root/'access-public.pem'
        access_public.write_bytes(TEST_ACCESS_PRIVATE_KEY.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        access_file=root/'access.private';access_file.write_text(issue_test_access_token(self.namespace),encoding='utf-8');access_file.chmod(0o600)
        config=root/'db_config.local.py'
        config.write_text('DATABASE='+repr(self.database_config)+'\nNAMESPACE='+repr(self.namespace)+'\nKEYS_PATH='+repr(str(keyfile))+'\nVAULT_PATH='+repr(str(root/'vault'))+'\nACCESS_PUBLIC_KEY_PATH='+repr(str(access_public))+'\n')
        session=root/'session.private';session.write_text('SESSION_A')
        def call(*args):
            read_commands={'run','observation','request','evidence','candidates','session','observed-session','observed-request','observed-evidence','observed-requests','observed-candidates','observed-workflows','workflow-state-evidence'}
            if args and args[0] in read_commands:args=(args[0],'--access-token-file',str(access_file),*args[1:])
            result=subprocess.run([sys.executable,'-m','p24_foundation','--config',str(config),*args],cwd=ROOT,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('SESSION_A',result.stdout)
            return json.loads(result.stdout)
        prepared=call('prepare-observation','--sources',a['snapshot_id'],'--cutoff','2026-10-20T07:40:00Z',
                      '--knowledge-at','2026-10-20T07:50:00Z','--expected-generation','0','--mode','design_fixture')
        p=prepared['publication_id'];self.assertEqual(call('observation')['generation'],0)
        self.assertEqual(call('publish-observation','--publication',p)['generation'],1)
        self.assertEqual(call('observed-session','--publication',p,'--session-file',str(session))['total_requests'],1)
        self.assertEqual(call('observed-request','--publication',p,'--request-id','request-A')['summary']['final_outcome'],'success')
        self.assertEqual(call('observed-requests','--publication',p)['total_requests'],1)
        self.assertEqual(call('observed-workflows','--publication',p)['status'],'not_provided')

    def test_additive_schema_has_106_tables_and_prior_migrations_are_versioned(self):
        self.assertEqual(initialize(self.c)['version'],'p24-foundation.2u.1')
        self.assertEqual(self.c.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema='p24_next' AND table_type='BASE TABLE'").fetchone(),(106,))
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.design_version WHERE version_key LIKE 'p24-foundation.%'").fetchone(),(11,))
