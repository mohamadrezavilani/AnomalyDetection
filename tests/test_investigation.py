"""Essential identity, counting, outcome separation and read-access probes."""
import copy
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from p24_foundation.errors import FoundationError
from p24_foundation.investigation import InvestigationReader, operation_card, request_card, scoped_outcome
from p24_foundation.publication import ObservationPublisher
from p24_foundation.reconstruction import reconstruct, select_events
from p24_foundation.store import FoundationStore, initialize
from p24_foundation.time import parse_time
from tests.helpers import TEST_KEYS,MANIFEST,batch,document,fixture,normalized,issue_test_access_token,test_access_policy


def summaries(rows):
    return reconstruct(select_events(normalized(rows),parse_time('2026-10-20T07:45:00Z').epoch_ns))


class InvestigationContractTests(unittest.TestCase):
    def test_session_cards_keep_all_support_security_and_failure_requests(self):
        rows=summaries(list(fixture('session_activity.sanitized.json').records))
        before=copy.deepcopy(rows);cards=[request_card(r) for r in rows]
        self.assertEqual(len(cards),10)
        self.assertEqual(sum(c['activity_group']=='application_support' for c in cards),5)
        self.assertEqual(sum(c['client_result']['outcome']=='failure' for c in cards),4)
        self.assertEqual(len({c['session_key'] for c in cards}),1)
        self.assertEqual(rows,before)

    def test_recorded_zero_duration_is_preserved_and_missing_duration_stays_missing(self):
        row=document();row['_source']['ExecutionTime']='0'
        self.assertEqual(request_card(summaries([row])[0])['client_result']['duration_ms'],'0')
        del row['_source']['ExecutionTime']
        self.assertIsNone(request_card(summaries([row])[0])['client_result']['duration_ms'])

    def test_missing_registration_session_is_not_replaced_with_its_ip(self):
        source=list(fixture('registration.sanitized.json').records)
        cards=[request_card(s) for s in summaries(source)]
        self.assertEqual(len(cards),2)
        self.assertTrue(all(c['session_key'] is None and c['identity_state']=='missing' for c in cards))
        by_endpoint={c['endpoint']:c for c in cards}
        self.assertEqual(by_endpoint['Core.v2/DeviceRegister']['access_check_context']['actions'],[
            dict(value='v2/DeviceRegister',sql_observations=1,evidence_basis='ud_prc_userSessionHasAccess.SQL.Parameters.action',mapping_state='unverified_call_context')])
        self.assertEqual(by_endpoint['Core.v1/DeviceRegister']['access_check_context']['actions'][0]['value'],'v1/DeviceRegister')
        self.assertIn('not_verified_service_mapping',by_endpoint['Core.v1/DeviceRegister']['access_check_context']['meaning'])

    def test_access_action_is_only_exposed_for_the_access_check_procedure(self):
        access=document(rid='A',oid='access',path='DBPath.app.ud_prc_userSessionHasAccess',
            message='(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: Ok)(SQL Parameters: @action=v1/ConfigBasic)')
        unrelated=document(rid='A',oid='other',path='DBPath.app.ud_prc_other',
            message='(Command Text: ud_prc_other)(Code: 1)(Result: Ok)(SQL Parameters: @action=v9/NotARealAction)')
        summary=summaries([document(rid='A',oid='client'),access,unrelated])[0]
        card=request_card(summary)
        self.assertEqual(card['access_check_context']['actions'][0]['value'],'v1/ConfigBasic')
        ops=summary['operations']
        wrapped=[dict(origin_key='origin',event_version_id='version',selection_state='selected',selection_reason='unique',
                      source_time_epoch_ns='1',endpoint='DBPath.app.'+name,source_role='sql',event_kind='sql',
                      descriptor=normalized([row])[0]['payload']) for name,row in (
                          ('ud_prc_userSessionHasAccess',access),('ud_prc_other',unrelated))]
        cards=[operation_card(row) for row in wrapped]
        self.assertEqual(next(c for c in cards if c['endpoint'].endswith('ud_prc_userSessionHasAccess'))['access_check_action'],'v1/ConfigBasic')
        self.assertIsNone(next(c for c in cards if c['endpoint'].endswith('ud_prc_other'))['access_check_action'])

    def test_successful_sql_verification_chain_is_not_an_account_authentication_verdict(self):
        rows=[document(path='Core.v1/LoginByOTP Line:72')]
        for name in ('oneTimePasswordValidate','oneTimePasswordConsume','userSessionVerify'):
            proc='ud_prc_'+name
            rows.append(document(oid=proc,path='DBPath.app.'+proc,
                message='(Command Text: '+proc+')(Code: 1)(Result: Ok)(SQL Parameters: @session=SESSION_A @identifier=SYNTHETIC_PRIVATE_IDENTIFIER @otpCode=SYNTHETIC_OTP)'))
        card=request_card(summaries(rows)[0])
        self.assertTrue(card['lifecycle']['sql_otp_verification_chain_observed'])
        self.assertEqual(card['lifecycle']['authentication_state'],'not_established')
        self.assertEqual(card['lifecycle']['account_binding'],'not_available')
        self.assertNotIn('SYNTHETIC_PRIVATE_IDENTIFIER',json.dumps(card))
        self.assertNotIn('SYNTHETIC_OTP',json.dumps(card))

    def test_unknown_bindings_and_scopes_remain_unknown_without_extra_payload_fields(self):
        o=scoped_outcome(dict(code='599',role='provider',layer='provider_body',outcome='unknown',
            validation='unresolved',unexpected_payload='SYNTHETIC_SECRET',meaning_source={'entry_id':'entry','source_sha256':'a'*64,'raw':'SYNTHETIC_SECRET'}))
        self.assertEqual(o['outcome'],'unknown');self.assertEqual(o['group'],'provider_application')
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(o))
        self.assertEqual(scoped_outcome({'role':'unknown','layer':'unknown'})['group'],'unclassified')


class InvestigationPostgresTests(unittest.TestCase):
    connection=None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest('disposable PostgreSQL configuration required')
        initialize(cls.connection)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.namespace='journey_'+uuid.uuid4().hex
        self.token=issue_test_access_token(self.namespace)
        self.store=FoundationStore(self.connection,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
        self.pub=ObservationPublisher(self.store);self.reader=InvestigationReader(self.store)

    def ingest(self,rows,source='source-A'):
        return self.store.ingest(batch(rows),source_key=source,interval_start='2026-10-20T07:25:00Z',
            interval_end='2026-10-20T07:45:00Z',observed_at='2026-10-20T07:40:00Z',receive_time_basis='synthetic_fixture')

    def publish(self,sources):
        prepared=self.pub.prepare([s['snapshot_id'] for s in sources],event_cutoff='2026-10-20T07:40:00Z',
            knowledge_at='2026-10-20T07:45:00Z',expected_generation=self.pub._current()[1],mode='historical_revised')
        return self.pub.publish(prepared['publication_id'])['publication_id']

    def test_session_continuity_conflicting_context_counts_and_pinned_pagination(self):
        rows=[document(rid='A',oid='A',session='S',ip='198.51.100.1'),
              document(rid='B',oid='B',session='S',ip='198.51.100.2'),
              document(rid='C',oid='C',session='S',ip='198.51.100.2',path='Core.v1/LoginByUserCredential',
                message='POST https://fixture.invalid/login HTTP/1.1 (GR0054 | Error)'),
              document(rid='Q',oid='Q',session='S'),
              document(rid='Q',oid='Q-sql',session='S',path='DBPath.app.ud_prc_userSessionHasAccess',
                message='(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: Ok)(SQL Parameters: @session=OTHER_SESSION @action=v1/ConfigBasic)'),
              document(rid='Z',oid='Z',session='N/A',path='Core.v2/DeviceRegister')]
        source=self.ingest(rows);p=self.publish([source])
        page=self.reader.session(p,'S',limit=1,access_token=self.token)
        totals=page['totals']
        self.assertEqual((totals['assigned_request_projections'],totals['assigned_client_http_requests'],totals['conflicting_context_request_projections']),(3,3,1))
        self.assertEqual(totals['assigned_distinct_network_sources'],2)
        self.assertEqual(totals['client_http_outcomes'],{'success':2,'failure':1,'unknown_or_conflicting':0})
        self.assertEqual(totals['activity_groups']['application_support_request_projections'],2)
        context=self.reader.session(p,'S',identity_scope='conflicting',access_token=self.token)
        self.assertEqual(len(context['items']),1);self.assertIsNone(context['items'][0]['session_key'])
        self.assertEqual(context['totals'],totals)
        with self.assertRaises(FoundationError):self.reader.session(p,'S',identity_scope='conflicting',cursor=page['next_cursor'],access_token=self.token)
        added=self.ingest([document(rid='D',oid='D',session='S')],'source-B');new=self.publish([source,added])
        self.assertEqual(self.reader.session(new,'S',access_token=self.token)['totals']['assigned_client_http_requests'],4)
        seen={page['items'][0]['request_key']};cursor=page['next_cursor']
        while cursor:
            next_page=self.reader.session(p,'S',limit=1,cursor=cursor,access_token=self.token)
            self.assertEqual(next_page['totals'],totals)
            seen.update(i['request_key'] for i in next_page['items']);cursor=next_page['next_cursor']
        self.assertEqual(len(seen),3);self.assertNotIn(self.store.request_key('D'),seen)

    def test_operation_expansion_retains_provider_body_failure_and_log_success_with_provenance(self):
        source=self.ingest(list(fixture('boundary.sanitized.json').records));p=self.publish([source])
        rid=MANIFEST['anchors']['boundary_request_id']
        card=self.reader.request(p,rid,access_token=self.token)['item']
        self.assertEqual(card['client_result']['code'],'GD2016')
        self.assertEqual(card['client_result']['outcome'],'failure')
        items=[];cursor=None
        while True:
            page=self.reader.operations(p,rid,limit=7,cursor=cursor,access_token=self.token)
            self.assertEqual(page['total_event_versions'],14);items.extend(page['items']);cursor=page['next_cursor']
            if not cursor:break
        self.assertEqual(len(items),14)
        provider=next(i for i in items if i['source_role']=='provider')
        self.assertEqual([(o['code'],o['group']) for o in provider['outcomes']],[('G00000','provider_log'),('GD2016','provider_application')])
        self.assertTrue(all(i['provenance'] for i in items))
        self.assertNotIn('descriptor',provider)
        service=self.reader.services(p,access_token=self.token)['items'][0]
        self.assertEqual(service['client_outcomes']['failure'],1)
        self.assertEqual(service['provider_observations'],1)

    def test_session_read_authorizes_before_publication_lookup_and_rejects_cross_scope_cursors(self):
        wrong_role=issue_test_access_token(self.namespace,roles=('preservation_officer',))
        with patch.object(self.reader.publisher,'_header',side_effect=AssertionError('must not inspect publication')):
            with self.assertRaises(FoundationError):self.reader.session(str(uuid.uuid4()),'S',access_token=wrong_role)
        source=self.ingest([document(rid=str(i),oid=str(i),session='S') for i in range(2)])
        p=self.publish([source]);page=self.reader.session(p,'S',limit=1,access_token=self.token)
        with self.assertRaises(FoundationError):self.reader.session(p,'OTHER_SESSION',cursor=page['next_cursor'],access_token=self.token)

    def test_opaque_request_lookup_matches_raw_reader_and_preserves_access_and_cursors(self):
        source=self.ingest(list(fixture('boundary.sanitized.json').records));p=self.publish([source])
        rid=MANIFEST['anchors']['boundary_request_id'];key=self.store.request_key(rid)
        self.assertEqual(self.reader.request(p,rid,access_token=self.token),self.reader.request_by_key(p,key,access_token=self.token))
        raw=self.reader.operations(p,rid,limit=7,access_token=self.token)
        opaque=self.reader.operations_by_key(p,key,limit=7,access_token=self.token)
        self.assertEqual(raw,opaque)
        later=self.reader.operations_by_key(p,key,limit=7,cursor=opaque['next_cursor'],access_token=self.token)
        self.assertEqual(len(raw['items'])+len(later['items']),14)
        wrong=issue_test_access_token(self.namespace,roles=('preservation_officer',))
        with patch.object(self.reader.publisher,'_header',side_effect=AssertionError('authorize first')):
            with self.assertRaises(FoundationError):self.reader.request_by_key(p,key,access_token=wrong)
            with self.assertRaises(FoundationError):self.reader.operations_by_key(p,key,access_token=wrong)
        with self.assertRaises(FoundationError):self.reader.request_by_key(p,'request:wrong:123',access_token=self.token)

    def test_service_totals_exact_versions_unknown_endpoint_and_pinned_pages(self):
        rows=[document(rid='A',oid='A',session='S'),document(rid='B',oid='B',session='T',message='POST https://fixture.invalid/config HTTP/1.1 (GR0054 | Error)'),
              document(rid='A',oid='A-sql',session='S',path='DBPath.app.procedure',message='(Command Text: procedure)(Code: 1)(Result: Ok)'),
              document(rid='C',oid='C',session='N/A',path='Core.v2/ConfigBasic'),
              document(rid='Q',oid='Q-sql',session='S',path='DBPath.app.procedure',message='(Command Text: procedure)(Code: 1)(Result: Ok)')]
        source=self.ingest(rows);p=self.publish([source])
        catalog=self.reader.services(p,access_token=self.token)
        self.assertEqual(catalog['total_endpoints'],3)
        groups={g['endpoint']:g for g in catalog['items']}
        self.assertEqual(groups['Core.v1/ConfigBasic']['client_http_requests'],2)
        self.assertEqual(groups['Core.v1/ConfigBasic']['sql_observations'],1)
        self.assertEqual(groups['Core.v1/ConfigBasic']['known_sessions'],2)
        # A known code in an unreviewed route binding remains unknown here.
        self.assertEqual(groups['Core.v1/ConfigBasic']['client_outcomes'],dict(success=1,failure=0,unknown_or_conflicting=1))
        self.assertEqual(groups[None]['client_http_requests'],0)
        self.assertEqual(groups[None]['request_projections'],1)
        self.assertEqual(groups['Core.v2/ConfigBasic']['missing_identity_requests'],1)
        key=groups['Core.v1/ConfigBasic']['service_key'];page=self.reader.service(p,key,limit=1,access_token=self.token)
        self.assertEqual(page['service']['client_http_requests'],2)
        extra=self.ingest([document(rid='D',oid='D')],'added-service');new=self.publish([source,extra])
        self.assertEqual(self.reader.service(new,key,access_token=self.token)['service']['client_http_requests'],3)
        following=self.reader.service(p,key,limit=1,cursor=page['next_cursor'],access_token=self.token)
        self.assertEqual(len(following['items']),1);self.assertEqual(following['service'],page['service'])
        self.assertNotEqual(following['items'][0]['request_key'],page['items'][0]['request_key'])
        with self.assertRaises(FoundationError):self.reader.service(new,key,cursor=page['next_cursor'],access_token=self.token)
        with self.assertRaises(FoundationError):self.reader.service(p,groups[None]['service_key'],cursor=page['next_cursor'],access_token=self.token)
        first=self.reader.services(p,limit=1,access_token=self.token)
        following=self.reader.services(p,limit=1,cursor=first['next_cursor'],access_token=self.token)
        self.assertEqual(following['total_endpoints'],3);self.assertNotEqual(first['items'][0]['service_key'],following['items'][0]['service_key'])

    def test_registration_context_keeps_competing_sessions_and_does_not_assign_registration(self):
        rows=[document(rid='R1',oid='R1',session='N/A',at='2026-10-20T07:29:58Z',path='Core.v2/DeviceRegister'),
              document(rid='R2',oid='R2',session='N/A',at='2026-10-20T07:29:58.1Z',path='Core.v1/DeviceRegister'),
              document(rid='S',oid='S',session='S',at='2026-10-20T07:29:59Z'),
              document(rid='T',oid='T',session='T',at='2026-10-20T07:30:00Z')]
        source=self.ingest(rows);p=self.publish([source]);before=self.reader.session(p,'S',access_token=self.token)
        page=self.reader.registration_context(p,'S',limit=1,access_token=self.token)
        self.assertEqual(page['total_candidates'],2)
        item=page['items'][0];self.assertEqual(page['candidate_session_counts'][item['registration_request_key']],2)
        self.assertFalse(item['basis']['verified_session_issuance'])
        self.assertEqual(self.reader.request_by_key(p,item['registration_request_key'],access_token=self.token)['item']['identity_state'],'missing')
        following=self.reader.registration_context(p,'S',limit=1,cursor=page['next_cursor'],access_token=self.token)
        self.assertNotEqual(item['registration_request_key'],following['items'][0]['registration_request_key'])
        with self.assertRaises(FoundationError):self.reader.registration_context(p,'T',cursor=page['next_cursor'],access_token=self.token)
        with self.assertRaises(FoundationError):self.pub.candidates(p,cursor=page['next_cursor'],access_token=self.token)
        self.assertEqual(self.reader.session(p,'S',access_token=self.token)['totals'],before['totals'])
        self.assertEqual(before['totals']['assigned_client_http_requests'],1)

    def test_new_exploration_routes_authorize_before_publication_metadata(self):
        wrong=issue_test_access_token(self.namespace,roles=('preservation_officer',))
        with patch.object(self.reader.publisher,'_header',side_effect=AssertionError('authorize first')):
            for operation in (lambda:self.reader.services(str(uuid.uuid4()),access_token=wrong),
                              lambda:self.reader.service(str(uuid.uuid4()),'unknown-service',access_token=wrong),
                              lambda:self.reader.registration_context(str(uuid.uuid4()),'S',access_token=wrong)):
                with self.assertRaises(FoundationError):operation()
